using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using No2SQL.Hosting;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// NO2SQL_OAUTH_AUTHORITY: JWT access tokens from an external identity provider, checked for exact
/// iss, single-string aud = the public MCP URL, typ, an asymmetric algorithm, lifetime (60 s skew)
/// and the required scope. Includes the token tests 6 and 7 of the P2-5 threat model.
/// </summary>
public sealed class JwtAuthTests : IDisposable
{
    private const string ChallengeWithoutError =
        "Bearer resource_metadata=\"https://mcp.example.test/.well-known/oauth-protected-resource/mcp\", scope=\"mcp:tools\"";

    private const string InvalidTokenChallenge =
        "Bearer error=\"invalid_token\", resource_metadata=\"https://mcp.example.test/.well-known/oauth-protected-resource/mcp\", scope=\"mcp:tools\"";

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    private readonly TestIdentityProvider _idp = new();
    private readonly CapturedLogs _logs = new();
    private readonly FakeTimeProvider _clock = new(DateTimeOffset.UtcNow);
    private readonly No2SqlHttpApp _app;
    private readonly HttpClient _client;

    public JwtAuthTests()
    {
        _app = new No2SqlHttpApp(
            services =>
            {
                _idp.Register(services);
                services.AddSingleton<TimeProvider>(_clock);
                services.AddLogging(logging => logging.AddProvider(_logs));
            },
            auth: TestIdentityProvider.Options());
        _client = _app.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _app.Dispose();
    }

    private DateTime Now => _clock.GetUtcNow().UtcDateTime;

    [Fact]
    public async Task A_valid_access_token_opens_the_MCP_endpoint()
    {
        var reply = await CallAsync(_idp.Token(issuedAt: Now));

        Assert.Equal(HttpStatusCode.OK, reply.Http.StatusCode);
        Assert.Equal("MCP connectivity test successful!", (string?)reply.Result["content"]?[0]?["text"]);
    }

    [Fact]
    public async Task The_caller_id_for_audit_lines_is_the_identity_providers_sub()
    {
        var caller = await AuthProbe.AuthenticateAsync(_app, "Bearer " + _idp.Token(issuedAt: Now));

        Assert.NotNull(caller);
        Assert.Equal("owner", caller.FindFirst("sub")?.Value);
    }

    [Theory]
    [InlineData("line\nbreak")]
    [InlineData("")]
    public async Task A_sub_that_is_empty_or_has_control_characters_is_not_copied(string subject)
    {
        var payload = JsonNode.Parse(TestIdentityProvider.GoodPayload(Now))!;
        payload["sub"] = subject;
        var token = _idp.SignedWithHeader("""{"alg":"ES256","kid":"ec-1","typ":"at+jwt"}""", payload.ToJsonString());

        var caller = await AuthProbe.AuthenticateAsync(_app, "Bearer " + token);

        Assert.NotNull(caller);
        Assert.Equal("identity-provider", caller.FindFirst("sub")?.Value);
    }

    [Fact]
    public async Task No_token_gets_401_pointing_at_the_resource_metadata()
    {
        var reply = await _client.ListToolsAsync(Cancel);

        Assert.Equal(HttpStatusCode.Unauthorized, reply.Http.StatusCode);
        Assert.Equal(ChallengeWithoutError, reply.Http.Headers.WwwAuthenticate.ToString());
        Assert.Equal("no-store", reply.Http.Headers.CacheControl?.ToString());
        Assert.Null(reply.Message);
    }

    [Fact]
    public async Task The_resource_metadata_has_exactly_the_agreed_keys_from_configuration()
    {
        foreach (var path in new[] { "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource" })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            request.Headers.Host = "evil.example";   // never used: every URL comes from NO2SQL_PUBLIC_URL
            using var response = await _client.SendAsync(request, Cancel);
            var body = await response.Content.ReadAsStringAsync(Cancel);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("application/json", response.Content.Headers.ContentType?.ToString());
            Assert.Equal(
                """{"resource":"https://mcp.example.test/mcp","authorization_servers":["https://login.example.test/"],"scopes_supported":["mcp:tools"],"bearer_methods_supported":["header"],"resource_name":"No2SQL"}""",
                body);
        }
    }

    [Theory]
    [InlineData("at+jwt", "ES256")]
    [InlineData("application/at+jwt", "ES256")]
    [InlineData("JWT", "RS256")]
    [InlineData("jwt", "PS256")]
    [InlineData("AT+JWT", "RS512")]
    public async Task Allowed_token_types_and_asymmetric_algorithms(string type, string algorithm)
    {
        SecurityKey key = algorithm.StartsWith("ES", StringComparison.Ordinal) ? _idp.EcKey : _idp.RsaKey;

        var reply = await CallAsync(_idp.Token(type: type, issuedAt: Now, signing: new SigningCredentials(key, algorithm)));

        Assert.Equal(HttpStatusCode.OK, reply.Http.StatusCode);
    }

    [Theory]
    [InlineData("scope", "openid mcp:tools offline_access")]
    [InlineData("scp", "mcp:tools")]
    public async Task The_scope_may_come_in_scope_or_scp(string claim, string value)
    {
        var reply = await CallAsync(_idp.Token(scope: value, scopeClaim: claim, issuedAt: Now));

        Assert.Equal(HttpStatusCode.OK, reply.Http.StatusCode);
    }

    [Fact]
    public async Task An_scp_array_with_the_scope_is_accepted()
    {
        var reply = await CallAsync(_idp.Token(scope: new[] { "profile", "mcp:tools" }, scopeClaim: "scp", issuedAt: Now));

        Assert.Equal(HttpStatusCode.OK, reply.Http.StatusCode);
    }

    [Theory]
    [InlineData("")]                      // no scope claim at all
    [InlineData("openid profile")]
    [InlineData("mcp:tools:extra")]
    [InlineData("MCP:TOOLS")]
    public async Task A_token_without_the_scope_gets_403_insufficient_scope(string scope)
    {
        var reply = await CallAsync(_idp.Token(scope: scope, issuedAt: Now));

        Assert.Equal(HttpStatusCode.Forbidden, reply.Http.StatusCode);
        Assert.Equal(
            "Bearer error=\"insufficient_scope\", resource_metadata=\"https://mcp.example.test/.well-known/oauth-protected-resource/mcp\", scope=\"mcp:tools\"",
            reply.Http.Headers.WwwAuthenticate.ToString());
        Assert.Null(reply.Message);
    }

    public static TheoryData<string, string> WrongAudiences => new()
    {
        { "https://other.example.test/mcp", "the access token is for another audience" },
        { "https://mcp.example.test/mcp/", "the access token is for another audience" },
        { "https://mcp.example.test", "the access token is for another audience" },
        { "HTTPS://MCP.EXAMPLE.TEST/mcp", "the access token is for another audience" },
    };

    [Theory]
    [MemberData(nameof(WrongAudiences))]
    public async Task A_token_for_another_audience_gets_401(string audience, string logged)
    {
        var reply = await CallAsync(_idp.Token(audience: audience, issuedAt: Now));

        AssertInvalidToken(reply);
        Assert.Contains(_logs.Lines, line => line.Contains(logged));
    }

    [Fact]
    public async Task An_audience_array_is_refused_even_when_it_contains_the_MCP_URL()
    {
        var reply = await CallAsync(_idp.Token(audience: new[] { TestIdentityProvider.McpUrl }, issuedAt: Now));

        AssertInvalidToken(reply);
    }

    [Theory]
    [InlineData("https://login.example.test")]        // the configured issuer without its trailing slash
    [InlineData("https://login.example.test/other")]
    [InlineData("https://evil.example/")]
    public async Task The_issuer_must_match_exactly(string issuer)
    {
        var reply = await CallAsync(_idp.Token(issuer: issuer, issuedAt: Now));

        AssertInvalidToken(reply);
        Assert.Contains(_logs.Lines, line => line.Contains("the access token is from another issuer"));
    }

    [Fact]
    public async Task The_hand_signed_control_token_is_accepted()
    {
        // Shows that SignedWithHeader makes valid tokens, so the typ test below fails for the typ alone.
        var token = _idp.SignedWithHeader("""{"alg":"ES256","kid":"ec-1","typ":"at+jwt"}""", TestIdentityProvider.GoodPayload(Now));

        Assert.Equal(HttpStatusCode.OK, (await CallAsync(token)).Http.StatusCode);
    }

    [Fact]
    public async Task A_token_without_typ_gets_401()
    {
        var token = _idp.SignedWithHeader("""{"alg":"ES256","kid":"ec-1"}""", TestIdentityProvider.GoodPayload(Now));

        AssertInvalidToken(await CallAsync(token));
    }

    [Theory]
    [InlineData("at+jwt; charset=x")]
    [InlineData("id_token+jwt")]
    [InlineData("dpop+jwt")]
    public async Task Other_typ_values_get_401(string type)
    {
        var reply = await CallAsync(_idp.Token(type: type, issuedAt: Now));

        AssertInvalidToken(reply);
    }

    [Fact]
    public async Task Expiry_is_checked_with_60_seconds_of_skew_against_the_injected_clock()
    {
        var expired61 = _idp.Token(issuedAt: Now.AddMinutes(-10), expires: Now.AddSeconds(-61));
        var expired30 = _idp.Token(issuedAt: Now.AddMinutes(-10), expires: Now.AddSeconds(-30));

        AssertInvalidToken(await CallAsync(expired61));
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(expired30)).Http.StatusCode);
        Assert.Contains(_logs.Lines, line => line.Contains("the access token has expired"));
    }

    [Fact]
    public async Task Moving_the_clock_past_the_expiry_makes_a_good_token_fail()
    {
        var token = _idp.Token(issuedAt: Now, expires: Now.AddMinutes(5));
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(token)).Http.StatusCode);

        _clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(61));

        AssertInvalidToken(await CallAsync(token));
    }

    [Fact]
    public async Task A_token_that_is_not_valid_yet_gets_401()
    {
        var reply = await CallAsync(_idp.Token(issuedAt: Now.AddMinutes(5), expires: Now.AddMinutes(15)));

        AssertInvalidToken(reply);
    }

    [Fact]
    public async Task Alg_none_gets_401()
    {
        var payload = new JsonObject
        {
            ["iss"] = TestIdentityProvider.Authority,
            ["aud"] = TestIdentityProvider.McpUrl,
            ["sub"] = "owner",
            ["scope"] = "mcp:tools",
            ["exp"] = new DateTimeOffset(Now.AddMinutes(10)).ToUnixTimeSeconds(),
        };

        var reply = await CallAsync(TestIdentityProvider.UnsignedToken(payload.ToJsonString()));

        AssertInvalidToken(reply);
    }

    [Theory]
    [InlineData(SecurityAlgorithms.HmacSha256)]
    [InlineData(SecurityAlgorithms.HmacSha384)]
    [InlineData(SecurityAlgorithms.HmacSha512)]
    public async Task HMAC_tokens_get_401_even_when_the_HMAC_key_is_trusted(string algorithm)
    {
        // Key confusion: an HMAC key made of the public key bytes, as an attacker would build it. It is
        // even put into the trusted key set with its own kid, so the signature itself is valid and only
        // the algorithm allow-list can refuse the token.
        var hmac = new SymmetricSecurityKey(_idp.RsaKey.Rsa.ExportSubjectPublicKeyInfo()) { KeyId = "hmac-1" };
        _idp.TrustedKeys.Add(hmac);
        using var app = new No2SqlHttpApp(_idp.Register, auth: TestIdentityProvider.Options());
        using var client = app.CreateClient();

        var reply = await CallAsync(_idp.Token(issuedAt: DateTime.UtcNow, signing: new SigningCredentials(hmac, algorithm)), client);

        AssertInvalidToken(reply);
    }

    [Fact]
    public async Task A_key_the_provider_does_not_publish_gets_401()
    {
        var stranger = new ECDsaSecurityKey(System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256)) { KeyId = "ec-1" };

        var reply = await CallAsync(_idp.Token(issuedAt: Now, signing: new SigningCredentials(stranger, SecurityAlgorithms.EcdsaSha256)));

        AssertInvalidToken(reply);
    }

    [Fact]
    public async Task A_tampered_payload_gets_401()
    {
        var parts = _idp.Token(scope: "openid", issuedAt: Now).Split('.');
        var payload = JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!;
        payload["scope"] = "mcp:tools";
        var tampered = parts[0] + "." + Base64UrlEncoder.Encode(payload.ToJsonString()) + "." + parts[2];

        AssertInvalidToken(await CallAsync(tampered));
    }

    [Fact]
    public async Task Failures_are_logged_with_reason_and_address_but_never_the_token()
    {
        var token = _idp.Token(audience: "https://other.example.test/mcp", issuedAt: Now);

        await CallAsync(token);

        var line = Assert.Single(_logs.Lines, l => l.Contains("401 for"));
        Assert.Contains("the access token is for another audience", line);
        Assert.DoesNotContain(_logs.Lines, l => l.Contains(token) || l.Contains(token.Split('.')[1]) || l.Contains(token.Split('.')[2]));
    }

    [Fact]
    public async Task The_static_token_still_works_next_to_the_identity_provider()
    {
        var staticToken = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        using var app = new No2SqlHttpApp(_idp.Register, auth: TestIdentityProvider.Options(staticToken));
        using var client = app.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await CallAsync(staticToken, client)).Http.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(_idp.Token(issuedAt: DateTime.UtcNow), client)).Http.StatusCode);
        AssertInvalidToken(await CallAsync(staticToken + "x", client));
    }

    [Fact]
    public async Task The_health_check_needs_no_token()
    {
        using var response = await _client.GetAsync("/healthz", Cancel);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static void AssertInvalidToken(McpReply reply)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, reply.Http.StatusCode);
        Assert.Equal(InvalidTokenChallenge, reply.Http.Headers.WwwAuthenticate.ToString());
        Assert.Null(reply.Message);
    }

    private Task<McpReply> CallAsync(string token, HttpClient? client = null) =>
        (client ?? _client).RpcAsync(
            "tools/call",
            new JsonObject { ["name"] = "test_connectivity", ["arguments"] = new JsonObject() },
            request => request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token),
            Cancel);
}
