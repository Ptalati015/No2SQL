using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using No2SQL.Hosting.OAuth;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// The token endpoint, the tokens it issues and what /mcp accepts (P2-5 threat model R19 to R22, R24, R28;
/// tests 4, 5, 6, 7, the token half of 14, and 18).
/// </summary>
public sealed class OAuthTokenTests : IDisposable
{
    private const string InvalidTokenChallenge =
        "Bearer error=\"invalid_token\", resource_metadata=\"https://mcp.example.test/.well-known/oauth-protected-resource/mcp\", scope=\"mcp:tools\"";

    private const string InvalidGrant =
        """{"error":"invalid_grant","error_description":"The authorization code or refresh token is invalid, expired, used or was issued to another client."}""";

    private const string ThrowJsonPath = "/test-only/throw-json";
    private const string ThrowHtmlPath = "/test-only/throw-html";

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    // The two throwing endpoints exist in this test host only (R24); the shipped binary has no fault hook.
    private readonly BuiltinAuthServer _server = new(configurePipeline: app =>
    {
        app.Map(ThrowJsonPath, branch => branch.Run(OAuthServerEndpoints.Guard(
            OAuthServerEndpoints.ErrorStyle.Json, (_, _) => throw new InvalidOperationException("detail-that-must-not-leak"))));
        app.Map(ThrowHtmlPath, branch => branch.Run(OAuthServerEndpoints.Guard(
            OAuthServerEndpoints.ErrorStyle.Html, (_, _) => throw new InvalidOperationException("detail-that-must-not-leak"))));
    });

    public void Dispose() => _server.Dispose();

    private static Dictionary<string, string?> CodeFields(FlowResult flow) => new()
    {
        ["grant_type"] = "authorization_code",
        ["code"] = flow.Code,
        ["code_verifier"] = flow.Verifier,
        ["client_id"] = flow.ClientId,
        ["redirect_uri"] = flow.RedirectUri,
        ["resource"] = BuiltinAuthServer.McpUrl,
    };

    private async Task<(HttpStatusCode Status, string Body)> TokenAsync(Dictionary<string, string?> fields)
    {
        using var response = await _server.TokenRawAsync(fields);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        return (response.StatusCode, await response.Content.ReadAsStringAsync(Cancel));
    }

    private async Task<HttpResponseMessage> TokenBodyAsync(string body, string contentType = "application/x-www-form-urlencoded", string ip = BuiltinAuthServer.DefaultClientIp)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, OAuthServerEndpoints.TokenPath) { Content = new StringContent(body, Encoding.UTF8) };
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        request.Headers.Add(BuiltinAuthServer.ClientIpHeader, ip);
        return await _server.Client.SendAsync(request, Cancel);
    }

    private static string[] Keys(JsonNode node) => [.. node.AsObject().Select(p => p.Key).Order(StringComparer.Ordinal)];

    // ---- R22: what a code buys ----

    [Fact]
    public async Task A_code_buys_an_ES256_access_token_with_exactly_the_R22_claims_and_a_refresh_token()
    {
        var flow = await _server.AuthorizeFullyAsync();

        using var response = await _server.TokenRawAsync(CodeFields(flow));
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Cancel))!;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal(new[] { "access_token", "expires_in", "refresh_token", "scope", "token_type" }, Keys(body));
        Assert.Equal("Bearer", (string)body["token_type"]!);
        Assert.Equal(3600, (int)body["expires_in"]!);
        Assert.Equal("mcp:tools offline_access", (string)body["scope"]!);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", (string)body["refresh_token"]!);   // 32 random bytes

        var accessToken = (string)body["access_token"]!;
        var (header, payload) = BuiltinAuthServer.Decode(accessToken);
        Assert.Equal(new[] { "alg", "kid", "typ" }, Keys(header));
        Assert.Equal("ES256", (string)header["alg"]!);
        Assert.Equal("at+jwt", (string)header["typ"]!);
        Assert.Equal(_server.ActiveKid(), (string)header["kid"]!);

        var now = _server.Clock.GetUtcNow().ToUnixTimeSeconds();
        Assert.Equal(new[] { "aud", "client_id", "exp", "iat", "iss", "jti", "scope", "sub" }, Keys(payload));
        Assert.Equal(BuiltinAuthServer.PublicUrl, (string)payload["iss"]!);
        Assert.Equal(JsonValueKind.String, payload["aud"]!.GetValueKind());
        Assert.Equal(BuiltinAuthServer.McpUrl, (string)payload["aud"]!);
        Assert.Equal("owner", (string)payload["sub"]!);
        Assert.Equal(flow.ClientId, (string)payload["client_id"]!);
        Assert.Equal("mcp:tools offline_access", (string)payload["scope"]!);
        Assert.Matches("^[A-Za-z0-9_-]{22}$", (string)payload["jti"]!);
        Assert.Equal(now, (long)payload["iat"]!);
        Assert.Equal(now + 3600, (long)payload["exp"]!);

        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(accessToken));
    }

    [Fact]
    public async Task The_access_token_lifetime_is_the_configured_one_and_ends_60_seconds_after_exp()
    {
        using var server = new BuiltinAuthServer(accessTokenLifetime: TimeSpan.FromMinutes(5));
        var flow = await server.AuthorizeFullyAsync();
        var (_, body) = await server.ExchangeAsync(flow);
        var accessToken = (string)body!["access_token"]!;

        Assert.Equal(300, (int)body["expires_in"]!);
        server.Clock.Advance(TimeSpan.FromSeconds(300 + 30));
        Assert.Equal(HttpStatusCode.OK, await server.McpStatusAsync(accessToken));   // inside the 60 s skew
        server.Clock.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal(HttpStatusCode.Unauthorized, await server.McpStatusAsync(accessToken));
    }

    [Fact]
    public async Task A_sign_in_that_asks_for_mcp_tools_only_still_gets_a_refresh_token()
    {
        // claude.ai and ChatGPT ask for mcp:tools without offline_access and expect to stay connected.
        var signedIn = await _server.SignInAsync(scope: "mcp:tools");

        var (status, body) = await _server.RefreshAsync(signedIn.RefreshToken, signedIn.ClientId);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("mcp:tools", (string)body!["scope"]!);
        Assert.Equal("mcp:tools", (string)BuiltinAuthServer.Decode(signedIn.AccessToken).Payload["scope"]!);
    }

    [Fact]
    public async Task The_bearer_token_setting_keeps_working_next_to_the_built_in_sign_in()
    {
        const string token = "static-token-0123456789abcdef0123456789abcdef";
        using var server = new BuiltinAuthServer(staticToken: token);
        var signedIn = await server.SignInAsync();

        Assert.Equal(HttpStatusCode.OK, await server.McpStatusAsync(token));
        Assert.Equal(HttpStatusCode.OK, await server.McpStatusAsync(signedIn.AccessToken));
        Assert.Equal(HttpStatusCode.Unauthorized, await server.McpStatusAsync(token + "x"));
    }

    // ---- R19: authorization codes ----

    [Fact]
    public async Task A_code_works_60_seconds_after_it_was_issued_and_not_at_61()
    {
        var atTheLimit = await _server.AuthorizeFullyAsync();
        _server.Clock.Advance(TimeSpan.FromSeconds(60));
        Assert.Equal(HttpStatusCode.OK, (await _server.ExchangeAsync(atTheLimit)).Status);

        var late = await _server.AuthorizeFullyAsync();
        _server.Clock.Advance(TimeSpan.FromSeconds(61));
        var (status, body) = await TokenAsync(CodeFields(late));
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(InvalidGrant, body);
    }

    [Fact]
    public async Task A_code_used_twice_is_refused_and_the_tokens_of_its_first_use_stop_working()
    {
        var signedIn = await _server.SignInAsync();
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(signedIn.AccessToken));

        var (status, body) = await TokenAsync(CodeFields(signedIn.Flow));

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(InvalidGrant, body);
        using var mcp = await _server.CallMcpAsync(signedIn.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, mcp.StatusCode);
        Assert.Equal(InvalidTokenChallenge, mcp.Headers.WwwAuthenticate.ToString());
        Assert.Equal(HttpStatusCode.BadRequest, (await _server.RefreshAsync(signedIn.RefreshToken, signedIn.ClientId)).Status);
        Assert.Contains(_server.Logs.Lines, line => line.Contains("Authorization code presented again"));
    }

    [Fact]
    public async Task A_reused_code_also_revokes_the_tokens_refreshed_since()
    {
        var signedIn = await _server.SignInAsync();
        var (_, refreshed) = await _server.RefreshAsync(signedIn.RefreshToken, signedIn.ClientId);
        var laterAccessToken = (string)refreshed!["access_token"]!;
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(laterAccessToken));

        await TokenAsync(CodeFields(signedIn.Flow));

        Assert.Equal(HttpStatusCode.Unauthorized, await _server.McpStatusAsync(laterAccessToken));
        Assert.Equal(HttpStatusCode.BadRequest, (await _server.RefreshAsync((string)refreshed["refresh_token"]!, signedIn.ClientId)).Status);
    }

    [Fact]
    public async Task An_unknown_code_a_wrong_verifier_another_client_and_another_redirect_URI_get_one_identical_answer()
    {
        var otherClient = await _server.RegisterAsync("https://other.example.test/callback");

        var unknownCode = CodeFields(await _server.AuthorizeFullyAsync());
        unknownCode["code"] = GrantStore.NewToken();
        var wrongVerifier = CodeFields(await _server.AuthorizeFullyAsync());
        wrongVerifier["code_verifier"] = BuiltinAuthServer.NewPkce().Verifier;
        var malformedVerifier = CodeFields(await _server.AuthorizeFullyAsync());
        malformedVerifier["code_verifier"] = "too-short";
        var anotherClient = CodeFields(await _server.AuthorizeFullyAsync());
        anotherClient["client_id"] = otherClient;
        var anotherRedirect = CodeFields(await _server.AuthorizeFullyAsync());
        anotherRedirect["redirect_uri"] = "https://client.example.test/callback/";

        foreach (var fields in new[] { unknownCode, wrongVerifier, malformedVerifier, anotherClient, anotherRedirect })
        {
            var (status, body) = await TokenAsync(fields);
            Assert.Equal(HttpStatusCode.BadRequest, status);
            Assert.Equal(InvalidGrant, body);
        }
    }

    [Fact]
    public async Task A_code_presented_with_the_wrong_verifier_is_used_up()
    {
        var flow = await _server.AuthorizeFullyAsync();
        var wrong = CodeFields(flow);
        wrong["code_verifier"] = BuiltinAuthServer.NewPkce().Verifier;
        await TokenAsync(wrong);

        var (status, body) = await TokenAsync(CodeFields(flow));

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(InvalidGrant, body);
    }

    [Fact]
    public async Task Codes_are_32_random_bytes_and_are_never_written_to_the_data_directory()
    {
        var signedIn = await _server.SignInAsync();

        Assert.Matches("^[A-Za-z0-9_-]{43}$", signedIn.Flow.Code);
        foreach (var file in Directory.GetFiles(_server.DataDirectory))
        {
            var text = File.ReadAllText(file);
            Assert.DoesNotContain(signedIn.Flow.Code, text);
            Assert.DoesNotContain(GrantStore.Hash(signedIn.Flow.Code), text);
            Assert.DoesNotContain(signedIn.Flow.Verifier, text);
        }
    }

    // ---- R20: the token endpoint's own rules ----

    [Theory]
    [InlineData("grant_type", "invalid_request")]
    [InlineData("code", "invalid_request")]
    [InlineData("code_verifier", "invalid_request")]
    [InlineData("client_id", "invalid_request")]
    [InlineData("redirect_uri", "invalid_request")]
    public async Task A_code_exchange_without_a_required_field_is_refused(string missing, string error)
    {
        var fields = CodeFields(await _server.AuthorizeFullyAsync());
        fields[missing] = null;

        var (status, body) = await TokenAsync(fields);

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(error, (string)JsonNode.Parse(body)!["error"]!);
    }

    [Fact]
    public async Task A_repeated_field_is_refused()
    {
        var flow = await _server.AuthorizeFullyAsync();
        var form = string.Join("&", CodeFields(flow).Select(f => $"{f.Key}={Uri.EscapeDataString(f.Value!)}")) + "&client_id=" + flow.ClientId;

        using var response = await TokenBodyAsync(form);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (string)JsonNode.Parse(await response.Content.ReadAsStringAsync(Cancel))!["error"]!);
    }

    [Theory]
    [InlineData("client_credentials")]
    [InlineData("password")]
    [InlineData("urn:ietf:params:oauth:grant-type:device_code")]
    [InlineData("urn:ietf:params:oauth:grant-type:jwt-bearer")]
    public async Task Other_grant_types_are_refused(string grantType)
    {
        var (status, body) = await TokenAsync(new() { ["grant_type"] = grantType, ["client_id"] = "anything" });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("""{"error":"unsupported_grant_type","error_description":"Only authorization_code and refresh_token are supported."}""", body);
    }

    [Theory]
    [InlineData("https://other.example.test/mcp")]
    [InlineData("https://mcp.example.test/")]
    [InlineData("https://mcp.example.test/mcp?x=1")]
    public async Task A_resource_other_than_the_MCP_URL_is_refused_and_the_code_is_not_used_up(string resource)
    {
        var flow = await _server.AuthorizeFullyAsync();
        var fields = CodeFields(flow);
        fields["resource"] = resource;

        var (status, body) = await TokenAsync(fields);

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("""{"error":"invalid_target","error_description":"The resource parameter must be the MCP endpoint of this server."}""", body);
        Assert.DoesNotContain("other.example.test", body);
    }

    [Fact]
    public async Task Only_form_encoded_bodies_up_to_16_KiB_are_read()
    {
        using var json = await TokenBodyAsync("""{"grant_type":"authorization_code"}""", "application/json");
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, json.StatusCode);
        Assert.Equal("no-store", json.Headers.CacheControl?.ToString());

        using var tooLarge = await TokenBodyAsync("grant_type=authorization_code&code=" + new string('a', 16 * 1024));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, tooLarge.StatusCode);
        Assert.Equal("no-store", tooLarge.Headers.CacheControl?.ToString());

        using var atTheLimit = await TokenBodyAsync("grant_type=x&code=" + new string('a', 16 * 1024 - "grant_type=x&code=".Length));
        Assert.Equal(HttpStatusCode.BadRequest, atTheLimit.StatusCode);
    }

    [Fact]
    public async Task The_31st_token_request_in_a_minute_from_one_address_is_refused()
    {
        for (var i = 0; i < 30; i++)
        {
            using var counted = await TokenBodyAsync("grant_type=refresh_token&client_id=c&refresh_token=unknown");
            Assert.Equal(HttpStatusCode.BadRequest, counted.StatusCode);
        }

        using var refused = await TokenBodyAsync("grant_type=refresh_token&client_id=c&refresh_token=unknown");
        Assert.Equal((HttpStatusCode)429, refused.StatusCode);
        Assert.Equal("no-store", refused.Headers.CacheControl?.ToString());
        Assert.InRange(int.Parse(refused.Headers.GetValues("Retry-After").Single()), 1, 60);

        using var otherAddress = await TokenBodyAsync("grant_type=refresh_token&client_id=c&refresh_token=unknown", ip: "198.51.100.7");
        Assert.Equal(HttpStatusCode.BadRequest, otherAddress.StatusCode);

        _server.Clock.Advance(TimeSpan.FromMinutes(1));
        using var later = await TokenBodyAsync("grant_type=refresh_token&client_id=c&refresh_token=unknown");
        Assert.Equal(HttpStatusCode.BadRequest, later.StatusCode);
    }

    // ---- R21: refresh tokens ----

    [Fact]
    public async Task A_refresh_rotates_the_token_and_a_used_one_revokes_the_whole_family()
    {
        var signedIn = await _server.SignInAsync();

        var (status, body) = await _server.RefreshAsync(signedIn.RefreshToken, signedIn.ClientId);
        var secondAccessToken = (string)body!["access_token"]!;
        var secondRefreshToken = (string)body["refresh_token"]!;

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(new[] { "access_token", "expires_in", "refresh_token", "scope", "token_type" }, Keys(body));
        Assert.Matches("^[A-Za-z0-9_-]{43}$", secondRefreshToken);
        Assert.NotEqual(signedIn.RefreshToken, secondRefreshToken);
        Assert.NotEqual(signedIn.AccessToken, secondAccessToken);
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(secondAccessToken));

        // The used token again: refused, and the newer token of the family and both access tokens with it.
        var (reused, reusedBody) = await TokenAsync(new() { ["grant_type"] = "refresh_token", ["refresh_token"] = signedIn.RefreshToken, ["client_id"] = signedIn.ClientId });
        Assert.Equal(HttpStatusCode.BadRequest, reused);
        Assert.Equal(InvalidGrant, reusedBody);
        Assert.Equal(HttpStatusCode.BadRequest, (await _server.RefreshAsync(secondRefreshToken, signedIn.ClientId)).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, await _server.McpStatusAsync(signedIn.AccessToken));
        Assert.Equal(HttpStatusCode.Unauthorized, await _server.McpStatusAsync(secondAccessToken));
        Assert.Contains(_server.Logs.Lines, line => line.Contains("its family is revoked"));
    }

    [Fact]
    public async Task One_clients_reuse_does_not_touch_another_clients_tokens()
    {
        var first = await _server.SignInAsync();
        var second = await _server.SignInAsync();
        await _server.RefreshAsync(first.RefreshToken, first.ClientId);

        await _server.RefreshAsync(first.RefreshToken, first.ClientId);   // reuse: revokes the first family only

        Assert.Equal(HttpStatusCode.Unauthorized, await _server.McpStatusAsync(first.AccessToken));
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(second.AccessToken));
        Assert.Equal(HttpStatusCode.OK, (await _server.RefreshAsync(second.RefreshToken, second.ClientId)).Status);
    }

    [Fact]
    public async Task A_family_ends_30_days_after_sign_in_however_often_it_was_refreshed()
    {
        var signedIn = await _server.SignInAsync();

        _server.Clock.Advance(TimeSpan.FromDays(29));
        var (status, body) = await _server.RefreshAsync(signedIn.RefreshToken, signedIn.ClientId);
        Assert.Equal(HttpStatusCode.OK, status);

        _server.Clock.Advance(TimeSpan.FromDays(1));
        var (late, lateBody) = await TokenAsync(new() { ["grant_type"] = "refresh_token", ["refresh_token"] = (string)body!["refresh_token"]!, ["client_id"] = signedIn.ClientId });
        Assert.Equal(HttpStatusCode.BadRequest, late);
        Assert.Equal(InvalidGrant, lateBody);
    }

    [Fact]
    public async Task An_unknown_refresh_token_and_another_clients_token_get_the_same_answer_and_use_nothing_up()
    {
        var signedIn = await _server.SignInAsync();
        var otherClient = await _server.RegisterAsync("https://other.example.test/callback");

        var unknown = await TokenAsync(new() { ["grant_type"] = "refresh_token", ["refresh_token"] = GrantStore.NewToken(), ["client_id"] = signedIn.ClientId });
        var otherClients = await TokenAsync(new() { ["grant_type"] = "refresh_token", ["refresh_token"] = signedIn.RefreshToken, ["client_id"] = otherClient });
        var missing = await TokenAsync(new() { ["grant_type"] = "refresh_token", ["client_id"] = signedIn.ClientId });

        Assert.Equal((HttpStatusCode.BadRequest, InvalidGrant), unknown);
        Assert.Equal((HttpStatusCode.BadRequest, InvalidGrant), otherClients);
        Assert.Equal(HttpStatusCode.BadRequest, missing.Status);
        Assert.Equal("invalid_request", (string)JsonNode.Parse(missing.Body)!["error"]!);
        Assert.Equal(HttpStatusCode.OK, (await _server.RefreshAsync(signedIn.RefreshToken, signedIn.ClientId)).Status);
    }

    [Fact]
    public async Task A_refresh_can_narrow_the_scope_and_never_widen_it()
    {
        var wide = await _server.SignInAsync(scope: "mcp:tools offline_access");
        var (narrowedStatus, narrowed) = await _server.RefreshAsync(wide.RefreshToken, wide.ClientId, scope: "mcp:tools");
        Assert.Equal(HttpStatusCode.OK, narrowedStatus);
        Assert.Equal("mcp:tools", (string)narrowed!["scope"]!);
        Assert.Equal("mcp:tools", (string)BuiltinAuthServer.Decode((string)narrowed["access_token"]!).Payload["scope"]!);

        var narrow = await _server.SignInAsync(scope: "mcp:tools");
        foreach (var scope in new[] { "mcp:tools offline_access", "admin", "mcp:tools admin" })
        {
            var (status, body) = await TokenAsync(new() { ["grant_type"] = "refresh_token", ["refresh_token"] = narrow.RefreshToken, ["client_id"] = narrow.ClientId, ["scope"] = scope });
            Assert.Equal(HttpStatusCode.BadRequest, status);
            Assert.Equal("invalid_scope", (string)JsonNode.Parse(body)!["error"]!);
            Assert.DoesNotContain("admin", body);
        }

        // A refused scope did not use the token up.
        Assert.Equal(HttpStatusCode.OK, (await _server.RefreshAsync(narrow.RefreshToken, narrow.ClientId)).Status);
    }

    [Fact]
    public async Task Only_hashes_of_refresh_tokens_are_stored_with_a_family_id_and_no_access_token()
    {
        var signedIn = await _server.SignInAsync();
        var (_, refreshed) = await _server.RefreshAsync(signedIn.RefreshToken, signedIn.ClientId);
        var secondRefreshToken = (string)refreshed!["refresh_token"]!;

        var stored = File.ReadAllText(Path.Combine(_server.DataDirectory, OAuthDataDirectory.GrantsFile));
        var grant = JsonNode.Parse(stored)!["grants"]!.AsArray().Single()!;

        Assert.Equal(GrantStore.Hash(secondRefreshToken), (string)grant["refresh_hash"]!);
        Assert.Equal(GrantStore.Hash(signedIn.RefreshToken), (string)grant["used_hashes"]!.AsArray().Single()!);
        Assert.Matches("^[A-Za-z0-9_-]{22}$", (string)grant["family"]!);
        Assert.Equal(signedIn.ClientId, (string)grant["client_id"]!);
        Assert.Equal(_server.Clock.GetUtcNow() + TimeSpan.FromDays(30), grant["expires_at"]!.GetValue<DateTimeOffset>());
        foreach (var file in Directory.GetFiles(_server.DataDirectory))
        {
            var text = File.ReadAllText(file);
            Assert.DoesNotContain(signedIn.RefreshToken, text);
            Assert.DoesNotContain(secondRefreshToken, text);
            Assert.DoesNotContain(signedIn.AccessToken, text);
            Assert.DoesNotContain((string)refreshed["access_token"]!, text);
            Assert.DoesNotContain(_server.Password!, text);
        }
    }

    // ---- R22: what the resource server accepts (tests 6 and 7) ----

    private static JsonObject Header() => new() { ["alg"] = "ES256", ["typ"] = "at+jwt" };

    [Fact]
    public async Task A_token_signed_with_the_active_key_from_the_key_file_is_accepted()
    {
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(_server.SignWithActiveKey(Header(), _server.GoodPayload())));

        var alternateType = Header();
        alternateType["typ"] = "application/at+jwt";
        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(_server.SignWithActiveKey(alternateType, _server.GoodPayload())));
    }

    [Theory]
    [InlineData("aud of another URL")]
    [InlineData("aud with a second entry")]
    [InlineData("no aud")]
    [InlineData("typ JWT")]
    [InlineData("no typ")]
    [InlineData("exp 61 s ago")]
    [InlineData("no exp")]
    [InlineData("another issuer")]
    [InlineData("issuer with a trailing slash")]
    [InlineData("no jti")]
    [InlineData("iat and nbf in the future")]
    public async Task A_token_signed_with_the_active_key_but_wrong_in_one_way_is_refused(string wrong)
    {
        var header = Header();
        var payload = _server.GoodPayload();
        var now = _server.Clock.GetUtcNow().ToUnixTimeSeconds();
        switch (wrong)
        {
            case "aud of another URL": payload["aud"] = "https://other.example.test/mcp"; break;
            case "aud with a second entry": payload["aud"] = new JsonArray(BuiltinAuthServer.McpUrl, "https://other.example.test/mcp"); break;
            case "no aud": payload.Remove("aud"); break;
            case "typ JWT": header["typ"] = "JWT"; break;
            case "no typ": header.Remove("typ"); break;
            case "exp 61 s ago": payload["iat"] = now - 600; payload["exp"] = now - 61; break;
            case "no exp": payload.Remove("exp"); break;
            case "another issuer": payload["iss"] = "https://other.example.test"; break;
            case "issuer with a trailing slash": payload["iss"] = BuiltinAuthServer.PublicUrl + "/"; break;
            case "no jti": payload.Remove("jti"); break;
            case "iat and nbf in the future": payload["iat"] = now + 120; payload["nbf"] = now + 120; break;
            default: throw new ArgumentOutOfRangeException(nameof(wrong));
        }

        using var response = await _server.CallMcpAsync(_server.SignWithActiveKey(header, payload));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(InvalidTokenChallenge, response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task A_token_that_expired_30_seconds_ago_is_still_accepted()
    {
        var payload = _server.GoodPayload();
        var now = _server.Clock.GetUtcNow().ToUnixTimeSeconds();
        payload["iat"] = now - 600;
        payload["exp"] = now - 30;

        Assert.Equal(HttpStatusCode.OK, await _server.McpStatusAsync(_server.SignWithActiveKey(Header(), payload)));
    }

    [Fact]
    public async Task Unsigned_tokens_and_HS256_tokens_keyed_with_the_public_key_are_refused()
    {
        var jwks = JsonNode.Parse(await _server.Client.GetStringAsync(OAuthServerEndpoints.JwksPath, Cancel))!["keys"]!.AsArray().Single()!;
        var kid = (string)jwks["kid"]!;
        var x = Base64UrlEncoder.DecodeBytes((string)jwks["x"]!);
        var y = Base64UrlEncoder.DecodeBytes((string)jwks["y"]!);
        using var publicKey = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
        var payload = Base64UrlEncoder.Encode(_server.GoodPayload().ToJsonString());

        var tokens = new List<string>();
        foreach (var alg in new[] { "none", "None", "NONE" })
        {
            var unsigned = Base64UrlEncoder.Encode(new JsonObject { ["alg"] = alg, ["typ"] = "at+jwt", ["kid"] = kid }.ToJsonString()) + "." + payload + ".";
            tokens.Add(unsigned);
        }

        // HS256 with each form of the public key an attacker can build from the JWKS as the HMAC secret.
        var hsInput = Base64UrlEncoder.Encode(new JsonObject { ["alg"] = "HS256", ["typ"] = "at+jwt", ["kid"] = kid }.ToJsonString()) + "." + payload;
        foreach (var secret in new[]
        {
            [.. x, .. y],
            [4, .. x, .. y],
            publicKey.ExportSubjectPublicKeyInfo(),
            Encoding.ASCII.GetBytes(publicKey.ExportSubjectPublicKeyInfoPem()),
            Encoding.ASCII.GetBytes(jwks.ToJsonString()),
            Encoding.ASCII.GetBytes((string)jwks["x"]!),
        })
        {
            tokens.Add(hsInput + "." + Base64UrlEncoder.Encode(HMACSHA256.HashData(secret, Encoding.ASCII.GetBytes(hsInput))));
        }

        // ES256 from a key that is not ours, under our kid and under its own.
        using var foreign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        foreach (var foreignKid in new[] { kid, "some-other-kid" })
        {
            var input = Base64UrlEncoder.Encode(new JsonObject { ["alg"] = "ES256", ["typ"] = "at+jwt", ["kid"] = foreignKid }.ToJsonString()) + "." + payload;
            tokens.Add(input + "." + Base64UrlEncoder.Encode(foreign.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256)));
        }

        foreach (var token in tokens)
        {
            using var response = await _server.CallMcpAsync(token);
            Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"accepted: {BuiltinAuthServer.Decode(token).Header.ToJsonString()}");
            Assert.Equal(InvalidTokenChallenge, response.Headers.WwwAuthenticate.ToString());
        }
    }

    // ---- R24: errors ----

    [Fact]
    public async Task An_unexpected_exception_becomes_server_error_with_an_error_id_that_is_only_in_the_log()
    {
        using var response = await _server.Client.GetAsync(ThrowJsonPath, Cancel);
        var body = await response.Content.ReadAsStringAsync(Cancel);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("""{"error":"server_error","error_description":"The server could not complete the request."}""", body);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var logged = Assert.Single(_server.Logs.Lines, line => line.Contains("error id"));
        Assert.Matches("failed for 203\\.0\\.113\\.10; error id [0-9a-f]{12}\\.", logged);
        Assert.Contains("detail-that-must-not-leak", logged);   // the exception is in the log, for the owner
    }

    [Fact]
    public async Task On_a_page_an_unexpected_exception_shows_the_error_id_and_nothing_of_the_exception()
    {
        using var response = await _server.Client.GetAsync(ThrowHtmlPath, Cancel);
        var body = await response.Content.ReadAsStringAsync(Cancel);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("frame-ancestors 'none'", string.Join(";", response.Headers.GetValues("Content-Security-Policy")));
        Assert.DoesNotContain("detail-that-must-not-leak", body);
        Assert.DoesNotContain("InvalidOperationException", body);
        var errorId = System.Text.RegularExpressions.Regex.Match(body, "error id ([0-9a-f]{12})").Groups[1].Value;
        Assert.NotEqual("", errorId);
        Assert.Contains(_server.Logs.Lines, line => line.Contains($"error id {errorId}."));
    }

    [Fact]
    public async Task Token_errors_carry_a_fixed_description_and_never_echo_the_request()
    {
        var marker = "echo-" + Guid.NewGuid().ToString("N");
        var bodies = new List<string>();
        foreach (var fields in new Dictionary<string, string?>[]
        {
            new() { ["grant_type"] = marker },
            new() { ["grant_type"] = "authorization_code", ["code"] = marker, ["code_verifier"] = marker, ["client_id"] = marker, ["redirect_uri"] = "https://" + marker + ".example/cb" },
            new() { ["grant_type"] = "refresh_token", ["refresh_token"] = marker, ["client_id"] = marker, ["scope"] = marker },
            new() { ["grant_type"] = "refresh_token", ["refresh_token"] = marker, ["client_id"] = marker, ["resource"] = "https://" + marker + ".example/mcp" },
        })
        {
            var (status, body) = await TokenAsync(fields);
            Assert.Equal(HttpStatusCode.BadRequest, status);
            Assert.Equal(new[] { "error", "error_description" }, Keys(JsonNode.Parse(body)!));
            bodies.Add(body);
        }

        Assert.All(bodies, body => Assert.DoesNotContain(marker, body));
    }

    // ---- R28: nothing secret in the log (test 18) ----

    [Fact]
    public async Task A_whole_run_logs_no_password_code_verifier_token_cookie_or_connection_string()
    {
        const string mongoPassword = "Mongo-Pass-7f3a9c";
        using var server = new BuiltinAuthServer(
            configureServices: services => services.AddLogging(logging => logging.SetMinimumLevel(LogLevel.Trace)),
            mongoConnectionString: $"mongodb://app:{mongoPassword}@db.internal.example:99999999/");

        // A wrong password, then a login, a consent, a code exchange, a refresh, tool calls, a reused code and a refused token.
        var clientId = await server.RegisterAsync();
        var (verifier, challenge) = BuiltinAuthServer.NewPkce();
        using var authorize = await server.AuthorizeAsync(BuiltinAuthServer.AuthorizeParameters(clientId, "https://client.example.test/callback", challenge));
        var loginPage = await authorize.Content.ReadAsStringAsync(Cancel);
        const string wrongGuess = "Wrong-Guess-51c2e8";   // typed into the login form on purpose; it is nobody's password
        using var failedLogin = await server.LoginAsync(loginPage, wrongGuess);
        using var login = await server.LoginAsync(loginPage, server.Password);
        var cookie = BuiltinAuthServer.SessionCookie(login);
        var consentPage = await login.Content.ReadAsStringAsync(Cancel);
        using var consent = await server.ConsentAsync(consentPage, cookie);
        var flow = new FlowResult(clientId, "https://client.example.test/callback", BuiltinAuthServer.FromLocation(consent, "code")!, verifier, cookie);
        var (_, tokens) = await server.ExchangeAsync(flow);
        var accessToken = (string)tokens!["access_token"]!;
        var refreshToken = (string)tokens["refresh_token"]!;
        using var call = await server.CallMcpAsync(accessToken);
        var (_, refreshed) = await server.RefreshAsync(refreshToken, clientId);
        using var secondCall = await server.CallMcpAsync((string)refreshed!["access_token"]!);
        await server.ExchangeAsync(flow);
        using var refusedCall = await server.CallMcpAsync(accessToken);
        Assert.Equal(HttpStatusCode.OK, call.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, refusedCall.StatusCode);

        var secrets = new Dictionary<string, string>
        {
            ["the owner password"] = server.Password!,
            ["the wrong password"] = wrongGuess,
            ["the authorization code"] = flow.Code,
            ["the code verifier"] = verifier,
            ["the first access token"] = accessToken,
            ["the first refresh token"] = refreshToken,
            ["the second access token"] = (string)refreshed["access_token"]!,
            ["the second refresh token"] = (string)refreshed["refresh_token"]!,
            ["the access token's signature"] = accessToken.Split('.')[2],
            ["the session cookie"] = cookie.Split('=')[1],
            ["the login form token"] = BuiltinAuthServer.Hidden(loginPage, "csrf"),
            ["the consent form token"] = BuiltinAuthServer.Hidden(consentPage, "csrf"),
            ["the MongoDB password"] = mongoPassword,
            ["a bearer token"] = "Bearer ey",
        };
        var log = server.Logs.Lines;
        Assert.Contains(log, line => line.Contains("Owner approved client"));   // the run was logged at all
        foreach (var (what, secret) in secrets)
        {
            Assert.False(log.Any(line => line.Contains(secret, StringComparison.Ordinal)), $"{what} is in the log");
        }
    }
}
