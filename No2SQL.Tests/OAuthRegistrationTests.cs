using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using No2SQL.Hosting.OAuth;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// The built-in authorization server's discovery documents and Dynamic Client Registration
/// (P2-5 threat model R1, R2, R4 to R7, R27; tests 10, 11, 15 and the JWKS half of 16).
/// </summary>
public sealed class OAuthRegistrationTests : IDisposable
{
    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    private readonly BuiltinAuthServer _server = new();

    public void Dispose() => _server.Dispose();

    [Fact]
    public async Task Authorization_server_metadata_is_exactly_the_R2_key_set_from_configuration()
    {
        foreach (var (header, value) in new[] { ("Host", "evil.example"), ("X-Forwarded-Host", "evil.example"), ("X-Forwarded-Proto", "http") })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, OAuthServerEndpoints.AuthorizationServerMetadataPath);
            request.Headers.TryAddWithoutValidation(header, value);
            using var response = await _server.Client.SendAsync(request, Cancel);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
            Assert.Equal(
                """{"issuer":"https://mcp.example.test","authorization_endpoint":"https://mcp.example.test/authorize","token_endpoint":"https://mcp.example.test/token","jwks_uri":"https://mcp.example.test/jwks","registration_endpoint":"https://mcp.example.test/register","scopes_supported":["mcp:tools","offline_access"],"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"client_id_metadata_document_supported":true}""",
                await response.Content.ReadAsStringAsync(Cancel));
        }
    }

    [Fact]
    public async Task Protected_resource_metadata_names_the_built_in_server()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/.well-known/oauth-protected-resource/mcp");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Host", "evil.example");
        using var response = await _server.Client.SendAsync(request, Cancel);

        Assert.Equal(
            """{"resource":"https://mcp.example.test/mcp","authorization_servers":["https://mcp.example.test"],"scopes_supported":["mcp:tools"],"bearer_methods_supported":["header"],"resource_name":"No2SQL"}""",
            await response.Content.ReadAsStringAsync(Cancel));
    }

    [Fact]
    public async Task The_MCP_endpoint_points_unauthenticated_clients_at_the_metadata()
    {
        var reply = await _server.Client.ListToolsAsync(Cancel);

        Assert.Equal(HttpStatusCode.Unauthorized, reply.Http.StatusCode);
        Assert.Equal(
            "Bearer resource_metadata=\"https://mcp.example.test/.well-known/oauth-protected-resource/mcp\", scope=\"mcp:tools\"",
            reply.Http.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task The_JWKS_has_public_parameters_only()
    {
        using var response = await _server.Client.GetAsync(OAuthServerEndpoints.JwksPath, Cancel);
        var key = JsonNode.Parse(await response.Content.ReadAsStringAsync(Cancel))!["keys"]!.AsArray().Single()!.AsObject();

        Assert.Equal(["alg", "crv", "kid", "kty", "use", "x", "y"], key.Select(p => p.Key).Order());
        Assert.Equal("ES256", (string?)key["alg"]);
        Assert.Equal("P-256", (string?)key["crv"]);
        Assert.False(key.ContainsKey("d"));
    }

    [Fact]
    public async Task A_registration_returns_exactly_the_public_client_fields()
    {
        using var response = await _server.RegisterRawAsync(
            """{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"client_name":"Claude","token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":"mcp:tools"}""");

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Cancel))!.AsObject();
        Assert.Equal(["client_id", "client_id_issued_at", "grant_types", "redirect_uris", "response_types", "token_endpoint_auth_method"], body.Select(p => p.Key).Order());
        Assert.Equal("none", (string?)body["token_endpoint_auth_method"]);
        Assert.Equal(_server.Clock.GetUtcNow().ToUnixTimeSeconds(), (long)body["client_id_issued_at"]!);
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("https://evil.example/#frag")]
    [InlineData("https://evil.example/cb#")]
    [InlineData("http://evil.example/")]
    [InlineData("https://user:pw@evil.example/cb")]
    [InlineData("https://*.evil.example/cb")]
    [InlineData("com.example.app:/callback")]
    [InlineData("data:text/html,hi")]
    [InlineData("file:///etc/passwd")]
    [InlineData("/relative/callback")]
    [InlineData("http://127.0.0.2/cb")]
    public async Task Unsafe_redirect_URIs_are_refused(string redirectUri)
    {
        using var response = await _server.RegisterRawAsync(new JsonObject { ["redirect_uris"] = new JsonArray(redirectUri) }.ToJsonString());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_redirect_uri", (string?)JsonNode.Parse(await response.Content.ReadAsStringAsync(Cancel))!["error"]);
    }

    [Theory]
    [InlineData("http://127.0.0.1:0/cb")]
    [InlineData("http://127.0.0.1:53123/callback")]
    [InlineData("http://[::1]:4000/cb")]
    [InlineData("http://localhost:8080/oauth/callback")]
    [InlineData("https://claude.ai/api/mcp/auth_callback")]
    [InlineData("https://chatgpt.com/connector_platform_oauth_redirect")]
    public async Task Https_and_loopback_redirect_URIs_are_accepted(string redirectUri) =>
        await _server.RegisterAsync(redirectUri);

    [Theory]
    [InlineData("""{"redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}""")]
    [InlineData("""{"redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"private_key_jwt"}""")]
    [InlineData("""{"redirect_uris":["https://a.example/cb"],"grant_types":["client_credentials"]}""")]
    [InlineData("""{"redirect_uris":["https://a.example/cb"],"grant_types":["authorization_code","implicit"]}""")]
    [InlineData("""{"redirect_uris":["https://a.example/cb"],"response_types":["token"]}""")]
    [InlineData("""{"redirect_uris":["https://a.example/cb"],"client_name":42}""")]
    [InlineData("""["https://a.example/cb"]""")]
    [InlineData("""{"redirect_uris":"https://a.example/cb"}""")]
    [InlineData("""not json""")]
    public async Task Registrations_that_ask_for_secrets_or_other_grants_are_refused(string json)
    {
        using var response = await _server.RegisterRawAsync(json);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.StartsWith("invalid_", (string?)JsonNode.Parse(await response.Content.ReadAsStringAsync(Cancel))!["error"]);
    }

    [Fact]
    public async Task Only_the_name_and_redirect_URIs_are_stored_and_no_URL_is_fetched()
    {
        var fetches = new List<string>();
        using var server = new BuiltinAuthServer(services => services.AddSingleton<CimdHandlerFactory>(_ => new StubHandler(request =>
        {
            fetches.Add(request.RequestUri!.ToString());
            return new HttpResponseMessage(HttpStatusCode.OK);
        })));

        using var response = await server.RegisterRawAsync("""
            {"redirect_uris":["https://a.example/cb"],"client_name":"A","logo_uri":"https://tracker.example/logo.png",
             "jwks_uri":"https://evil.example/jwks","policy_uri":"https://evil.example/p","tos_uri":"https://evil.example/t",
             "software_statement":"eyJ...","client_uri":"https://a.example/","contacts":["x@example.com"]}
            """);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var stored = await File.ReadAllTextAsync(Path.Combine(server.DataDirectory, OAuthDataDirectory.ClientsFile), Cancel);
        Assert.DoesNotContain("evil.example", stored);
        Assert.DoesNotContain("tracker.example", stored);
        Assert.DoesNotContain("example.com", stored);
        Assert.Empty(fetches);
    }

    [Fact]
    public async Task A_client_name_keeps_printable_characters_only_and_at_most_64()
    {
        var name = "Chat‮GPT\u0007​ " + new string('x', 100);
        var clientId = await _server.RegisterAsync(name: name);

        var stored = _server.Services.GetRequiredService<ClientStore>().Find(clientId)!.ClientName!;
        Assert.DoesNotContain('‮', stored);
        Assert.DoesNotContain('\u0007', stored);
        Assert.DoesNotContain('​', stored);
        Assert.StartsWith("ChatGPT ", stored);
        Assert.Equal(64, stored.Length);
    }

    [Fact]
    public async Task Registration_needs_JSON_and_at_most_16_KiB()
    {
        using var form = await _server.RegisterRawAsync("redirect_uris=https://a.example/cb", contentType: "application/x-www-form-urlencoded");
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, form.StatusCode);

        var big = new JsonObject { ["redirect_uris"] = new JsonArray("https://a.example/cb"), ["client_name"] = new string('x', 17 * 1024) };
        using var tooBig = await _server.RegisterRawAsync(big.ToJsonString());
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, tooBig.StatusCode);
    }

    [Fact]
    public async Task The_11th_registration_from_one_address_in_an_hour_is_refused()
    {
        for (var i = 0; i < 10; i++)
        {
            await _server.RegisterAsync(ip: "198.51.100.7");
        }

        using var refused = await _server.RegisterRawAsync("""{"redirect_uris":["https://a.example/cb"]}""", ip: "198.51.100.7");
        Assert.Equal((HttpStatusCode)429, refused.StatusCode);
        Assert.True(int.Parse(refused.Headers.GetValues("Retry-After").Single()) is > 0 and <= 3600);

        await _server.RegisterAsync(ip: "198.51.100.8");   // another address is not affected

        _server.Clock.Advance(TimeSpan.FromHours(1));
        await _server.RegisterAsync(ip: "198.51.100.7");   // the window has passed
    }

    [Fact]
    public async Task When_the_store_is_full_the_oldest_never_approved_client_is_evicted()
    {
        var store = _server.Services.GetRequiredService<ClientStore>();
        var first = await _server.RegisterAsync(ip: "10.1.0.0");
        _server.Clock.Advance(TimeSpan.FromSeconds(1));
        for (var i = 1; i < store.MaxClients; i++)
        {
            await _server.RegisterAsync(ip: $"10.1.{i / 10}.{i % 10}");
        }

        var newest = await _server.RegisterAsync(ip: "10.2.0.1");

        Assert.Null(store.Find(first));
        Assert.NotNull(store.Find(newest));
        Assert.Equal(store.MaxClients, ClientStore.ReadAll(_server.Directory).Clients.Count);
    }

    [Fact]
    public async Task When_every_stored_client_is_approved_a_new_registration_gets_429()
    {
        var store = _server.Services.GetRequiredService<ClientStore>();
        for (var i = 0; i < store.MaxClients; i++)
        {
            var clientId = await _server.RegisterAsync(ip: $"10.3.{i / 10}.{i % 10}");
            store.RecordApproval(clientId, "https://client.example.test/callback", isMetadataDocumentClient: false);
        }

        using var refused = await _server.RegisterRawAsync("""{"redirect_uris":["https://a.example/cb"]}""", ip: "10.4.0.1");

        Assert.Equal((HttpStatusCode)429, refused.StatusCode);
        Assert.True(refused.Headers.Contains("Retry-After"));
        Assert.Equal(store.MaxClients, ClientStore.ReadAll(_server.Directory).Clients.Count);
    }
}

/// <summary>An HTTP handler that answers from a function, for metadata-document fetches in tests.</summary>
internal sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> answer) : HttpMessageHandler
{
    public StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer) : this(_ => throw new InvalidOperationException())
    {
        _async = answer;
    }

    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? _async;

    public int Calls;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Calls);
        return _async is not null ? _async(request, cancellationToken) : Task.FromResult(answer(request));
    }
}
