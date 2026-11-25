using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using No2SQL.Hosting;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>NO2SQL_HTTP_TOKEN: one bearer token in the Authorization header, nothing else.</summary>
public sealed class StaticTokenAuthTests : IDisposable
{
    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    private readonly string _token = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
    private readonly CapturedLogs _logs = new();
    private readonly No2SqlHttpApp _app;
    private readonly HttpClient _client;

    public StaticTokenAuthTests()
    {
        _app = new No2SqlHttpApp(
            services => services.AddLogging(logging => logging.AddProvider(_logs)),
            auth: new HttpAuthOptions { StaticToken = _token });
        _client = _app.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _app.Dispose();
    }

    [Fact]
    public async Task No_token_gets_401_with_a_plain_Bearer_challenge_and_an_empty_body()
    {
        var reply = await _client.ListToolsAsync(Cancel);

        Assert.Equal(HttpStatusCode.Unauthorized, reply.Http.StatusCode);
        Assert.Equal("Bearer", reply.Http.Headers.WwwAuthenticate.ToString());   // no metadata to point at without an identity provider
        Assert.Null(reply.Message);
    }

    [Fact]
    public async Task The_right_token_opens_the_MCP_endpoint()
    {
        var reply = await _client.RpcAsync("tools/call", new JsonObject { ["name"] = "test_connectivity", ["arguments"] = new JsonObject() },
            request => request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token), Cancel);

        Assert.Equal(HttpStatusCode.OK, reply.Http.StatusCode);
        Assert.Equal("MCP connectivity test successful!", (string?)reply.Result["content"]?[0]?["text"]);
    }

    [Fact]
    public async Task The_caller_id_for_audit_lines_is_a_fingerprint_of_the_token_never_the_token()
    {
        var caller = await AuthProbe.AuthenticateAsync(_app, "Bearer " + _token);

        var hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(_token)));
        Assert.NotNull(caller);
        Assert.Equal("static-token:" + hash[..8], caller.FindFirst("sub")?.Value);
        Assert.DoesNotContain(caller.Claims, claim => claim.Value.Contains(_token, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("bearer")]
    [InlineData("BEARER")]
    public async Task The_scheme_name_is_case_insensitive(string scheme) => Assert.Equal(HttpStatusCode.OK, (await Send($"{scheme} {_token}")).StatusCode);

    [Fact]
    public async Task A_wrong_token_gets_401_invalid_token_and_is_never_echoed()
    {
        var wrong = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

        using var response = await Send("Bearer " + wrong);
        var body = await response.Content.ReadAsStringAsync(Cancel);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer error=\"invalid_token\"", response.Headers.WwwAuthenticate.ToString());
        Assert.Empty(body);
        Assert.DoesNotContain(wrong, response.Headers.ToString());
        Assert.Contains(_logs.Lines, line => line.Contains("401 for") && line.Contains("the token is not NO2SQL_HTTP_TOKEN"));
        Assert.DoesNotContain(_logs.Lines, line => line.Contains(wrong) || line.Contains(_token));
    }

    [Theory]
    [InlineData("Basic dXNlcjpwYXNzd29yZA==")]
    [InlineData("Token {0}")]
    [InlineData("Bearer")]
    [InlineData("Bearer ")]
    [InlineData("Bearer {0} extra")]
    [InlineData("Bearer \"{0}\"")]
    [InlineData("{0}")]
    public async Task Anything_but_one_Bearer_header_gets_401(string header) =>
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(string.Format(header, _token))).StatusCode);

    [Fact]
    public async Task A_prefix_or_extension_of_the_token_gets_401()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send("Bearer " + _token[..^1])).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send("Bearer " + _token + "A")).StatusCode);
    }

    [Fact]
    public async Task The_token_is_accepted_only_in_the_header()
    {
        using var inQuery = await _client.PostAsync($"/mcp?access_token={Uri.EscapeDataString(_token)}", Json(), Cancel);
        using var asForm = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new FormUrlEncodedContent([new("access_token", _token)]),
        };
        using var formResponse = await _client.SendAsync(asForm, Cancel);
        using var asCookie = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = Json() };
        asCookie.Headers.Add("Cookie", "access_token=" + _token);
        using var cookieResponse = await _client.SendAsync(asCookie, Cancel);

        Assert.Equal(HttpStatusCode.Unauthorized, inQuery.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, cookieResponse.StatusCode);
        // A form body never reaches the endpoint: routing answers 415 for the content type before
        // authorization runs. Either way no MCP answer comes back.
        Assert.Contains(formResponse.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.UnsupportedMediaType });
        Assert.Empty(await formResponse.Content.ReadAsStringAsync(Cancel));
    }

    [Fact]
    public async Task Two_Authorization_headers_get_401()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = Json() };
        request.Headers.TryAddWithoutValidation("Authorization", ["Bearer " + _token, "Bearer " + _token]);

        using var response = await _client.SendAsync(request, Cancel);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task The_health_check_stays_open_and_there_is_no_resource_metadata()
    {
        using var health = await _client.GetAsync("/healthz", Cancel);
        using var metadata = await _client.GetAsync("/.well-known/oauth-protected-resource/mcp", Cancel);

        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, metadata.StatusCode);
    }

    [Fact]
    public async Task The_SDK_client_works_with_the_token_the_way_the_Responses_API_sends_it()
    {
        var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(_client.BaseAddress!, "/mcp"),
                TransportMode = HttpTransportMode.StreamableHttp,
                AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer " + _token },
            },
            _client,
            loggerFactory: null,
            ownsHttpClient: false);

        await using var mcp = await McpClient.CreateAsync(transport, cancellationToken: Cancel);
        var tools = await mcp.ListToolsAsync(cancellationToken: Cancel);

        Assert.Equal(10, tools.Count);
    }

    private async Task<HttpResponseMessage> Send(string authorization)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = Json() };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        request.Headers.Add("MCP-Protocol-Version", McpHttp.ProtocolVersion);
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        return await _client.SendAsync(request, Cancel);
    }

    private static StringContent Json() => new(
        """{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", System.Text.Encoding.UTF8, "application/json");
}
