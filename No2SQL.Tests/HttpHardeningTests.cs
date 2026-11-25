using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.AspNetCore;
using No2SQL.Hosting;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// P2-6 hardening on the in-memory server (Mark's acceptance criteria, numbered as in the spec).
/// Kestrel-only limits (body size of a chunked request, connection limits) are in KestrelLimitsTests.
/// </summary>
public class HttpHardeningTests
{
    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    private static readonly string[] SecurityHeaders = ["X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", "Content-Security-Policy"];

    private static HttpRequestMessage McpPost(string? contentType = "application/json", string body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}")
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body)) };
        if (contentType is not null)
        {
            request.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        }

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        request.Headers.Add("MCP-Protocol-Version", McpHttp.ProtocolVersion);
        return request;
    }

    // 1
    [Theory]
    [InlineData("/mcp")]
    [InlineData("/healthz")]
    [InlineData("/anything")]
    public async Task An_unknown_Host_gets_400_with_an_empty_body(string path)
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();
        using var request = new HttpRequestMessage(path == "/mcp" ? HttpMethod.Post : HttpMethod.Get, path);
        request.Headers.Host = "evil.example";

        using var response = await client.SendAsync(request, Cancel);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync(Cancel));
        Assert.All(SecurityHeaders, h => Assert.True(response.Headers.Contains(h), h));
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("localhost:8787")]
    [InlineData("127.0.0.1:8787")]
    [InlineData("[::1]:8787")]
    public async Task Loopback_Host_values_pass(string host)
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        request.Headers.Host = host;

        using var response = await client.SendAsync(request, Cancel);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // 2
    [Theory]
    [InlineData("https://evil.example", HttpStatusCode.Forbidden)]
    [InlineData("null", HttpStatusCode.Forbidden)]
    [InlineData("not an origin", HttpStatusCode.Forbidden)]
    [InlineData("http://localhost:8788", HttpStatusCode.Forbidden)]   // exact port
    [InlineData("http://localhost:8787", HttpStatusCode.OK)]
    [InlineData("HTTP://LOCALHOST:8787", HttpStatusCode.OK)]           // scheme and host are case-insensitive
    [InlineData(null, HttpStatusCode.OK)]                              // server-to-server clients send none
    public async Task Origin_must_be_absent_or_allowed(string? origin, HttpStatusCode expected)
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();
        using var request = McpPost();
        if (origin is not null)
        {
            request.Headers.TryAddWithoutValidation("Origin", origin);
        }

        using var response = await client.SendAsync(request, Cancel);

        Assert.Equal(expected, response.StatusCode);
        Assert.DoesNotContain(response.Headers, h => h.Key.StartsWith("Access-Control-", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task The_public_URL_origin_passes()
    {
        var hardening = Options(new() { ["NO2SQL_PUBLIC_URL"] = "https://no2sql.example.com" });
        using var app = new No2SqlHttpApp(null, null, hardening);
        using var client = app.CreateClient();
        using var request = McpPost();
        request.Headers.Host = "no2sql.example.com";
        request.Headers.TryAddWithoutValidation("Origin", "https://no2sql.example.com");

        using var response = await client.SendAsync(request, Cancel);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // 3
    [Theory]
    [InlineData("text/plain")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(";;;")]
    [InlineData("application/json-seq")]
    [InlineData("application/x-www-form-urlencoded")]
    public async Task A_wrong_missing_or_unparseable_Content_Type_gets_415_and_no_stack_trace(string? contentType)
    {
        var logs = new CapturingLoggerProvider();
        using var app = new No2SqlHttpApp(services => services.AddSingleton<ILoggerProvider>(logs));
        using var client = app.CreateClient();
        using var request = McpPost(contentType);

        using var response = await client.SendAsync(request, Cancel);

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync(Cancel));
        Assert.DoesNotContain(logs.Entries, e => e.Exception is not null || e.Level >= LogLevel.Warning);
    }

    [Theory]
    [InlineData("/token", "application/x-www-form-urlencoded", true)]
    [InlineData("/revoke", "application/x-www-form-urlencoded", true)]
    [InlineData("/login", "application/x-www-form-urlencoded; charset=utf-8", true)]
    [InlineData("/consent", "application/x-www-form-urlencoded", true)]
    [InlineData("/register", "application/json", true)]
    [InlineData("/token", "application/json", false)]
    [InlineData("/login", "application/json", false)]
    [InlineData("/register", "application/x-www-form-urlencoded", false)]
    public async Task OAuth_paths_take_their_own_Content_Type(string path, string contentType, bool accepted)
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new StringContent("a=b") };
        request.Content.Headers.Remove("Content-Type");
        request.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);

        using var response = await client.SendAsync(request, Cancel);

        // The endpoints arrive with P2-5, so an accepted request reaches routing and gets 404.
        Assert.Equal(accepted ? HttpStatusCode.NotFound : HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    [Fact]
    public async Task An_endpoint_that_sets_its_own_CSP_and_Cache_Control_keeps_them()
    {
        using var app = new No2SqlHttpApp(services => services.AddSingleton<IStartupFilter>(new PageEndpoint()));
        using var client = app.CreateClient();

        using var response = await client.GetAsync("/authorize", Cancel);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("default-src 'self'; form-action https://client.example", response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.True(response.Headers.CacheControl is { Private: true, NoStore: false, MaxAge.TotalSeconds: 0 }, "the page's own Cache-Control");
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
    }

    [Fact]
    public async Task Body_buffering_comes_after_the_rate_limiter()
    {
        var hardening = HttpHardeningOptions.Defaults with { RateLimitPerIpPerMinute = 1 };
        using var app = new No2SqlHttpApp(null, null, hardening);
        using var client = app.CreateClient();
        using var first = McpPost();
        await client.SendAsync(first, Cancel);

        // Over the limit and over the size: the limiter answers first, without reading the body.
        using var second = McpPost(body: new string(' ', 2 * 1024 * 1024));
        using var response = await client.SendAsync(second, Cancel);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
    }

    [Theory]
    [InlineData("application/json")]
    [InlineData("application/json; charset=utf-8")]
    [InlineData("Application/JSON")]
    public async Task A_JSON_Content_Type_passes(string contentType)
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();
        using var request = McpPost(contentType);

        using var response = await client.SendAsync(request, Cancel);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // 4 (declared length; a chunked body is in KestrelLimitsTests)
    [Fact]
    public async Task A_body_declared_over_the_limit_gets_413()
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();
        using var tooBig = McpPost(body: new string(' ', 2 * 1024 * 1024));
        using var atLimit = McpPost(body: "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}" + new string(' ', 1024 * 1024 - 64));

        using var rejected = await client.SendAsync(tooBig, Cancel);
        using var accepted = await client.SendAsync(atLimit, Cancel);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, rejected.StatusCode);
        Assert.NotEqual(HttpStatusCode.RequestEntityTooLarge, accepted.StatusCode);
    }

    // 5
    [Fact]
    public async Task The_token_limit_applies_per_token_and_resets_with_the_window()
    {
        var hardening = HttpHardeningOptions.Defaults with { RateLimitPerMinute = 3, RateLimitWindow = TimeSpan.FromSeconds(2) };
        using var app = new No2SqlHttpApp(null, null, hardening);
        using var client = app.CreateClient();

        async Task<HttpResponseMessage> Send(string token)
        {
            using var request = McpPost();
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return await client.SendAsync(request, Cancel);
        }

        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await Send("token-a")).StatusCode);
        }

        using var limited = await Send("token-a");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.True(int.Parse(limited.Headers.GetValues("Retry-After").Single()) >= 1);
        var body = JsonNode.Parse(await limited.Content.ReadAsStringAsync(Cancel))!;
        Assert.Equal(-32000, (int)body["error"]!["code"]!);

        Assert.Equal(HttpStatusCode.OK, (await Send("token-b")).StatusCode);

        await Task.Delay(TimeSpan.FromSeconds(2.5), Cancel);
        Assert.Equal(HttpStatusCode.OK, (await Send("token-a")).StatusCode);
    }

    // 6a
    [Fact]
    public async Task The_per_IP_ceiling_caps_callers_that_change_token_every_request()
    {
        var hardening = HttpHardeningOptions.Defaults with { RateLimitPerIpPerMinute = 5, RateLimitPerMinute = 100 };
        using var app = new No2SqlHttpApp(null, null, hardening);
        using var client = app.CreateClient();

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 6; i++)
        {
            using var request = McpPost();
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Guid.NewGuid().ToString());
            using var response = await client.SendAsync(request, Cancel);
            statuses.Add(response.StatusCode);
        }

        Assert.Equal([.. Enumerable.Repeat(HttpStatusCode.OK, 5), HttpStatusCode.TooManyRequests], statuses);
    }

    // 6
    [Fact]
    public async Task Requests_over_the_concurrency_limit_get_429_at_once()
    {
        using var silentMongo = new TcpListener(IPAddress.Loopback, 0);
        silentMongo.Start();
        var port = ((IPEndPoint)silentMongo.LocalEndpoint).Port;
        var hardening = HttpHardeningOptions.Defaults with { MaxConcurrentCalls = 2 };
        using var app = new No2SqlHttpApp(null, $"mongodb://127.0.0.1:{port}/?directConnection=true", hardening);
        using var client = app.CreateClient();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Cancel);

        var slow = Enumerable.Range(0, 2)
            .Select(_ => client.CallToolAsync("list_databases", cancellationToken: stop.Token))
            .ToList();
        await Task.Delay(TimeSpan.FromMilliseconds(500), Cancel);

        var started = DateTime.UtcNow;
        using var third = McpPost();
        using var response = await client.SendAsync(third, Cancel);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(2), "rejected without waiting");
        stop.Cancel();
        await Task.WhenAll(slow.Select(t => t.ContinueWith(_ => { }, TaskScheduler.Default)));
    }

    // 7
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task X_Forwarded_For_counts_only_from_a_trusted_proxy(bool trusted)
    {
        var hardening = HttpHardeningOptions.Defaults with
        {
            RateLimitPerIpPerMinute = 2,
            TrustedProxies = trusted ? [IPNetwork.Parse("10.0.0.0/24")] : [],
        };
        using var app = new No2SqlHttpApp(
            services => services.AddSingleton<IStartupFilter>(new FromAddress(IPAddress.Parse("10.0.0.5"))),
            null, hardening);
        using var client = app.CreateClient();

        async Task<HttpStatusCode> Send(string forwardedFor)
        {
            using var request = McpPost();
            request.Headers.Add("X-Forwarded-For", forwardedFor);
            using var response = await client.SendAsync(request, Cancel);
            return response.StatusCode;
        }

        Assert.Equal(HttpStatusCode.OK, await Send("1.2.3.4"));
        Assert.Equal(HttpStatusCode.OK, await Send("1.2.3.4"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await Send("1.2.3.4"));

        // Another client behind the same proxy: its own partition only when the proxy is trusted.
        Assert.Equal(trusted ? HttpStatusCode.OK : HttpStatusCode.TooManyRequests, await Send("5.6.7.8"));
    }

    // 8
    [Fact]
    public async Task An_unhandled_exception_gives_the_generic_JSON_RPC_error_and_logs_the_id()
    {
        var logs = new CapturingLoggerProvider();
        using var app = new No2SqlHttpApp(services =>
        {
            services.AddSingleton<ILoggerProvider>(logs);
            // A fault inside the HTTP handler, outside the SDK's per-request error handling.
            services.Configure<HttpServerTransportOptions>(o =>
                o.ConfigureSessionOptions = (_, _, _) => throw new InvalidOperationException("sensitive-detail-7f3a"));
        });
        using var client = app.CreateClient();
        using var request = McpPost();

        using var response = await client.SendAsync(request, Cancel);
        var body = await response.Content.ReadAsStringAsync(Cancel);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var json = JsonNode.Parse(body)!;
        Assert.Equal(-32603, (int)json["error"]!["code"]!);
        var message = (string)json["error"]!["message"]!;
        var errorId = System.Text.RegularExpressions.Regex.Match(message, "error id ([0-9a-f]{8})\\.$").Groups[1].Value;
        Assert.NotEmpty(errorId);
        Assert.DoesNotContain("sensitive-detail", body);
        Assert.DoesNotContain("InvalidOperationException", body);
        Assert.DoesNotContain(" at ", body);

        var logged = Assert.Single(logs.Entries, e => e.Exception is not null);
        Assert.Contains(errorId, logged.Message);
        Assert.Equal("sensitive-detail-7f3a", logged.Exception!.Message);
    }

    // 9
    [Theory]
    [InlineData("GET", "/healthz", false)]
    [InlineData("POST", "/mcp", true)]
    [InlineData("GET", "/nothing-here", false)]
    [InlineData("GET", "/authorize", true)]
    public async Task Every_response_has_the_security_headers_and_no_Server_header(string method, string path, bool noStore)
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();
        using var request = method == "POST" ? McpPost() : new HttpRequestMessage(HttpMethod.Get, path);

        using var response = await client.SendAsync(request, Cancel);

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("default-src 'none'; frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.False(response.Headers.Contains("Server"));
        Assert.False(response.Headers.Contains("Strict-Transport-Security"), "no HSTS over plain http");
        if (noStore || path == "/healthz")
        {
            Assert.True(response.Headers.CacheControl?.NoStore, "Cache-Control: no-store");
        }
    }

    [Theory]
    [InlineData(true, "https", true)]
    [InlineData(true, "http", false)]
    [InlineData(false, "https", false)]
    public async Task HSTS_only_when_enabled_and_the_effective_scheme_is_https(bool hsts, string forwardedProto, bool expected)
    {
        var hardening = HttpHardeningOptions.Defaults with { Hsts = hsts, TrustedProxies = [IPNetwork.Parse("10.0.0.0/24")] };
        using var app = new No2SqlHttpApp(
            services => services.AddSingleton<IStartupFilter>(new FromAddress(IPAddress.Parse("10.0.0.5"))),
            null, hardening);
        using var client = app.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        request.Headers.Add("X-Forwarded-Proto", forwardedProto);

        using var response = await client.SendAsync(request, Cancel);

        Assert.Equal(expected, response.Headers.Contains("Strict-Transport-Security"));
    }

    // 10
    [Theory]
    [InlineData("/")]
    [InlineData("/anything")]
    public async Task Unknown_paths_get_404_with_an_empty_body(string path)
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();

        using var response = await client.GetAsync(path, Cancel);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync(Cancel));
    }

    // 11
    [Fact]
    public async Task A_call_longer_than_the_request_timeout_ends_with_504()
    {
        using var silentMongo = new TcpListener(IPAddress.Loopback, 0);
        silentMongo.Start();
        var port = ((IPEndPoint)silentMongo.LocalEndpoint).Port;
        var hardening = HttpHardeningOptions.Defaults with { RequestTimeout = TimeSpan.FromSeconds(2) };
        using var app = new No2SqlHttpApp(null, $"mongodb://127.0.0.1:{port}/?directConnection=true", hardening);
        using var client = app.CreateClient();
        var started = DateTime.UtcNow;

        // The SDK starts its event stream before the tool runs, so the timeout cannot turn the answer
        // into a 504 any more: it ends the stream instead (the spec's second outcome). Either way the
        // request must not outlive the timeout by more than a second.
        HttpStatusCode? status = null;
        try
        {
            var reply = await client.CallToolAsync("list_databases", cancellationToken: Cancel);
            status = reply.Http.StatusCode;
        }
        catch (HttpRequestException)
        {
        }

        var elapsed = DateTime.UtcNow - started;
        Assert.True(status is null or HttpStatusCode.GatewayTimeout, $"unexpected status {status}");
        Assert.True(elapsed >= TimeSpan.FromSeconds(1.5) && elapsed < TimeSpan.FromSeconds(3), $"ended after {elapsed}, expected about 2 s");
    }

    // 15
    [Fact]
    public async Task Healthz_is_rate_limited_per_IP()
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 61; i++)
        {
            using var response = await client.GetAsync("/healthz", Cancel);
            statuses.Add(response.StatusCode);
        }

        Assert.All(statuses.Take(60), s => Assert.Equal(HttpStatusCode.OK, s));
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[60]);
    }

    // 16 (the OAuth endpoints arrive with P2-5; the per-IP limit already applies to their paths)
    [Theory]
    [InlineData("/authorize")]
    [InlineData("/login")]
    [InlineData("/consent")]
    public async Task The_authorize_paths_are_limited_to_20_per_minute_per_IP(string path)
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 21; i++)
        {
            using var response = await client.GetAsync(path, Cancel);
            statuses.Add(response.StatusCode);
        }

        Assert.DoesNotContain(HttpStatusCode.TooManyRequests, statuses.Take(20));
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[20]);
    }

    private static HttpHardeningOptions Options(Dictionary<string, string?> variables)
    {
        HttpBindings.TryParse(null, out var bindings, out _);
        Assert.True(HttpHardeningOptions.TryParse(name => variables.GetValueOrDefault(name), bindings, out var options, out var error), error);
        return options!;
    }

    // Stands in for a P2-5 HTML page that sets its own CSP and caching, mapped after the app's endpoints.
    private sealed class PageEndpoint : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            next(app);
            app.Run(context =>
            {
                context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; form-action https://client.example";
                context.Response.Headers.CacheControl = "private, max-age=0";
                return context.Response.WriteAsync("<html></html>");
            });
        };
    }

    // The in-memory server has no client address; this sets one, as a proxy's address would be.
    private sealed class FromAddress(IPAddress address) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress = address;
                return nextMiddleware(context);
            });
            next(app);
        };
    }
}
