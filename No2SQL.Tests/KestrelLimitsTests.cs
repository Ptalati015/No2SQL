using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using No2SQL.Hosting;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// P2-6 limits that only a real Kestrel enforces: a chunked body over the limit (criterion 4) and
/// the configured Kestrel limits (criterion 17). Listens on a random loopback port.
/// </summary>
public sealed class KestrelLimitsTests : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly HttpClient _client;

    public KestrelLimitsTests()
    {
        var hardening = HttpHardeningOptions.Defaults;
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        builder.WebHost.UseKestrelCore().ConfigureKestrel(kestrel =>
        {
            HttpHardening.ConfigureLimits(kestrel, hardening);
            kestrel.Listen(IPAddress.Loopback, 0);
        });
        HttpServer.ConfigureServices(builder.Services, mongoConnectionString: null, hardening);
        _app = builder.Build();
        HttpServer.ConfigurePipeline(_app);
        _app.StartAsync(TestContext.Current.CancellationToken).GetAwaiter().GetResult();

        var address = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        _client = new HttpClient { BaseAddress = new Uri(address) };
    }

    public async ValueTask DisposeAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
    }

    private static HttpRequestMessage McpPost(HttpContent content)
    {
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = content };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        request.Headers.Add("MCP-Protocol-Version", McpHttp.ProtocolVersion);
        return request;
    }

    [Fact]
    public async Task A_chunked_body_over_the_limit_gets_413()
    {
        var body = new MemoryStream(new byte[2 * 1024 * 1024]);
        using var content = new StreamContent(body);   // no Content-Length: sent chunked
        using var request = McpPost(content);
        request.Headers.TransferEncodingChunked = true;

        using var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task A_declared_body_over_the_limit_gets_413_and_no_Server_header()
    {
        using var content = new ByteArrayContent(new byte[2 * 1024 * 1024]);
        using var request = McpPost(content);

        using var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.False(response.Headers.Contains("Server"));
    }

    [Fact]
    public void The_Kestrel_limits_are_set()
    {
        var limits = _app.Services.GetRequiredService<IOptions<KestrelServerOptions>>().Value;

        Assert.False(limits.AddServerHeader);
        Assert.Equal(1048576, limits.Limits.MaxRequestBodySize);
        Assert.Equal(256, limits.Limits.MaxConcurrentConnections);
        Assert.Equal(16 * 1024, limits.Limits.MaxRequestHeadersTotalSize);
        Assert.Equal(4 * 1024, limits.Limits.MaxRequestLineSize);
        Assert.Equal(TimeSpan.FromSeconds(15), limits.Limits.RequestHeadersTimeout);
        Assert.Equal(TimeSpan.FromSeconds(130), limits.Limits.KeepAliveTimeout);
    }
}
