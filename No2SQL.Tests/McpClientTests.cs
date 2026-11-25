using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>A real MCP client (the SDK's own) against HTTP mode, as a check that the endpoint is usable end to end.</summary>
public class McpClientTests
{
    [Fact]
    public async Task The_SDK_client_connects_lists_the_tools_and_calls_one()
    {
        var cancel = TestContext.Current.CancellationToken;
        using var app = new No2SqlHttpApp();
        using var http = app.CreateClient();

        var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(http.BaseAddress!, "/mcp"),
                TransportMode = HttpTransportMode.StreamableHttp,
            },
            http,
            loggerFactory: null,
            ownsHttpClient: false);

        await using var client = await McpClient.CreateAsync(transport, cancellationToken: cancel);

        var tools = await client.ListToolsAsync(cancellationToken: cancel);
        var result = await client.CallToolAsync("test_connectivity", cancellationToken: cancel);

        Assert.Equal("No2SQL", client.ServerInfo?.Name);
        Assert.Equal(10, tools.Count);
        Assert.NotEqual(true, result.IsError);
        Assert.Equal("MCP connectivity test successful!", Assert.IsType<TextContentBlock>(Assert.Single(result.Content)).Text);
    }
}
