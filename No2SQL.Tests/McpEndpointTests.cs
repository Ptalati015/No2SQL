using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using No2SQL.Hosting;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>The MCP endpoint over HTTP: same server identity, tools and answers as stdio, and no sessions.</summary>
public class McpEndpointTests
{
    private static readonly string[] ExpectedTools =
    [
        "compare_id_fields_to_ids",
        "generate_erd_dot",
        "generate_erd_mermaid",
        "generate_erd_plant_uml",
        "generate_seeders_for_collection",
        "generate_sql_schema",
        "generate_sql_schema_advanced",
        "list_databases",
        "list_inferred_relationships",
        "test_connectivity",
    ];

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Initialize_reports_No2SQL_and_starts_no_session()
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();

        var reply = await client.InitializeAsync(Cancel);

        Assert.Equal(HttpStatusCode.OK, reply.Http.StatusCode);
        Assert.Equal("No2SQL", (string?)reply.Result["serverInfo"]?["name"]);
        Assert.Equal(No2SqlServices.ServerVersion, (string?)reply.Result["serverInfo"]?["version"]);
        Assert.Equal(McpHttp.ProtocolVersion, (string?)reply.Result["protocolVersion"]);
        Assert.NotNull(reply.Result["capabilities"]?["tools"]);
        Assert.False(reply.Http.Headers.Contains("Mcp-Session-Id"), "stateless mode must not hand out a session id");
    }

    [Fact]
    public async Task Tools_list_has_the_ten_tools_with_read_only_annotations()
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();

        var reply = await client.ListToolsAsync(Cancel);

        var tools = reply.Result["tools"]!.AsArray();
        Assert.Equal(ExpectedTools, tools.Select(t => (string)t!["name"]!).Order(StringComparer.Ordinal));
        Assert.All(tools, tool =>
        {
            var annotations = tool!["annotations"];
            Assert.True((bool?)annotations?["readOnlyHint"], $"{tool["name"]}: readOnlyHint");
            Assert.False((bool?)annotations?["destructiveHint"], $"{tool["name"]}: destructiveHint");
            Assert.True((bool?)annotations?["idempotentHint"], $"{tool["name"]}: idempotentHint");
            Assert.False((bool?)annotations?["openWorldHint"], $"{tool["name"]}: openWorldHint");
            Assert.False(string.IsNullOrWhiteSpace((string?)tool["title"]));
            Assert.False(string.IsNullOrWhiteSpace((string?)tool["description"]));
        });
    }

    [Fact]
    public async Task The_cancellation_token_of_a_tool_is_not_part_of_its_input_schema()
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();

        var reply = await client.ListToolsAsync(Cancel);

        var tools = reply.Result["tools"]!.AsArray().ToDictionary(t => (string)t!["name"]!, t => t!["inputSchema"]!);
        Assert.All(tools, tool => Assert.DoesNotContain("cancellationToken", tool.Value.ToJsonString(), StringComparison.OrdinalIgnoreCase));
        Assert.Equal([], PropertyNames(tools["test_connectivity"]));
        Assert.Equal([], PropertyNames(tools["list_databases"]));
        Assert.Equal(["databaseName"], PropertyNames(tools["generate_sql_schema"]));
        Assert.Equal(["databaseName", "overrides"], PropertyNames(tools["generate_sql_schema_advanced"]));
        Assert.Equal(["collectionName", "databaseName"], PropertyNames(tools["generate_seeders_for_collection"]));
        Assert.Equal(["databaseName", "source"], PropertyNames(tools["generate_erd_mermaid"]));
    }

    [Fact]
    public async Task Test_connectivity_succeeds_without_MongoDB()
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();

        var reply = await client.CallToolAsync("test_connectivity", cancellationToken: Cancel);

        Assert.Equal(HttpStatusCode.OK, reply.Http.StatusCode);
        Assert.Null(reply.Result["isError"]);
        Assert.Equal("MCP connectivity test successful!", (string?)reply.Result["content"]?[0]?["text"]);
    }

    [Fact]
    public async Task A_tool_that_needs_MongoDB_answers_isError_with_the_fixed_message_when_it_is_not_configured()
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();

        var reply = await client.CallToolAsync("list_databases", cancellationToken: Cancel);

        Assert.Equal(HttpStatusCode.OK, reply.Http.StatusCode);
        Assert.True((bool?)reply.Result["isError"]);
        Assert.Equal(
            "No MongoDB connection string is set. Whoever runs this server sets NO2SQL_MONGO, or " +
            "NO2SQL_MONGO_FILE to a file that holds it, in the server's environment (for a local server, the " +
            "env section of the MCP client's configuration), then restarts the server.",
            (string?)reply.Result["content"]?[0]?["text"]);
    }

    [Fact]
    public async Task An_unusable_connection_string_is_never_echoed()
    {
        // Built at run time so no credential-shaped literal sits in the repository. The port is out
        // of range, so the driver refuses to parse the string.
        var password = Guid.NewGuid().ToString("N");
        using var app = new No2SqlHttpApp(mongoConnectionString: $"mongodb://app:{password}@db.internal.example:99999999/");
        using var client = app.CreateClient();

        var reply = await client.CallToolAsync("generate_sql_schema", new JsonObject { ["databaseName"] = "shop" }, Cancel);

        var json = reply.Message!.ToJsonString();
        Assert.True((bool?)reply.Result["isError"]);
        Assert.Matches(
            "^The value of NO2SQL_MONGO or NO2SQL_MONGO_FILE is not a valid MongoDB connection string\\. Whoever " +
            "runs this server corrects it in the server's environment, then restarts the server\\. " +
            "See server logs with error id [0-9a-f]{8}\\.$",
            (string?)reply.Result["content"]?[0]?["text"]);
        Assert.DoesNotContain(password, json);
        Assert.DoesNotContain("db.internal.example", json);
    }

    [Fact]
    public async Task An_unknown_tool_and_an_unknown_method_are_JSON_RPC_errors()
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();

        var unknownTool = await client.CallToolAsync("no_such_tool", cancellationToken: Cancel);
        var unknownMethod = await client.RpcAsync("no/such/method", cancellationToken: Cancel);

        Assert.Equal(-32602, (int?)unknownTool.Error?["code"]);
        Assert.Equal(-32601, (int?)unknownMethod.Error?["code"]);
    }

    [Theory]
    [InlineData("GET", "/mcp", HttpStatusCode.MethodNotAllowed)]      // no server-to-client stream in stateless mode
    [InlineData("DELETE", "/mcp", HttpStatusCode.MethodNotAllowed)]   // no session to end
    [InlineData("GET", "/sse", HttpStatusCode.NotFound)]              // legacy SSE transport is off
    [InlineData("POST", "/message", HttpStatusCode.NotFound)]
    [InlineData("GET", "/", HttpStatusCode.NotFound)]
    [InlineData("GET", "/mcp/", HttpStatusCode.MethodNotAllowed)]
    [InlineData("GET", "/swagger", HttpStatusCode.NotFound)]
    public async Task Only_POST_mcp_and_GET_healthz_are_served(string method, string path, HttpStatusCode expected)
    {
        using var app = new No2SqlHttpApp();
        using var client = app.CreateClient();
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        request.Headers.Accept.ParseAdd("text/event-stream");

        using var response = await client.SendAsync(request, Cancel);

        Assert.Equal(expected, response.StatusCode);
    }

    private static string[] PropertyNames(JsonNode inputSchema) =>
        inputSchema["properties"] is JsonObject properties
            ? [.. properties.Select(p => p.Key).Order(StringComparer.Ordinal)]
            : [];
}
