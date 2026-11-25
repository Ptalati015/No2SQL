using System.Net;
using System.Net.Sockets;
using ModelContextProtocol.Protocol;
using No2SQL.Core;
using No2SQL.Security;
using No2SQL.Sql;
using No2SQL.Visuals;

namespace No2SQL.Tests;

/// <summary>
/// Every tool hands its CancellationToken to MongoDB and stops when it is cancelled, so a request
/// timeout can end the work. The "MongoDB" here is a local socket that accepts connections and never
/// answers, which is what a hung or unreachable server looks like to the driver.
/// </summary>
public sealed class ToolCancellationTests : IDisposable
{
    private readonly TcpListener _silentServer = new(IPAddress.Loopback, 0);
    private readonly SchemaTools _tools;

    public ToolCancellationTests()
    {
        _silentServer.Start();
        var port = ((IPEndPoint)_silentServer.LocalEndpoint).Port;
        var mongo = new MongoConnection($"mongodb://127.0.0.1:{port}/?directConnection=true");
        _tools = new SchemaTools(mongo, new SchemaAnalyzer(mongo), new ScriptGenerator(mongo), new ErdGenerator(), new McpGuardrails());
    }

    public void Dispose() => _silentServer.Dispose();

    public static TheoryData<string> MongoTools =>
    [
        "list_databases",
        "list_inferred_relationships",
        "compare_id_fields_to_ids",
        "generate_sql_schema",
        "generate_sql_schema_advanced",
        "generate_seeders_for_collection",
        "generate_erd_mermaid",
        "generate_erd_plant_uml",
        "generate_erd_dot",
    ];

    [Theory]
    [MemberData(nameof(MongoTools))]
    public async Task A_tool_waiting_for_MongoDB_stops_when_its_token_is_cancelled(string tool)
    {
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var started = DateTime.UtcNow;

        var call = Call(tool, cancel.Token);
        await Task.Delay(TimeSpan.FromMilliseconds(300), TestContext.Current.CancellationToken);
        Assert.False(call.IsCompleted, "the tool should still be waiting for the server that never answers");
        cancel.Cancel();

        // Not an isError result: a cancelled request is dropped, it is not answered with an error id.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);

        // Without the token the driver would keep trying for its 30 second server selection timeout.
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(10), "cancellation should end the call at once");
    }

    [Fact]
    public async Task Test_connectivity_takes_the_token_too()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _tools.TestConnectivity(cancelled.Token));
        Assert.NotEqual(true, (await _tools.TestConnectivity(CancellationToken.None)).IsError);
    }

    private Task<CallToolResult> Call(string tool, CancellationToken token) => tool switch
    {
        "list_databases" => _tools.ListDatabases(token),
        "list_inferred_relationships" => _tools.ListInferredRelationships("shop", token),
        "compare_id_fields_to_ids" => _tools.CompareIdFieldsToIds("shop", token),
        "generate_sql_schema" => _tools.GenerateSqlSchema("shop", token),
        "generate_sql_schema_advanced" => _tools.GenerateSqlSchemaAdvanced("shop", null, token),
        "generate_seeders_for_collection" => _tools.GenerateSeedersForCollection("shop", "orders", token),
        "generate_erd_mermaid" => _tools.GenerateErdMermaid("shop", "sql", token),
        "generate_erd_plant_uml" => _tools.GenerateErdPlantUml("shop", "sql", token),
        "generate_erd_dot" => _tools.GenerateErdDot("shop", "sql", token),
        _ => throw new ArgumentOutOfRangeException(nameof(tool), tool, "not a MongoDB tool"),
    };
}
