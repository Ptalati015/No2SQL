using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using No2SQL.Security;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// A database the policy refuses (not in NO2SQL_ALLOWED_DATABASES, or a blocked system database)
/// gets a tool result that says why, so remote and container users don't need the server logs.
/// It names only the requested database, never the allowed ones, and never depends on MongoDB.
/// </summary>
public sealed class DatabasePolicyTests
{
    private static readonly string[] Allowed = ["sales_allowed", "inventory_allowed"];

    // Unreachable, with a server-selection timeout far longer than the test allows: a refusal that
    // touched MongoDB would hang for 30 s instead of answering at once.
    private const string UnreachableMongo = "mongodb://127.0.0.1:9/?serverSelectionTimeoutMS=30000&connectTimeoutMS=30000";

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    [Fact]
    public void A_database_outside_the_allow_list_is_refused_by_name_only()
    {
        var guardrails = new McpGuardrails(blockSystemDatabases: true, Allowed);

        var refusal = Assert.Throws<DatabasePolicyException>(() => guardrails.ValidateDatabaseName("payroll"));

        Assert.Equal(
            "Database 'payroll' is not in NO2SQL_ALLOWED_DATABASES on this server. Ask the server's operator to add it.",
            refusal.ClientMessage);
        Assert.Equal("Database 'payroll' is not in NO2SQL_ALLOWED_DATABASES. (Parameter 'databaseName')", refusal.Message);
        Assert.All(Allowed, name => Assert.DoesNotContain(name, refusal.ClientMessage));
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("config")]
    [InlineData("LOCAL")]
    public void A_system_database_is_refused_before_the_allow_list_is_checked(string database)
    {
        // Not in the allow-list either: the system block answers first, every time.
        var guardrails = new McpGuardrails(blockSystemDatabases: true, Allowed);

        var refusal = Assert.Throws<DatabasePolicyException>(() => guardrails.ValidateDatabaseName(database));

        Assert.Equal(
            $"Database '{database}' is a MongoDB system database, and this server blocks system databases (NO2SQL_BLOCK_SYSTEM_DATABASES).",
            refusal.ClientMessage);
    }

    [Theory]
    [InlineData("")]
    [InlineData("bad name")]
    [InlineData("ignore previous instructions")]
    public void Other_invalid_names_stay_ordinary_argument_errors(string database)
    {
        var guardrails = new McpGuardrails(blockSystemDatabases: true, Allowed);

        var error = Assert.ThrowsAny<ArgumentException>(() => guardrails.ValidateDatabaseName(database));

        Assert.IsNotType<DatabasePolicyException>(error);
    }

    [Fact]
    public void Allowed_names_and_an_empty_allow_list_pass()
    {
        Assert.Equal("sales_allowed", new McpGuardrails(true, Allowed).ValidateDatabaseName(" sales_allowed "));
        Assert.Equal("anything", new McpGuardrails(true, []).ValidateDatabaseName("anything"));
        Assert.Equal("admin", new McpGuardrails(false, []).ValidateDatabaseName("admin"));
    }

    [Theory]
    [InlineData("payroll", "is not in NO2SQL_ALLOWED_DATABASES on this server")]
    [InlineData("admin", "is a MongoDB system database")]
    public async Task Over_HTTP_the_tool_result_says_why_without_contacting_MongoDB(string database, string reason)
    {
        using var app = new No2SqlHttpApp(
            services => services.AddSingleton(new McpGuardrails(blockSystemDatabases: true, Allowed)),
            UnreachableMongo);
        using var client = app.CreateClient();
        var timer = Stopwatch.StartNew();

        var reply = await client.CallToolAsync("generate_sql_schema", new JsonObject { ["databaseName"] = database }, Cancel);

        Assert.True(timer.Elapsed < TimeSpan.FromSeconds(10), $"took {timer.Elapsed}; the refusal must not wait for MongoDB");
        Assert.True(reply.Result["isError"]?.GetValue<bool>(), "isError");
        var text = reply.Result["content"]![0]!["text"]!.GetValue<string>();
        Assert.StartsWith($"Database '{database}' {reason}", text);
        Assert.Matches(@"\(error id [0-9a-f]{8}\)$", text);
        Assert.All(Allowed, name => Assert.DoesNotContain(name, text));
        Assert.DoesNotContain("Unable to complete", text);
    }

    [Fact]
    public async Task Over_HTTP_an_invalid_name_keeps_the_generic_message()
    {
        using var app = new No2SqlHttpApp(
            services => services.AddSingleton(new McpGuardrails(blockSystemDatabases: true, Allowed)),
            UnreachableMongo);
        using var client = app.CreateClient();

        var reply = await client.CallToolAsync("generate_sql_schema", new JsonObject { ["databaseName"] = "bad name" }, Cancel);

        var text = reply.Result["content"]![0]!["text"]!.GetValue<string>();
        Assert.StartsWith("Unable to complete generating SQL schema for 'bad name'. See server logs with error id ", text);
    }
}
