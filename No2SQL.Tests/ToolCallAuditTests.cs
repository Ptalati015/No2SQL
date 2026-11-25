using System.Net;
using System.Security.Claims;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using No2SQL.Hosting;
using No2SQL.Tests.Infrastructure;

namespace No2SQL.Tests;

/// <summary>
/// P2-7: one audit log line per tool call (tool, database, collection, caller, outcome, duration), and
/// nothing secret in any log entry or response: not the Authorization or Cookie header, not other
/// arguments, not the connection string.
/// </summary>
public class ToolCallAuditTests
{
    private const string ConnectionPassword = "audit-test-password";

    // A valid connection string for a server that is not there: tools that need MongoDB fail fast.
    private const string UnreachableMongo =
        $"mongodb://auditor:{ConnectionPassword}@127.0.0.1:9/?serverSelectionTimeoutMS=300&connectTimeoutMS=300";

    private static CancellationToken Cancel => TestContext.Current.CancellationToken;

    private static (No2SqlHttpApp App, CapturingLoggerProvider Logs) CreateApp(
        Action<IServiceCollection>? configure = null, string? mongoConnectionString = null)
    {
        var logs = new CapturingLoggerProvider();
        var app = new No2SqlHttpApp(services =>
        {
            services.AddSingleton<ILoggerProvider>(logs);
            configure?.Invoke(services);
        }, mongoConnectionString);
        return (app, logs);
    }

    [Fact]
    public async Task Each_tool_call_writes_one_audit_line_with_its_fields()
    {
        var clock = new FakeTimeProvider();
        var (app, logs) = CreateApp(services => services.AddSingleton<TimeProvider>(clock));
        using var _ = app;
        using var client = app.CreateClient();

        await client.CallToolAsync("test_connectivity", cancellationToken: Cancel);
        await client.CallToolAsync("generate_seeders_for_collection", new JsonObject
        {
            ["databaseName"] = "shop",
            ["collectionName"] = "orders",
        }, Cancel);
        await client.ListToolsAsync(Cancel);   // not a tool call: no audit line

        var lines = logs.InCategory(ToolCallAudit.Category).Select(e => e.Message).ToList();
        Assert.Equal(
        [
            "tool call: tool=\"test_connectivity\" database=- collection=- caller=\"anonymous\" outcome=ok duration_ms=0",
            "tool call: tool=\"generate_seeders_for_collection\" database=\"shop\" collection=\"orders\" caller=\"anonymous\" outcome=error duration_ms=0",
        ], lines);
        Assert.All(logs.InCategory(ToolCallAudit.Category), e => Assert.Equal(LogLevel.Information, e.Level));
    }

    [Fact]
    public async Task The_caller_is_the_sub_claim_of_a_signed_in_user()
    {
        var (app, logs) = CreateApp(services => services.AddSingleton<IStartupFilter>(new SignInAs("user-42")));
        using var _ = app;
        using var client = app.CreateClient();

        await client.CallToolAsync("test_connectivity", cancellationToken: Cancel);

        var line = Assert.Single(logs.InCategory(ToolCallAudit.Category)).Message;
        Assert.Contains("caller=\"user-42\"", line);
    }

    [Fact]
    public async Task Names_from_the_caller_cannot_break_the_line()
    {
        var (app, logs) = CreateApp();
        using var _ = app;
        using var client = app.CreateClient();

        await client.CallToolAsync("generate_sql_schema", new JsonObject
        {
            ["databaseName"] = "shop\ninfo: No2SQL.Audit[0] tool call: tool=\"forged\"" + new string('x', 300),
        }, Cancel);

        var line = Assert.Single(logs.InCategory(ToolCallAudit.Category)).Message;
        Assert.DoesNotContain('\n', line);
        Assert.Contains("database=\"shop\\ninfo: No2SQL.Audit[0] tool call: tool=\\u0022forged\\u0022", line);
        Assert.Contains("...\" collection=-", line);
        Assert.True(line.Length < 400, "a long name is cut");
    }

    [Fact]
    public async Task Headers_other_arguments_and_the_connection_string_appear_in_no_log_or_response()
    {
        const string token = "bearer-canary-0f9e8d7c";
        const string cookie = "cookie-canary-6b5a4c3d";
        const string argument = "argument-canary-2e1f0a9b";
        var (app, logs) = CreateApp(mongoConnectionString: UnreachableMongo);
        using var _ = app;
        using var client = app.CreateClient();
        void AddSecretHeaders(HttpRequestMessage request)
        {
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
            request.Headers.TryAddWithoutValidation("Cookie", $"session={cookie}");
        }

        var replies = new List<McpReply>
        {
            await client.RpcAsync("tools/call", new JsonObject
            {
                ["name"] = "generate_sql_schema_advanced",
                ["arguments"] = new JsonObject
                {
                    ["databaseName"] = "shop",
                    ["overrides"] = new JsonArray(new JsonObject { ["note"] = argument }),
                    ["unknown"] = argument,
                },
            }, AddSecretHeaders, Cancel),
            await client.RpcAsync("tools/call", new JsonObject { ["name"] = "list_databases" }, AddSecretHeaders, Cancel),
            await client.RpcAsync("tools/call", new JsonObject { ["name"] = "no_such_tool", ["arguments"] = new JsonObject { ["x"] = argument } }, AddSecretHeaders, Cancel),
            await client.RpcAsync("no2sql/unknown", new JsonObject { ["x"] = argument }, AddSecretHeaders, Cancel),
        };

        var responses = new List<string>();
        foreach (var reply in replies)
        {
            responses.Add(reply.Message?.ToJsonString() ?? string.Empty);
            responses.Add(reply.Http.Headers.ToString() + reply.Http.Content.Headers);
        }

        using var health = await client.GetAsync(HttpServer.HealthPath, Cancel);
        responses.Add(await health.Content.ReadAsStringAsync(Cancel));

        var logText = logs.AllText;
        Assert.NotEmpty(logs.InCategory(ToolCallAudit.Category));
        foreach (var secret in new[] { token, cookie, argument, ConnectionPassword, UnreachableMongo })
        {
            Assert.DoesNotContain(secret, logText);
            Assert.All(responses, r => Assert.DoesNotContain(secret, r));
        }
    }

    // Stands in for the authentication of P2-4/P2-5: every request arrives signed in as one user.
    private sealed class SignInAs(string subject) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", subject)], authenticationType: "test"));
                return nextMiddleware(context);
            });
            next(app);
        };
    }
}
