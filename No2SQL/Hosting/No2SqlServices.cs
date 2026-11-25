using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using No2SQL.Core;
using No2SQL.Security;
using No2SQL.Sql;
using No2SQL.Visuals;

namespace No2SQL.Hosting;

/// <summary>
/// Everything the stdio and HTTP hosts have in common: the MongoDB connection, the analyzers and
/// generators, the guardrails, the MCP server identity and the tools. Each host adds only its transport.
/// </summary>
internal static class No2SqlServices
{
    public const string MongoVariable = "NO2SQL_MONGO";

    /// <summary>
    /// The package version (for example "1.0.3") for the MCP server identity, instead of the four-part
    /// assembly version. Build metadata after '+' (commit hash) is dropped.
    /// </summary>
    public static string ServerVersion { get; } = ResolveServerVersion();

    /// <summary>
    /// Reads NO2SQL_MONGO, the only source of the MongoDB connection string. It is not parsed here:
    /// MongoConnection builds the client on the first tool call that needs it, so the server starts,
    /// lists its tools and answers test_connectivity even when the variable is missing or wrong.
    /// </summary>
    public static string? ReadMongoConnectionString()
    {
        var mongoConn = Environment.GetEnvironmentVariable(MongoVariable);
        if (string.IsNullOrWhiteSpace(mongoConn))
        {
            Console.Error.WriteLine(
                "[No2SQL] NO2SQL_MONGO is not set. The server is running, but tools that read MongoDB will ask for it.");
        }

        return mongoConn;
    }

    /// <summary>Registers the No2SQL services and the MCP server with its tools, without a transport.</summary>
    public static IMcpServerBuilder AddNo2SqlServices(this IServiceCollection services, string? mongoConnectionString)
    {
        services.AddSingleton(new MongoConnection(mongoConnectionString));
        services.AddScoped(sp => new SchemaAnalyzer(sp.GetRequiredService<MongoConnection>()));
        services.AddScoped(sp => new ScriptGenerator(sp.GetRequiredService<MongoConnection>()));
        services.AddScoped(sp => new ErdGenerator());
        services.AddSingleton(sp => new McpGuardrails());

        // The clock for every rule that depends on time (token lifetimes, rate limits, timeouts,
        // durations in logs). Take TimeProvider from DI instead of calling DateTime.UtcNow or
        // Stopwatch, so tests can replace it with a fake clock.
        services.TryAddSingleton(TimeProvider.System);

        return services
            .AddMcpServer(options =>
            {
                options.ServerInfo = new() { Name = "No2SQL", Version = ServerVersion };
            })
            .WithTools<SchemaTools>();
    }

    private static string ResolveServerVersion()
    {
        var assembly = typeof(No2SqlServices).Assembly;
        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return string.IsNullOrWhiteSpace(informationalVersion)
            ? assembly.GetName().Version?.ToString(3) ?? "0.0.0"
            : informationalVersion.Split('+')[0];
    }
}
