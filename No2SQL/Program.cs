using System.Reflection;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using No2SQL.Core;
using No2SQL.Security;
using No2SQL.Sql;
using No2SQL.Visuals;

[assembly: InternalsVisibleTo("No2SQL.Test")]

var builder = Host.CreateApplicationBuilder(args);

// Configure all logs to go to stderr (stdout is used for the MCP protocol messages).
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

// NO2SQL_MONGO is the only source of the MongoDB connection string. It is not parsed here:
// MongoConnection builds the client on the first tool call that needs it, so the server starts,
// lists its tools and answers test_connectivity even when the variable is missing or wrong.
var mongoConn = Environment.GetEnvironmentVariable("NO2SQL_MONGO");
if (string.IsNullOrWhiteSpace(mongoConn))
{
    Console.Error.WriteLine(
        "[No2SQL] NO2SQL_MONGO is not set. The server is running, but tools that read MongoDB will ask for it.");
}

builder.Services.AddSingleton(new MongoConnection(mongoConn));
builder.Services.AddScoped(sp => new SchemaAnalyzer(sp.GetRequiredService<MongoConnection>()));
builder.Services.AddScoped(sp => new ScriptGenerator(sp.GetRequiredService<MongoConnection>()));
builder.Services.AddScoped(sp => new ErdGenerator());
builder.Services.AddSingleton(sp => new McpGuardrails());


// Report the package version (e.g. "1.0.3") in the MCP initialize response instead of the
// four-part assembly version. Build metadata after '+' (commit hash) is dropped.
var informationalVersion = typeof(Program).Assembly
    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
var serverVersion = string.IsNullOrWhiteSpace(informationalVersion)
    ? typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"
    : informationalVersion.Split('+')[0];

// Add the MCP services: the transport to use (stdio) and the tools to register.
builder.Services
    .AddMcpServer(options =>
    {
        options.ServerInfo = new() { Name = "No2SQL", Version = serverVersion };
    })
    .WithStdioServerTransport()
    .WithTools<SchemaTools>();

await builder.Build().RunAsync();
