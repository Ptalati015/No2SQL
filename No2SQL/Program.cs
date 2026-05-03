using System.Runtime.CompilerServices;
using Microsoft.Extensions.Configuration;
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

// Resolve MongoDB connection string from env var first, then appsettings if it's a real value.
var envMongoConn = Environment.GetEnvironmentVariable("NO2SQL_MONGO");
var configMongoConn = builder.Configuration.GetConnectionString("MongoDb");

var mongoConn = !string.IsNullOrWhiteSpace(envMongoConn)
    ? envMongoConn
    : (string.IsNullOrWhiteSpace(configMongoConn) || configMongoConn.Contains("<", StringComparison.Ordinal))
        ? null
        : configMongoConn;

builder.Services.AddScoped(sp => new SchemaAnalyzer(mongoConn));
builder.Services.AddScoped(sp => new ScriptGenerator(mongoConn));
builder.Services.AddScoped(sp => new ErdGenerator());
builder.Services.AddSingleton(sp => new McpGuardrails());


// Add the MCP services: the transport to use (stdio) and the tools to register.
builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithTools<SchemaTools>();

await builder.Build().RunAsync();
