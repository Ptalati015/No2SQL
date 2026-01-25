using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using No2SQL.Core;

var builder = Host.CreateApplicationBuilder(args);

// Configure all logs to go to stderr (stdout is used for the MCP protocol messages).
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

// Load connection string from appsettings.json or environment variable
var mongoConn = builder.Configuration.GetConnectionString("MongoDb")
    ?? Environment.GetEnvironmentVariable("NO2SQL_MONGO");

builder.Services.AddScoped(sp => new SchemaAnalyzer(mongoConn));


// Add the MCP services: the transport to use (stdio) and the tools to register.
builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithTools<RandomNumberTools>()
    .WithTools<SchemaTools>();

await builder.Build().RunAsync();
