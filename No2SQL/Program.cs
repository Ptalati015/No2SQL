using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using No2SQL.Hosting;
using No2SQL.Security;

[assembly: InternalsVisibleTo("No2SQL.Test")]
[assembly: InternalsVisibleTo("No2SQL.Tests")]

// stdio is the default transport. HTTP mode is opt-in with --http or NO2SQL_TRANSPORT=http.
if (!StartupOptions.TryParse(args, Environment.GetEnvironmentVariable(StartupOptions.TransportVariable), out var startup, out var startupError))
{
    Console.Error.WriteLine($"[No2SQL] {startupError}");
    return 2;
}

if (startup.Transport == TransportKind.Http)
{
    return await HttpServer.RunAsync(startup);
}

// Every stderr line is masked for the secrets this process knows. stdout carries the MCP protocol
// and is not touched.
RedactingTextWriter.InstallOnConsole(SecretRedactor.Process, includeStdout: false);
SecretRedactor.Process.AddSecretVariables(Environment.GetEnvironmentVariable);

if (!No2SqlServices.TryReadMongoConnectionString(out var mongoConn, out var mongoError))
{
    Console.Error.WriteLine($"[No2SQL] {mongoError}");
    return 2;
}

var builder = Host.CreateApplicationBuilder(startup.HostArgs);

// Configure all logs to go to stderr (stdout is used for the MCP protocol messages), one line each.
builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

// The services and tools are shared with HTTP mode; only the transport differs.
builder.Services
    .AddNo2SqlServices(mongoConn)
    .WithStdioServerTransport();

await builder.Build().RunAsync();
return 0;
