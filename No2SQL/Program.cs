using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using No2SQL.Hosting;

[assembly: InternalsVisibleTo("No2SQL.Test")]
[assembly: InternalsVisibleTo("No2SQL.Tests")]

// "No2SQL oauth ..." is the owner's command line for the built-in sign-in. It changes the data directory
// and exits; it never starts a server.
if (args.Length > 0 && args[0] == No2SQL.Hosting.OAuth.OAuthCli.Command)
{
    return No2SQL.Hosting.OAuth.OAuthCli.Run(args[1..], Environment.GetEnvironmentVariable, TimeProvider.System, Console.Out, Console.Error);
}

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

var builder = Host.CreateApplicationBuilder(startup.HostArgs);

// Configure all logs to go to stderr (stdout is used for the MCP protocol messages).
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

var mongoConn = No2SqlServices.ReadMongoConnectionString();

// The services and tools are shared with HTTP mode; only the transport differs.
builder.Services
    .AddNo2SqlServices(mongoConn)
    .WithStdioServerTransport();

await builder.Build().RunAsync();
return 0;
