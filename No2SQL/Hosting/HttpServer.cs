using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.AspNetCore;

namespace No2SQL.Hosting;

/// <summary>
/// HTTP mode (<c>--http</c> or NO2SQL_TRANSPORT=http): the same MCP server as stdio, served as
/// stateless Streamable HTTP at <see cref="McpPath"/>, plus a health check at <see cref="HealthPath"/>.
/// <see cref="ConfigureServices"/> and <see cref="ConfigurePipeline"/> are the whole application; the
/// test host (No2SQL.Tests) runs the same two methods on an in-memory server.
/// </summary>
internal static class HttpServer
{
    public const string McpPath = "/mcp";
    public const string HealthPath = "/healthz";

    // The complete health check answer. It never carries a version, an address or a MongoDB status.
    public const string HealthBody = "{\"status\":\"ok\"}";

    // Exit code for a start-up refusal caused by configuration (as opposed to a crash).
    private const int ConfigurationError = 2;

    public static async Task<int> RunAsync(StartupOptions options)
    {
        if (!HttpBindings.TryParse(Environment.GetEnvironmentVariable(HttpBindings.UrlsVariable), out var bindings, out var error))
        {
            Console.Error.WriteLine($"[No2SQL] {error}");
            return ConfigurationError;
        }

        if (!HttpHardeningOptions.TryParse(Environment.GetEnvironmentVariable, bindings, out var hardening, out error))
        {
            Console.Error.WriteLine($"[No2SQL] {error}");
            return ConfigurationError;
        }

        // HTTP mode has no authentication yet, so it must not be reachable from other machines by
        // accident: anything but a loopback address needs the explicit --allow-anonymous flag.
        var exposed = bindings.Where(b => !b.IsLoopback).Select(b => b.DisplayUrl).ToList();
        if (exposed.Count > 0 && !options.AllowAnonymous)
        {
            Console.Error.WriteLine(
                $"[No2SQL] Refusing to start: {string.Join(", ", exposed)} can be reached from other machines and HTTP mode has no authentication. " +
                $"Listen on a loopback address (the default is {HttpBindings.DefaultUrls}), or pass {StartupOptions.AllowAnonymousFlag} to expose the MongoDB tools to anyone who can reach that address.");
            return ConfigurationError;
        }

        // HTTP mode logs to stdout, the stream container platforms collect (in stdio mode stdout belongs
        // to the MCP protocol, so logs go to stderr there). The code shared with stdio writes its notices
        // and error ids with Console.Error, so that is pointed at stdout as well: one stream, in order.
        // Only a failed start-up (the refusals above, or a port that cannot be bound) is reported on stderr.
        var stderr = Console.Error;
        Console.SetError(Console.Out);

        var mongoConn = No2SqlServices.ReadMongoConnectionString();

        // An empty builder on purpose: no appsettings.json, no ASPNETCORE_* or DOTNET_* variables and
        // no command-line configuration. The listen addresses come from NO2SQL_HTTP_URLS only, so the
        // check above cannot be bypassed by another configuration source adding an endpoint.
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());

        // ASP.NET Core's own categories are limited to warnings so request lines (path and query
        // string) are not logged. The level cannot be lowered from outside: there is no configuration source.
        builder.Logging.AddConsole();
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);

        builder.WebHost.UseKestrelCore().ConfigureKestrel(kestrel =>
        {
            HttpHardening.ConfigureLimits(kestrel, hardening!);
            foreach (var binding in bindings)
            {
                if (binding.IsLocalhostName)
                {
                    kestrel.ListenLocalhost(binding.Port);
                }
                else if (binding.Address is { } address)
                {
                    kestrel.Listen(address, binding.Port);
                }
                else
                {
                    kestrel.ListenAnyIP(binding.Port);
                }
            }
        });

        ConfigureServices(builder.Services, mongoConn, hardening);

        await using var app = builder.Build();
        ConfigurePipeline(app);

        var listenUrls = string.Join(", ", bindings.Select(b => b.DisplayUrl));
        try
        {
            await app.StartAsync();
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            // A port that is taken, or an address this machine does not have. The host has already
            // logged the details; finish with one line that names the setting to change.
            stderr.WriteLine($"[No2SQL] Could not listen on {listenUrls} ({ex.Message}). Check {HttpBindings.UrlsVariable}.");
            return 1;
        }

        // Written on every start, never only once: there is no sign-in in front of the tools yet.
        if (exposed.Count > 0)
        {
            Console.Out.WriteLine(
                $"[No2SQL] WARNING: {StartupOptions.AllowAnonymousFlag} is set. {string.Join(", ", exposed)} has no authentication: anyone who can reach it can use the MongoDB tools.");
        }
        else
        {
            Console.Out.WriteLine(
                "[No2SQL] WARNING: HTTP mode has no authentication. It listens on this machine only; any local program can use the MongoDB tools.");
        }

        Console.Out.WriteLine($"[No2SQL] HTTP mode: MCP endpoint {McpPath} and health check {HealthPath} on {listenUrls}.");
        Console.Out.WriteLine($"[No2SQL] HTTP hardening: {hardening!.Summary()}.");
        foreach (var warning in hardening.Warnings)
        {
            Console.Out.WriteLine($"[No2SQL] WARNING: {warning}");
        }

        await app.WaitForShutdownAsync();
        return 0;
    }

    /// <summary>
    /// The services of HTTP mode: the shared No2SQL services and tools, routing, the hardening layer
    /// (<see cref="HttpHardening"/>) and the MCP SDK's Streamable HTTP transport.
    /// </summary>
    /// <param name="hardening">Null means the defaults for the default listen address.</param>
    public static void ConfigureServices(IServiceCollection services, string? mongoConnectionString, HttpHardeningOptions? hardening = null)
    {
        services.AddRoutingCore();
        services.AddHttpHardening(hardening ?? HttpHardeningOptions.Defaults);
        services
            .AddNo2SqlServices(mongoConnectionString)
            // Stateless Streamable HTTP: no Mcp-Session-Id, no GET stream, no legacy SSE endpoints.
            // Set explicitly so a later change of the SDK default cannot switch sessions on.
            .WithHttpTransport(transport => transport.SessionMode = HttpServerSessionMode.Stateless);
    }

    /// <summary>
    /// The whole request pipeline: the hardening layer around routing (see <see cref="HttpHardening"/>
    /// for the order) and two endpoints. Any other path is a 404 with an empty body. There is
    /// deliberately no developer exception page, no static files, no HTTPS redirection, no CORS and
    /// no request logging.
    /// </summary>
    public static void ConfigurePipeline(IApplicationBuilder app)
    {
        app.UseHttpHardeningBeforeRouting();
        app.UseHttpHardeningAfterRouting();
        app.UseEndpoints(endpoints =>
        {
            // Liveness only: no authentication, no MongoDB call, a fixed body.
            endpoints.MapGet(HealthPath, static context =>
            {
                context.Response.ContentType = "application/json";
                context.Response.Headers.CacheControl = "no-store";
                return context.Response.WriteAsync(HealthBody);
            }).WithRequestTimeout("health");
            endpoints.MapMcp(McpPath);
        });
    }
}
