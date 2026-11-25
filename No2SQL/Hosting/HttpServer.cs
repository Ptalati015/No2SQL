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

        if (!HttpAuthOptions.TryParse(Environment.GetEnvironmentVariable, out var auth, out error))
        {
            Console.Error.WriteLine($"[No2SQL] {error}");
            return ConfigurationError;
        }

        if (StartupRefusal(bindings, auth, options.AllowAnonymous) is { } refusal)
        {
            Console.Error.WriteLine($"[No2SQL] {refusal}");
            return ConfigurationError;
        }

        var exposed = bindings.Where(b => !b.IsLoopback).Select(b => b.DisplayUrl).ToList();

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

        // ASP.NET Core's own categories are limited to warnings so request lines (path, query string,
        // headers) are never logged. The level cannot be lowered from outside: there is no configuration
        // source. The sign-in handler's base class logs every unauthenticated request at Information;
        // the handler writes its own line with the reason instead.
        builder.Logging.AddConsole();
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.Logging.AddFilter(typeof(BearerAuthenticationHandler).FullName, LogLevel.Warning);

        builder.WebHost.UseKestrelCore().ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
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

        ConfigureServices(builder.Services, mongoConn, auth);

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

        // Written on every start, never only once.
        if (auth.RequiresSignIn)
        {
            var methods = new List<string>();
            if (auth.HasStaticToken)
            {
                methods.Add($"the bearer token in {HttpAuthOptions.TokenVariable}");
            }

            if (auth.HasAuthority)
            {
                methods.Add($"access tokens from {auth.Authority} for {auth.McpUrl} with scope {auth.Scope}");
            }

            Console.Out.WriteLine($"[No2SQL] Sign-in required on {McpPath}: {string.Join(", or ", methods)}.");
        }
        else if (exposed.Count > 0)
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

        await app.WaitForShutdownAsync();
        return 0;
    }

    /// <summary>
    /// Why HTTP mode must not start with these settings, or null when it may. Without sign-in the
    /// server must not be reachable from other machines by accident: anything but a loopback address
    /// needs sign-in configured or the explicit --allow-anonymous flag.
    /// </summary>
    public static string? StartupRefusal(IReadOnlyList<HttpBinding> bindings, HttpAuthOptions auth, bool allowAnonymous)
    {
        if (allowAnonymous && auth.RequiresSignIn)
        {
            return $"{StartupOptions.AllowAnonymousFlag} cannot be combined with {HttpAuthOptions.TokenVariable} or {HttpAuthOptions.AuthorityVariable}. " +
                "Remove the flag to require sign-in, or unset both variables to run without it.";
        }

        var exposed = bindings.Where(b => !b.IsLoopback).Select(b => b.DisplayUrl).ToList();
        if (exposed.Count > 0 && !auth.RequiresSignIn && !allowAnonymous)
        {
            return $"Refusing to start: {string.Join(", ", exposed)} can be reached from other machines and no sign-in is configured. " +
                $"Set {HttpAuthOptions.TokenVariable} or {HttpAuthOptions.AuthorityVariable}, listen on a loopback address (the default is {HttpBindings.DefaultUrls}), " +
                $"or pass {StartupOptions.AllowAnonymousFlag} to expose the MongoDB tools to anyone who can reach that address.";
        }

        return null;
    }

    /// <summary>
    /// The services of HTTP mode: the shared No2SQL services and tools, routing, sign-in when it is
    /// configured, and the MCP SDK's Streamable HTTP transport.
    /// </summary>
    public static void ConfigureServices(IServiceCollection services, string? mongoConnectionString, HttpAuthOptions auth)
    {
        services.AddRoutingCore();
        services.AddNo2SqlHttpAuth(auth);
        services
            .AddNo2SqlServices(mongoConnectionString)
            // Stateless Streamable HTTP: no Mcp-Session-Id, no GET stream, no legacy SSE endpoints.
            // Set explicitly so a later change of the SDK default cannot switch sessions on.
            .WithHttpTransport(transport => transport.SessionMode = HttpServerSessionMode.Stateless);
    }

    /// <summary>
    /// The whole request pipeline: routing, sign-in when it is configured, the MCP endpoint, the health
    /// check and (with an identity provider) the protected resource metadata. There is deliberately no
    /// developer exception page, no static files, no HTTPS redirection and no request logging.
    /// </summary>
    public static void ConfigurePipeline(IApplicationBuilder app)
    {
        var auth = app.ApplicationServices.GetRequiredService<HttpAuthOptions>();

        app.UseRouting();
        if (auth.RequiresSignIn)
        {
            app.UseAuthentication();
            app.UseAuthorization();
        }

        app.UseEndpoints(endpoints =>
        {
            // Liveness only: no authentication, no MongoDB call, a fixed body.
            endpoints.MapGet(HealthPath, static context =>
            {
                context.Response.ContentType = "application/json";
                context.Response.Headers.CacheControl = "no-store";
                return context.Response.WriteAsync(HealthBody);
            });

            var mcp = endpoints.MapMcp(McpPath);
            if (auth.RequiresSignIn)
            {
                mcp.RequireAuthorization(HttpAuth.McpPolicy);
                endpoints.MapNo2SqlAuthEndpoints(auth);
            }
        });
    }
}
