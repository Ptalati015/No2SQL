using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace No2SQL.Hosting;

/// <summary>
/// The hardening layer of HTTP mode (P2-6, Mark's spec in PR #58): forwarded headers from trusted
/// proxies only, Host filtering, a generic error body, security headers, request timeouts, an Origin
/// check, a Content-Type check, body size and rate limits, and Kestrel limits. Built from the
/// framework's own middleware; the Origin and Content-Type checks are the only custom pieces.
/// </summary>
internal static class HttpHardening
{
    public const string HttpLogCategory = "No2SQL.Http";

    // OAuth endpoints arrive with P2-5; the checks and limits for them are already in place.
    private static readonly string[] OAuthPaths = ["/authorize", "/login", "/consent", "/token", "/register", "/revoke"];

    private const string RateLimitedBody = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,\"message\":\"Rate limit exceeded.\"},\"id\":null}";

    public static void AddHttpHardening(this IServiceCollection services, HttpHardeningOptions options)
    {
        services.AddSingleton(options);

        services.AddHostFiltering(filtering =>
        {
            filtering.AllowedHosts = [.. options.AllowedHosts];
            filtering.AllowEmptyHosts = false;
            filtering.IncludeFailureMessage = false;
        });

        if (options.TrustedProxies.Count > 0)
        {
            services.Configure<ForwardedHeadersOptions>(forwarded =>
            {
                forwarded.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                forwarded.ForwardLimit = 1;
                forwarded.KnownProxies.Clear();
                forwarded.KnownIPNetworks.Clear();
                foreach (var network in options.TrustedProxies)
                {
                    forwarded.KnownIPNetworks.Add(network);
                }
            });
        }

        services.AddRequestTimeouts(timeouts =>
        {
            timeouts.DefaultPolicy = new RequestTimeoutPolicy { Timeout = options.RequestTimeout, TimeoutStatusCode = StatusCodes.Status504GatewayTimeout };
            timeouts.AddPolicy("health", new RequestTimeoutPolicy { Timeout = TimeSpan.FromSeconds(5), TimeoutStatusCode = StatusCodes.Status504GatewayTimeout });
        });

        services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.GlobalLimiter = PartitionedRateLimiter.CreateChained(
                PerIpLimiter(options), PerTokenLimiter(options), ConcurrencyLimiter(options));
            limiter.OnRejected = static (context, cancellationToken) =>
            {
                var retryAfter = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var wait) ? wait : TimeSpan.FromSeconds(1);
                var response = context.HttpContext.Response;
                response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
                if (context.HttpContext.Request.Path.Equals(HttpServer.McpPath))
                {
                    response.ContentType = "application/json";
                    return new ValueTask(response.WriteAsync(RateLimitedBody, cancellationToken));
                }

                return ValueTask.CompletedTask;
            };
        });
    }

    /// <summary>The hardening middleware in Mark's order, up to and including routing.</summary>
    public static void UseHttpHardeningBeforeRouting(this IApplicationBuilder app)
    {
        var options = app.ApplicationServices.GetRequiredService<HttpHardeningOptions>();
        var logger = app.ApplicationServices.GetRequiredService<ILoggerFactory>().CreateLogger(HttpLogCategory);

        if (options.TrustedProxies.Count > 0)
        {
            app.UseForwardedHeaders();
        }

        // Registered before Host filtering so its 400 carries the headers as well. The values are
        // written when the response starts, after forwarded headers have set the effective scheme.
        app.Use((context, next) =>
        {
            context.Response.OnStarting(() => AddSecurityHeaders(context, options.Hsts));
            return next(context);
        });

        app.UseHostFiltering();

        app.UseExceptionHandler(new ExceptionHandlerOptions
        {
            // Only this handler logs, once, with the error id.
            SuppressDiagnosticsCallback = static _ => true,
            ExceptionHandler = context => WriteInternalError(context, logger),
        });

        app.UseRouting();
    }

    /// <summary>The hardening middleware that runs after routing and before the endpoints.</summary>
    public static void UseHttpHardeningAfterRouting(this IApplicationBuilder app)
    {
        var options = app.ApplicationServices.GetRequiredService<HttpHardeningOptions>();
        app.UseRequestTimeouts();
        app.Use((context, next) => CheckOriginAndContentType(context, next, options));
        app.UseRateLimiter();
    }

    /// <summary>Kestrel's limits (Mark's section 3). Not used by the in-memory test server.</summary>
    public static void ConfigureLimits(KestrelServerOptions kestrel, HttpHardeningOptions options)
    {
        kestrel.AddServerHeader = false;
        kestrel.Limits.MaxRequestBodySize = options.MaxBodyBytes;
        kestrel.Limits.MaxConcurrentConnections = options.MaxConnections;
        kestrel.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
        kestrel.Limits.MaxRequestLineSize = 4 * 1024;
        kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(15);
        kestrel.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(130);
    }

    /// <summary>The rate-limit key for a bearer token: SHA-256, first 16 bytes, hex. The raw token is never kept.</summary>
    internal static string TokenPartitionKey(string token) =>
        "token:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)).AsSpan(0, 16));

    private static Task AddSecurityHeaders(HttpContext context, bool hsts)
    {
        var headers = context.Response.Headers;
        headers.XContentTypeOptions = "nosniff";
        headers["Referrer-Policy"] = "no-referrer";
        headers.XFrameOptions = "DENY";
        headers.ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'";
        if (IsMcpOrOAuth(context.Request.Path))
        {
            headers.CacheControl = "no-store";
        }

        if (hsts && context.Request.IsHttps)
        {
            headers.StrictTransportSecurity = "max-age=31536000";
        }

        return Task.CompletedTask;
    }

    private static async Task WriteInternalError(HttpContext context, ILogger logger)
    {
        var exception = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;

        // Kestrel's own rejections (a body over the size limit, a client that sends too slowly) keep
        // their status code. They are the client's fault, not a server error, so no error id.
        if (exception is Microsoft.AspNetCore.Http.BadHttpRequestException badRequest)
        {
            context.Response.StatusCode = badRequest.StatusCode;
            return;
        }

        var errorId = Guid.NewGuid().ToString("N")[..8];
        logger.LogError(exception, "[HTTP:{ErrorId}] Unhandled exception for {Method} {Path}.", errorId, context.Request.Method, context.Request.Path.Value);

        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        var path = context.Request.Path;
        if (path.Equals(HttpServer.McpPath))
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                $"{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32603,\"message\":\"Internal error. See server logs with error id {errorId}.\"}},\"id\":null}}");
        }
        else if (IsOAuth(path))
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"server_error\"}");
        }
    }

    // Origin (403) and Content-Type (415) checks, and the body-size limit (413). They run before the
    // MCP SDK reads the request, so a rejected request never reaches it.
    private static async Task CheckOriginAndContentType(HttpContext context, RequestDelegate next, HttpHardeningOptions options)
    {
        var request = context.Request;
        if (!IsMcpOrOAuth(request.Path))
        {
            await next(context);
            return;
        }

        // A browser page on another site (or one rebound to this address by DNS) sends its Origin.
        // Server-to-server clients send none. No CORS headers are ever written.
        if (request.Headers.Origin is { Count: > 0 } origin
            && (origin.Count > 1 || !options.IsAllowedOrigin(origin.ToString())))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        if (HttpMethods.IsPost(request.Method))
        {
            var expected = request.Path.Equals("/token") ? "application/x-www-form-urlencoded" : "application/json";
            if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType)
                || !contentType.MediaType.Equals(expected, StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
                return;
            }

            var maxBody = request.Path.Equals(HttpServer.McpPath) ? options.MaxBodyBytes : Math.Min(options.MaxBodyBytes, 16 * 1024);
            if (request.ContentLength > maxBody)
            {
                context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
                return;
            }

            if (request.ContentLength is null && !await BufferChunkedBody(context, maxBody))
            {
                context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
                return;
            }
        }

        await next(context);
    }

    // A chunked body has no declared length. It is read here, up to the limit, so an oversized one
    // gets 413 before the SDK sees it (the SDK would report Kestrel's error as a bad request).
    private static async Task<bool> BufferChunkedBody(HttpContext context, long maxBody)
    {
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } bodySize)
        {
            bodySize.MaxRequestBodySize = maxBody;
        }

        context.Request.EnableBuffering(bufferThreshold: 64 * 1024, bufferLimit: maxBody);
        try
        {
            await context.Request.Body.DrainAsync(context.RequestAborted);
        }
        catch (Exception ex) when (ex is Microsoft.AspNetCore.Http.BadHttpRequestException or IOException)
        {
            return false;
        }

        context.Request.Body.Position = 0;
        return true;
    }

    private static bool IsOAuth(PathString path) => OAuthPaths.Any(p => path.Equals(p));

    private static bool IsMcpOrOAuth(PathString path) => path.Equals(HttpServer.McpPath) || IsOAuth(path);

    private static string ClientIp(HttpContext context) => context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    // First in the chain, before authentication: a per-IP ceiling for every limited path, so a caller
    // that sends a new made-up token on each request is still capped.
    private static PartitionedRateLimiter<HttpContext> PerIpLimiter(HttpHardeningOptions options) =>
        PartitionedRateLimiter.Create<HttpContext, string>(context =>
        {
            var path = context.Request.Path;
            var (group, permits, window) =
                path.Equals(HttpServer.McpPath) ? ("mcp", options.RateLimitPerIpPerMinute, options.RateLimitWindow)
                : path.Equals(HttpServer.HealthPath) ? ("health", 60, options.RateLimitWindow)
                : path.Equals("/token") ? ("oauth-token", 30, options.RateLimitWindow)
                : path.Equals("/register") ? ("oauth-register", 10, options.RateLimitWindow * 60)
                : path.Equals("/authorize") || path.Equals("/login") || path.Equals("/consent") ? ("oauth-authorize", 20, options.RateLimitWindow)
                : (null, 0, TimeSpan.Zero);

            return group is null
                ? RateLimitPartition.GetNoLimiter("unlimited")
                : RateLimitPartition.GetFixedWindowLimiter($"{group}|{ClientIp(context)}", _ => FixedWindow(permits, window));
        });

    // Second: per bearer token (hashed), or per IP for a request without one, on /mcp only.
    private static PartitionedRateLimiter<HttpContext> PerTokenLimiter(HttpHardeningOptions options) =>
        PartitionedRateLimiter.Create<HttpContext, string>(context =>
        {
            if (!context.Request.Path.Equals(HttpServer.McpPath))
            {
                return RateLimitPartition.GetNoLimiter("unlimited");
            }

            var authorization = context.Request.Headers.Authorization.ToString();
            var key = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) && authorization.Length > 7
                ? TokenPartitionKey(authorization[7..].Trim())
                : "ip:" + ClientIp(context);
            return RateLimitPartition.GetFixedWindowLimiter(key, _ => FixedWindow(options.RateLimitPerMinute, options.RateLimitWindow));
        });

    // Third: requests in flight on /mcp, for all callers together.
    private static PartitionedRateLimiter<HttpContext> ConcurrencyLimiter(HttpHardeningOptions options) =>
        PartitionedRateLimiter.Create<HttpContext, string>(context =>
            context.Request.Path.Equals(HttpServer.McpPath)
                ? RateLimitPartition.GetConcurrencyLimiter("mcp", _ => new ConcurrencyLimiterOptions { PermitLimit = options.MaxConcurrentCalls, QueueLimit = 0 })
                : RateLimitPartition.GetNoLimiter("unlimited"));

    private static FixedWindowRateLimiterOptions FixedWindow(int permits, TimeSpan window) => new()
    {
        PermitLimit = permits,
        Window = window,
        QueueLimit = 0,
        AutoReplenishment = true,
    };
}
