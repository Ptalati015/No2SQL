using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace No2SQL.Hosting;

/// <summary>
/// One audit log line per tool call: the tool, the database and collection it was asked about, who
/// called, how it ended and how long it took. No other argument is logged, since any other value
/// (overrides, a source text) could carry data the caller did not mean to put in a log.
/// </summary>
internal static class ToolCallAudit
{
    public const string Category = "No2SQL.Audit";

    // The only arguments that are logged. Every tool that reads MongoDB names them this way.
    private const string DatabaseArgument = "databaseName";
    private const string CollectionArgument = "collectionName";

    // Long enough for any MongoDB name, short enough that one call cannot flood the log.
    internal const int MaxValueLength = 128;

    public static IMcpServerBuilder WithToolCallAudit(this IMcpServerBuilder builder) =>
        builder.WithRequestFilters(filters => filters.AddCallToolFilter(next => async (context, cancellationToken) =>
        {
            var services = context.Services;
            var clock = services?.GetService<TimeProvider>() ?? TimeProvider.System;
            var logger = services?.GetService<ILoggerFactory>()?.CreateLogger(Category);
            var started = clock.GetTimestamp();
            var outcome = "exception";
            try
            {
                var result = await next(context, cancellationToken);
                outcome = result.IsError == true ? "error" : "ok";
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                outcome = "cancelled";
                throw;
            }
            finally
            {
                if (logger is not null && logger.IsEnabled(LogLevel.Information))
                {
                    var arguments = context.Params?.Arguments;
                    logger.LogInformation(
                        "tool call: tool={Tool} database={Database} collection={Collection} caller={Caller} outcome={Outcome} duration_ms={DurationMs}",
                        Quote(context.Params?.Name),
                        Quote(StringArgument(arguments, DatabaseArgument)),
                        Quote(StringArgument(arguments, CollectionArgument)),
                        Quote(CallerId(context.User)),
                        outcome,
                        (long)clock.GetElapsedTime(started).TotalMilliseconds);
                }
            }
        }));

    /// <summary>
    /// Who called: the "sub" (or name identifier) claim of a signed-in caller, otherwise "anonymous" (a
    /// stdio client, or an HTTP request while HTTP mode has no authentication). Authentication (P2-4/P2-5)
    /// sets the claim; for a bearer token it is a hash prefix of the token, never the token itself.
    /// </summary>
    internal static string CallerId(ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true)
        {
            return "anonymous";
        }

        return user.FindFirst("sub")?.Value ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "authenticated";
    }

    private static string? StringArgument(IDictionary<string, JsonElement>? arguments, string name) =>
        arguments is not null && arguments.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    // Values come from the caller, so they are JSON-quoted: a newline or a quote in a name cannot
    // start a fake log line or break the key=value layout. "-" means the argument was not given.
    internal static string Quote(string? value)
    {
        if (value is null)
        {
            return "-";
        }

        if (value.Length > MaxValueLength)
        {
            value = value[..MaxValueLength] + "...";
        }

        return $"\"{JsonEncodedText.Encode(value)}\"";
    }
}
