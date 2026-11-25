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

    /// <summary>A file that holds the connection string (a Docker or Kubernetes secret). It wins over NO2SQL_MONGO.</summary>
    public const string MongoFileVariable = "NO2SQL_MONGO_FILE";

    // A connection string is short; anything bigger is the wrong file (or a device that never ends).
    internal const int MaxMongoFileChars = 64 * 1024;

    /// <summary>
    /// Reads the MongoDB connection string from NO2SQL_MONGO_FILE when it is set, otherwise from
    /// NO2SQL_MONGO, and registers it with <see cref="SecretRedactor.Process"/> so it is masked in every
    /// log line. The string is not parsed here: MongoConnection builds the client on the first tool call
    /// that needs it, so the server starts, lists its tools and answers test_connectivity even when the
    /// variable is missing or wrong. A NO2SQL_MONGO_FILE that cannot be read is a configuration error and
    /// returns false: the operator asked for the file, so the server does not quietly run without it.
    /// </summary>
    public static bool TryReadMongoConnectionString(out string? connectionString, out string? error) =>
        TryReadMongoConnectionString(Environment.GetEnvironmentVariable, Console.Error, SecretRedactor.Process, out connectionString, out error);

    internal static bool TryReadMongoConnectionString(
        Func<string, string?> readVariable,
        TextWriter notices,
        SecretRedactor redactor,
        out string? connectionString,
        out string? error)
    {
        connectionString = null;
        error = null;

        var fromVariable = readVariable(MongoVariable);
        redactor.AddConnectionString(fromVariable);

        var path = readVariable(MongoFileVariable);
        if (string.IsNullOrWhiteSpace(path))
        {
            if (string.IsNullOrWhiteSpace(fromVariable))
            {
                notices.WriteLine(
                    $"[No2SQL] {MongoVariable} is not set. The server is running, but tools that read MongoDB will ask for it.");
            }

            connectionString = fromVariable;
            return true;
        }

        if (!TryReadSecretFile(path, out var fromFile, out var fileWarning, out error))
        {
            return false;
        }

        redactor.AddConnectionString(fromFile);

        if (fileWarning is not null)
        {
            notices.WriteLine($"[No2SQL] WARNING: {fileWarning}");
        }

        if (!string.IsNullOrWhiteSpace(fromVariable))
        {
            notices.WriteLine($"[No2SQL] Both {MongoFileVariable} and {MongoVariable} are set; using {MongoFileVariable}.");
        }

        connectionString = fromFile;
        return true;
    }

    // Only the path, the exception type and fixed text go into the messages: never the contents.
    private static bool TryReadSecretFile(string path, out string? contents, out string? warning, out string? error)
    {
        contents = null;
        warning = null;
        error = null;

        string text;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!OperatingSystem.IsWindows())
            {
                // The mode of the opened file, so a symbolic link (how Kubernetes mounts secrets) is followed.
                var mode = File.GetUnixFileMode(stream.SafeFileHandle);
                if ((mode & (UnixFileMode.GroupRead | UnixFileMode.OtherRead)) != 0)
                {
                    warning = $"{MongoFileVariable} ({path}) can be read by other users (mode {Convert.ToString((int)mode, 8)}). " +
                        "Restrict it, for example with chmod 600.";
                }
            }

            using var reader = new StreamReader(stream);
            var buffer = new char[MaxMongoFileChars + 1];
            var read = reader.ReadBlock(buffer, 0, buffer.Length);
            if (read > MaxMongoFileChars)
            {
                error = $"{MongoFileVariable} ({path}) is larger than {MaxMongoFileChars / 1024} KiB; it should hold only the MongoDB connection string.";
                return false;
            }

            text = new string(buffer, 0, read);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            error = $"{MongoFileVariable} is set, but {path} could not be read ({ex.GetType().Name}).";
            return false;
        }

        // Files written by an editor or by "echo" end with a newline; that is not part of the string.
        text = text.TrimEnd('\r', '\n');
        if (string.IsNullOrWhiteSpace(text))
        {
            error = $"{MongoFileVariable} is set, but {path} is empty.";
            return false;
        }

        contents = text;
        return true;
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
            .WithTools<SchemaTools>()
            .WithToolCallAudit();
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
