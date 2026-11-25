namespace No2SQL.Hosting;

internal enum TransportKind
{
    Stdio,
    Http,
}

/// <summary>
/// What the command line and NO2SQL_TRANSPORT ask for. stdio is the default: with no arguments and
/// no NO2SQL_TRANSPORT the server starts exactly as it did before HTTP mode existed.
/// </summary>
internal sealed record StartupOptions(TransportKind Transport, bool AllowAnonymous, string[] HostArgs)
{
    public const string TransportVariable = "NO2SQL_TRANSPORT";
    public const string HttpFlag = "--http";
    public const string AllowAnonymousFlag = "--allow-anonymous";

    /// <summary>
    /// Resolves the transport. The <c>--http</c> flag wins over NO2SQL_TRANSPORT, so a command line
    /// can override an environment default (for example a container image that sets http).
    /// </summary>
    /// <param name="args">The process arguments.</param>
    /// <param name="transportVariable">The value of NO2SQL_TRANSPORT, or null when it is not set.</param>
    /// <param name="options">The resolved options when the method returns true.</param>
    /// <param name="error">A message for the operator when the method returns false.</param>
    public static bool TryParse(string[] args, string? transportVariable, out StartupOptions options, out string? error)
    {
        var httpFlag = false;
        var allowAnonymous = false;
        var others = new List<string>();

        foreach (var arg in args)
        {
            if (string.Equals(arg, HttpFlag, StringComparison.OrdinalIgnoreCase))
            {
                httpFlag = true;
            }
            else if (string.Equals(arg, AllowAnonymousFlag, StringComparison.OrdinalIgnoreCase))
            {
                allowAnonymous = true;
            }
            else
            {
                others.Add(arg);
            }
        }

        var transport = TransportKind.Stdio;
        var fromVariable = transportVariable?.Trim();
        if (httpFlag)
        {
            transport = TransportKind.Http;
        }
        else if (!string.IsNullOrEmpty(fromVariable))
        {
            if (string.Equals(fromVariable, "http", StringComparison.OrdinalIgnoreCase))
            {
                transport = TransportKind.Http;
            }
            else if (!string.Equals(fromVariable, "stdio", StringComparison.OrdinalIgnoreCase))
            {
                options = new StartupOptions(TransportKind.Stdio, false, args);
                error = $"{TransportVariable} must be 'stdio' or 'http'.";
                return false;
            }
        }

        if (transport == TransportKind.Http && others.Count > 0)
        {
            // HTTP mode takes its settings from NO2SQL_* variables only. An argument it does not know
            // is more likely a typo than something to ignore, so stop instead of guessing.
            options = new StartupOptions(transport, allowAnonymous, args);
            error = $"Unknown argument in HTTP mode. The only arguments are {HttpFlag} and {AllowAnonymousFlag}.";
            return false;
        }

        // stdio keeps receiving its arguments untouched, as before. HTTP mode passes none on.
        options = new StartupOptions(transport, allowAnonymous, transport == TransportKind.Stdio ? args : []);
        error = null;
        return true;
    }
}
