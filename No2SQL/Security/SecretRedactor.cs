namespace No2SQL.Security;

/// <summary>
/// The secrets this process knows (the MongoDB connection string and its password, the HTTP token, the
/// owner password) and a replacement of each of them in any text. Every line the server writes to stdout
/// or stderr passes through <see cref="Redact"/> (see <see cref="RedactingTextWriter"/>), exception text
/// included, so a secret that reaches a log message by any path is masked before it is written.
/// </summary>
/// <remarks>
/// This is the second line of defence: code must still never put a secret into a message. A value is
/// registered once it is known, so register a secret only after anything that must show it on purpose
/// (for example a generated password printed once) has been written.
/// </remarks>
internal sealed class SecretRedactor
{
    public const string Mask = "[redacted]";

    // Shorter values are not masked: replacing every "abc" in every log line would make the logs
    // unreadable, and a secret that short is not protected by hiding it.
    public const int MinimumLength = 4;

    // The environment variables that hold a secret directly, beside NO2SQL_MONGO (registered by the
    // code that reads it, because it can also come from NO2SQL_MONGO_FILE).
    public static readonly string[] SecretVariables = ["NO2SQL_HTTP_TOKEN", "NO2SQL_OWNER_PASSWORD"];

    private readonly object _gate = new();

    // Longest first, so a password inside the connection string does not break up the longer match.
    private volatile string[] _secrets = [];

    /// <summary>The redactor behind stdout and stderr of this process.</summary>
    public static SecretRedactor Process { get; } = new();

    public void Add(string? secret)
    {
        if (string.IsNullOrWhiteSpace(secret) || secret.Length < MinimumLength)
        {
            return;
        }

        lock (_gate)
        {
            if (Array.IndexOf(_secrets, secret) >= 0)
            {
                return;
            }

            _secrets = [.. _secrets.Append(secret).OrderByDescending(s => s.Length)];
        }
    }

    /// <summary>Registers a MongoDB connection string, and its password both as written and percent-decoded.</summary>
    public void AddConnectionString(string? connectionString)
    {
        Add(connectionString);
        if (FindPassword(connectionString) is { } password)
        {
            Add(password);
            Add(Uri.UnescapeDataString(password));
        }
    }

    /// <summary>Registers the values of <see cref="SecretVariables"/> that are set.</summary>
    public void AddSecretVariables(Func<string, string?> readVariable)
    {
        foreach (var name in SecretVariables)
        {
            Add(readVariable(name));
        }
    }

    public string Redact(string text)
    {
        var secrets = _secrets;
        foreach (var secret in secrets)
        {
            if (text.Contains(secret, StringComparison.Ordinal))
            {
                text = text.Replace(secret, Mask, StringComparison.Ordinal);
            }
        }

        return text;
    }

    // The password of mongodb://user:password@host or mongodb+srv://user:password@host. Not a full URI
    // parser on purpose: it must also find the password in strings the driver rejects as malformed.
    private static string? FindPassword(string? connectionString)
    {
        if (string.IsNullOrEmpty(connectionString))
        {
            return null;
        }

        var schemeEnd = connectionString.IndexOf("://", StringComparison.Ordinal);
        var rest = schemeEnd >= 0 ? connectionString[(schemeEnd + 3)..] : connectionString;
        var queryStart = rest.IndexOf('?');
        if (queryStart >= 0)
        {
            rest = rest[..queryStart];
        }

        // The last '@' before the options, so an unescaped '@' or '/' in the password stays part of it.
        var at = rest.LastIndexOf('@');
        if (at <= 0)
        {
            return null;
        }

        var userInfo = rest[..at];
        var colon = userInfo.IndexOf(':');
        return colon >= 0 && colon < userInfo.Length - 1 ? userInfo[(colon + 1)..] : null;
    }
}
