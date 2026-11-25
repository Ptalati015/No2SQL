namespace No2SQL.Security;

/// <summary>
/// A database the server's policy refuses: not in NO2SQL_ALLOWED_DATABASES, or a blocked system
/// database. Unlike other errors, the client is told why, because remote and container users
/// usually can't read the server's logs. <see cref="ClientMessage"/> names only the database the
/// caller asked for (already validated as an identifier), never the allowed names, and says nothing
/// about whether the database exists: the check runs before any MongoDB call.
/// </summary>
internal sealed class DatabasePolicyException : ArgumentException
{
    private DatabasePolicyException(string message, string clientMessage)
        : base(message, "databaseName")
    {
        ClientMessage = clientMessage;
    }

    public string ClientMessage { get; }

    public static DatabasePolicyException NotAllowed(string databaseName) => new(
        $"Database '{databaseName}' is not in NO2SQL_ALLOWED_DATABASES.",
        $"Database '{databaseName}' is not in NO2SQL_ALLOWED_DATABASES on this server. " +
        "Ask the server's operator to add it.");

    public static DatabasePolicyException SystemDatabase(string databaseName) => new(
        $"Database '{databaseName}' is blocked by policy.",
        $"Database '{databaseName}' is a MongoDB system database, and this server blocks system " +
        "databases (NO2SQL_BLOCK_SYSTEM_DATABASES).");
}
