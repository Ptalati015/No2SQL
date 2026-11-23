namespace No2SQL.Core;

/// <summary>Why a MongoDB client could not be built from configuration.</summary>
public enum MongoConnectionProblem
{
    /// <summary>No connection string was supplied.</summary>
    NotConfigured,

    /// <summary>A connection string was supplied, but the driver could not parse it.</summary>
    InvalidConnectionString
}

/// <summary>
/// Thrown when the MongoDB client cannot be built from configuration. The message is fixed text:
/// it never contains the connection string, and no inner exception is attached.
/// </summary>
public sealed class MongoConnectionSetupException : Exception
{
    public MongoConnectionSetupException(MongoConnectionProblem problem, string? causeType = null)
        : base(problem == MongoConnectionProblem.NotConfigured
            ? "The MongoDB connection string is not configured."
            : "The MongoDB connection string is not valid.")
    {
        Problem = problem;
        CauseType = causeType;
    }

    public MongoConnectionProblem Problem { get; }

    /// <summary>Type name of the driver exception that rejected the connection string, if any.</summary>
    public string? CauseType { get; }
}
