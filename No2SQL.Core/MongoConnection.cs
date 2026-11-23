using MongoDB.Driver;

namespace No2SQL.Core;

/// <summary>
/// Holds the MongoDB connection string and builds the <see cref="MongoClient"/> on first use.
/// Nothing is parsed or connected at construction, so a host can start, list its tools and answer
/// calls that do not need MongoDB even when the connection string is missing or wrong.
/// </summary>
public sealed class MongoConnection
{
    private readonly Lazy<MongoClient> _client;

    public MongoConnection(string? connectionString)
    {
        _client = new Lazy<MongoClient>(() => CreateClient(connectionString));
    }

    /// <summary>
    /// The shared client, built on first access.
    /// </summary>
    /// <exception cref="MongoConnectionSetupException">
    /// The connection string is missing or the driver could not parse it.
    /// </exception>
    public MongoClient Client => _client.Value;

    private static MongoClient CreateClient(string? connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new MongoConnectionSetupException(MongoConnectionProblem.NotConfigured);
        }

        try
        {
            return new MongoClient(connectionString);
        }
        catch (Exception ex)
        {
            // The driver's message can quote the whole connection string, password included
            // (MongoConfigurationException: "The connection string '...' is not valid."), so the
            // original exception is dropped on purpose. Only its type name is kept.
            throw new MongoConnectionSetupException(
                MongoConnectionProblem.InvalidConnectionString,
                ex.GetType().Name);
        }
    }
}
