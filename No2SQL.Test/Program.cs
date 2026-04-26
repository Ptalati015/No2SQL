using System.Text.Json;
using System.Text.RegularExpressions;
using No2SQL.Core;
using No2SQL.Sql;

const string TestDatabaseEnvVar = "NO2SQL_TEST_DATABASE";
const string TestCollectionEnvVar = "NO2SQL_TEST_COLLECTION";
const string TestRowsPerChunkEnvVar = "NO2SQL_TEST_ROWS_PER_CHUNK";
const string TestLimitEnvVar = "NO2SQL_TEST_LIMIT";
const string TestBatchSizeEnvVar = "NO2SQL_TEST_BATCH_SIZE";

const int DefaultRowsPerChunk = 2;
const int DefaultLimit = 1000;
const int DefaultBatchSize = 100;

if (args.Length > 0 && string.Equals(args[0], "--test-stream", StringComparison.OrdinalIgnoreCase))
{
    await RunStreamSeederValidationAsync(args);
    return;
}

var databaseName = ResolveStringArgOrEnv(args, 0, TestDatabaseEnvVar);
if (string.IsNullOrWhiteSpace(databaseName))
{
    Console.Error.WriteLine($"Missing database name. Provide args[0] or set {TestDatabaseEnvVar}.");
    return;
}

string? connectionString = await ResolveConnectionStringAsync();

if (string.IsNullOrWhiteSpace(connectionString))
{
    Console.Error.WriteLine("Missing MongoDB connection string. Set NO2SQL_MONGO or No2SQL/appsettings.json:ConnectionStrings:MongoDb");
    return;
}

try
{
    var analyzer = new SchemaAnalyzer(connectionString);
    var scriptGenerator = new ScriptGenerator(connectionString);

    var collections = await analyzer.AnalyzeCollectionsAsync(databaseName);
    var relationships = await analyzer.GetRelationshipsAsync(databaseName);
    var output = scriptGenerator.GenerateSqlFromInference(collections, relationships);

    if (!string.IsNullOrWhiteSpace(output.ErrorMessage))
    {
        Console.WriteLine(output.ErrorMessage);
        return;
    }

    Console.WriteLine(output.FullScript);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error generating SQL schema for database '{databaseName}': {ex.Message}");
}

static async Task RunStreamSeederValidationAsync(string[] args)
{
    var databaseName = ResolveStringArgOrEnv(args, 1, TestDatabaseEnvVar);
    var collectionName = ResolveStringArgOrEnv(args, 2, TestCollectionEnvVar);
    var rowsPerChunk = ResolveIntArgOrEnv(args, 3, TestRowsPerChunkEnvVar, DefaultRowsPerChunk);
    var limit = ResolveIntArgOrEnv(args, 4, TestLimitEnvVar, DefaultLimit);
    var batchSize = ResolveIntArgOrEnv(args, 5, TestBatchSizeEnvVar, DefaultBatchSize);

    if (string.IsNullOrWhiteSpace(databaseName) || string.IsNullOrWhiteSpace(collectionName))
    {
        Console.Error.WriteLine($"Usage: --test-stream <databaseName> <collectionName> [rowsPerChunk] [limit] [batchSize]\nOr set env vars: {TestDatabaseEnvVar}, {TestCollectionEnvVar}, {TestRowsPerChunkEnvVar}, {TestLimitEnvVar}, {TestBatchSizeEnvVar}.");
        return;
    }

    string? connectionString = await ResolveConnectionStringAsync();
    if (string.IsNullOrWhiteSpace(connectionString))
    {
        Console.Error.WriteLine("Missing MongoDB connection string. Set NO2SQL_MONGO or No2SQL/appsettings.json:ConnectionStrings:MongoDb");
        return;
    }

    try
    {
        var scriptGenerator = new ScriptGenerator(connectionString);
        var chunks = new List<string>();

        await foreach (var chunk in scriptGenerator.GenerateInsertStatementsForCollectionStream(
            databaseName,
            collectionName,
            batchSize: batchSize,
            limit: limit,
            rowsPerChunk: rowsPerChunk))
        {
            chunks.Add(chunk);
        }

        if (chunks.Count == 0)
        {
            Console.WriteLine($"No documents found in '{databaseName}.{collectionName}'.");
            return;
        }

        var firstChunkColumnBlock = ExtractColumnBlock(chunks[0]);
        for (int i = 0; i < chunks.Count; i++)
        {
            var chunk = chunks[i];
            ValidateChunkShape(chunk, collectionName, rowsPerChunk, i + 1);

            var currentColumnBlock = ExtractColumnBlock(chunk);
            if (!string.Equals(firstChunkColumnBlock, currentColumnBlock, StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Chunk {i + 1} has a different column layout than chunk 1.");
            }
        }

        Console.WriteLine($"Streaming seeder validation passed for '{databaseName}.{collectionName}'.");
        Console.WriteLine($"Chunks: {chunks.Count}, rowsPerChunk: {rowsPerChunk}, limit: {limit}, batchSize: {batchSize}");
        Console.WriteLine("First chunk preview:");
        Console.WriteLine(chunks[0]);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Streaming seeder validation failed: {ex.Message}");
    }
}

static void ValidateChunkShape(string chunk, string collectionName, int rowsPerChunk, int chunkNumber)
{
    var normalized = chunk.Replace("\r", string.Empty);
    var trimmed = normalized.Trim();

    if (!trimmed.StartsWith($"INSERT INTO `{collectionName}` (", StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"Chunk {chunkNumber} does not start with expected INSERT header.");
    }

    if (!normalized.Contains(") VALUES\n", StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"Chunk {chunkNumber} is missing VALUES clause.");
    }

    if (!trimmed.EndsWith(";", StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"Chunk {chunkNumber} does not terminate with ';'.");
    }

    var rowCount = Regex.Matches(normalized, "(?m)^\\($").Count;
    if (rowCount == 0)
    {
        throw new InvalidOperationException($"Chunk {chunkNumber} has no VALUES rows.");
    }

    if (rowCount > rowsPerChunk)
    {
        throw new InvalidOperationException($"Chunk {chunkNumber} has {rowCount} rows, exceeding rowsPerChunk={rowsPerChunk}.");
    }
}

static string ExtractColumnBlock(string chunk)
{
    var marker = ") VALUES";
    var index = chunk.IndexOf(marker, StringComparison.Ordinal);
    if (index < 0)
    {
        throw new InvalidOperationException("Unable to extract column block: missing VALUES marker.");
    }

    return chunk[..index].Trim();
}

static async Task<string?> ResolveConnectionStringAsync()
{
    string? connectionString = Environment.GetEnvironmentVariable("NO2SQL_MONGO");
    if (!string.IsNullOrWhiteSpace(connectionString))
    {
        return connectionString;
    }

    var appSettingsPath = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "No2SQL", "appsettings.json");
    if (!File.Exists(appSettingsPath))
    {
        return null;
    }

    var json = await File.ReadAllTextAsync(appSettingsPath);
    using var doc = JsonDocument.Parse(json);
    if (doc.RootElement.TryGetProperty("ConnectionStrings", out var cs) &&
        cs.TryGetProperty("MongoDb", out var mongoDb))
    {
        var fromConfig = mongoDb.GetString();
        if (!string.IsNullOrWhiteSpace(fromConfig) && !fromConfig.Contains("<", StringComparison.Ordinal))
        {
            return fromConfig;
        }
    }

    return null;
}

static string? ResolveStringArgOrEnv(string[] args, int index, string envVar)
{
    if (index < args.Length && !string.IsNullOrWhiteSpace(args[index]))
    {
        return args[index];
    }

    return Environment.GetEnvironmentVariable(envVar);
}

static int ResolveIntArgOrEnv(string[] args, int index, string envVar, int fallback)
{
    if (index < args.Length && int.TryParse(args[index], out var fromArg))
    {
        return fromArg;
    }

    var fromEnv = Environment.GetEnvironmentVariable(envVar);
    if (int.TryParse(fromEnv, out var parsedEnv))
    {
        return parsedEnv;
    }

    return fallback;
}
