using System.Text.Json;
using No2SQL.Core;
using No2SQL.Sql;

var databaseName = args.Length > 0 ? args[0] : "School";

string? connectionString = Environment.GetEnvironmentVariable("NO2SQL_MONGO");
if (string.IsNullOrWhiteSpace(connectionString))
{
    var appSettingsPath = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "No2SQL", "appsettings.json");
    if (File.Exists(appSettingsPath))
    {
        var json = await File.ReadAllTextAsync(appSettingsPath);
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("ConnectionStrings", out var cs) &&
            cs.TryGetProperty("MongoDb", out var mongoDb))
        {
            connectionString = mongoDb.GetString();
        }
    }
}

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
