using System.ComponentModel;
using ModelContextProtocol.Server;
using No2SQL.Core;

internal class SchemaTools
{
    private readonly SchemaAnalyzer _analyzer;
    public SchemaTools(SchemaAnalyzer schemaAnalyzer)
    {
        _analyzer = schemaAnalyzer;
    }
    
    [McpServerTool]
    [Description("Test AnalyzeAsync on a MongoDB database.")]
    public async Task<string> TestAnalyze(
        [Description("Database name")] string databaseName)
    {
        try
        {
            var res = await _analyzer.AnalyzeAsync(databaseName);
            return  $"Schema analysis for database '{databaseName}':\n" +
                string.Join("\n", res.Select(kvp => 
                    $"- Collection '{kvp.Key}': Fields: {string.Join(", ", kvp.Value)}"));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in TestAnalyze: {ex.Message}");
            Console.Error.WriteLine($"Error in TestAnalyze: {ex.Message}\n{ex.StackTrace}");
            return $"Error analyzing database '{databaseName}': {ex.Message}";
        }
    }

    [McpServerTool]
    [Description("List all available databases on the MongoDB server.")]
    public async Task<string> ListDatabases()
    {
        try
        {
            var databases = await _analyzer.ListDatabasesAsync();
            return $"Available databases ({databases.Count}):\n" +
                string.Join("\n", databases.Select(db => $"- {db}"));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in ListDatabases: {ex.Message}\n{ex.StackTrace}");
            return $"Error listing databases: {ex.Message}";
        }
    }

    [McpServerTool]
    [Description("Find Foreign Keys in a MongoDB database.")]
    public async Task<string> FindForeignKeys(
        [Description("Database name")] string databaseName)
    {
        try
        {
            var foreignKeys = await _analyzer.FindForeignKeysAsync(databaseName);
            return $"Foreign keys in database '{databaseName}':\n" +
                string.Join("\n", foreignKeys.Select(kvp =>
                    $"- Collection '{kvp.Key}': References: {string.Join(", ", kvp.Value)}"));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in FindForeignKeys: {ex.Message}\n{ex.StackTrace}");
            return $"Error finding foreign keys in database '{databaseName}': {ex.Message}";
        }
    }
}