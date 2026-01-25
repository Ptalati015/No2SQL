using System.ComponentModel;
using ModelContextProtocol.Server;
using No2SQL.Core;
using No2SQL.Core.Models;
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
    [Description("List all Collections and their inferred Id Like fields on a MongoDB database.")]
    public async Task<string> ListCollectionsWithIdLikeFields(
        [Description("Database name")] string databaseName)
    {
        try
        {
            var res = await _analyzer.GetAllIdLikeFieldsAsync(databaseName);
            return  $"Collections with Id Like fields for database '{databaseName}':\n" +
                string.Join("\n", res.Select(kvp => 
                    $"- Collection '{kvp.Key}': Id Like Fields: {string.Join(", ", kvp.Value)}"));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in ListCollectionsWithIdLikeFields: {ex.Message}");
            Console.Error.WriteLine($"Error in ListCollectionsWithIdLikeFields: {ex.Message}\n{ex.StackTrace}");
            return $"Error listing collections with Id Like fields for database '{databaseName}': {ex.Message}";
        }
    }

    [McpServerTool]
    [Description("List all Collections and their inferred Foreign Key Like fields on a MongoDB database.")]
    public async Task<string> ListInferredRelationships(
        [Description("Database name")] string databaseName)
    {
        try
        {
            var res = await _analyzer.GetFieldRelationshipsAsync(databaseName);
            return  $"Inferred Relationships for database '{databaseName}':\n" +
                string.Join("\n", res.Select(kvp => 
                    $"- Collection '{kvp.Key}': Foreign Key Like Fields: {string.Join(", ", kvp.Value)}"));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in ListInferredRelationships: {ex.Message}");
            Console.Error.WriteLine($"Error in ListInferredRelationships: {ex.Message}\n{ex.StackTrace}");
            return $"Error listing inferred relationships for database '{databaseName}': {ex.Message}";
        }
    }
}