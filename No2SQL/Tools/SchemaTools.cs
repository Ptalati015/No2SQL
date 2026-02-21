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
    [Description("List ID-like fields in each collection.")]
    public async Task<string> ListInferredRelationships(string databaseName)
    {
        try
        {
            var res = await _analyzer.GetFieldRelationshipsAsync(databaseName);
            if (res.Count == 0)
            {
                return $"No ID-like fields found in database '{databaseName}'.";
            }

            return $"ID-like fields in '{databaseName}':\n" +
                string.Join("\n", res.Select(kvp =>
                    $"- Collection '{kvp.Key}': {string.Join(", ", kvp.Value)}"));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in ListInferredRelationships: {ex.Message}\n{ex.StackTrace}");
            return $"Error listing inferred relationships for database '{databaseName}': {ex.Message}";
        }
    }


    // [McpServerTool]
    // [Description("Compare Fields to infer relationships on a MongoDB database.")]
    // public async Task<string> CompareIdFieldsToIds(
    //     [Description("Database name")] string databaseName)
    // {
    //     try
    //     {
    //         var res = await _analyzer.CompareIdFieldsToIdsAsync(databaseName);
    //         if (res.Count == 0)
    //         {
    //             return $"No inferred relationships found by comparing Id Like fields to _id values for database '{databaseName}'.";
    //         }
    //         return  $"Inferred Relationships by comparing Id Like fields to _id values for database '{databaseName}':\n" +
    //             string.Join("\n", res.Select(r => 
    //                 $"- From Collection '{r.FromCollection}' To Collection '{r.ToCollection}' " +
    //                 $"via Field '{r.FieldName}' with Confidence {r.Confidence:P2}"));
    //     }
    //     catch (Exception ex)
    //     {
    //         Console.Error.WriteLine($"Error in CompareIdFieldsToIds: {ex.Message}");
    //         Console.Error.WriteLine($"Error in CompareIdFieldsToIds: {ex.Message}\n{ex.StackTrace}");
    //         return $"Error comparing Id Like fields to _id values for database '{databaseName}': {ex.Message}";
    //     }
    // }
}