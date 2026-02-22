using System.ComponentModel;
using ModelContextProtocol.Server;
using No2SQL.Core;
using No2SQL.Core.Models;
using No2SQL.Sql;
using No2SQL.Sql.Models;
internal class SchemaTools
{
    private readonly SchemaAnalyzer _analyzer;
    private readonly ScriptGenerator _scriptGenerator;
    public SchemaTools(SchemaAnalyzer schemaAnalyzer, ScriptGenerator scriptGenerator)
    {
        _analyzer = schemaAnalyzer;
        _scriptGenerator = scriptGenerator;
    }

    [McpServerTool]
    [Description("Test MCP server connectivity.")]
    public async Task<string> TestConnectivity()
    {
        try
        {

            return "MCP connectivity test successful!";
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in TestConnectivity: {ex.Message}\n{ex.StackTrace}");
            return $"Error testing connectivity: {ex.Message}";
        }
    }

    [McpServerTool]
    [Description("Test AnalyzeAsync on a MongoDB database.")]
    public async Task<string> TestAnalyze(
        [Description("Database name")] string databaseName)
    {
        try
        {
            var res = await _analyzer.AnalyzeAsync(databaseName);
            return $"Schema analysis for database '{databaseName}':\n" +
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


    [McpServerTool]
    [Description("Infer relationships on a MongoDB database.")]
    public async Task<string> CompareIdFieldsToIds(
        [Description("Database name")] string databaseName)
    {
        try
        {
            var res = await _analyzer.GetRelationshipsAsync(databaseName);
            if (res.Count == 0)
            {
                return $"No inferred relationships found by comparing Id Like fields to _id values for database '{databaseName}'.";
            }
            return $"Inferred Relationships by comparing Id Like fields to _id values for database '{databaseName}':\n" +
                string.Join("\n", res.Select(r =>
                    $"- {r.FromCollection}' -> To Collection '{r.ToCollection}' " +
                    $"via Field '{r.FieldName}' ({r.Confidence:P2})"));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in CompareIdFieldsToIds: {ex.Message}");
            Console.Error.WriteLine($"Error in CompareIdFieldsToIds: {ex.Message}\n{ex.StackTrace}");
            return $"Error comparing Id Like fields to _id values for database '{databaseName}': {ex.Message}";
        }
    }

    [McpServerTool]
    [Description("Generate SQL schema for a MongoDB database.")]
    public async Task<string> GenerateSqlSchema(
        [Description("Database name")] string databaseName)
    {
        try
        {
            var collections = await _analyzer.AnalyzeCollectionsAsync(databaseName);
            var relationships = await _analyzer.GetRelationshipsAsync(databaseName);
            var sqlSchema = _scriptGenerator.GenerateSqlFromInference(collections, relationships);
            return sqlSchema.FullScript;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in GenerateSqlSchema: {ex.Message}");
            Console.Error.WriteLine($"Error in GenerateSqlSchema: {ex.Message}\n{ex.StackTrace}");
            return $"Error generating SQL schema for database '{databaseName}': {ex.Message}";
        }
    }

    [McpServerTool]
    [Description("Generate SQL schema with optional user-provided relationships.")]
    public async Task<SqlSchemaOutput> GenerateSqlSchemaAdvanced(string databaseName, List<UserRelationshipOverride> overrides = null)
    {
        try
        {
            var collections = await _analyzer.AnalyzeCollectionsAsync(databaseName);
            var inferred = await _analyzer.GetRelationshipsAsync(databaseName);

            if (overrides == null || overrides.Count == 0)
                return _scriptGenerator.GenerateSqlFromInference(collections, inferred);

            return _scriptGenerator.GenerateSqlWithOverrides(collections, inferred, overrides);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in GenerateSqlSchemaAdvanced: {ex}");
            throw;
        }
    }

    [McpServerTool]
[Description("Generate SQL INSERT statements for all documents in a MongoDB collection.")]
public async Task<List<string>> GenerateSeedersForCollection(
    [Description("Database name")] string databaseName,
    [Description("Collection name")] string collectionName)
{
    try
    {
       
        var response = await _scriptGenerator.GenerateInsertStatementsForCollection(databaseName, collectionName);
        if (response == null || response.Count == 0)
        {
            Console.Error.WriteLine($"No documents found in collection '{collectionName}' of database '{databaseName}'.");
            return [];
        }
        return response;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error in GenerateSeedersForCollection: {ex}");
        throw;
    }
}
}