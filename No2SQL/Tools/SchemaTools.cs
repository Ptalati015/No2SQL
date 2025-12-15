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
            return $"Error analyzing database '{databaseName}': {ex.Message}";
        }
    }
}