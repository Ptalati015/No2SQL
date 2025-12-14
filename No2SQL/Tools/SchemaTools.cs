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
    public async Task<Dictionary<string, List<string>>> TestAnalyze(
        [Description("Database name")] string databaseName)
    {
        return await _analyzer.AnalyzeAsync(databaseName);
    }
}