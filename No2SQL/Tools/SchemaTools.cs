using System.ComponentModel;
using ModelContextProtocol.Server;
using No2SQL.Core;
using No2SQL.Core.Models;
using No2SQL.Security;
using No2SQL.Sql;
using No2SQL.Sql.Models;
using No2SQL.Visuals;
internal class SchemaTools
{
    private readonly SchemaAnalyzer _analyzer;
    private readonly ScriptGenerator _scriptGenerator;
    private readonly ErdGenerator _erdGenerator;
    private readonly McpGuardrails _guardrails;

    public SchemaTools(
        SchemaAnalyzer schemaAnalyzer,
        ScriptGenerator scriptGenerator,
        ErdGenerator erdGenerator,
        McpGuardrails guardrails)
    {
        _analyzer = schemaAnalyzer;
        _scriptGenerator = scriptGenerator;
        _erdGenerator = erdGenerator;
        _guardrails = guardrails;
    }

    [McpServerTool]
    [Description("Test MCP server connectivity.")]
    public Task<string> TestConnectivity()
    {
        try
        {
            return Task.FromResult("MCP connectivity test successful!");
        }
        catch (Exception ex)
        {
            return Task.FromResult(HandleToolError("testing MCP connectivity", ex));
        }
    }

    [McpServerTool]
    [Description("List all available databases on the MongoDB server.")]
    public async Task<string> ListDatabases()
    {
        try
        {
            var databases = await _analyzer.ListDatabasesAsync();

            var visibleDatabases = databases;
            var allowedEnv = Environment.GetEnvironmentVariable("NO2SQL_ALLOWED_DATABASES");
            if (!string.IsNullOrWhiteSpace(allowedEnv))
            {
                var allowed = allowedEnv
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                visibleDatabases = databases.Where(db => allowed.Contains(db)).ToList();
            }

            var output = $"Available databases ({visibleDatabases.Count}):\n" +
                string.Join("\n", visibleDatabases.Select(db => $"- {db}"));
            return output;
        }
        catch (Exception ex)
        {
            return HandleToolError("listing databases", ex);
        }
    }

    [McpServerTool]
    [Description("List ID-like fields in each collection.")]
    public async Task<string> ListInferredRelationships(string databaseName)
    {
        try
        {
            databaseName = _guardrails.ValidateDatabaseName(databaseName);

            var res = await _analyzer.GetFieldRelationshipsAsync(databaseName);
            if (res.Count == 0)
            {
                return $"No ID-like fields found in database '{databaseName}'.";
            }

            var output = $"ID-like fields in '{databaseName}':\n" +
                string.Join("\n", res.Select(kvp =>
                    $"- Collection '{kvp.Key}': {string.Join(", ", kvp.Value)}"));
            return output;
        }
        catch (Exception ex)
        {
            return HandleToolError("listing inferred relationships", ex, databaseName);
        }
    }


    [McpServerTool]
    [Description("Infer relationships on a MongoDB database.")]
    public async Task<string> CompareIdFieldsToIds(
        [Description("Database name")] string databaseName)
    {
        try
        {
            databaseName = _guardrails.ValidateDatabaseName(databaseName);

            var res = await _analyzer.GetRelationshipsAsync(databaseName);
            if (res.Count == 0)
            {
                return $"No inferred relationships found by comparing Id Like fields to _id values for database '{databaseName}'.";
            }

            var output = $"Inferred Relationships by comparing Id Like fields to _id values for database '{databaseName}':\n" +
                string.Join("\n", res.Select(r =>
                    $"- '{r.FromCollection}' -> To Collection '{r.ToCollection}' " +
                    $"via Field '{r.FieldName}' ({r.Confidence:P2})"));
            return output;
        }
        catch (Exception ex)
        {
            return HandleToolError("comparing Id-like fields to _id values", ex, databaseName);
        }
    }

    [McpServerTool]
    [Description("Generate SQL schema for a MongoDB database.")]
    public async Task<string> GenerateSqlSchema(
        [Description("Database name")] string databaseName)
    {
        try
        {
            databaseName = _guardrails.ValidateDatabaseName(databaseName);

            var collections = await _analyzer.AnalyzeCollectionsAsync(databaseName);
            var relationships = await _analyzer.GetRelationshipsAsync(databaseName);
            var sqlSchema = _scriptGenerator.GenerateSqlFromInference(collections, relationships);
            return sqlSchema.FullScript;
        }
        catch (Exception ex)
        {
            return HandleToolError("generating SQL schema", ex, databaseName);
        }
    }

    [McpServerTool]
    [Description("Generate SQL schema with optional user-provided relationships.")]
    public async Task<SqlSchemaOutput> GenerateSqlSchemaAdvanced(string databaseName, List<UserRelationshipOverride>? overrides = null)
    {
        try
        {
            databaseName = _guardrails.ValidateDatabaseName(databaseName);
            overrides = _guardrails.ValidateOverrides(overrides);

            var collections = await _analyzer.AnalyzeCollectionsAsync(databaseName);
            var inferred = await _analyzer.GetRelationshipsAsync(databaseName);

            if (overrides == null || overrides.Count == 0)
            {
                return _scriptGenerator.GenerateSqlFromInference(collections, inferred);
            }

            return _scriptGenerator.GenerateSqlWithOverrides(collections, inferred, overrides);
        }
        catch (Exception ex)
        {
            var message = HandleToolError("generating advanced SQL schema", ex, databaseName);
            return new SqlSchemaOutput
            {
                ErrorMessage = message
            };
        }
    }

    [McpServerTool]
    [Description(
    "Generate SQL INSERT statements for documents in a MongoDB collection. "
    )]
    public async Task<List<string>> GenerateSeedersForCollection(
    [Description("Database name")] string databaseName,
    [Description("Collection name")] string collectionName)
    {
        try
        {
            databaseName = _guardrails.ValidateDatabaseName(databaseName);
            collectionName = _guardrails.ValidateCollectionName(collectionName);

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
            var message = HandleToolError(
                "generating SQL seeders",
                ex,
                $"{SanitizeLabel(databaseName)}.{SanitizeLabel(collectionName)}");
            throw new InvalidOperationException(message);
        }
    }


    [McpServerTool]
    [Description("Generate a Mermaid ER diagram. Source can be auto, mongo, or sql.")]
    public async Task<string> GenerateErdMermaid(string databaseName, string source = "sql")
    {
        try
        {
            databaseName = _guardrails.ValidateDatabaseName(databaseName);
            source = _guardrails.ValidateSource(source);

            var schemas = await _analyzer.AnalyzeCollectionsAsync(databaseName);
            var relationships = await _analyzer.GetRelationshipsAsync(databaseName);

            var useSql = source.ToLower() switch
            {
                "sql" => true,
                "mongo" => false,
                _ => true // auto
            };

            string diagram = string.Empty;

            if (useSql)
            {
                var sql = _scriptGenerator.GenerateSqlFromInference(schemas, relationships);

                if (sql.ErrorMessage == null)
                {
                    diagram = _erdGenerator.GenerateMermaidFromSql(sql);
                }
                else
                {
                    if (source == "sql")
                        return $"SQL ERD failed: {sql.ErrorMessage}";
                }
            }

            if (string.IsNullOrEmpty(diagram))
            {
                diagram = _erdGenerator.GenerateMermaidFromMongo(schemas, relationships);
            }

            return diagram;
        }
        catch (Exception ex)
        {
            return HandleToolError("generating Mermaid ERD", ex, databaseName);
        }
    }

    [McpServerTool]
    [Description("Generate a PlantUML ER diagram. Source can be auto, mongo, or sql.")]
    public async Task<string> GenerateErdPlantUml(string databaseName, string source = "sql")
    {
        try
        {
            databaseName = _guardrails.ValidateDatabaseName(databaseName);
            source = _guardrails.ValidateSource(source);

            var schemas = await _analyzer.AnalyzeCollectionsAsync(databaseName);
            var relationships = await _analyzer.GetRelationshipsAsync(databaseName);

            var useSql = source.ToLower() switch
            {
                "sql" => true,
                "mongo" => false,
                _ => true // auto
            };

            string diagram = string.Empty;

            if (useSql)
            {
                var sql = _scriptGenerator.GenerateSqlFromInference(schemas, relationships);

                if (sql.ErrorMessage == null)
                {
                    diagram = _erdGenerator.GeneratePlantUmlFromSql(sql);
                }
                else
                {
                    if (source == "sql")
                        return $"SQL ERD failed: {sql.ErrorMessage}";
                }
            }

            if (string.IsNullOrEmpty(diagram))
            {
                diagram = _erdGenerator.GeneratePlantUmlFromMongo(schemas, relationships);
            }

            return diagram;
        }
        catch (Exception ex)
        {
            return HandleToolError("generating PlantUML ERD", ex, databaseName);
        }
    }

    [McpServerTool]
    [Description("Generate a GraphViz DOT ER diagram. Source can be auto, mongo, or sql.")]
    public async Task<string> GenerateErdDot(string databaseName, string source = "sql")
    {
        try
        {
            databaseName = _guardrails.ValidateDatabaseName(databaseName);
            source = _guardrails.ValidateSource(source);

            var schemas = await _analyzer.AnalyzeCollectionsAsync(databaseName);
            var relationships = await _analyzer.GetRelationshipsAsync(databaseName);

            var useSql = source.ToLower() switch
            {
                "sql" => true,
                "mongo" => false,
                _ => true // auto
            };

            string diagram = string.Empty;

            if (useSql)
            {
                var sql = _scriptGenerator.GenerateSqlFromInference(schemas, relationships);

                if (sql.ErrorMessage == null)
                {
                    diagram = _erdGenerator.GenerateGraphVizFromSql(sql);
                }
                else
                {
                    if (source == "sql")
                        return $"SQL ERD failed: {sql.ErrorMessage}";
                }
            }

            if (string.IsNullOrEmpty(diagram))
            {
                diagram = _erdGenerator.GenerateGraphVizFromMongo(schemas, relationships);
            }

            return diagram;
        }
        catch (Exception ex)
        {
            return HandleToolError("generating DOT ERD", ex, databaseName);
        }
    }

    private static string HandleToolError(string operation, Exception ex, string? subject = null)
    {
        var errorId = Guid.NewGuid().ToString("N")[..8];
        var subjectSuffix = string.IsNullOrWhiteSpace(subject) ? string.Empty : $" for '{SanitizeLabel(subject)}'";

        Console.Error.WriteLine(
            $"[MCP:{errorId}] {operation}{subjectSuffix} failed. {ex.GetType().Name}: {ex.Message}");

        return $"Unable to complete {operation}{subjectSuffix}. See server logs with error id {errorId}.";
    }

    private static string SanitizeLabel(string input)
    {
        var trimmed = input.Trim();
        if (trimmed.Length == 0)
        {
            return "(empty)";
        }

        var compact = trimmed
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Replace("\t", " ");

        const int maxLength = 120;
        return compact.Length <= maxLength ? compact : compact[..maxLength] + "...";
    }

}