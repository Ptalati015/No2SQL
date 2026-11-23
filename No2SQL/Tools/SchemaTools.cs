using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Server;
using MongoDB.Driver;
using No2SQL.Core;
using No2SQL.Core.Models;
using No2SQL.Security;
using No2SQL.Sql;
using No2SQL.Sql.Models;
using No2SQL.Visuals;
// Every tool is annotated read-only, non-destructive, idempotent and closed-world.
// If a tool ever writes data, touches files or calls another network service, update its annotations.
internal class SchemaTools
{
    // Returned by every tool that reads MongoDB when NO2SQL_MONGO is not set. Fixed text, no values.
    private const string MongoNotConfiguredMessage =
        "NO2SQL_MONGO is not set. Set the NO2SQL_MONGO environment variable to your MongoDB connection string " +
        "in this server's MCP client configuration, then restart the server.";

    private readonly MongoConnection _mongo;
    private readonly SchemaAnalyzer _analyzer;
    private readonly ScriptGenerator _scriptGenerator;
    private readonly ErdGenerator _erdGenerator;
    private readonly McpGuardrails _guardrails;

    public SchemaTools(
        MongoConnection mongo,
        SchemaAnalyzer schemaAnalyzer,
        ScriptGenerator scriptGenerator,
        ErdGenerator erdGenerator,
        McpGuardrails guardrails)
    {
        _mongo = mongo;
        _analyzer = schemaAnalyzer;
        _scriptGenerator = scriptGenerator;
        _erdGenerator = erdGenerator;
        _guardrails = guardrails;
    }

    [McpServerTool(Title = "Test connectivity", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Checks that the No2SQL MCP server is running and answering. Returns a success message; it does not contact MongoDB, so use list_databases to check the database connection.")]
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

    [McpServerTool(Title = "List databases", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Lists the MongoDB databases this server can see, filtered by NO2SQL_ALLOWED_DATABASES when it is set and without the system databases admin, config and local unless NO2SQL_BLOCK_SYSTEM_DATABASES is false. Use it first to find the database name the other tools need.")]
    public async Task<string> ListDatabases()
    {
        try
        {
            RequireMongo();

            var databases = await _analyzer.ListDatabasesAsync();
            var visibleDatabases = _guardrails.FilterVisibleDatabases(databases);

            var output = $"Available databases ({visibleDatabases.Count}):\n" +
                string.Join("\n", visibleDatabases.Select(db => $"- {db}"));
            return output;
        }
        catch (Exception ex)
        {
            return HandleToolError("listing databases", ex);
        }
    }

    [McpServerTool(Title = "List ID-like fields", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Lists, per collection, the fields whose names look like references to another document (for example userId or order_id). Use it for a quick look at likely relationships before checking them with compare_id_fields_to_ids.")]
    public async Task<string> ListInferredRelationships(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName)
    {
        try
        {
            RequireMongo();
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


    [McpServerTool(Title = "Infer relationships", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Infers relationships by matching the values of ID-like fields against the _id values of other collections. Returns each source collection, target collection, field and a confidence percentage; use it to see which foreign keys the SQL schema will get.")]
    public async Task<string> CompareIdFieldsToIds(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName)
    {
        try
        {
            RequireMongo();
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

    [McpServerTool(Title = "Generate SQL schema", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates a SQL script (CREATE TABLE, indexes and foreign keys) for a MongoDB database from sampled documents and inferred relationships. Returns the script as text; use generate_sql_schema_advanced to add or correct relationships yourself.")]
    public async Task<string> GenerateSqlSchema(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName)
    {
        try
        {
            RequireMongo();
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

    [McpServerTool(Title = "Generate SQL schema (advanced)", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates the SQL schema like generate_sql_schema, but also applies relationships you supply. Returns structured output with tables, foreign keys, indexes, the full script and an error message if generation failed; use it when inferred relationships are missing or wrong.")]
    public async Task<SqlSchemaOutput> GenerateSqlSchemaAdvanced(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
        [Description("Optional relationships to add to the inferred ones. Each item names fromCollection, fromField, toCollection and toField, and replaces any inferred relationship on the same fromCollection and fromField. Leave empty to use inferred relationships only.")] List<UserRelationshipOverride>? overrides = null)
    {
        try
        {
            RequireMongo();
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

    [McpServerTool(Title = "Generate SQL seed data", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates SQL INSERT statements for the documents in one MongoDB collection (up to the first 1000 documents). Returns a list of INSERT chunks; use it after creating the schema to load sample data.")]
    public async Task<List<string>> GenerateSeedersForCollection(
    [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
    [Description("Name of the collection to export as INSERT statements.")] string collectionName)
    {
        try
        {
            RequireMongo();
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

            // This tool reports failure by throwing, and the MCP SDK only passes the message of an
            // McpException on to the client. A connection setup problem has to reach the user, so it
            // uses McpException; every other failure keeps the SDK's generic text, as before.
            if (ex is MongoConnectionSetupException)
            {
                throw new McpException(message);
            }

            throw new InvalidOperationException(message);
        }
    }


    [McpServerTool(Title = "Generate Mermaid ERD", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates an entity-relationship diagram of a MongoDB database. Returns a Mermaid erDiagram you can render in Markdown viewers such as GitHub.")]
    public async Task<string> GenerateErdMermaid(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
        [Description("Where the diagram comes from. Allowed values: sql (default; built from the generated SQL schema, fails if SQL generation fails), auto (tries sql, falls back to mongo), mongo (built straight from the sampled collections).")] string source = "sql")
    {
        try
        {
            RequireMongo();
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

    [McpServerTool(Title = "Generate PlantUML ERD", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates an entity-relationship diagram of a MongoDB database. Returns PlantUML source you can render with any PlantUML tool.")]
    public async Task<string> GenerateErdPlantUml(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
        [Description("Where the diagram comes from. Allowed values: sql (default; built from the generated SQL schema, fails if SQL generation fails), auto (tries sql, falls back to mongo), mongo (built straight from the sampled collections).")] string source = "sql")
    {
        try
        {
            RequireMongo();
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

    [McpServerTool(Title = "Generate GraphViz DOT ERD", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates an entity-relationship diagram of a MongoDB database. Returns GraphViz DOT source you can render with dot or any GraphViz viewer.")]
    public async Task<string> GenerateErdDot(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
        [Description("Where the diagram comes from. Allowed values: sql (default; built from the generated SQL schema, fails if SQL generation fails), auto (tries sql, falls back to mongo), mongo (built straight from the sampled collections).")] string source = "sql")
    {
        try
        {
            RequireMongo();
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

    // Builds the MongoDB client on first use. Called before a tool validates its arguments or
    // touches MongoDB, so a missing or invalid NO2SQL_MONGO always gives the same answer.
    private void RequireMongo() => _ = _mongo.Client;

    private static string HandleToolError(string operation, Exception ex, string? subject = null)
    {
        if (ex is MongoConnectionSetupException { Problem: MongoConnectionProblem.NotConfigured })
        {
            Console.Error.WriteLine($"[MCP] {operation} not run: NO2SQL_MONGO is not set.");
            return MongoNotConfiguredMessage;
        }

        var errorId = Guid.NewGuid().ToString("N")[..8];

        if (ex is MongoConnectionSetupException invalid)
        {
            // Type and error id only. The driver's own message can quote the connection string.
            Console.Error.WriteLine(
                $"[MCP:{errorId}] {operation} not run: NO2SQL_MONGO is not a valid MongoDB connection string ({invalid.CauseType}).");

            return "NO2SQL_MONGO is not a valid MongoDB connection string. Correct it in this server's MCP client " +
                $"configuration, then restart the server. See server logs with error id {errorId}.";
        }

        var subjectSuffix = string.IsNullOrWhiteSpace(subject) ? string.Empty : $" for '{SanitizeLabel(subject)}'";

        // A MongoConfigurationException message can quote the connection string, so only its type is logged.
        var detail = HasMongoConfigurationException(ex) ? "(message withheld)" : ex.Message;

        Console.Error.WriteLine(
            $"[MCP:{errorId}] {operation}{subjectSuffix} failed. {ex.GetType().Name}: {detail}");

        return $"Unable to complete {operation}{subjectSuffix}. See server logs with error id {errorId}.";
    }

    private static bool HasMongoConfigurationException(Exception ex)
    {
        for (Exception? current = ex; current != null; current = current.InnerException)
        {
            if (current is MongoConfigurationException)
            {
                return true;
            }
        }

        return false;
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