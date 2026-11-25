using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
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
// Every tool returns a CallToolResult: failures go out with isError: true (see Failure below).
// Every tool takes the request's CancellationToken and hands it to the MongoDB calls. When the request is
// cancelled (by the client, or by a request timeout in HTTP mode) the tool stops and throws
// OperationCanceledException instead of returning an error result, so the MCP SDK drops the request.
internal class SchemaTools
{
    // Returned by every tool that reads MongoDB when no connection string is set. Fixed text, no values.
    // Worded for both modes: the person calling the tool may not be the one who runs the server (a
    // remote HTTP server used from ChatGPT or claude.ai), and the string may come from a file.
    private const string MongoNotConfiguredMessage =
        "No MongoDB connection string is set. Whoever runs this server sets NO2SQL_MONGO, or " +
        "NO2SQL_MONGO_FILE to a file that holds it, in the server's environment (for a local server, the " +
        "env section of the MCP client's configuration), then restarts the server.";

    // The start of the message for a connection string the driver can't parse. Never quotes the value.
    private const string MongoInvalidMessage =
        "The value of NO2SQL_MONGO or NO2SQL_MONGO_FILE is not a valid MongoDB connection string. Whoever " +
        "runs this server corrects it in the server's environment, then restarts the server.";

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
    [Description("Checks that the No2SQL MCP server is running and answering. Returns a success message; it does not contact MongoDB and works even when NO2SQL_MONGO is not set, so use list_databases to check the database connection.")]
    public Task<CallToolResult> TestConnectivity(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            return Task.FromResult(Success("MCP connectivity test successful!"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Failure(HandleToolError("testing MCP connectivity", ex)));
        }
    }

    [McpServerTool(Title = "List databases", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Lists the MongoDB databases this server can see, filtered by NO2SQL_ALLOWED_DATABASES when it is set and without the system databases admin, config and local unless NO2SQL_BLOCK_SYSTEM_DATABASES is false. Use it first to find the database name the other tools need.")]
    public async Task<CallToolResult> ListDatabases(CancellationToken cancellationToken = default)
    {
        try
        {
            RequireMongo();

            var databases = await _analyzer.ListDatabasesAsync(cancellationToken);
            var visibleDatabases = _guardrails.FilterVisibleDatabases(databases);

            var output = $"Available databases ({visibleDatabases.Count}):\n" +
                string.Join("\n", visibleDatabases.Select(db => $"- {db}"));
            return Success(output);
        }
        catch (Exception ex)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Failure(HandleToolError("listing databases", ex));
        }
    }

    [McpServerTool(Title = "List ID-like fields", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Lists, per collection, the fields whose names look like references to another document (for example userId or order_id). Use it for a quick look at likely relationships before checking them with compare_id_fields_to_ids.")]
    public async Task<CallToolResult> ListInferredRelationships(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
        CancellationToken cancellationToken = default)
    {
        try
        {
            RequireMongo();
            databaseName = _guardrails.ValidateDatabaseName(databaseName);

            var res = await _analyzer.GetFieldRelationshipsAsync(databaseName, cancellationToken);
            if (res.Count == 0)
            {
                return Success($"No ID-like fields found in database '{databaseName}'.");
            }

            var output = $"ID-like fields in '{databaseName}':\n" +
                string.Join("\n", res.Select(kvp =>
                    $"- Collection '{kvp.Key}': {string.Join(", ", kvp.Value)}"));
            return Success(output);
        }
        catch (Exception ex)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Failure(HandleToolError("listing inferred relationships", ex, databaseName));
        }
    }


    [McpServerTool(Title = "Infer relationships", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Infers relationships by matching the values of ID-like fields against the _id values of other collections. Returns each source collection, target collection, field and a confidence percentage; use it to see which foreign keys the SQL schema will get.")]
    public async Task<CallToolResult> CompareIdFieldsToIds(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
        CancellationToken cancellationToken = default)
    {
        try
        {
            RequireMongo();
            databaseName = _guardrails.ValidateDatabaseName(databaseName);

            var res = await _analyzer.GetRelationshipsAsync(databaseName, cancellationToken);
            if (res.Count == 0)
            {
                return Success($"No inferred relationships found by comparing Id Like fields to _id values for database '{databaseName}'.");
            }

            var output = $"Inferred Relationships by comparing Id Like fields to _id values for database '{databaseName}':\n" +
                string.Join("\n", res.Select(r =>
                    $"- '{r.FromCollection}' -> To Collection '{r.ToCollection}' " +
                    $"via Field '{r.FieldName}' ({r.Confidence:P2})"));
            return Success(output);
        }
        catch (Exception ex)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Failure(HandleToolError("comparing Id-like fields to _id values", ex, databaseName));
        }
    }

    [McpServerTool(Title = "Generate SQL schema", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates a SQL script (CREATE TABLE, indexes and foreign keys) for a MongoDB database from sampled documents and inferred relationships. Returns the script as text; use generate_sql_schema_advanced to add or correct relationships yourself.")]
    public async Task<CallToolResult> GenerateSqlSchema(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
        CancellationToken cancellationToken = default)
    {
        try
        {
            RequireMongo();
            databaseName = _guardrails.ValidateDatabaseName(databaseName);

            var collections = await _analyzer.AnalyzeCollectionsAsync(databaseName, cancellationToken);
            var relationships = await _analyzer.GetRelationshipsAsync(databaseName, cancellationToken);
            var sqlSchema = _scriptGenerator.GenerateSqlFromInference(collections, relationships);
            return Success(sqlSchema.FullScript);
        }
        catch (Exception ex)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Failure(HandleToolError("generating SQL schema", ex, databaseName));
        }
    }

    [McpServerTool(Title = "Generate SQL schema (advanced)", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates the SQL schema like generate_sql_schema, but also applies relationships you supply. Returns a JSON object with tables, foreign keys, indexes and the full script; use it when inferred relationships are missing or wrong.")]
    public async Task<CallToolResult> GenerateSqlSchemaAdvanced(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
        [Description("Optional relationships to add to the inferred ones. Each item names fromCollection, fromField, toCollection and toField, and replaces any inferred relationship on the same fromCollection and fromField. Leave empty to use inferred relationships only.")] List<UserRelationshipOverride>? overrides = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            RequireMongo();
            databaseName = _guardrails.ValidateDatabaseName(databaseName);
            overrides = _guardrails.ValidateOverrides(overrides);

            var collections = await _analyzer.AnalyzeCollectionsAsync(databaseName, cancellationToken);
            var inferred = await _analyzer.GetRelationshipsAsync(databaseName, cancellationToken);

            var output = overrides == null || overrides.Count == 0
                ? _scriptGenerator.GenerateSqlFromInference(collections, inferred)
                : _scriptGenerator.GenerateSqlWithOverrides(collections, inferred, overrides);

            return output.ErrorMessage == null ? SuccessJson(output) : Failure(output.ErrorMessage);
        }
        catch (Exception ex)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Failure(HandleToolError("generating advanced SQL schema", ex, databaseName));
        }
    }

    [McpServerTool(Title = "Generate SQL seed data", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates SQL INSERT statements for the documents in one MongoDB collection (up to the first 1000 documents). Returns a JSON array of INSERT chunks (empty if the collection has no documents); use it after creating the schema to load sample data.")]
    public async Task<CallToolResult> GenerateSeedersForCollection(
    [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
    [Description("Name of the collection to export as INSERT statements.")] string collectionName,
    CancellationToken cancellationToken = default)
    {
        try
        {
            RequireMongo();
            databaseName = _guardrails.ValidateDatabaseName(databaseName);
            collectionName = _guardrails.ValidateCollectionName(collectionName);

            var response = await _scriptGenerator.GenerateInsertStatementsForCollection(databaseName, collectionName, cancellationToken);
            if (response == null || response.Count == 0)
            {
                Console.Error.WriteLine($"No documents found in collection '{collectionName}' of database '{databaseName}'.");
                return SuccessJson(new List<string>());
            }

            return SuccessJson(response);
        }
        catch (Exception ex)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Failure(HandleToolError(
                "generating SQL seeders",
                ex,
                $"{SanitizeLabel(databaseName)}.{SanitizeLabel(collectionName)}"));
        }
    }


    [McpServerTool(Title = "Generate Mermaid ERD", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates an entity-relationship diagram of a MongoDB database. Returns a Mermaid erDiagram you can render in Markdown viewers such as GitHub.")]
    public async Task<CallToolResult> GenerateErdMermaid(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
        [Description("Where the diagram comes from. Allowed values: sql (default; built from the generated SQL schema, fails if SQL generation fails), auto (tries sql, falls back to mongo), mongo (built straight from the sampled collections).")] string source = "sql",
        CancellationToken cancellationToken = default)
    {
        try
        {
            RequireMongo();
            databaseName = _guardrails.ValidateDatabaseName(databaseName);
            source = _guardrails.ValidateSource(source);

            var schemas = await _analyzer.AnalyzeCollectionsAsync(databaseName, cancellationToken);
            var relationships = await _analyzer.GetRelationshipsAsync(databaseName, cancellationToken);

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
                        return Failure($"SQL ERD failed: {sql.ErrorMessage}");
                }
            }

            if (string.IsNullOrEmpty(diagram))
            {
                diagram = _erdGenerator.GenerateMermaidFromMongo(schemas, relationships);
            }

            return Success(diagram);
        }
        catch (Exception ex)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Failure(HandleToolError("generating Mermaid ERD", ex, databaseName));
        }
    }

    [McpServerTool(Title = "Generate PlantUML ERD", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates an entity-relationship diagram of a MongoDB database. Returns PlantUML source you can render with any PlantUML tool.")]
    public async Task<CallToolResult> GenerateErdPlantUml(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
        [Description("Where the diagram comes from. Allowed values: sql (default; built from the generated SQL schema, fails if SQL generation fails), auto (tries sql, falls back to mongo), mongo (built straight from the sampled collections).")] string source = "sql",
        CancellationToken cancellationToken = default)
    {
        try
        {
            RequireMongo();
            databaseName = _guardrails.ValidateDatabaseName(databaseName);
            source = _guardrails.ValidateSource(source);

            var schemas = await _analyzer.AnalyzeCollectionsAsync(databaseName, cancellationToken);
            var relationships = await _analyzer.GetRelationshipsAsync(databaseName, cancellationToken);

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
                        return Failure($"SQL ERD failed: {sql.ErrorMessage}");
                }
            }

            if (string.IsNullOrEmpty(diagram))
            {
                diagram = _erdGenerator.GeneratePlantUmlFromMongo(schemas, relationships);
            }

            return Success(diagram);
        }
        catch (Exception ex)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Failure(HandleToolError("generating PlantUML ERD", ex, databaseName));
        }
    }

    [McpServerTool(Title = "Generate GraphViz DOT ERD", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Generates an entity-relationship diagram of a MongoDB database. Returns GraphViz DOT source you can render with dot or any GraphViz viewer.")]
    public async Task<CallToolResult> GenerateErdDot(
        [Description("Name of the MongoDB database to analyze. Use list_databases to see the names you can use.")] string databaseName,
        [Description("Where the diagram comes from. Allowed values: sql (default; built from the generated SQL schema, fails if SQL generation fails), auto (tries sql, falls back to mongo), mongo (built straight from the sampled collections).")] string source = "sql",
        CancellationToken cancellationToken = default)
    {
        try
        {
            RequireMongo();
            databaseName = _guardrails.ValidateDatabaseName(databaseName);
            source = _guardrails.ValidateSource(source);

            var schemas = await _analyzer.AnalyzeCollectionsAsync(databaseName, cancellationToken);
            var relationships = await _analyzer.GetRelationshipsAsync(databaseName, cancellationToken);

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
                        return Failure($"SQL ERD failed: {sql.ErrorMessage}");
                }
            }

            if (string.IsNullOrEmpty(diagram))
            {
                diagram = _erdGenerator.GenerateGraphVizFromMongo(schemas, relationships);
            }

            return Success(diagram);
        }
        catch (Exception ex)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Failure(HandleToolError("generating DOT ERD", ex, databaseName));
        }
    }

    // Success results carry the same content the MCP SDK builds from a plain return value
    // (a string becomes one text block, any other object one JSON text block using the SDK's
    // default serializer options), so successful output is unchanged by returning CallToolResult.
    private static CallToolResult Success(string text) =>
        new() { Content = [new TextContentBlock { Text = text }] };

    private static CallToolResult SuccessJson(object value) =>
        Success(JsonSerializer.Serialize(value, McpJsonUtilities.DefaultOptions.GetTypeInfo(typeof(object))));

    // A failed call: the same sanitized text as before, flagged isError so clients can tell.
    private static CallToolResult Failure(string message) =>
        new() { IsError = true, Content = [new TextContentBlock { Text = message }] };

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

            return $"{MongoInvalidMessage} See server logs with error id {errorId}.";
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