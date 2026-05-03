using MongoDB.Bson;
using MongoDB.Driver;
using No2SQL.Core.Models;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using No2SQL.Utils;
using No2SQL.Sql.Models;
using System.Text;
using System.Globalization;
using System.Runtime.CompilerServices;
using MongoDB.Bson.IO;
namespace No2SQL.Sql;

public class ScriptGenerator
{
    private readonly MongoClient _client;
    private static readonly IFormatProvider Invariant = CultureInfo.InvariantCulture;
    private static readonly JsonWriterSettings CompactJsonSettings = new()
    {
        Indent = false,
        OutputMode = JsonOutputMode.RelaxedExtendedJson
    };

    public ScriptGenerator(string? connectionString)
    {
        if (string.IsNullOrEmpty(connectionString))
        {
            throw new ArgumentNullException(nameof(connectionString), "Connection string cannot be null or empty.");
        }
        _client = new MongoClient(connectionString);
    }

    public SqlSchemaOutput GenerateSqlFromInference(List<CollectionSchema> collections, List<Relationship> relationships)
    {
        var output = new SqlSchemaOutput();
        var collectionDict = collections.ToDictionary(c => c.Name, c => c);

        // 1. Generate tables
        foreach (var col in collections)
        {
            if (col.IsEmbedded)
                continue;

            var table = GenerateCreateTable(
                col.Name,
                col.Fields,
                col.PrimaryKey
            );

            output.Tables.Add(table);
        }

        // 2. Generate foreign keys
        foreach (var rel in relationships)
        {
            var targetCollection = collectionDict.GetValueOrDefault(rel.ToCollection);
            if (targetCollection == null)
                continue; // Should not happen, but just in case
            var pkField = targetCollection.PrimaryKey;

            var fk = GenerateForeignKey(rel, pkField);
            output.ForeignKeys.Add(fk);

            // 3. Generate index for FK
            var index = GenerateIndex(rel.FromCollection, rel.FieldName);
            output.Indexes.Add(index);
        }

        // 4. Build full script
        var sb = new StringBuilder();

        sb.AppendLine("-- TABLES");
        foreach (var t in output.Tables)
            sb.AppendLine(t.CreateTableSql + "\n");

        sb.AppendLine("-- FOREIGN KEYS");
        foreach (var fk in output.ForeignKeys)
            sb.AppendLine(fk.Sql + "\n");

        sb.AppendLine("-- INDEXES");
        foreach (var idx in output.Indexes)
            sb.AppendLine(idx.Sql + "\n");

        output.FullScript = sb.ToString();

        return output;
    }

    public SqlSchemaOutput GenerateSqlWithOverrides(List<CollectionSchema> collections, List<Relationship> inferred, List<UserRelationshipOverride> overrides)
    {
        var merged = MergeRelationships(inferred, overrides);
        return GenerateSqlFromInference(collections, merged);
    }

    public async Task<List<string>> GenerateInsertStatementsForCollection(string databaseName, string collectionName)
    {
        var statements = new List<string>();

        await foreach (var statement in GenerateInsertStatementsForCollectionStream(databaseName, collectionName))
        {
            statements.Add(statement);
        }

        return statements;
    }

    public async IAsyncEnumerable<string> GenerateInsertStatementsForCollectionStream(
        string databaseName,
        string collectionName,
        int batchSize = 100,
        int limit = 1000,
        int rowsPerChunk = 100,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(databaseName))
        {
            throw new ArgumentException("Database name cannot be null or empty.", nameof(databaseName));
        }

        if (string.IsNullOrWhiteSpace(collectionName))
        {
            throw new ArgumentException("Collection name cannot be null or empty.", nameof(collectionName));
        }

        if (batchSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(batchSize), "Batch size must be greater than zero.");
        }

        if (limit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "Limit must be greater than zero.");
        }

        if (rowsPerChunk <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(rowsPerChunk), "Rows per chunk must be greater than zero.");
        }

        var db = _client.GetDatabase(databaseName);
        var collection = db.GetCollection<BsonDocument>(collectionName);
        var filter = new BsonDocument();

        var options = new FindOptions<BsonDocument>
        {
            BatchSize = batchSize,
            Limit = limit
        };

        // Pass 1: discover a deterministic column set using first-seen order.
        var seenColumns = new HashSet<string>(StringComparer.Ordinal);
        var orderedColumns = new List<string>();

        using (IAsyncCursor<BsonDocument> discoveryCursor = await collection.FindAsync(filter, options, cancellationToken))
        {
            while (await discoveryCursor.MoveNextAsync(cancellationToken))
            {
                foreach (BsonDocument document in discoveryCursor.Current)
                {
                    foreach (var element in document.Elements)
                    {
                        if (seenColumns.Add(element.Name))
                        {
                            orderedColumns.Add(element.Name);
                        }
                    }
                }
            }
        }

        if (orderedColumns.Count == 0)
        {
            yield break;
        }

        // Pass 2: emit independently executable INSERT chunks with bounded memory.
        var chunkRows = new List<string>(rowsPerChunk);

        using (IAsyncCursor<BsonDocument> dataCursor = await collection.FindAsync(filter, options, cancellationToken))
        {
            while (await dataCursor.MoveNextAsync(cancellationToken))
            {
                foreach (BsonDocument document in dataCursor.Current)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var rowValues = new List<string>(orderedColumns.Count);
                    foreach (var column in orderedColumns)
                    {
                        if (document.TryGetValue(column, out var value))
                        {
                            rowValues.Add($"    {ToSqlLiteralPretty(value)}");
                        }
                        else
                        {
                            rowValues.Add("    NULL");
                        }
                    }

                    var rowBlock =
$@"(
{string.Join(",\n", rowValues)}
)";

                    chunkRows.Add(rowBlock);

                    if (chunkRows.Count == rowsPerChunk)
                    {
                        yield return BuildInsertChunk(collectionName, orderedColumns, chunkRows);
                        chunkRows.Clear();
                    }
                }
            }
        }

        if (chunkRows.Count > 0)
        {
            yield return BuildInsertChunk(collectionName, orderedColumns, chunkRows);
        }
    }

    private static string BuildInsertChunk(string collectionName, List<string> columns, List<string> rowBlocks)
    {
        var columnSql = string.Join(",\n", columns.Select(c => $"    {QuoteIdentifier(c)}"));
        var valuesSql = string.Join(",\n", rowBlocks);

        var sb = new StringBuilder();
        sb.AppendLine($"INSERT INTO {QuoteIdentifier(collectionName)} (");
        sb.AppendLine(columnSql);
        sb.AppendLine(") VALUES");
        sb.AppendLine(valuesSql);
        sb.AppendLine(";");

        return sb.ToString();
    }

    private static SqlTableDefinition GenerateCreateTable(string collectionName, Dictionary<string, BsonType> fields, string primaryKey)
    {
        var table = new SqlTableDefinition
        {
            TableName = collectionName,
            PrimaryKey = primaryKey
        };

        var columnSql = new List<string>();

        foreach (var field in fields)
        {
            var sqlType = Util.InferMySqlType(field.Value);

            table.Columns.Add(new SqlColumnDefinition
            {
                Name = field.Key,
                SqlType = sqlType,
                IsNullable = field.Key != primaryKey
            });

            columnSql.Add(
                $"  {QuoteIdentifier(field.Key)} {sqlType} {(field.Key == primaryKey ? "NOT NULL" : "")}"
            );
        }

        columnSql.Add($"  PRIMARY KEY ({QuoteIdentifier(primaryKey)})");

        table.CreateTableSql =
                $@"CREATE TABLE {QuoteIdentifier(collectionName)} (
            {string.Join(",\n", columnSql)}
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

        return table;
    }

    private static SqlIndexDefinition GenerateIndex(string table, string column)
    {
        var indexName = $"idx_{table}_{column}";

        return new SqlIndexDefinition
        {
            Table = table,
            Column = column,
            IndexName = indexName,
            Sql = $"CREATE INDEX {QuoteIdentifier(indexName)} ON {QuoteIdentifier(table)}({QuoteIdentifier(column)});"
        };
    }

    private static SqlForeignKeyDefinition GenerateForeignKey(Relationship rel, string pkField)
    {
        var fkName = $"fk_{rel.FromCollection}_{rel.ToCollection}_{rel.FieldName}";

        var sql =
            $@"ALTER TABLE {QuoteIdentifier(rel.FromCollection)}
        ADD CONSTRAINT {QuoteIdentifier(fkName)}
        FOREIGN KEY ({QuoteIdentifier(rel.FieldName)})
        REFERENCES {QuoteIdentifier(rel.ToCollection)}({QuoteIdentifier(pkField)})
        ON DELETE SET NULL;";

        return new SqlForeignKeyDefinition
        {
            FromTable = rel.FromCollection,
            FromColumn = rel.FieldName,
            ToTable = rel.ToCollection,
            ToColumn = pkField,
            ConstraintName = fkName,
            Sql = sql
        };
    }

    private static List<Relationship> MergeRelationships(List<Relationship> inferred, List<UserRelationshipOverride> overrides)
    {
        var result = new List<Relationship>(inferred);

        foreach (var o in overrides)
        {
            // Remove any inferred relationship that conflicts
            result.RemoveAll(r =>
                r.FromCollection == o.FromCollection &&
                r.FieldName == o.FromField);

            // Add the override as a 100% confidence relationship
            result.Add(new Relationship
            {
                FromCollection = o.FromCollection,
                FieldName = o.FromField,
                ToCollection = o.ToCollection,
                ToField = o.ToField,
                Confidence = 1.0
            });
        }

        return result;
    }

    private static string ToSqlLiteralPretty(BsonValue value)
    {
        if (value == null || value.IsBsonNull)
            return "NULL";

        return value.BsonType switch
        {
            BsonType.String => $"'{Escape(value.AsString)}'",
            BsonType.ObjectId => $"'{value.AsObjectId.ToString()}'",
            BsonType.Int32 => value.AsInt32.ToString(Invariant),
            BsonType.Int64 => value.AsInt64.ToString(Invariant),
            BsonType.Double => value.AsDouble.ToString(Invariant),
            BsonType.Decimal128 => value.AsDecimal.ToString(Invariant),
            BsonType.Boolean => value.AsBoolean ? "TRUE" : "FALSE",
            BsonType.DateTime => $"'{value.ToUniversalTime():yyyy-MM-dd HH:mm:ss}'",

            BsonType.Array or BsonType.Document =>
                $"'{Escape(value.ToJson(CompactJsonSettings))}'",

            _ => $"'{Escape(value.ToString() ?? string.Empty)}'"
        };
    }

    private static string Escape(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        var sb = new StringBuilder(input.Length + 16);

        foreach (var ch in input)
        {
            switch (ch)
            {
                case '\'':
                    sb.Append("''");      // SQL single-quote escape
                    break;
                case '\\':
                    sb.Append("\\\\");    // Escape backslash
                    break;
                case '\n':
                    sb.Append("\\n");     // Literal \n
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                default:
                    sb.Append(ch);
                    break;
            }
        }

        return sb.ToString();
    }

    private static string QuoteIdentifier(string identifier)
    {
        return $"`{EscapeIdentifier(identifier)}`";
    }

    private static string EscapeIdentifier(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            throw new ArgumentException("SQL identifier cannot be null or whitespace.", nameof(identifier));
        }

        // MySQL identifier escaping: embedded backticks are escaped by doubling.
        return identifier.Replace("`", "``");
    }

}
