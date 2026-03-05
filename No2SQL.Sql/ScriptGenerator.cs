using MongoDB.Bson;
using MongoDB.Driver;
using No2SQL.Core.Models;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using No2SQL.Utils;
using No2SQL.Sql.Models;
using System.Text;
namespace No2SQL.Sql;

public class ScriptGenerator
{
    private readonly MongoClient _client;

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
        var db = _client.GetDatabase(databaseName);
        var collection = db.GetCollection<BsonDocument>(collectionName);

        // Use a IAsyncCursor<BsonDocument> to efficiently stream documents if the collection is large
        var filter = new BsonDocument(); // No filter, get all documents
        var options = new FindOptions<BsonDocument>
        {
            BatchSize = 100
        };



        var allColumns = new HashSet<string>();


        var valueBlocks = new List<string>();


        using (IAsyncCursor<BsonDocument> cursor = await collection.FindAsync(filter, options))
        {
            int batchCount = 0;
            // MoveNextAsync() moves to the next batch and returns true if a batch is available
            while (await cursor.MoveNextAsync())
            {
                // cursor.Current contains the current batch as an IEnumerable<TDocument>
                IEnumerable<BsonDocument> documents = cursor.Current;
                batchCount++;

                foreach (BsonDocument document in documents)
                {
                    var rowValues = new List<string>();
                    foreach (var element in document.Elements)
                    {
                        allColumns.Add(element.Name);
                        if (document.Contains(element.Name))
                            rowValues.Add($"    {ToSqlLiteralPretty(document[element.Name])}");
                        else
                            rowValues.Add("    NULL");
                    }
                    var block =
    $@"(
{string.Join(",\n", rowValues)}
)";
                    valueBlocks.Add(block);
                }
            }
        }



        // Format column list
        var columnSql = allColumns
            .Select(c => $"    `{c}`")
            .ToList();
        // Final SQL
        var sql =
    $@"INSERT INTO `{collectionName}` (
{string.Join(",\n", columnSql)}
) VALUES
{string.Join(",\n,\n", valueBlocks)}
;
";

        return [NormalizeIndentation(sql)];
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
                $"  `{field.Key}` {sqlType} {(field.Key == primaryKey ? "NOT NULL" : "")}"
            );
        }

        columnSql.Add($"  PRIMARY KEY (`{primaryKey}`)");

        table.CreateTableSql =
                $@"CREATE TABLE `{collectionName}` (
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
            Sql = $"CREATE INDEX `{indexName}` ON `{table}`(`{column}`);"
        };
    }

    private static SqlForeignKeyDefinition GenerateForeignKey(Relationship rel, string pkField)
    {
        var fkName = $"fk_{rel.FromCollection}_{rel.ToCollection}_{rel.FieldName}";

        var sql =
            $@"ALTER TABLE `{rel.FromCollection}`
        ADD CONSTRAINT `{fkName}`
        FOREIGN KEY (`{rel.FieldName}`)
        REFERENCES `{rel.ToCollection}`(`{pkField}`)
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
        if (value.IsBsonNull) return "NULL";

        return value.BsonType switch
        {
            BsonType.String => $"'{Escape(value.AsString)}'",
            BsonType.ObjectId => $"'{value.AsObjectId.ToString()}'",
            BsonType.Int32 => value.AsInt32.ToString(),
            BsonType.Int64 => value.AsInt64.ToString(),
            BsonType.Double => value.AsDouble.ToString(),
            BsonType.Boolean => value.AsBoolean ? "TRUE" : "FALSE",
            BsonType.DateTime => $"'{value.ToUniversalTime():yyyy-MM-dd HH:mm:ss}'",

            BsonType.Array or BsonType.Document =>
                $"'{Escape(value.ToJson(new MongoDB.Bson.IO.JsonWriterSettings
                {
                    Indent = true,
                    IndentChars = "    "
                }))}'",

            _ => $"'{Escape(value.ToString())}'"
        };
    }

    private static string NormalizeIndentation(string sql)
    {
        var lines = sql.Replace("\r", "").Split('\n');

        var minIndent = lines
            .Where(l => l.Trim().Length > 0)
            .Select(l => l.TakeWhile(Char.IsWhiteSpace).Count())
            .DefaultIfEmpty(0)
            .Min();

        var normalized = string.Join("\n", lines.Select(l =>
            l.Length >= minIndent ? l[minIndent..] : l
        ));

        return normalized.Trim() + "\n";


    }
    private static string Escape(string s) => s.Replace("'", "''");

}
