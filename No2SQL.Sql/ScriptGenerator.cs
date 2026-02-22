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
            var targetCollection = collections.FirstOrDefault(c => c.Name == rel.ToCollection);
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
}
