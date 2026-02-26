using MongoDB.Bson;
using MongoDB.Driver;
using No2SQL.Core.Models;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using No2SQL.Utils;
using No2SQL.Sql.Models;
using System.Text;
namespace No2SQL.Visuals;

public class ErdGenerator
{
    private readonly MongoClient _client;

    public ErdGenerator(string? connectionString)
    {
        if (string.IsNullOrEmpty(connectionString))
        {
            throw new ArgumentNullException(nameof(connectionString), "Connection string cannot be null or empty.");
        }
        _client = new MongoClient(connectionString);
    }

    // Mongodb Visual Generator

    public string GenerateMermaidFromMongo(List<CollectionSchema> schemas, List<Relationship> relationships)
    {
        var sb = new StringBuilder();
        sb.AppendLine("erDiagram");

        foreach (var schema in schemas.Where(s => !s.IsEmbedded))
        {
            sb.AppendLine($"    {schema.Name} {{");

            foreach (var field in schema.Fields)
            {
                var name = field.Key;
                var type = Util.MapBsonType(field.Value);
                var pk = schema.PrimaryKey == name ? " PK" : "";
                var nullable = schema.Nullability.TryGetValue(name, out var n) && n ? "?" : "";

                sb.AppendLine($"        {type} {name}{nullable}{pk}");
            }

            sb.AppendLine("    }");
            sb.AppendLine();
        }

        foreach (var rel in relationships)
        {
            var toField = string.IsNullOrWhiteSpace(rel.ToField)
                ? "_id"
                : rel.ToField;

            // ToCollection = parent (one), FromCollection = child (many)
            sb.AppendLine(
                $"    {rel.ToCollection} ||--o{{ {rel.FromCollection} : \"{rel.FieldName} → {toField}\"");
        }


        return sb.ToString().Trim() + "\n";
    }

    public string GeneratePlantUmlFromMongo(List<CollectionSchema> schemas, List<Relationship> relationships)
    {
        var sb = new StringBuilder();
        sb.AppendLine("@startuml");
        sb.AppendLine();

        // Render entities
        foreach (var schema in schemas.Where(s => !s.IsEmbedded))
        {
            sb.AppendLine($"entity {schema.Name} {{");

            foreach (var field in schema.Fields)
            {
                var name = field.Key;
                var type = Util.MapBsonType(field.Value);
                var pk = schema.PrimaryKey == name ? "*" : "";
                var nullable = schema.Nullability.TryGetValue(name, out var n) && n ? "?" : "";

                sb.AppendLine($"        {pk} {name}{nullable} : {type}");
            }

            sb.AppendLine("}");
            sb.AppendLine();
        }

        // Render relationships
        foreach (var rel in relationships)
        {
            var toField = string.IsNullOrWhiteSpace(rel.ToField)
                ? "_id"
                : rel.ToField;

            // Parent = ToCollection, Child = FromCollection
            sb.AppendLine(
                $"{rel.ToCollection} ||--o{{ {rel.FromCollection} : {rel.FieldName} → {toField}");
        }

        sb.AppendLine();
        sb.AppendLine("@enduml");

        return sb.ToString().Trim() + "\n";
    }

    public string GenerateGraphVizFromMongo(List<CollectionSchema> schemas, List<Relationship> relationships)
    {
        var sb = new StringBuilder();
        sb.AppendLine("digraph ERD {");
        sb.AppendLine("    rankdir=LR;");
        sb.AppendLine("    node [shape=record, fontsize=10, fontname=\"Consolas\"];");
        sb.AppendLine();

        // Render nodes
        foreach (var schema in schemas.Where(s => !s.IsEmbedded))
        {
            sb.AppendLine($"    {schema.Name} [label=\"{{{schema.Name}|");

            foreach (var field in schema.Fields)
            {
                var name = field.Key;
                var type = Util.MapBsonType(field.Value);
                var pk = schema.PrimaryKey == name ? "*" : "";
                var nullable = schema.Nullability.TryGetValue(name, out var n) && n ? "?" : "";

                sb.AppendLine($"        {pk}{name}{nullable} : {type}\\l");
            }

            sb.AppendLine("    }}\"];");
            sb.AppendLine();
        }

        // Render edges
        foreach (var rel in relationships)
        {
            var toField = string.IsNullOrWhiteSpace(rel.ToField)
                ? "_id"
                : rel.ToField;

            sb.AppendLine(
                $"    {rel.ToCollection} -> {rel.FromCollection} [label=\"{rel.FieldName} → {toField}\"];");
        }

        sb.AppendLine("}");
        return sb.ToString().Trim() + "\n";
    }

    public string GenerateMermaidFromSql(SqlSchemaOutput sql)
    {
        var sb = new StringBuilder();
        sb.AppendLine("erDiagram");

        // Render tables
        foreach (var table in sql.Tables)
        {
            var tableName = table.TableName; // keep original casing or normalize if you prefer

            sb.AppendLine($"    {tableName} {{");

            foreach (var col in table.Columns)
            {
                var type = Util.MapSqlType(col.SqlType);
                var pk = table.PrimaryKey == col.Name ? " PK" : "";
                var nullable = col.IsNullable ? "?" : "";

                sb.AppendLine($"        {type} {col.Name}{nullable}{pk}");
            }

            sb.AppendLine("    }");
            sb.AppendLine();
        }

        // Render foreign keys
        foreach (var fk in sql.ForeignKeys)
        {
            sb.AppendLine(
                $"    {fk.ToTable} ||--o{{ {fk.FromTable} : \"{fk.FromColumn} → {fk.ToColumn}\"");
        }

        return sb.ToString().Trim() + "\n";
    }

    public string GeneratePlantUmlFromSql(SqlSchemaOutput sql)
    {
        var sb = new StringBuilder();
        sb.AppendLine("@startuml");
        sb.AppendLine();

        // Render entities (tables)
        foreach (var table in sql.Tables)
        {
            var tableName = table.TableName;

            sb.AppendLine($"entity {tableName} {{");

            foreach (var col in table.Columns)
            {
                var type = Util.MapSqlType(col.SqlType);
                var pk = table.PrimaryKey == col.Name ? "*" : "";
                var nullable = col.IsNullable ? "?" : "";

                sb.AppendLine($"        {pk} {col.Name}{nullable} : {type}");
            }

            sb.AppendLine("}");
            sb.AppendLine();
        }

        // Render relationships (foreign keys)
        foreach (var fk in sql.ForeignKeys)
        {
            var toField = string.IsNullOrWhiteSpace(fk.ToColumn)
                ? "_id"
                : fk.ToColumn;

            sb.AppendLine(
                $"{fk.ToTable} ||--o{{ {fk.FromTable} : {fk.FromColumn} → {toField}");
        }

        sb.AppendLine();
        sb.AppendLine("@enduml");

        return sb.ToString().Trim() + "\n";
    }
}

