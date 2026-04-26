using MongoDB.Bson;
using No2SQL.Core.Models;
using System.Collections.Generic;
using No2SQL.Utils;
using No2SQL.Sql.Models;
using System.Text;
using System.Globalization;
using System.Security.Cryptography;
namespace No2SQL.Visuals;

public class ErdGenerator
{
    // Mongodb Visual Generator

    public string GenerateMermaidFromMongo(List<CollectionSchema> schemas, List<Relationship> relationships)
    {
        var deduplicatedRelationships = DeduplicateRelationships(relationships);
        var sb = new StringBuilder();
        sb.AppendLine("erDiagram");

        var schemaNames = schemas
            .Where(s => !s.IsEmbedded)
            .Select(s => s.Name);
        var idMap = BuildUniqueIdMap(schemaNames);

        foreach (var schema in schemas.Where(s => !s.IsEmbedded))
        {
            if (!idMap.TryGetValue(schema.Name, out var safeId))
            {
                continue;
            }

            sb.AppendLine($"    {safeId} {{");

            foreach (var field in schema.Fields)
            {
                var name = field.Key;
                var type = Util.MapBsonType(field.Value);
                var pk = schema.PrimaryKey == name ? " PK" : "";
                var isNullable = schema.Nullability.TryGetValue(name, out var n) && n;
                var nullableComment = isNullable ? " \"null\"" : "";
                var safeFieldName = EscapeMermaidAttributeName(name);

                sb.AppendLine($"        {type} {safeFieldName}{pk}{nullableComment}");
            }

            sb.AppendLine("    }");
            sb.AppendLine();
        }

        foreach (var rel in deduplicatedRelationships)
        {
            var toField = string.IsNullOrWhiteSpace(rel.ToField)
                ? "_id"
                : rel.ToField;

            if (!idMap.TryGetValue(rel.ToCollection, out var toId) || !idMap.TryGetValue(rel.FromCollection, out var fromId))
            {
                sb.AppendLine($"    %% Skipped invalid relationship {EscapeMermaidLabel(rel.FromCollection)}.{EscapeMermaidLabel(rel.FieldName)} -> {EscapeMermaidLabel(rel.ToCollection)}.{EscapeMermaidLabel(toField)}");
                continue;
            }

            var relationLabel = EscapeMermaidLabel($"{rel.FieldName} -> {toField}");

            // ToCollection = parent (one), FromCollection = child (many)
            sb.AppendLine(
                $"    {toId} ||--o{{ {fromId} : \"{relationLabel}\"");
        }


        return sb.ToString().Trim() + "\n";
    }

    public string GeneratePlantUmlFromMongo(List<CollectionSchema> schemas, List<Relationship> relationships)
    {
        var deduplicatedRelationships = DeduplicateRelationships(relationships);
        var sb = new StringBuilder();
        sb.AppendLine("@startuml");
        sb.AppendLine();

        var schemaNames = schemas
            .Where(s => !s.IsEmbedded)
            .Select(s => s.Name);
        var idMap = BuildUniqueIdMap(schemaNames);

        // Render entities
        foreach (var schema in schemas.Where(s => !s.IsEmbedded))
        {
            if (!idMap.TryGetValue(schema.Name, out var safeId))
            {
                continue;
            }

            sb.AppendLine($"entity {safeId} as \"{EscapePlantUmlLabel(schema.Name)}\" {{");

            foreach (var field in schema.Fields)
            {
                var name = field.Key;
                var type = Util.MapBsonType(field.Value);
                var pk = schema.PrimaryKey == name ? "*" : "";
                var nullable = schema.Nullability.TryGetValue(name, out var n) && n ? "?" : "";
                var safeFieldName = EscapePlantUmlAttributeName(name);

                sb.AppendLine($"        {pk} {safeFieldName}{nullable} : {type}");
            }

            sb.AppendLine("}");
            sb.AppendLine();
        }

        // Render relationships
        foreach (var rel in deduplicatedRelationships)
        {
            var toField = string.IsNullOrWhiteSpace(rel.ToField)
                ? "_id"
                : rel.ToField;

            if (!idMap.TryGetValue(rel.ToCollection, out var toId) || !idMap.TryGetValue(rel.FromCollection, out var fromId))
            {
                sb.AppendLine($"' Skipped invalid relationship {EscapePlantUmlLabel(rel.FromCollection)}.{EscapePlantUmlLabel(rel.FieldName)} -> {EscapePlantUmlLabel(rel.ToCollection)}.{EscapePlantUmlLabel(toField)}");
                continue;
            }

            var relationLabel = EscapePlantUmlLabel($"{rel.FieldName} -> {toField}");

            // Parent = ToCollection, Child = FromCollection
            sb.AppendLine(
                $"{toId} ||--o{{ {fromId} : {relationLabel}");
        }

        sb.AppendLine();
        sb.AppendLine("@enduml");

        return sb.ToString().Trim() + "\n";
    }

    public string GenerateGraphVizFromMongo(List<CollectionSchema> schemas, List<Relationship> relationships)
    {
        var deduplicatedRelationships = DeduplicateRelationships(relationships);
        var sb = new StringBuilder();
        sb.AppendLine("digraph ERD {");
        sb.AppendLine("    rankdir=LR;");
        sb.AppendLine("    node [shape=record, fontsize=10, fontname=\"Consolas\"];");
        sb.AppendLine();

        var schemaNames = schemas
            .Where(s => !s.IsEmbedded)
            .Select(s => s.Name);
        var idMap = BuildUniqueIdMap(schemaNames);

        // Render nodes
        foreach (var schema in schemas.Where(s => !s.IsEmbedded))
        {
            if (!idMap.TryGetValue(schema.Name, out var safeId))
            {
                continue;
            }

            var labelBuilder = new StringBuilder();
            labelBuilder.Append('{');
            labelBuilder.Append(EscapeDotLabel(schema.Name));
            labelBuilder.Append('|');

            foreach (var field in schema.Fields)
            {
                var name = field.Key;
                var type = Util.MapBsonType(field.Value);
                var pk = schema.PrimaryKey == name ? "*" : "";
                var nullable = schema.Nullability.TryGetValue(name, out var n) && n ? "?" : "";
                labelBuilder.Append(EscapeDotLabel($"{pk}{name}{nullable} : {type}"));
                labelBuilder.Append("\\l");
            }

            labelBuilder.Append('}');

            sb.AppendLine($"    \"{BuildDotSafeId(safeId)}\" [label=\"{labelBuilder}\"];");
            sb.AppendLine();
        }

        // Render edges
        foreach (var rel in deduplicatedRelationships)
        {
            var toField = string.IsNullOrWhiteSpace(rel.ToField)
                ? "_id"
                : rel.ToField;

            if (!idMap.TryGetValue(rel.ToCollection, out var toId) || !idMap.TryGetValue(rel.FromCollection, out var fromId))
            {
                sb.AppendLine($"    // Skipped invalid relationship {EscapeDotLabel(rel.FromCollection)}.{EscapeDotLabel(rel.FieldName)} -> {EscapeDotLabel(rel.ToCollection)}.{EscapeDotLabel(toField)}");
                continue;
            }

            sb.AppendLine(
                $"    \"{BuildDotSafeId(toId)}\" -> \"{BuildDotSafeId(fromId)}\" [label=\"{EscapeDotLabel($"{rel.FieldName} -> {toField}")}\"];");
        }

        sb.AppendLine("}");
        return sb.ToString().Trim() + "\n";
    }

    public string GenerateMermaidFromSql(SqlSchemaOutput sql)
    {
        var deduplicatedFks = DeduplicateForeignKeys(sql.ForeignKeys);
        var sb = new StringBuilder();
        sb.AppendLine("erDiagram");

        var idMap = BuildUniqueIdMap(sql.Tables.Select(t => t.TableName));

        // Render tables
        foreach (var table in sql.Tables)
        {
            if (!idMap.TryGetValue(table.TableName, out var safeId))
            {
                continue;
            }

            sb.AppendLine($"    {safeId} {{");

            foreach (var col in table.Columns)
            {
                var type = Util.MapSqlType(col.SqlType);
                var pk = table.PrimaryKey == col.Name ? " PK" : "";
                var nullableComment = col.IsNullable ? " \"null\"" : "";
                var safeFieldName = EscapeMermaidAttributeName(col.Name);

                sb.AppendLine($"        {type} {safeFieldName}{pk}{nullableComment}");
            }

            sb.AppendLine("    }");
            sb.AppendLine();
        }

        // Render foreign keys
        foreach (var fk in deduplicatedFks)
        {
            if (!idMap.TryGetValue(fk.ToTable, out var toId) || !idMap.TryGetValue(fk.FromTable, out var fromId))
            {
                sb.AppendLine($"    %% Skipped invalid relationship {EscapeMermaidLabel(fk.FromTable)}.{EscapeMermaidLabel(fk.FromColumn)} -> {EscapeMermaidLabel(fk.ToTable)}.{EscapeMermaidLabel(fk.ToColumn)}");
                continue;
            }

            sb.AppendLine(
                $"    {toId} ||--o{{ {fromId} : \"{EscapeMermaidLabel($"{fk.FromColumn} -> {fk.ToColumn}")}\"");
        }

        return sb.ToString().Trim() + "\n";
    }

    public string GeneratePlantUmlFromSql(SqlSchemaOutput sql)
    {
        var deduplicatedFks = DeduplicateForeignKeys(sql.ForeignKeys);
        var sb = new StringBuilder();
        sb.AppendLine("@startuml");
        sb.AppendLine();

        var idMap = BuildUniqueIdMap(sql.Tables.Select(t => t.TableName));

        // Render entities (tables)
        foreach (var table in sql.Tables)
        {
            if (!idMap.TryGetValue(table.TableName, out var safeId))
            {
                continue;
            }

            sb.AppendLine($"entity {safeId} as \"{EscapePlantUmlLabel(table.TableName)}\" {{");

            foreach (var col in table.Columns)
            {
                var type = Util.MapSqlType(col.SqlType);
                var pk = table.PrimaryKey == col.Name ? "*" : "";
                var nullable = col.IsNullable ? "?" : "";
                var safeFieldName = EscapePlantUmlAttributeName(col.Name);

                sb.AppendLine($"        {pk} {safeFieldName}{nullable} : {type}");
            }

            sb.AppendLine("}");
            sb.AppendLine();
        }

        // Render relationships (foreign keys)
        foreach (var fk in deduplicatedFks)
        {
            var toField = string.IsNullOrWhiteSpace(fk.ToColumn)
                ? "_id"
                : fk.ToColumn;

            if (!idMap.TryGetValue(fk.ToTable, out var toId) || !idMap.TryGetValue(fk.FromTable, out var fromId))
            {
                sb.AppendLine($"' Skipped invalid relationship {EscapePlantUmlLabel(fk.FromTable)}.{EscapePlantUmlLabel(fk.FromColumn)} -> {EscapePlantUmlLabel(fk.ToTable)}.{EscapePlantUmlLabel(toField)}");
                continue;
            }

            sb.AppendLine(
                $"{toId} ||--o{{ {fromId} : {EscapePlantUmlLabel($"{fk.FromColumn} -> {toField}")}");
        }

        sb.AppendLine();
        sb.AppendLine("@enduml");

        return sb.ToString().Trim() + "\n";
    }

    public string GenerateGraphVizFromSql(SqlSchemaOutput sql)
    {
        var deduplicatedFks = DeduplicateForeignKeys(sql.ForeignKeys);
        var sb = new StringBuilder();
        sb.AppendLine("digraph ERD {");
        sb.AppendLine("    rankdir=LR;");
        sb.AppendLine("    graph [splines=ortho, nodesep=0.6, ranksep=0.8];");
        sb.AppendLine("    node [shape=record, fontsize=10, fontname=\"Consolas\"];");
        sb.AppendLine();

        var idMap = BuildUniqueIdMap(sql.Tables.Select(t => t.TableName));

        // Render tables as record-shaped nodes
        foreach (var table in sql.Tables)
        {
            if (!idMap.TryGetValue(table.TableName, out var safeId))
            {
                continue;
            }

            var labelBuilder = new StringBuilder();
            labelBuilder.Append('{');
            labelBuilder.Append(EscapeDotLabel(table.TableName));
            labelBuilder.Append('|');

            foreach (var col in table.Columns)
            {
                var type = Util.MapSqlType(col.SqlType);
                var pk = table.PrimaryKey == col.Name ? "*" : "";
                var nullable = col.IsNullable ? "?" : "";
                labelBuilder.Append(EscapeDotLabel($"{pk}{col.Name}{nullable} : {type}"));
                labelBuilder.Append("\\l");
            }

            labelBuilder.Append('}');

            sb.AppendLine($"    \"{BuildDotSafeId(safeId)}\" [label=\"{labelBuilder}\"];");
            sb.AppendLine();
        }

        // Render foreign key edges
        foreach (var fk in deduplicatedFks)
        {
            var toField = string.IsNullOrWhiteSpace(fk.ToColumn)
                ? "_id"
                : fk.ToColumn;

            if (!idMap.TryGetValue(fk.ToTable, out var toId) || !idMap.TryGetValue(fk.FromTable, out var fromId))
            {
                sb.AppendLine($"    // Skipped invalid relationship {EscapeDotLabel(fk.FromTable)}.{EscapeDotLabel(fk.FromColumn)} -> {EscapeDotLabel(fk.ToTable)}.{EscapeDotLabel(toField)}");
                continue;
            }

            sb.AppendLine(
                $"    \"{BuildDotSafeId(toId)}\" -> \"{BuildDotSafeId(fromId)}\" [label=\"{EscapeDotLabel($"{fk.FromColumn} -> {toField}")}\"];");
        }

        sb.AppendLine("}");
        return sb.ToString().Trim() + "\n";
    }

    private static Dictionary<string, string> BuildUniqueIdMap(IEnumerable<string> names)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        var used = new HashSet<string>(StringComparer.Ordinal);

        foreach (var raw in names.Where(n => !string.IsNullOrWhiteSpace(n)).Distinct(StringComparer.Ordinal))
        {
            var baseId = BuildRendererSafeId(raw);
            var candidate = baseId;

            if (!used.Add(candidate))
            {
                var hash = ComputeStableShortHash(raw);
                candidate = $"{baseId}_{hash}";

                var counter = 1;
                while (!used.Add(candidate))
                {
                    candidate = $"{baseId}_{hash}_{counter.ToString(CultureInfo.InvariantCulture)}";
                    counter++;
                }
            }

            map[raw] = candidate;
        }

        return map;
    }

    private static string BuildRendererSafeId(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return "_item";
        }

        var sb = new StringBuilder(raw.Length);
        foreach (var ch in raw)
        {
            if (char.IsLetterOrDigit(ch) || ch == '_')
            {
                sb.Append(ch);
            }
            else
            {
                sb.Append('_');
            }
        }

        var normalized = CollapseUnderscores(sb.ToString().Trim('_'));
        if (normalized.Length == 0)
        {
            normalized = "_item";
        }

        if (!char.IsLetter(normalized[0]) && normalized[0] != '_')
        {
            normalized = $"_{normalized}";
        }

        return normalized;
    }

    private static string BuildDotSafeId(string raw)
    {
        return BuildRendererSafeId(raw);
    }

    private static string EscapeMermaidLabel(string value)
    {
        var normalized = NormalizeWhitespaceAndControls(value);
        return normalized
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
    }

    private static string EscapeMermaidAttributeName(string value)
    {
        var normalized = NormalizeWhitespaceAndControls(value);
        var sb = new StringBuilder(normalized.Length);
        foreach (var ch in normalized)
        {
            if (char.IsLetterOrDigit(ch) || ch == '_' || ch == '-')
            {
                sb.Append(ch);
            }
            else
            {
                sb.Append('_');
            }
        }

        var sanitized = CollapseUnderscores(sb.ToString().Trim('_'));
        return sanitized.Length == 0 ? "field" : sanitized;
    }

    private static string EscapePlantUmlLabel(string value)
    {
        var normalized = NormalizeWhitespaceAndControls(value);
        return normalized
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
    }

    private static string EscapePlantUmlAttributeName(string value)
    {
        var normalized = NormalizeWhitespaceAndControls(value);
        var sb = new StringBuilder(normalized.Length);
        foreach (var ch in normalized)
        {
            if (ch == ':')
            {
                sb.Append('_');
                continue;
            }

            if (char.IsControl(ch))
            {
                continue;
            }

            sb.Append(ch);
        }

        var sanitized = CollapseUnderscores(sb.ToString());
        return sanitized.Length == 0 ? "field" : sanitized;
    }

    private static string EscapeDotLabel(string value)
    {
        var normalized = NormalizeWhitespaceAndControls(value);
        var sb = new StringBuilder(normalized.Length + 16);

        foreach (var ch in normalized)
        {
            switch (ch)
            {
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '"':
                    sb.Append("\\\"");
                    break;
                case '{':
                case '}':
                case '|':
                case '<':
                case '>':
                    sb.Append('\\');
                    sb.Append(ch);
                    break;
                default:
                    sb.Append(ch);
                    break;
            }
        }

        return sb.ToString();
    }

    private static string NormalizeWhitespaceAndControls(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var normalized = value
            .Replace("\r\n", " ", StringComparison.Ordinal)
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Replace('\t', ' ');

        var sb = new StringBuilder(normalized.Length);
        foreach (var ch in normalized)
        {
            if (!char.IsControl(ch))
            {
                sb.Append(ch);
            }
        }

        return sb.ToString();
    }

    private static string CollapseUnderscores(string value)
    {
        if (value.Length == 0)
        {
            return value;
        }

        var sb = new StringBuilder(value.Length);
        var previousUnderscore = false;

        foreach (var ch in value)
        {
            if (ch == '_')
            {
                if (previousUnderscore)
                {
                    continue;
                }

                previousUnderscore = true;
                sb.Append(ch);
                continue;
            }

            previousUnderscore = false;
            sb.Append(ch);
        }

        return sb.ToString();
    }

    private static string ComputeStableShortHash(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash[..4]).ToLowerInvariant();
    }

    private static IEnumerable<Relationship> DeduplicateRelationships(IEnumerable<Relationship> rels)
    {
        return rels
            .GroupBy(r => $"{r.FromCollection}\0{r.ToCollection}\0{r.FieldName}")
            .Select(g => g.OrderByDescending(r => r.Confidence).First());
    }

    private static IEnumerable<SqlForeignKeyDefinition> DeduplicateForeignKeys(IEnumerable<SqlForeignKeyDefinition> fks)
    {
        return fks.DistinctBy(fk => (fk.FromTable, fk.ToTable, fk.FromColumn));
    }
}

