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

}
