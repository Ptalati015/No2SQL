using MongoDB.Bson;
namespace No2SQL.Utils
{
    public static class Util
    {

        public static string Singularize(string name)
        {

            if (name.EndsWith("ies")) return name[..^3] + "y";
            if (name.EndsWith("s")) return name[..^1];
            return name;
        }

        public static string NormalizeId(BsonValue value)
        {
            if (value == null || value.IsBsonNull)
                return null;

            // If it's already an ObjectId
            if (value.IsObjectId)
                return value.AsObjectId.ToString();

            // If it's a string that looks like an ObjectId
            if (value.IsString)
            {
                var s = value.AsString.Trim();

                // Handle {"$oid": "..."} format
                if (s.StartsWith("{") && s.Contains("$oid"))
                {
                    try
                    {
                        var doc = BsonDocument.Parse(s);
                        if (doc.Contains("$oid"))
                            return doc["$oid"].AsString;
                    }
                    catch { }
                }

                // Try to parse as ObjectId
                if (ObjectId.TryParse(s, out var oid))
                    return oid.ToString();

                // Otherwise return raw string
                return s;
            }

            // Handle numeric IDs
            if (value.IsInt32 || value.IsInt64 || value.IsDouble)
                return value.ToString();

            return value.ToString();
        }

        public static string DetectPrimaryKeyField(BsonDocument doc)
        {
            // 1. Domain-specific IDs (teacherId, studentId, chairTeacherId, etc.)
            foreach (var el in doc.Elements)
            {
                if (el.Name.EndsWith("Id", StringComparison.OrdinalIgnoreCase) &&
                    !el.Name.Equals("_id", StringComparison.OrdinalIgnoreCase))
                {
                    return el.Name;
                }
            }

            // 2. Generic ID fields
            if (doc.Contains("id")) return "id";
            if (doc.Contains("Id")) return "Id";
            if (doc.Contains("ID")) return "ID";

            // 3. Fallback: _id
            if (doc.Contains("_id")) return "_id";

            // 4. Last fallback: any field ending in "id"
            foreach (var el in doc.Elements)
            {
                if (el.Name.EndsWith("id", StringComparison.OrdinalIgnoreCase))
                    return el.Name;
            }

            return null;

        }
        public static string InferMySqlType(BsonType type)
        {
            return type switch
            {
                BsonType.ObjectId => "VARCHAR(24)",
                BsonType.String => "TEXT",
                BsonType.Int32 => "INT",
                BsonType.Int64 => "BIGINT",
                BsonType.Double => "DOUBLE",
                BsonType.Decimal128 => "DECIMAL(38,18)",
                BsonType.Boolean => "BOOLEAN",
                BsonType.DateTime => "DATETIME",
                BsonType.Array => "JSON",
                BsonType.Document => "JSON",
                _ => "JSON"
            };
        }
    }

}


