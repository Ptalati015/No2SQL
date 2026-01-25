using MongoDB.Bson;
namespace No2SQL.Utils
{
    public static class Util
{

    public static string Singularize(string name) {

        if (name.EndsWith("ies")) return name[..^3] + "y";
        if (name.EndsWith("s")) return name[..^1];
        return name;
    }

   public static string NormalizeId(BsonValue value) {
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

}
    
}


