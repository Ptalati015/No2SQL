using MongoDB.Bson;
namespace No2SQL.Utils;

public static class Util
{

    public static string Singularize(string name) {

        if (name.EndsWith("ies")) return name[..^3] + "y";
        if (name.EndsWith("s")) return name[..^1];
        return name;
    }

    public static string NormalizeId(BsonValue value) {

        if (value == null || value.IsBsonNull) return null;
        if (value.IsObjectId) return value.AsObjectId.ToString();
        return value?.ToString() ?? string.Empty;
    }

}
