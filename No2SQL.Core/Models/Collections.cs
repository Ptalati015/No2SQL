using MongoDB.Bson;
using MongoDB.Driver;
namespace No2SQL.Core.Models
{
    public class CollectionSchema
    {
        public string Name { get; set; }

        // Field name → BsonType
        public Dictionary<string, BsonType> Fields { get; set; } = new();

        // Field name → isNullable
        public Dictionary<string, bool> Nullability { get; set; } = new();

        // The detected primary key field (e.g., _id, id, teacherId)
        public string PrimaryKey { get; set; }

        public Dictionary<string, List<string>> SampleValues { get; set; } = new();

        public bool IsEmbedded { get; set; } = false;
    }


}