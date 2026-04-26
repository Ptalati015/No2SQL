using MongoDB.Bson;
using MongoDB.Driver;
using No2SQL.Core.Models;
using System.Text.RegularExpressions;
using No2SQL.Utils;
namespace No2SQL.Core;


public partial class SchemaAnalyzer
{
    private readonly MongoClient _client;
    public SchemaAnalyzer(string? connectionString)
    {
        if (string.IsNullOrEmpty(connectionString))
        {
            throw new ArgumentNullException(nameof(connectionString), "Connection string cannot be null or empty.");
        }
        _client = new MongoClient(connectionString);
    }
    /// <summary>
    /// Analyzes the specified database and returns a schema summary.
    /// </summary>
    /// <param name="databaseName">The name of the MongoDB database to inspect</param>
    /// <returns>A dictionary mapping collection names to field metadata</returns>
    public async Task<Dictionary<string, List<string>>> AnalyzeAsync(string databaseName)
    {
        try
        {
            var result = new Dictionary<string, List<string>>();
            var db = _client.GetDatabase(databaseName);
            // Get all collections in the database
            var collections = await db.ListCollectionNamesAsync();
            var collectionNames = await collections.ToListAsync();

            foreach (var collectionName in collectionNames)
            {
                var collection = db.GetCollection<BsonDocument>(collectionName);

                var sample = await collection.Find(Builders<BsonDocument>.Filter.Empty).Limit(1).FirstOrDefaultAsync();

                var fields = new List<string>();

                if (sample != null)
                {
                    foreach (var kvp in sample.ToBsonDocument().Elements)
                    {
                        fields.Add($"{kvp.Name} ({kvp.Value.BsonType})");
                    }
                }

                result[collectionName] = fields;
            }

            return result;

        }
        catch (Exception ex)
        {
            if (ex.InnerException != null)
            {
                Console.Error.WriteLine($"Inner Exception: {ex.InnerException.Message}");
            }
            Console.Error.WriteLine($"Error in AnalyzeAsync: {ex.Message}\n{ex.StackTrace}");
            throw new Exception($"Error analyzing database '{databaseName}': {ex.Message}", ex);

        }

    }

    /// <summary>
    /// Lists all available databases on the MongoDB server.
    /// </summary>
    /// <returns>A list of database names</returns>
    public async Task<List<string>> ListDatabasesAsync()
    {
        try
        {
            var databases = await _client.ListDatabaseNamesAsync();
            return await databases.ToListAsync();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error listing databases: {ex.Message}\n{ex.StackTrace}");
            throw new Exception($"Error listing databases: {ex.Message}", ex);
        }
    }


    public async Task<Dictionary<string, SampledCollection>> SampleCollectionsAsync(string databaseName)
    {
        var db = _client.GetDatabase(databaseName);

        var collections = await db.ListCollectionNamesAsync();
        var collectionNames = await collections.ToListAsync();

        var fkPattern = MyRegex();

        var result = new Dictionary<string, SampledCollection>();

        foreach (var name in collectionNames)
        {
            var col = db.GetCollection<BsonDocument>(name);

            // Sample once
            var docs = await col.Find(FilterDefinition<BsonDocument>.Empty)
                                .Limit(300)
                                .ToListAsync();

            var sampled = new SampledCollection
            {
                Name = name,
                Documents = docs
            };

            if (docs.Count == 0)
            {
                result[name] = sampled;
                continue;
            }

            // Detect PK field from first doc
            sampled.PrimaryKeyField = Util.DetectPrimaryKeyField(docs[0]);

            // Extract PK values
            if (sampled.PrimaryKeyField != null)
            {
                sampled.PrimaryKeyValues = docs
                    .Where(d => d.Contains(sampled.PrimaryKeyField))
                    .Select(d => Util.NormalizeId(d.GetValue(sampled.PrimaryKeyField)))
                    .Where(v => v is not null)
                    .Select(v => v!)
                    .ToHashSet();
            }

            // Discover ID-like fields
            foreach (var doc in docs)
            {
                foreach (var element in doc.Elements)
                {
                    if (fkPattern.IsMatch(element.Name))
                    {
                        sampled.IdLikeFields.Add(element.Name);
                    }
                }
            }

            // Extract ID-like field values
            foreach (var field in sampled.IdLikeFields)
            {
                var values = docs
                    .Where(d => d.Contains(field))
                    .Select(d => Util.NormalizeId(d.GetValue(field)))
                    .Where(v => v is not null)
                    .Select(v => v!)
                    .ToHashSet();

                sampled.IdLikeFieldValues[field] = values;
            }

            result[name] = sampled;
        }

        return result;
    }

    /// <summary>
    /// Gets field relationships for a specific collection in the specified database.
    /// </summary>
    /// <param name="databaseName"></param>
    /// <returns></returns>
    public async Task<Dictionary<string, List<string>>> GetFieldRelationshipsAsync(string databaseName)
    {
        var samples = await SampleCollectionsAsync(databaseName);

        return samples.ToDictionary(
            kvp => kvp.Key,
            kvp => kvp.Value.IdLikeFields.ToList()
        );

    }

    /// <summary>
    /// Gets all relationships by comparing ID-like fields to actual _id values across collections in the specified database.
    /// </summary>
    /// <param name="databaseName"></param>
    /// <returns></returns>
    public async Task<List<Relationship>> GetRelationshipsAsync(string databaseName)
    {
        var samples = await SampleCollectionsAsync(databaseName);
        var relationships = new List<Relationship>();

        foreach (var source in samples.Values)
        {
            foreach (var fkField in source.IdLikeFields)
            {
                if (fkField == "_id")
                    continue;

                if (!source.IdLikeFieldValues.TryGetValue(fkField, out var fkValues))
                    continue;

                if (fkValues.Count == 0)
                    continue;

                foreach (var target in samples.Values)
                {
                    if (source.Name == target.Name)
                        continue;

                    if (target.Name.StartsWith("embedded_"))
                        continue;

                    var targetIds = target.PrimaryKeyValues;

                    var matches = fkValues.Intersect(targetIds).Count();
                    if (matches == 0)
                        continue;

                    var confidence = (double)matches / fkValues.Count;
                    if (confidence < 0.01)
                        continue;

                    relationships.Add(new Relationship
                    {
                        FromCollection = source.Name,
                        ToCollection = target.Name,
                        FieldName = fkField,
                        Confidence = confidence
                    });
                }
            }
        }

        return relationships;

    }
   
    public async Task<List<CollectionSchema>> AnalyzeCollectionsAsync(string databaseName)
    {
        var samples = await SampleCollectionsAsync(databaseName);
        var result = new List<CollectionSchema>();

        foreach (var kvp in samples)
        {
            var name = kvp.Key;
            var sample = kvp.Value;
            var docs = sample.Documents;

            if (docs.Count == 0)
            {
                result.Add(new CollectionSchema
                {
                    Name = name,
                    PrimaryKey = "_id"
                });
                continue;
            }

            var schema = new CollectionSchema
            {
                Name = name,
                PrimaryKey = sample.PrimaryKeyField ?? "_id"
            };

            foreach (var doc in docs)
            {
                foreach (var el in doc.Elements)
                {
                    var field = el.Name;

                    if (!schema.Fields.ContainsKey(field))
                        schema.Fields[field] = el.Value.BsonType;

                    if (!schema.Nullability.ContainsKey(field))
                        schema.Nullability[field] = false;

                    if (el.Value.IsBsonNull)
                        schema.Nullability[field] = true;

                    if (!schema.SampleValues.ContainsKey(field))
                        schema.SampleValues[field] = new List<string>();

                    var normalized = Util.NormalizeId(el.Value);
                    if (normalized != null && schema.SampleValues[field].Count < 20)
                        schema.SampleValues[field].Add(normalized);
                }
            }

            schema.Nullability[schema.PrimaryKey] = false;
            schema.IsEmbedded = name.StartsWith("embedded_");

            result.Add(schema);
        }

        return result;
    }

    
    [GeneratedRegex(@"(.+?)(_id|Id)$", RegexOptions.IgnoreCase, "en-US")]
    private static partial Regex MyRegex();

}

public class SampledCollection
{
    public string Name { get; set; } = "";
    public List<BsonDocument> Documents { get; set; } = new();
    public HashSet<string> IdLikeFields { get; set; } = new();
    public Dictionary<string, HashSet<string>> IdLikeFieldValues { get; set; } = new();
    public string? PrimaryKeyField { get; set; }
    public HashSet<string> PrimaryKeyValues { get; set; } = new();
}