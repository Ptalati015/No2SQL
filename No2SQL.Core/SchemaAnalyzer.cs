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
            Console.Error.WriteLine($"Error in TestAnalyze: {ex.Message}\n{ex.StackTrace}");
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


    /// <summary>
    /// Finds potential foreign key relationships in the specified database based on naming conventions.
    /// </summary>
    /// <param name="databaseName"></param>
    /// <returns></returns>
    public async Task<List<Relationship>> FindForeignKeysAsync(string databaseName)
    {
        var db = _client.GetDatabase(databaseName);

        // Get all collections
        var collections = await db.ListCollectionNamesAsync();
        var collectionNames = await collections.ToListAsync();

        // Precompute cache per collection
        var cache = new Dictionary<string, CollectionCache>();
        foreach (var name in collectionNames)
        {
            var col = db.GetCollection<BsonDocument>(name);
            var docs = await col.Find(FilterDefinition<BsonDocument>.Empty)
                                .Limit(200)
                                .ToListAsync();

            cache[name] = new CollectionCache
            {
                NormalizedName = Util.Singularize(name.ToLower()),
                Samples = docs,
                TargetIds = docs
                    .Select(d => Util.NormalizeId(d.GetValue("_id", BsonNull.Value)))
                    .Where(v => v != null)
                    .ToHashSet()
            };
        }

        var relationships = new List<Relationship>();
        var fkPattern = MyRegex();

        // FK inference using cached data
        foreach (var sourceCollection in collectionNames)
        {
            var source = cache[sourceCollection];

            foreach (var doc in source.Samples)
            {
                foreach (var element in doc.Elements)
                {
                    var match = fkPattern.Match(element.Name);
                    if (!match.Success) continue;

                    var fkPrefix = match.Groups[1].Value;
                    var normalizedFk = Util.Singularize(fkPrefix.ToLower());

                    foreach (var targetCollection in collectionNames)
                    {
                        var target = cache[targetCollection];

                        // Naming match
                        if (normalizedFk != target.NormalizedName)
                            continue;

                        // Sample FK values
                        var fkValues = source.Samples
                            .Select(d => d.GetValue(element.Name, BsonNull.Value))
                            .Where(v => !v.IsBsonNull)
                            .Take(50)
                            .Select(v => Util.NormalizeId(v))
                            .ToHashSet();

                        var matches = fkValues.Intersect(target.TargetIds).Count();
                        var confidence = (double)matches / Math.Max(1, fkValues.Count);

                        if (matches > 0)
                        {
                            relationships.Add(new Relationship
                            {
                                FromCollection = sourceCollection,
                                ToCollection = targetCollection,
                                FieldName = element.Name,
                                Confidence = confidence
                            });
                        }
                    }
                }
            }
        }

        return relationships;
    }
    /// <summary>
    /// Gets all fields that look like foreign keys (ending with _id, Id, or ID) in each collection of the specified database.
    /// </summary>
    /// <param name="databaseName"></param>
    /// <returns></returns>
    public async Task<Dictionary<string, HashSet<string>>> GetAllIdLikeFieldsAsync(string databaseName)
    {
        var db = _client.GetDatabase(databaseName);

        var result = new Dictionary<string, HashSet<string>>();
        var fkPattern = new Regex(@"(.+?)(_id|Id|ID)$", RegexOptions.IgnoreCase);

        var collections = await db.ListCollectionNamesAsync();
        var collectionNames = await collections.ToListAsync();

        foreach (var collectionName in collectionNames)
        {
            var fields = new HashSet<string>();
            var collection = db.GetCollection<BsonDocument>(collectionName);

            var sampleDocs = await collection.Find(FilterDefinition<BsonDocument>.Empty)
                                            .Limit(200)
                                            .ToListAsync();

            foreach (var doc in sampleDocs)
            {
                foreach (var element in doc.Elements)
                {
                    if (fkPattern.IsMatch(element.Name))
                    {
                        fields.Add(element.Name);
                    }
                }
            }

            result[collectionName] = fields;
        }

        return result;
    }


    /// <summary>
    /// Gets all values for fields that look like foreign keys (ending with _id, Id, or ID) in each collection of the specified database.
    /// </summary>
    /// <param name="databaseName"></param>
    /// <returns> A dictionary where the keys are collection names and the values are dictionaries mapping field names to lists of their values. </returns>
    public async Task<Dictionary<string, Dictionary<string, List<string>>>> GetAllIdLikeFieldValuesAsync(string databaseName)
    {
        var db = _client.GetDatabase(databaseName);

        var result = new Dictionary<string, Dictionary<string, List<string>>>();

        var idLikeFields = await GetAllIdLikeFieldsAsync(databaseName);

        foreach (var collectionName in idLikeFields.Keys)
        {
            var fields = idLikeFields[collectionName];
            var collection = db.GetCollection<BsonDocument>(collectionName);

            var sampleDocs = await collection.Find(FilterDefinition<BsonDocument>.Empty)
                                            .Limit(500)
                                            .ToListAsync();

            var fieldValues = new Dictionary<string, List<string>>();

            foreach (var field in fields)
            {
                var values = sampleDocs
                    .Where(d => d.Contains(field))
                    .Select(d => Util.NormalizeId(d.GetValue(field)))
                    .Where(v => v != null)
                    .Distinct()
                    .ToList();

                fieldValues[field] = values;
            }

            result[collectionName] = fieldValues;
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
        var result = new Dictionary<string, List<string>>();

        var idLikeFields = await GetAllIdLikeFieldsAsync(databaseName);

        foreach (var kvp in idLikeFields)
        {
            var collectionName = kvp.Key;
            var fields = kvp.Value.ToList();

            result[collectionName] = fields;
        }

        return result;
    }

    /// <summary>
    /// Gets all relationships by comparing ID-like fields to actual _id values across collections in the specified database.
    /// </summary>
    /// <param name="databaseName"></param>
    /// <returns></returns>
    public async Task<List<Relationship>> GetRelationshipsAsync(string databaseName)
    {
        var relationships = new List<Relationship>();

        // 1. Load all primary key values per collection
        var allIds = await GetAllPrimaryKeysAsync(databaseName);

        // // 2. Load all ID-like fields per collection
        // var idLikeFields = await GetAllIdLikeFieldsAsync(databaseName);

        // 3. Load all values for each ID-like field
        var idLikeFieldValues = await GetAllIdLikeFieldValuesAsync(databaseName);

        foreach (var sourceCollection in idLikeFieldValues.Keys)
        {
            var fields = idLikeFieldValues[sourceCollection];

            foreach (var fkField in fields.Keys)
            {
                // Skip self-id fields
                if (fkField == "_id")
                    continue;

                var fkValues = fields[fkField];
                if (fkValues.Count == 0)
                    continue;

                foreach (var targetCollection in allIds.Keys)
                {
                    // Skip self-relationships
                    if (sourceCollection == targetCollection)
                        continue;

                    // Skip embedded collections
                    if (targetCollection.StartsWith("embedded_"))
                        continue;

                    var targetIds = allIds[targetCollection];

                    // Count matches
                    var matches = fkValues.Intersect(targetIds).Count();
                    if (matches == 0)
                        continue;

                    // Compute confidence
                    double confidence = (double)matches / fkValues.Count;

                    // Skip weak matches (< 10%)
                    if (confidence < 0.01)
                        continue;

                    relationships.Add(new Relationship
                    {
                        FromCollection = sourceCollection,
                        ToCollection = targetCollection,
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
        var db = _client.GetDatabase(databaseName);
        var result = new List<CollectionSchema>();

        var collections = await db.ListCollectionNamesAsync();
        var collectionNames = await collections.ToListAsync();

        foreach (var collectionName in collectionNames)
        {
            var collection = db.GetCollection<BsonDocument>(collectionName);

            var docs = await collection.Find(FilterDefinition<BsonDocument>.Empty)
                                       .Limit(300)
                                       .ToListAsync();

            if (docs.Count == 0)
            {
                result.Add(new CollectionSchema
                {
                    Name = collectionName,
                    PrimaryKey = "_id"
                });
                continue;
            }

            var schema = new CollectionSchema
            {
                Name = collectionName,
                PrimaryKey = Util.DetectPrimaryKeyField(docs[0])
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

            // PK must be NOT NULL
            schema.Nullability[schema.PrimaryKey] = false;

            // Mark embedded collections
            schema.IsEmbedded = collectionName.StartsWith("embedded_");

            result.Add(schema);
        }

        return result;
    }
    // Helper Methods 

    /// <summary>
    /// Gets all _id values for each collection in the specified database.
    /// </summary>
    /// <param name="databaseName"></param>
    /// <returns></returns>
    private async Task<Dictionary<string, List<string>>> GetAllIdsInDatabaseAsync(string databaseName)
    {
        var db = _client.GetDatabase(databaseName);
        var result = new Dictionary<string, List<string>>();

        var collections = await db.ListCollectionNamesAsync();
        var collectionNames = await collections.ToListAsync();

        foreach (var collectionName in collectionNames)
        {
            var ids = new List<string>();
            var collection = db.GetCollection<BsonDocument>(collectionName);

            var cursor = await collection.Find(FilterDefinition<BsonDocument>.Empty).ToCursorAsync();
            while (await cursor.MoveNextAsync())
            {
                foreach (var doc in cursor.Current)
                {
                    var idValue = doc.GetValue("_id", BsonNull.Value);
                    if (!idValue.IsBsonNull)
                    {
                        ids.Add(Util.NormalizeId(idValue));
                    }
                }
            }

            result[collectionName] = ids;
        }

        return result;
    }

    public async Task<Dictionary<string, List<string>>> GetAllPrimaryKeysAsync(string databaseName)
    {
        var db = _client.GetDatabase(databaseName);
        var result = new Dictionary<string, List<string>>();

        var collections = await db.ListCollectionNamesAsync();
        var collectionNames = await collections.ToListAsync();

        foreach (var collectionName in collectionNames)
        {
            var collection = db.GetCollection<BsonDocument>(collectionName);
            var docs = await collection.Find(FilterDefinition<BsonDocument>.Empty)
                                    .Limit(1000)
                                    .ToListAsync();

            if (docs.Count == 0)
            {
                result[collectionName] = new List<string>();
                continue;
            }

            var pkField = Util.DetectPrimaryKeyField(docs[0]);
            if (pkField == null)
            {
                result[collectionName] = new List<string>();
                continue;
            }

            var values = docs
                .Where(d => d.Contains(pkField))
                .Select(d => Util.NormalizeId(d.GetValue(pkField)))
                .Where(v => v != null)
                .Distinct()
                .ToList();

            result[collectionName] = values;
        }

        return result;
    }

    [GeneratedRegex(@"(.+?)(_id|Id)$", RegexOptions.IgnoreCase, "en-US")]
    private static partial Regex MyRegex();
}

internal class CollectionCache
{
    public string NormalizedName { get; set; }
    public List<BsonDocument> Samples { get; set; }
    public HashSet<string> TargetIds { get; set; }
}