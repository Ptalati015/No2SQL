using MongoDB.Bson;
using MongoDB.Driver;
using No2SQL.Core.Models;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using No2SQL.Utils;
using System.Security.Cryptography.X509Certificates;
namespace No2SQL.Core;


public class SchemaAnalyzer
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
            
            } catch(Exception ex)
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
        public async Task<List<Relationship>> FindForeignKeysAsync(string databaseName) {
            var db = _client.GetDatabase(databaseName);

            // Get all collections
            var collections = await db.ListCollectionNamesAsync();
            var collectionNames = await collections.ToListAsync();

            // Preload sample documents for each collection
            var samples = new Dictionary<string, List<BsonDocument>>();
            foreach (var name in collectionNames)
            {
                var col = db.GetCollection<BsonDocument>(name);
                samples[name] = await col.Find(FilterDefinition<BsonDocument>.Empty)
                                        .Limit(200)
                                        .ToListAsync();
            }

            var relationships = new List<Relationship>();
            var fkPattern = new Regex(@"(.+?)(_id|Id)$", RegexOptions.IgnoreCase);

            foreach (var sourceCollection in collectionNames)
            {
                foreach (var doc in samples[sourceCollection])
                {
                    foreach (var element in doc.Elements)
                    {
                        var match = fkPattern.Match(element.Name);
                        if (!match.Success) continue;

                        var fkPrefix = match.Groups[1].Value; // e.g. "movie" from "movie_id"
                        var normalizedFk = Util.Singularize(fkPrefix.ToLower());

                        foreach (var targetCollection in collectionNames)
                        {
                            var normalizedTarget = Util.Singularize(targetCollection.ToLower());    
                            // Check naming match
                            if (normalizedFk != normalizedTarget)
                                continue;

                            // Validate by sampling referenced IDs
                            var fkValues = samples[sourceCollection]
                                .Select(d => d.GetValue(element.Name, BsonNull.Value))
                                .Where(v => !v.IsBsonNull)
                                .Take(50)
                                .Select(v => Util.NormalizeId(v))
                                .ToHashSet();

                            var targetIds = samples[targetCollection]
                                .Select(d => Util.NormalizeId(d.GetValue("_id", BsonNull.Value)))
                                .Where(v => v != null)
                                .ToHashSet();

                            var matches = fkValues.Intersect(targetIds).Count();
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
        public async Task<Dictionary<string, HashSet<string>>> GetAllIdLikeFieldsAsync(string databaseName) {
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
        /// Compares Id Like fields to actual _id values to infer relationships in the specified database.
        /// </summary>
        /// <param name="databaseName"></param>
        /// <returns></returns>
    //     public async Task<List<Relationship>> InferRelationshipsAsync(string databaseName)
    //     {
    //         var relationships = new List<Relationship>();

    //         var idLikeFields = await GetAllIdLikeFieldsAsync(databaseName);
    //         var db = _client.GetDatabase(databaseName);

    //         foreach (var sourceCollectionName in idLikeFields.Keys)
    //         {
    //             var fkFields = idLikeFields[sourceCollectionName];
    //             if (!fkFields.Any()) continue;

    //             var sourceCollection = db.GetCollection<BsonDocument>(sourceCollectionName);

    //             // Sample source documents
    //             var sampleDocs = await sourceCollection
    //                 .Find(FilterDefinition<BsonDocument>.Empty)
    //                 .Limit(300)
    //                 .ToListAsync();

    //             foreach (var fkField in fkFields)
    //             {
    //                 var fkValues = ExtractFkValues(sampleDocs, fkField);
    //                 if (fkValues.Count < 3) continue;

    //                 foreach (var targetCollectionName in await db.ListCollectionNames().ToListAsync())
    //                 {
    //                     if (targetCollectionName == sourceCollectionName) continue;
    //                     if (targetCollectionName.StartsWith("embedded_")) continue;

    //                     var targetCollection = db.GetCollection<BsonDocument>(targetCollectionName);

    //                     var filter = Builders<BsonDocument>.Filter.In("_id", fkValues);
    //                     var matchCount = await targetCollection.CountDocumentsAsync(filter);

    //                     if (matchCount == 0) continue;

    //                     var confidence = ComputeConfidence(matchCount, fkValues.Count);

    //                     relationships.Add(new Relationship
    //                     {
    //                         FromCollection = sourceCollectionName,
    //                         ToCollection = targetCollectionName,
    //                         FieldName = fkField,
    //                         Confidence = confidence,
    //                         Cardinality = InferCardinality(sampleDocs, fkField)
    //                     });
    //                 }
    //             }
    //         }

    //         return relationships;
    // }




      // Helper Methods 

      /// <summary>
      /// Gets all _id values for each collection in the specified database.
      /// </summary>
      /// <param name="databaseName"></param>
      /// <returns></returns>
      private async Task<Dictionary<string, List<string>>> GetAllIdsInDatabaseAsync(string databaseName) {
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
}
