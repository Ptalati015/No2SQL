using MongoDB.Bson;
using MongoDB.Driver;
using System.Collections.Generic;
using System.Threading.Tasks;


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


}
