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

}
