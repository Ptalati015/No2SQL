

using System;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using No2SQL.Core;

namespace No2SQL.Core.Helpers.Deprecated
{
    // This file contains deprecated helper methods that are no longer used in the main codebase.
    // They are kept here for reference and potential future use, but should not be called from anywhere else.
    // Please do not add new code to this file. Instead, create new helper methods in the appropriate places in the main codebase.
    public class DeprecatedHelper
    {
        public async Task<Dictionary<string, List<string>>> GetFieldRelationshipsAsync(string databaseName)
        {
            // var samples = await SampleCollectionsAsync(databaseName);

            // return samples.ToDictionary(
            //     kvp => kvp.Key,
            //     kvp => kvp.Value.IdLikeFields.ToList()
            // );
            return null;
        }

        public async Task<Dictionary<string, List<string>>> GetAllPrimaryKeysAsync(string databaseName)
        {
            // var samples = await SampleCollectionsAsync(databaseName);

            // return samples.ToDictionary(
            //     kvp => kvp.Key,
            //     kvp => kvp.Value.PrimaryKeyValues.ToList()
            // );
            return null;
        }

        private async Task<Dictionary<string, HashSet<string>>> GetAllIdLikeFieldsAsync(string databaseName)
        {
            // var samples = await SampleCollectionsAsync(databaseName);

            // return samples.ToDictionary(
            //     kvp => kvp.Key,
            //     kvp => kvp.Value.IdLikeFields
            // );
            return null;
        }

        private async Task<Dictionary<string, Dictionary<string, List<string>>>> GetAllIdLikeFieldValuesAsync(string databaseName)
        {
            // var samples = await SampleCollectionsAsync(databaseName);

            // return samples.ToDictionary(
            //     kvp => kvp.Key,
            //     kvp => kvp.Value.IdLikeFieldValues
            //         .ToDictionary(f => f.Key, f => f.Value.ToList())
            // );
            return null;
        }
    }
}