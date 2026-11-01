using System.ComponentModel;

namespace No2SQL.Sql.Models
{
    public class UserRelationshipOverride
    {
        [Description("Collection that holds the reference field.")]
        public string FromCollection { get; set; } = string.Empty;
        [Description("Field in fromCollection that points to the other collection.")]
        public string FromField { get; set; } = string.Empty;
        [Description("Collection being referenced.")]
        public string ToCollection { get; set; } = string.Empty;
        [Description("Field in toCollection that is referenced, usually _id.")]
        public string ToField { get; set; } = string.Empty;
    }
}
