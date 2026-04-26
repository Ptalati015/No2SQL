namespace No2SQL.Sql.Models
{
    public class UserRelationshipOverride
    {
        public string FromCollection { get; set; } = string.Empty;
        public string FromField { get; set; } = string.Empty;
        public string ToCollection { get; set; } = string.Empty;
        public string ToField { get; set; } = string.Empty;
    }
}
