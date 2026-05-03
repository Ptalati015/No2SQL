namespace No2SQL.Sql.Models
{

    public class SqlSchemaOutput
    {
        public List<SqlTableDefinition> Tables { get; set; } = new();
        public List<SqlForeignKeyDefinition> ForeignKeys { get; set; } = new();
        public List<SqlIndexDefinition> Indexes { get; set; } = new();
        public string FullScript { get; set; } = string.Empty;
        public string? ErrorMessage { get; set; }
    }

    public class SqlTableDefinition
    {
        public string TableName { get; set; } = string.Empty;
        public List<SqlColumnDefinition> Columns { get; set; } = new();
        public string PrimaryKey { get; set; } = string.Empty;
        public string CreateTableSql { get; set; } = string.Empty;
    }

    public class SqlColumnDefinition
    {
        public string Name { get; set; } = string.Empty;
        public string SqlType { get; set; } = string.Empty;
        public bool IsNullable { get; set; }
    }

    public class SqlForeignKeyDefinition
    {
        public string FromTable { get; set; } = string.Empty;
        public string FromColumn { get; set; } = string.Empty;
        public string ToTable { get; set; } = string.Empty;
        public string ToColumn { get; set; } = string.Empty;
        public string ConstraintName { get; set; } = string.Empty;
        public string Sql { get; set; } = string.Empty;
    }

    public class SqlIndexDefinition
    {
        public string Table { get; set; } = string.Empty;
        public string Column { get; set; } = string.Empty;
        public string IndexName { get; set; } = string.Empty;
        public string Sql { get; set; } = string.Empty;
    }
}