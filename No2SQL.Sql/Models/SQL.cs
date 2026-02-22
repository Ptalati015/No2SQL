namespace No2SQL.Sql.Models
{

    public class SqlSchemaOutput
    {
        public List<SqlTableDefinition> Tables { get; set; } = new();
        public List<SqlForeignKeyDefinition> ForeignKeys { get; set; } = new();
        public List<SqlIndexDefinition> Indexes { get; set; } = new();
        public string FullScript { get; set; }
    }

    public class SqlTableDefinition
    {
        public string TableName { get; set; }
        public List<SqlColumnDefinition> Columns { get; set; } = new();
        public string PrimaryKey { get; set; }
        public string CreateTableSql { get; set; }
    }

    public class SqlColumnDefinition
    {
        public string Name { get; set; }
        public string SqlType { get; set; }
        public bool IsNullable { get; set; }
    }

    public class SqlForeignKeyDefinition
    {
        public string FromTable { get; set; }
        public string FromColumn { get; set; }
        public string ToTable { get; set; }
        public string ToColumn { get; set; }
        public string ConstraintName { get; set; }
        public string Sql { get; set; }
    }

    public class SqlIndexDefinition
    {
        public string Table { get; set; }
        public string Column { get; set; }
        public string IndexName { get; set; }
        public string Sql { get; set; }
    }
}