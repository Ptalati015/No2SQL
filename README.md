# No2SQL

## License

No2SQL is licensed under the MIT License.

© 2026 Preet Talati

“No2SQL” is a trademark of Preet Talati.

## Description

No2SQL — An MCP server and NuGet package that transforms MongoDB/non-relational schemas into relational database models with ER diagrams and SQL scripts. Built with C# and secured with modern libraries, No2SQL bridges the gap between NoSQL and SQL for developers migrating or visualizing data structures.

## Contributions

Forks and derivative works are welcome under the MIT License.

However, modifications to the official No2SQL repository
will only be accepted at the sole discretion of the maintainer.

Submitting a pull request does not guarantee inclusion.

## Local Test Defaults

The repository test harness in `No2SQL.Test/Program.cs` supports environment-variable overrides so local sample defaults are configurable:

- `NO2SQL_TEST_DATABASE`: Database name used when no database argument is supplied.
- `NO2SQL_TEST_COLLECTION`: Collection name used by `--test-stream` when not passed as an argument.
- `NO2SQL_TEST_ROWS_PER_CHUNK`: Optional chunk-size override for stream seeder validation.
- `NO2SQL_TEST_LIMIT`: Optional max document count override for stream seeder validation.
- `NO2SQL_TEST_BATCH_SIZE`: Optional Mongo cursor batch size override for stream seeder validation.

CLI arguments still take precedence over environment variables.
