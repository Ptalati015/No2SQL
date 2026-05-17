# No2SQL

No2SQL is an MCP server and NuGet package that helps you move from MongoDB to SQL by:

- discovering collections and relationship candidates,
- generating SQL schema scripts,
- generating SQL seed (INSERT) statements,
- producing ER diagrams in Mermaid, PlantUML, and GraphViz DOT formats.

## Who This Is For

- Teams migrating from MongoDB to relational databases
- Engineers documenting NoSQL structures in ERD form
- AI-assisted workflows where Copilot can call data-migration tools through MCP

## Quick Start

### 1. Configure MongoDB connection

Set your MongoDB connection string with either:

1. Environment variable `NO2SQL_MONGO` (recommended)
2. `No2SQL/appsettings.json` connection string `ConnectionStrings:MongoDb`

Example format:

```text
mongodb+srv://<username>:<password>@<cluster-host>/<database>?retryWrites=true&w=majority
```

### 2. Add No2SQL as an MCP server

For VS Code, create `.vscode/mcp.json`:

```json
{
	"servers": {
		"No2SQL": {
			"type": "stdio",
			"command": "dnx",
			"args": [
				"No2SQL",
				"--version",
				"0.1.0",
				"--yes"
			]
		}
	}
}
```

For local development from source (instead of NuGet package):

```json
{
	"servers": {
		"No2SQL": {
			"type": "stdio",
			"command": "dotnet",
			"args": [
				"run",
				"--project",
				"No2SQL"
			]
		}
	}
}
```

### 3. Try it in Copilot Chat

Example prompts:

- "Use No2SQL to list my MongoDB databases."
- "Infer relationships for database mydb."
- "Generate SQL schema for database mydb."
- "Generate Mermaid ERD for mydb using SQL source."
- "Generate SQL INSERT statements for collection orders in mydb."

## MCP Tools Exposed

- `TestConnectivity`: Verify MCP server connectivity.
- `ListDatabases`: List available databases (respects allowlist policy).
- `ListInferredRelationships`: List ID-like fields by collection.
- `CompareIdFieldsToIds`: Infer relationships by matching ID-like fields to `_id` values.
- `GenerateSqlSchema`: Generate SQL schema from inferred relationships.
- `GenerateSqlSchemaAdvanced`: Generate SQL schema with optional relationship overrides.
- `GenerateSeedersForCollection`: Generate SQL INSERT seed statements for one collection.
- `GenerateErdMermaid`: Generate Mermaid ERD (`source`: `sql`, `mongo`, `auto`).
- `GenerateErdPlantUml`: Generate PlantUML ERD (`source`: `sql`, `mongo`, `auto`).
- `GenerateErdDot`: Generate GraphViz DOT ERD (`source`: `sql`, `mongo`, `auto`).

## Security Guardrails

No2SQL includes input validation and database access guardrails.

Environment variables:

- `NO2SQL_ALLOWED_DATABASES`: Optional comma-separated database allowlist.
- `NO2SQL_BLOCK_SYSTEM_DATABASES`: Defaults to `true`; blocks `admin`, `config`, `local`.

Tool inputs are validated for:

- identifier format and length,
- diagram source values (`sql`, `mongo`, `auto`),
- relationship override fields,
- prompt-injection style marker patterns.

Recommended production baseline:

1. Set `NO2SQL_ALLOWED_DATABASES` to a strict allowlist.
2. Keep `NO2SQL_BLOCK_SYSTEM_DATABASES=true`.

## Build, Test, Publish

Build solution:

```bash
dotnet build No2SQL.sln
```

Run test harness:

```bash
dotnet run --project No2SQL.Test
```

Pack NuGet:

```bash
dotnet pack -c Release
```

Publish NuGet package:

```bash
dotnet nuget push artifacts/release/*.nupkg --api-key <your-api-key> --source https://api.nuget.org/v3/index.json
```

## Local Test Defaults

`No2SQL.Test/Program.cs` supports environment variable overrides:

- `NO2SQL_TEST_DATABASE`: Database used when none is supplied.
- `NO2SQL_TEST_COLLECTION`: Collection used by `--test-stream` when none is supplied.
- `NO2SQL_TEST_ROWS_PER_CHUNK`: Optional chunk-size override for stream seeder checks.
- `NO2SQL_TEST_LIMIT`: Optional max document count override for stream seeder checks.
- `NO2SQL_TEST_BATCH_SIZE`: Optional Mongo cursor batch size override for stream seeder checks.

CLI arguments take precedence over environment variables.

## Contributions

Forks and derivative works are welcome under the MIT License.

Changes to the official No2SQL repository are accepted at the maintainer's discretion.
Submitting a pull request does not guarantee inclusion.

## License

No2SQL is licensed under the MIT License.

Copyright (c) 2026 Preet Talati

"No2SQL" is a trademark of Preet Talati.
