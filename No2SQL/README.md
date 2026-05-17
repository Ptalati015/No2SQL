# No2SQL MCP Server

No2SQL helps you analyze MongoDB databases and generate SQL-friendly outputs:

- inferred relationships,
- SQL schema scripts,
- SQL INSERT seed statements,
- ER diagrams in Mermaid, PlantUML, and GraphViz DOT.

## Install and Configure

### MongoDB connection

Set MongoDB connection string using either:

1. `NO2SQL_MONGO` environment variable (recommended)
2. `ConnectionStrings:MongoDb` in `No2SQL/appsettings.json`

Example format:

```text
mongodb+srv://<username>:<password>@<cluster-host>/<database>?retryWrites=true&w=majority
```

### Use from NuGet in VS Code

Create `.vscode/mcp.json`:

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

### Use from source during development

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

## Available MCP Tools

- `TestConnectivity`
- `ListDatabases`
- `ListInferredRelationships`
- `CompareIdFieldsToIds`
- `GenerateSqlSchema`
- `GenerateSqlSchemaAdvanced`
- `GenerateSeedersForCollection`
- `GenerateErdMermaid`
- `GenerateErdPlantUml`
- `GenerateErdDot`

## Example Copilot Prompts

- "Use No2SQL to list my databases."
- "Infer relationships for database mydb."
- "Generate SQL schema for mydb."
- "Generate Mermaid ERD for mydb with source sql."
- "Generate SQL seeders for collection orders in mydb."

## Security Guardrails

The server validates tool inputs and supports policy-based controls.

Environment variables:

- `NO2SQL_ALLOWED_DATABASES`: Optional comma-separated allowlist.
- `NO2SQL_BLOCK_SYSTEM_DATABASES`: Defaults to `true`; blocks `admin`, `config`, `local`.

Validation covers:

- `databaseName`
- `collectionName`
- `source` values (`sql`, `mongo`, `auto`)
- override fields (`fromCollection`, `fromField`, `toCollection`, `toField`)
- prompt-injection marker patterns

Recommended baseline:

1. Set a strict `NO2SQL_ALLOWED_DATABASES` allowlist.
2. Keep `NO2SQL_BLOCK_SYSTEM_DATABASES=true`.

## Build and Publish

Pack:

```bash
dotnet pack -c Release
```

Publish:

```bash
dotnet nuget push bin/Release/*.nupkg --api-key <your-api-key> --source https://api.nuget.org/v3/index.json
```

## References

- [Model Context Protocol docs](https://modelcontextprotocol.io/)
- [MCP servers in VS Code](https://code.visualstudio.com/docs/copilot/chat/mcp-servers)
- [MCP servers in Visual Studio](https://learn.microsoft.com/visualstudio/ide/mcp-servers)
