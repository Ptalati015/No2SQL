# No2SQL

No2SQL is an MCP server and NuGet package that helps you move from MongoDB to SQL by:

- discovering collections and relationship candidates,
- generating SQL schema scripts,
- generating SQL seed (INSERT) statements,
- producing ER diagrams in Mermaid, PlantUML, and GraphViz DOT formats.

---

## Who This Is For

- Teams migrating from MongoDB to relational databases
- Engineers documenting NoSQL structures in ERD form
- AI-assisted workflows where Copilot can call data-migration tools through MCP

---

## Quick Start

### 1. Configure MongoDB connection

Set your MongoDB connection string via the environment variable `NO2SQL_MONGO` (recommended).

Example format:

```
mongodb+srv://<username>:<password>@<cluster-host>/<database>?retryWrites=true&w=majority
```

You can also set it via `No2SQL/appsettings.json` under `ConnectionStrings:MongoDb`.

---

## Installing the No2SQL MCP Server

The No2SQL MCP server is distributed as a standalone executable inside a NuGet package.  
**You do NOT need .NET installed and you do NOT need a .NET project.**

### 1. Download the package

**Option A — Using curl**
```bash
curl -L https://www.nuget.org/api/v2/package/No2SQL/1.0.3 -o No2SQL.1.0.3.nupkg
```

**Option B — Using PowerShell**
```powershell
Invoke-WebRequest https://www.nuget.org/api/v2/package/No2SQL/1.0.3 -OutFile No2SQL.1.0.3.nupkg
```

**Option C — Download manually**  
Visit https://www.nuget.org/packages/No2SQL and click **Download package**.

### 2. Extract the package

A `.nupkg` is a ZIP archive:

```bash
unzip No2SQL.1.0.3.nupkg -d no2sql
```

Executables will be located under:

```
/tools/win-x64/No2SQL.exe
/tools/linux-x64/No2SQL
/tools/osx-arm64/No2SQL
```

### 3. Configure your MCP client

> ⚠️ **Important:** Always include the `env` block with your MongoDB connection string. Without it, the server starts but cannot reach your database and tools will silently fail.

#### VS Code (recommended)

Add to your **User Settings JSON** (`Ctrl+Shift+P` → *Open User Settings (JSON)*):

```json
"mcp.servers": {
  "no2sql": {
    "command": "path/to/no2sql/tools/win-x64/No2SQL.exe",
    "env": {
      "NO2SQL_MONGO": "your-mongodb-connection-string",
      "NO2SQL_BLOCK_SYSTEM_DATABASES": "true"
    }
  }
}
```

Alternatively, VS Code will create a dedicated `mcp.json` file (at `%APPDATA%\Code\User\mcp.json` on Windows). If you use that route, make sure to add the `env` block there too:

```json
{
  "servers": {
    "no2sql": {
      "type": "stdio",
      "command": "path/to/no2sql/tools/win-x64/No2SQL.exe",
      "args": [],
      "env": {
        "NO2SQL_MONGO": "your-mongodb-connection-string",
        "NO2SQL_BLOCK_SYSTEM_DATABASES": "true"
      }
    }
  },
  "inputs": []
}
```

After saving, reload the window: `Ctrl+Shift+P` → **Developer: Reload Window**.

#### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "no2sql": {
      "command": "path/to/no2sql/tools/win-x64/No2SQL.exe",
      "env": {
        "NO2SQL_MONGO": "your-mongodb-connection-string",
        "NO2SQL_BLOCK_SYSTEM_DATABASES": "true"
      }
    }
  }
}
```

#### GitHub Copilot MCP

```json
{
  "mcpServers": {
    "no2sql": {
      "command": "path/to/no2sql/tools/win-x64/No2SQL.exe",
      "env": {
        "NO2SQL_MONGO": "your-mongodb-connection-string",
        "NO2SQL_BLOCK_SYSTEM_DATABASES": "true"
      }
    }
  }
}
```

---

### 4. Verify the server is registered (VS Code)

After reloading, open the Command Palette (`Ctrl+Shift+P`) and run **MCP: List Servers**.  
You should see `no2sql` listed. If it doesn't appear, double-check the executable path and that your settings were saved to the correct file.

### 5. Test it in Copilot Chat

1. Open **Copilot Chat** in VS Code
2. Click the **tools icon** (plug or hammer icon) at the bottom of the chat input
3. Confirm `no2sql` appears in the tools list and is enabled
4. Type a prompt — Copilot will route it through No2SQL automatically:

```
Use No2SQL to list my MongoDB databases.
```

If the tools icon shows `no2sql` and the prompt returns your database list, you're fully set up.

**More example prompts:**

```
Infer relationships for database mydb.
Generate SQL schema for database mydb.
Generate Mermaid ERD for mydb using SQL source.
Generate SQL INSERT statements for collection orders in mydb.
```

---

## MCP Tools Exposed

| Tool | Description |
|------|-------------|
| `TestConnectivity` | Verify MCP server connectivity |
| `ListDatabases` | List available databases (respects allowlist policy) |
| `ListInferredRelationships` | List ID-like fields by collection |
| `CompareIdFieldsToIds` | Infer relationships by matching ID-like fields to `_id` values |
| `GenerateSqlSchema` | Generate SQL schema from inferred relationships |
| `GenerateSqlSchemaAdvanced` | Generate SQL schema with optional relationship overrides |
| `GenerateSeedersForCollection` | Generate SQL INSERT seed statements for one collection |
| `GenerateErdMermaid` | Generate Mermaid ERD (source: sql, mongo, auto) |
| `GenerateErdPlantUml` | Generate PlantUML ERD (source: sql, mongo, auto) |
| `GenerateErdDot` | Generate GraphViz DOT ERD (source: sql, mongo, auto) |

---

## Security Guardrails

No2SQL includes input validation and database access guardrails.

**Environment variables:**

- `NO2SQL_ALLOWED_DATABASES` — optional comma-separated database allowlist
- `NO2SQL_BLOCK_SYSTEM_DATABASES` — defaults to `true`; blocks `admin`, `config`, `local`

**Tool inputs are validated for:**

- identifier format and length
- diagram source values (`sql`, `mongo`, `auto`)
- relationship override fields
- prompt-injection style marker patterns

**Recommended production baseline:**

- Set `NO2SQL_ALLOWED_DATABASES` to a strict allowlist
- Keep `NO2SQL_BLOCK_SYSTEM_DATABASES=true`

---

## Build, Test, Publish

**Build solution:**
```bash
dotnet build No2SQL.sln
```

**Run test harness:**
```bash
dotnet run --project No2SQL.Test
```

**Pack NuGet:**
```bash
dotnet pack -c Release
```

**Publish NuGet package:**
```bash
dotnet nuget push **/bin/Release/*.nupkg --api-key <your-api-key> --source https://api.nuget.org/v3/index.json
```

---

## Local Test Defaults

`No2SQL.Test/Program.cs` supports environment variable overrides:

| Variable | Description |
|----------|-------------|
| `NO2SQL_TEST_DATABASE` | Database used when none is supplied |
| `NO2SQL_TEST_COLLECTION` | Collection used by `--test-stream` when none is supplied |
| `NO2SQL_TEST_ROWS_PER_CHUNK` | Optional chunk-size override for stream seeder checks |
| `NO2SQL_TEST_LIMIT` | Optional max document count override for stream seeder checks |
| `NO2SQL_TEST_BATCH_SIZE` | Optional Mongo cursor batch size override for stream seeder checks |

CLI arguments take precedence over environment variables.

---

## Contributions

Forks and derivative works are welcome under the MIT License.

Changes to the official No2SQL repository are accepted at the maintainer's discretion. Submitting a pull request does not guarantee inclusion.

---

## License

No2SQL is licensed under the MIT License.

Copyright (c) 2026 Preet Talati

"No2SQL" is a trademark of Preet Talati.