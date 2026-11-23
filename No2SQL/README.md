# No2SQL MCP Server

<!-- mcp-name: io.github.Ptalati015/no2sql -->

No2SQL is an MCP server that helps you move from MongoDB to SQL. It lets your AI assistant:

- discover collections and likely relationships,
- generate SQL schema scripts,
- generate SQL seed (INSERT) statements,
- draw ER diagrams in Mermaid, PlantUML and GraphViz DOT.

It works with any AI client that runs local MCP servers, including Claude Desktop, Claude Code, VS Code, Cursor, Windsurf, OpenAI Codex CLI and the OpenAI Agents SDK.

## Install

No2SQL is a local MCP server. Your AI client starts it on your own machine and talks to it over stdio. There are two ways to install it.

### Option A: download the zip (no .NET needed)

1. Download the zip for your platform from the [v1.1.2 release](https://github.com/Ptalati015/No2SQL/releases/tag/v1.1.2):

   | Platform | File |
   |---|---|
   | Windows x64 | `No2SQL-1.1.2-win-x64.zip` |
   | Windows ARM64 | `No2SQL-1.1.2-win-arm64.zip` |
   | macOS Apple silicon | `No2SQL-1.1.2-osx-arm64.zip` |
   | macOS Intel | `No2SQL-1.1.2-osx-x64.zip` |
   | Linux x64 | `No2SQL-1.1.2-linux-x64.zip` |
   | Linux ARM64 | `No2SQL-1.1.2-linux-arm64.zip` |

   Also download `SHA256SUMS.txt` from the same release.

2. Verify the download (recommended). Run this in the folder that holds both files:

   ```bash
   # Linux
   sha256sum -c SHA256SUMS.txt --ignore-missing

   # macOS
   shasum -a 256 -c SHA256SUMS.txt --ignore-missing
   ```

   ```powershell
   # Windows: compare the output with the matching line in SHA256SUMS.txt
   (Get-FileHash .\No2SQL-1.1.2-win-x64.zip -Algorithm SHA256).Hash
   ```

   Every release also has a build provenance attestation. If you have the [GitHub CLI](https://cli.github.com/), you can check that the zip was built by this repository's release workflow. Sign in with `gh auth login` first:

   ```bash
   gh attestation verify No2SQL-1.1.2-<platform>.zip --repo Ptalati015/No2SQL
   ```

3. macOS only: the exe is not notarized, so Gatekeeper blocks it the first time. Clear the quarantine flag on the one file you downloaded, before you unzip it:

   ```bash
   xattr -d com.apple.quarantine No2SQL-1.1.2-osx-arm64.zip
   ```

   If you already unzipped it, run the same command on the exe instead (`xattr -d com.apple.quarantine /path/to/No2SQL`). Don't turn Gatekeeper off.

4. Unzip it somewhere permanent, such as `~/tools/no2sql` or `C:\tools\no2sql`. The zip holds one file to run, `No2SQL` (`No2SQL.exe` on Windows), next to `LICENSE`, `NOTICE` and `TRADEMARK.md`. On Linux and macOS it is already executable.

Your client config uses the **absolute path** to that file as its `command`, with no `args`.

### Option B: run it with `dnx` (.NET 10 SDK)

If you have the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0), `dnx` downloads No2SQL from NuGet and runs it, so there is nothing to unzip:

```bash
dnx No2SQL@1.1.2 --yes
```

You don't run this yourself. Your client config uses `dnx` as its `command` and `["No2SQL@1.1.2", "--yes"]` as its `args`. If a client says it can't find `dnx` (Claude Desktop on macOS often starts with a short `PATH`), use the full path from `which dnx` (or `where dnx` on Windows).

## Configure

No2SQL reads these environment variables. Set them in your MCP client's `env` config, as the examples below show. Never pass the connection string as a command-line argument.

| Variable | Required | What it does |
|---|---|---|
| `NO2SQL_MONGO` | Yes | MongoDB connection string, for example `mongodb+srv://<user>:<password>@<cluster-host>/`. It contains credentials, so treat it as a secret. |
| `NO2SQL_ALLOWED_DATABASES` | Recommended | Comma-separated list of the databases No2SQL may read, for example `sales,inventory`. If it is empty, every database is readable except the system ones. |
| `NO2SQL_BLOCK_SYSTEM_DATABASES` | No | Defaults to `true`, which blocks `admin`, `config` and `local` and hides them from `list_databases`, even if they are in `NO2SQL_ALLOWED_DATABASES`. Leave it on. |

Without `NO2SQL_MONGO` the server still starts, lists its tools and answers `test_connectivity`. Every other tool returns an error saying that `NO2SQL_MONGO` is not set, and if the value isn't a valid MongoDB connection string, the error says that instead. Fix it in your client's `env` config and restart the server.

## Set up your AI client

Each example uses the zip install on macOS or Linux (`/Users/you/tools/no2sql/No2SQL`). Change the path to where you unzipped it. On Windows, escape the backslashes in JSON (`"C:\\tools\\no2sql\\No2SQL.exe"`).

**Using `dnx` instead?** Replace the `command` and `args` lines in any example with:

```json
"command": "dnx",
"args": ["No2SQL@1.1.2", "--yes"],
```

### Claude Desktop

Open **Settings → Developer → Edit Config**, or edit the file directly:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "no2sql": {
      "command": "/Users/you/tools/no2sql/No2SQL",
      "args": [],
      "env": {
        "NO2SQL_MONGO": "mongodb+srv://<user>:<password>@<cluster-host>/",
        "NO2SQL_ALLOWED_DATABASES": "mydb"
      }
    }
  }
}
```

Quit and reopen Claude Desktop. No2SQL's tools then appear in the tools menu of the chat box.

### Claude Code

Add a `.mcp.json` file to your project root. Claude Code expands `${NO2SQL_MONGO}` from your shell environment, so the file holds no secret and is safe to commit:

```json
{
  "mcpServers": {
    "no2sql": {
      "command": "/Users/you/tools/no2sql/No2SQL",
      "args": [],
      "env": {
        "NO2SQL_MONGO": "${NO2SQL_MONGO}",
        "NO2SQL_ALLOWED_DATABASES": "mydb"
      }
    }
  }
}
```

Set `NO2SQL_MONGO` in your shell profile (for example `~/.zshrc`), then start `claude` in that project and approve the server when asked. Check it with `claude mcp list`, or with `/mcp` inside a session. Never put the real connection string in a `.mcp.json` that you commit.

### VS Code (GitHub Copilot agent mode)

Needs VS Code 1.102 or later. Create `.vscode/mcp.json` in your workspace, or run **MCP: Open User Configuration** for all workspaces. VS Code asks for the connection string the first time the server starts and stores it securely, so it never sits in the file:

```json
{
  "inputs": [
    {
      "type": "promptString",
      "id": "no2sql-mongo",
      "description": "MongoDB connection string for No2SQL",
      "password": true
    }
  ],
  "servers": {
    "no2sql": {
      "type": "stdio",
      "command": "/Users/you/tools/no2sql/No2SQL",
      "args": [],
      "env": {
        "NO2SQL_MONGO": "${input:no2sql-mongo}",
        "NO2SQL_ALLOWED_DATABASES": "mydb"
      }
    }
  }
}
```

Run **MCP: List Servers** to start it, then open Copilot Chat in **Agent** mode and check that No2SQL's tools are enabled under the tools icon. Older guides show an `"mcp.servers"` block in `settings.json`; use `mcp.json` as shown here instead.

### Cursor

Edit `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one project):

```json
{
  "mcpServers": {
    "no2sql": {
      "command": "/Users/you/tools/no2sql/No2SQL",
      "args": [],
      "env": {
        "NO2SQL_MONGO": "mongodb+srv://<user>:<password>@<cluster-host>/",
        "NO2SQL_ALLOWED_DATABASES": "mydb"
      }
    }
  }
}
```

Open **Cursor Settings → MCP** and check that `no2sql` shows a green dot. Don't commit a project `.cursor/mcp.json` that holds a real connection string.

### Windsurf

Edit `~/.codeium/windsurf/mcp_config.json`, or open it from the MCP servers panel in Cascade:

```json
{
  "mcpServers": {
    "no2sql": {
      "command": "/Users/you/tools/no2sql/No2SQL",
      "args": [],
      "env": {
        "NO2SQL_MONGO": "mongodb+srv://<user>:<password>@<cluster-host>/",
        "NO2SQL_ALLOWED_DATABASES": "mydb"
      }
    }
  }
}
```

Press the refresh button in the MCP panel to load it.

### OpenAI Codex CLI

Add this to `~/.codex/config.toml`:

```toml
[mcp_servers.no2sql]
command = "/Users/you/tools/no2sql/No2SQL"
args = []
env = { NO2SQL_MONGO = "mongodb+srv://<user>:<password>@<cluster-host>/", NO2SQL_ALLOWED_DATABASES = "mydb" }
```

For `dnx`, use `command = "dnx"` and `args = ["No2SQL@1.1.2", "--yes"]`. Start `codex` and run `/mcp` to see the server.

### OpenAI Agents SDK (Python)

The Agents SDK can start local stdio servers itself. This example reads the connection string from your environment:

```python
import asyncio
import os

from agents import Agent, Runner
from agents.mcp import MCPServerStdio


async def main():
    async with MCPServerStdio(
        name="No2SQL",
        params={
            "command": "/Users/you/tools/no2sql/No2SQL",
            "args": [],
            "env": {
                "NO2SQL_MONGO": os.environ["NO2SQL_MONGO"],
                "NO2SQL_ALLOWED_DATABASES": "mydb",
            },
        },
    ) as no2sql:
        agent = Agent(
            name="Migration helper",
            instructions="Use the No2SQL tools to analyze MongoDB and produce SQL.",
            mcp_servers=[no2sql],
        )
        result = await Runner.run(agent, "Generate a SQL schema for the mydb database.")
        print(result.final_output)


asyncio.run(main())
```

### Not supported yet

ChatGPT, claude.ai on the web and mobile, and the hosted Claude and OpenAI APIs (the Responses API `mcp` tool and the Claude API MCP connector) can only reach remote MCP servers over HTTPS. No2SQL runs locally over stdio for now. Remote mode is planned for a later release.

## Try it

Once your client shows the No2SQL tools, ask:

```
Use No2SQL to list my MongoDB databases.
Infer the relationships in database mydb.
Generate a SQL schema for mydb.
Generate a Mermaid ERD for mydb.
Generate SQL INSERT statements for the orders collection in mydb.
```

If a tool answers that `NO2SQL_MONGO` is not set, add it to the `env` block of your client config and restart the client. `test_connectivity` works without it, so it only shows that the server is running.

## MCP tools

All tools only read from MongoDB. Each one carries MCP tool annotations that mark it read-only, non-destructive and idempotent, so clients can tell it is safe to run.

| Tool | What it does |
|------|-------------|
| `test_connectivity` | Checks that the server is running. It doesn't contact MongoDB and works even when `NO2SQL_MONGO` is not set. |
| `list_databases` | Lists the databases you can analyze: only those in `NO2SQL_ALLOWED_DATABASES` when it is set, and never `admin`, `config` or `local` unless `NO2SQL_BLOCK_SYSTEM_DATABASES` is `false`. |
| `list_inferred_relationships` | Lists the ID-like fields (such as `userId`) in each collection. |
| `compare_id_fields_to_ids` | Infers relationships by matching ID-like field values to `_id` values, with a confidence score. |
| `generate_sql_schema` | Generates a SQL script with CREATE TABLE statements, indexes and foreign keys. |
| `generate_sql_schema_advanced` | Same as above, plus relationships you supply yourself, returned as JSON with tables, foreign keys, indexes and the full script. |
| `generate_seeders_for_collection` | Generates SQL INSERT statements for up to 1000 documents of one collection. |
| `generate_erd_mermaid` | Generates a Mermaid ER diagram (`source`: `sql`, `auto` or `mongo`). |
| `generate_erd_plant_uml` | Generates a PlantUML ER diagram (`source`: `sql`, `auto` or `mongo`). |
| `generate_erd_dot` | Generates a GraphViz DOT ER diagram (`source`: `sql`, `auto` or `mongo`). |

## Security guardrails

No2SQL validates every tool input: identifier format and length, `source` values, relationship override fields and prompt-injection marker patterns.

A failed tool call comes back as an MCP error (`isError: true`), so your client can tell a failure from a result. Error text never includes the connection string or a stack trace. A missing or invalid `NO2SQL_MONGO` gets a fixed message naming the variable, and any other failure gets a short reason with an error id, while the details go to the server log.

Recommended baseline:

- Set `NO2SQL_ALLOWED_DATABASES` to only the databases you want analyzed.
- Keep `NO2SQL_BLOCK_SYSTEM_DATABASES=true`.
- Use a MongoDB user with read-only permissions.
- Keep the connection string in your client's `env` config or a secret prompt, never on a command line or in a committed file.

## More

- Source, issues and releases: https://github.com/Ptalati015/No2SQL
- [Model Context Protocol docs](https://modelcontextprotocol.io/)

No2SQL is licensed under the MIT License. "No2SQL" is a trademark of Preet Talati.
