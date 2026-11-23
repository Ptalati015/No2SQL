# Changelog

All notable changes to No2SQL are listed here, newest first.

## 1.1.2 — 2026-11

Backlog fixes: No2SQL behaves well when misconfigured, and AI clients can tell when a tool failed.

### Security
- Fixed a credential leak: in every release before 1.1.2 an unparseable `NO2SQL_MONGO` was written to stderr in full, password included. If you ever saw a connection-string error from No2SQL 1.1.1 or earlier, treat your MCP client's server log as containing that credential, delete the log, and rotate the password (#50).

### Changed
- **Behaviour change:** tool failures are now reported as MCP tool errors (`isError: true`) instead of normal results, so AI clients can tell a call failed. The message text is unchanged: an error id and a short reason (#52).
- `list_databases` hides `admin`, `config` and `local` when `NO2SQL_BLOCK_SYSTEM_DATABASES` is true (the default), even if they appear in `NO2SQL_ALLOWED_DATABASES`. It now lists only databases the other tools accept (#48).
- The server starts and `test_connectivity` works without `NO2SQL_MONGO`. Tools that need MongoDB return one clear message naming `NO2SQL_MONGO` instead of failing at startup (#50).
- **Behaviour change:** `NO2SQL_MONGO` is the only configuration source. The `ConnectionStrings:MongoDb` fallback is removed, so the undocumented `ConnectionStrings__MongoDb` environment variable and `--ConnectionStrings:MongoDb=` argument are no longer read (#50).

### Added
- CI gate: `server.json` is validated against its `$schema`, its `io.github.` name must match the GitHub owner's casing, and both READMEs must carry the exact `mcp-name` marker. The smoke test checks that a malformed connection string never leaks its password and that failing tools return `isError: true` (#49, #51, #52). Its Python dependencies are pinned by hash (#53).

## 1.1.1 — 2026-11

Fixes the MCP Registry listing. No change to the server or its tools.

### Changed
- Server name is now `io.github.Ptalati015/no2sql` in `server.json` and in the README `mcp-name` marker. The MCP Registry matches the `io.github.<GitHub login>` namespace case-sensitively, so the lowercase name from 1.1.0 could not be published.
- `server.json` uses the 2025-12-11 schema; 2025-10-17 is deprecated by the registry publisher.

## 1.1.0 — 2026-11

Easy setup in every AI tool that runs local MCP servers.

### Added
- Run No2SQL with one command on .NET 10: `dnx No2SQL@1.1.0 --yes`. The NuGet package is now an `McpServer` tool package with self-contained RID packages (#43).
- Per-platform downloads on GitHub Releases for win-x64, win-arm64, linux-x64, linux-arm64, osx-x64 and osx-arm64, with `SHA256SUMS.txt`. No .NET needed (#42).
- MCP tool annotations (title, read-only, non-destructive, idempotent, closed-world) and clearer tool and parameter descriptions (#41).
- `server.json` marks `NO2SQL_MONGO` as required and secret and documents the guardrail variables (#39).
- README rewritten with both install paths and copy-paste setup for Claude Desktop, Claude Code, VS Code, Cursor, Windsurf, OpenAI Codex CLI and the OpenAI Agents SDK, plus the MCP Registry `mcp-name` marker (#44).
- CI smoke test: starts the server over stdio, checks the handshake, all 10 tools and their annotations, and that no environment values leak (#40).

### Changed
- `initialize` reports the package version in `serverInfo` instead of `1.0.0.0` (#43).
- `No2SQL.nuspec` removed; the csproj is the single packaging source (#43).

### Not yet supported
- ChatGPT, claude.ai web and mobile, and the hosted Claude and OpenAI APIs need a remote (HTTP) mode, planned for a later release.
