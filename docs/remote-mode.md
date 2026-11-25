# Remote mode: run No2SQL next to your database

Local AI clients (Claude Desktop, Claude Code, VS Code, Cursor, Windsurf, Codex CLI) start No2SQL on your own machine over stdio. Nothing in this guide changes that, and the [README](../README.md) covers that setup.

ChatGPT, claude.ai (web and mobile) and the OpenAI Responses API run in OpenAI's or Anthropic's cloud. They can't start a program on your computer, so they need an HTTPS URL. Remote mode is No2SQL running as an HTTP server that you host yourself, next to your MongoDB. Your connection string stays in the server's own environment and is never sent to a client.

**Contents:** [1. Start HTTP mode](#1-start-http-mode) · [2. Choose how clients sign in](#2-choose-how-clients-sign-in) · [3. Keep the database side safe](#3-keep-the-database-side-safe) · [4. Put it behind HTTPS](#4-put-it-behind-https) · [5. Connect your client](#5-connect-your-client) · [6. Troubleshooting](#6-troubleshooting)

## 1. Start HTTP mode

Use the same `No2SQL` you installed from the zip, and add `--http`. The examples in this guide are for a macOS or Linux shell.

Run this line **on its own**, then type or paste your connection string at the prompt. It stays out of your shell history and off the screen. (If you paste it together with the lines after it, `read` takes the next pasted line as the connection string.)

```sh
printf 'MongoDB connection string: '; stty -echo; IFS= read -r NO2SQL_MONGO; stty echo; echo; export NO2SQL_MONGO
```

Then:

```sh
export NO2SQL_ALLOWED_DATABASES='mydb'
./No2SQL --http
```

- The MCP endpoint is `http://127.0.0.1:8787/mcp` (stateless Streamable HTTP). `GET /healthz` returns `{"status":"ok"}`. It needs no sign-in and doesn't contact MongoDB.
- `NO2SQL_TRANSPORT=http` does the same as `--http`, which is handy in containers. With neither one set, No2SQL is the stdio server, exactly as before.
- By default No2SQL listens only on `127.0.0.1:8787`, so nothing else on your network can reach it. To listen elsewhere, set `NO2SQL_HTTP_URLS`, for example `http://0.0.0.0:8787`. Only plain `http://` addresses are accepted. TLS goes in front of No2SQL (section 4).
- **No2SQL refuses to start on an address other machines can reach unless sign-in is configured** (section 2). `--allow-anonymous` overrides this, warns on every start, and can't be combined with sign-in. Use it only behind something else that already authenticates every caller.
- In HTTP mode, logs go to stdout. Every tool call writes one audit line: the tool, the database and collection, who called, the outcome and how long it took. Logs never contain the connection string, a token or a password.

## 2. Choose how clients sign in

| You want to use | Sign-in to configure |
|---|---|
| OpenAI Responses API, scripts, Claude Code over HTTP | A static bearer token (`NO2SQL_HTTP_TOKEN`) |
| ChatGPT or claude.ai, just for you, without running an identity provider | The built-in sign-in (`NO2SQL_OAUTH_BUILTIN=true`) |
| ChatGPT or claude.ai, for several people, or with your company's single sign-on | An external identity provider (`NO2SQL_OAUTH_AUTHORITY`) |

You can set a static token together with either OAuth mode. ChatGPT and claude.ai can't send a static token, so they need one of the OAuth modes.

### Static bearer token

Generate a random token and give it to No2SQL:

```sh
export NO2SQL_HTTP_TOKEN="$(openssl rand -base64 32)"
```

- The token must be at least 32 characters. Short tokens, tokens with fewer than 10 distinct characters, and placeholder values like `changeme` are refused at start-up.
- Clients must send it as `Authorization: Bearer <token>`. No2SQL ignores a token anywhere else (query string, cookie or body).

### Built-in sign-in

With the built-in sign-in, No2SQL runs its own small OAuth server. When ChatGPT or claude.ai connects, your browser opens a No2SQL page that asks for **your owner password** and then asks you to approve that client. Only a client you approve gets tokens.

```sh
export NO2SQL_OAUTH_BUILTIN=true
export NO2SQL_PUBLIC_URL='https://no2sql.example.com'
```

| Variable | Required | What it does |
|---|---|---|
| `NO2SQL_OAUTH_BUILTIN` | Yes | `true` turns on the built-in sign-in. It can't be combined with `NO2SQL_OAUTH_AUTHORITY`. |
| `NO2SQL_PUBLIC_URL` | Yes | The exact `https://` origin clients use, with no path. Plain `http://` is accepted only for `localhost`, `127.0.0.1` or `[::1]`. |
| `NO2SQL_OWNER_PASSWORD` | No | Your owner password, at least 12 characters. If it isn't set, No2SQL generates a 24-character password at the first start and prints it once (see below). |
| `NO2SQL_DATA_DIR` | No | An absolute path for the sign-in state. Defaults to `~/.no2sql`. In the container image it is `/data`. No2SQL reads it only when the built-in sign-in is on. |
| `NO2SQL_OAUTH_ACCESS_TOKEN_MINUTES` | No | How long an access token lasts, from 5 to 1440 minutes. Defaults to 60. Clients refresh their tokens on their own, so you rarely need to change it. |

**Your owner password.** If you leave `NO2SQL_OWNER_PASSWORD` unset, the first start prints a block like this on stderr, once:

```
[No2SQL] Owner password for the built-in sign-in, shown only this once:
[No2SQL]     <24 random letters and digits>
```

Put it in a password manager. Only its SHA-256 hash is kept, in `owner-password.json` in the data directory. To get a new password, delete that file and restart, or set `NO2SQL_OWNER_PASSWORD`. If you'd rather set your own, run this line on its own before you start No2SQL:

```sh
printf 'Owner password (12+ characters): '; stty -echo; IFS= read -r NO2SQL_OWNER_PASSWORD; stty echo; echo; export NO2SQL_OWNER_PASSWORD
```

**The data directory** holds `signing-keys.json` (the private key that signs every access token), `clients.json`, `refresh-tokens.json`, `owner-password.json` (only for a generated password) and a `.lock` file. No2SQL creates the directory with mode 0700 and every file with mode 0600, and refuses to start if it can't write there. Keep it on storage that survives restarts. If it is lost, every client has to sign in again.

**Manage sign-ins** with these commands. Run them as the user that runs the server, with the same `NO2SQL_DATA_DIR`. They work while the server is running, and the server applies them within a second, without a restart.

```sh
./No2SQL oauth list                 # clients, approvals, live sign-ins and signing keys
./No2SQL oauth revoke <client_id>   # sign one client out
./No2SQL oauth revoke-all           # sign everyone out and replace the signing key
./No2SQL oauth rotate-keys          # new signing key; the old one keeps working until its tokens expire
```

In the Compose example (section 4), run them inside the container: `docker compose exec no2sql dotnet /app/No2SQL.dll oauth list`.

How long things last: access tokens 60 minutes (or `NO2SQL_OAUTH_ACCESS_TOKEN_MINUTES`). Refresh tokens are replaced on every use. A sign-in ends after 30 days, and then the client asks you to sign in again. When a client publishes a metadata document, your approval of it is remembered for 30 days, but you still type the password each time.

> **Security note: read this before you turn on the built-in sign-in**
>
> - **Anyone who can read the data directory can mint tokens.** `signing-keys.json` is the private signing key. Whoever has it can create access tokens that No2SQL accepts, without your password. Keep the directory owner-only (No2SQL sets 0700 and 0600) and treat every backup or snapshot of it like a password file. If a copy is lost or leaked, or after you restore an old backup, run `No2SQL oauth revoke-all`.
> - **The owner password is the only credential.** There is no user name and no second factor. Anyone who knows the password can approve any client, including their own. Use a long random password, never reuse it, and keep it in a password manager. Login attempts are rate-limited, which makes guessing a long random password impractical but doesn't protect a dictionary word.
> - **`No2SQL oauth revoke-all` is the panic button.** It deletes every refresh token and every never-approved client, forgets remembered approvals, and replaces the signing key, so every access token stops working within a second. Run it if you suspect the password, the data directory or a connected AI account was compromised, then change the owner password.
> - **`NO2SQL_PUBLIC_URL` must be the exact public origin**: the scheme, host and port that clients type, with no path. Every address No2SQL publishes (sign-in pages, token endpoint, the audience of every token) is built from it, and it never trusts the `Host` or `X-Forwarded-*` headers for this. If it doesn't match the URL you give ChatGPT or claude.ai, sign-in fails.
> - **If you let No2SQL generate the password, it is in the server's log.** In a container, anyone who can run `docker logs` can read it. After you've saved it, recreate the container to drop that log (`docker compose up -d --force-recreate no2sql`). The data directory keeps the password's hash, so the password stays the same.
> - **Every approved client can read everything the connection string and allow-list permit.** There is no per-client limit in 1.2.0. Use a read-only MongoDB user and `NO2SQL_ALLOWED_DATABASES` (section 3).
> - **Refresh tokens are stored by OpenAI or Anthropic.** If one of those accounts is compromised, it can read your data until you run `revoke-all`, for 30 days at most.
> - **One owner, one server.** The built-in sign-in is for a single person and a single running copy of No2SQL. Two replicas would not share sign-ins or rate limits.
> - **Use an external identity provider instead** when several people need access, when you need single sign-on or a second factor, when you want to remove people centrally, or when you run more than one replica.

### External identity provider

```sh
export NO2SQL_PUBLIC_URL='https://no2sql.example.com'
export NO2SQL_OAUTH_AUTHORITY='https://login.example.com/'   # the issuer, exactly as in the token's "iss"
export NO2SQL_OAUTH_SCOPE='mcp:tools'                         # optional; this is the default
```

- `NO2SQL_PUBLIC_URL` is the `https://` address clients use, with no path. The MCP endpoint is always `<NO2SQL_PUBLIC_URL>/mcp`, and access tokens must have exactly that as their audience (`aud`).
- **Copy `NO2SQL_OAUTH_AUTHORITY` character for character from the `issuer` in your identity provider's metadata** (`<authority>/.well-known/openid-configuration`). A missing or extra trailing slash makes every token fail.
- The authority must use `https://`. No2SQL finds its keys through OpenID Connect metadata.
- Tokens must be signed with RS, PS or ES (256, 384 or 512), carry `typ` `at+jwt` or `JWT`, and include the scope. `aud` may be a single string or an array that holds only the MCP URL. If your identity provider adds other audiences, create a dedicated API or resource for No2SQL.
- No2SQL publishes protected resource metadata at `/.well-known/oauth-protected-resource/mcp`, and every 401 points clients to it. That is how ChatGPT and claude.ai find your identity provider.

## 3. Keep the database side safe

- Create a **read-only MongoDB user** that can only read the databases you want analyzed (the `read` role on each one). No2SQL only reads, and a read-only user makes sure of it.
- **Always set `NO2SQL_ALLOWED_DATABASES`** on a server that other people or services can reach. Leave `NO2SQL_BLOCK_SYSTEM_DATABASES` at `true`.
- In containers, give No2SQL the connection string as a secret file with `NO2SQL_MONGO_FILE`, for example `/run/secrets/mongo`. If both are set, the file wins. A trailing newline is ignored. No2SQL warns at start-up if other users can read the file, so set it to mode 0600 or 0400.
- One No2SQL server uses one connection string. To analyze several clusters, run one No2SQL per cluster and add each as its own connector.

## 4. Put it behind HTTPS

ChatGPT and claude.ai need a public `https://` URL. No2SQL serves plain HTTP on purpose, so put a TLS proxy in front of it, on the same machine or private network. Traffic between the proxy and No2SQL is not encrypted.

### Docker and Compose with Caddy

The image is `ghcr.io/ptalati015/no2sql`, for linux-x64 and linux-arm64. It runs as the non-root user `app` (UID 1654), starts HTTP mode on `0.0.0.0:8787`, and works with a read-only root filesystem. It has no sign-in or secret baked in, so it refuses to start until you give it a token or an OAuth setting. Pin a version tag such as `:1.2.0` rather than `latest`, and update when a release ships, because releases carry .NET runtime patches.

The repository has a ready-made example in [`deploy/compose/`](../deploy/compose/): No2SQL behind [Caddy](https://caddyserver.com/), which gets a TLS certificate for your domain. Only Caddy publishes ports. You need a DNS name that points at the machine, with ports 80 and 443 open.

1. Copy the example files and create the folders:

   ```sh
   cp env.example .env                  # set NO2SQL_DOMAIN and NO2SQL_ALLOWED_DATABASES
   cp no2sql.env.example no2sql.env     # choose the sign-in, see below
   chmod 600 .env no2sql.env
   mkdir -p secrets data
   ```

2. Put the sign-in settings in `no2sql.env`. For a static token, set `NO2SQL_HTTP_TOKEN` to the output of `openssl rand -base64 48`. For the built-in sign-in, add `NO2SQL_OAUTH_BUILTIN=true`. Compose already sets `NO2SQL_PUBLIC_URL` to `https://<NO2SQL_DOMAIN>`. You can set both.

3. Run this line **on its own**, then type or paste the connection string at the prompt. The subshell's umask creates the file as 0600 from the start.

   ```sh
   printf 'MongoDB connection string: '; stty -echo; IFS= read -r conn; stty echo; echo; (umask 077 && printf '%s' "$conn" > secrets/mongo.txt); unset conn
   ```

4. Give the secret and the data folder to the image's user, then start:

   ```sh
   sudo chown 1654:1654 secrets/mongo.txt data
   sudo chmod 0400 secrets/mongo.txt
   sudo chmod 0700 data
   docker compose up -d
   ```

5. With the built-in sign-in and no `NO2SQL_OWNER_PASSWORD`, read the generated password once with `docker compose logs no2sql`, save it, then run `docker compose up -d --force-recreate no2sql` to drop it from the log.

What the example sets, and why:

- `stop_grace_period: 30s`. By default, `docker stop` kills a container 10 seconds after asking it to stop. The longer grace period lets tool calls in flight finish.
- `NO2SQL_MONGO_FILE: /run/secrets/mongo`, from the Compose secret `./secrets/mongo.txt`. Compose mounts it with the host file's owner and mode, which is why step 4 sets them.
- `./data:/data`. `/data` is the only writable path in the container, and the image sets `NO2SQL_DATA_DIR=/data`. The built-in sign-in keeps its state there (see the security note in section 2). A token or an external identity provider writes nothing there. A folder Docker creates for a bind mount belongs to root, which is why step 1 creates it.
- `NO2SQL_HTTP_TRUSTED_PROXIES: "172.30.87.2/32"`, Caddy's fixed address, so rate limits see the real client address. `NO2SQL_HTTP_HSTS: "true"`, because Caddy always serves HTTPS.
- `read_only: true`, `cap_drop: [ALL]` and `no-new-privileges`.
- `.env`, `no2sql.env`, `secrets/` and `data/` are git-ignored. Never commit them.

Running it:

- `GET https://<NO2SQL_DOMAIN>/healthz` returns 200 without sign-in. It is rate-limited, so probe it 2 seconds or more apart. The image has no built-in `HEALTHCHECK`.
- `docker inspect` shows port 8080. That comes from the .NET base image, and No2SQL ignores it.

**Stdio from the same image.** For a local stdio server with no ports, run `docker run -i --rm -e NO2SQL_TRANSPORT=stdio -e NO2SQL_MONGO ghcr.io/ptalati015/no2sql:1.2.0` as the client's `command`, with `NO2SQL_MONGO` in the client's `env` config. `-e NO2SQL_MONGO` without a value passes the variable through, so the connection string never appears in the command.

### A tunnel, for testing

To try a server on your laptop from ChatGPT or claude.ai, expose it with [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) or [ngrok](https://ngrok.com/docs/), for example `ngrok http 8787`. Then:

- Set `NO2SQL_PUBLIC_URL` to the tunnel's `https://` address and restart No2SQL. Requests for any other host name get 400.
- Set `NO2SQL_HTTP_TRUSTED_PROXIES=127.0.0.1`, because the tunnel connects from the same machine. Otherwise every caller shares one address for rate limits and login throttling.
- **Keep sign-in on while tunneling.** Anyone who learns the tunnel URL can reach your server. Tunnels are for testing, not for a deployment other people rely on.

### Proxy and limit settings

The defaults suit a server behind a reverse proxy on the same host. Each setting is optional.

| Variable | Default | What it does |
|---|---|---|
| `NO2SQL_HTTP_ALLOWED_HOSTS` | The host in `NO2SQL_PUBLIC_URL`, the listening host, and `localhost`, `127.0.0.1`, `[::1]` | Host names accepted in the `Host` header, separated by commas. Others get 400. `*` is refused. The host in `NO2SQL_PUBLIC_URL` is always accepted. |
| `NO2SQL_HTTP_ALLOWED_ORIGINS` | The origin of `NO2SQL_PUBLIC_URL`, and `http://localhost:<port>` (also `127.0.0.1` and `[::1]`) | Browser origins accepted, as `https://host[:port]` separated by commas. A request with any other `Origin` header gets 403. Requests without an `Origin` header, which is how AI clients call, are not affected. |
| `NO2SQL_HTTP_TRUSTED_PROXIES` | None | IP addresses or CIDR ranges of your proxy. Only these may set `X-Forwarded-For`, so rate limits see the real client address. |
| `NO2SQL_HTTP_RATE_LIMIT_PER_MINUTE` | 60 | Requests to `/mcp` per minute for each bearer token (or each address, without a token). Over the limit gets 429 with `Retry-After`. |
| `NO2SQL_HTTP_RATE_LIMIT_PER_IP_PER_MINUTE` | 300 | Requests to `/mcp` per minute from each client address. |
| `NO2SQL_HTTP_MAX_CONCURRENT_CALLS` | 16 | Requests to `/mcp` running at once, for all callers together. |
| `NO2SQL_HTTP_MAX_BODY_BYTES` | 1048576 (1 MiB) | Largest request body. Larger gets 413. |
| `NO2SQL_HTTP_REQUEST_TIMEOUT_SECONDS` | 120 | Longest a request may run, from 1 to 3600. Longer gets 504. |
| `NO2SQL_HTTP_MAX_CONNECTIONS` | 256 | Open connections. |
| `NO2SQL_HTTP_HSTS` | On when `NO2SQL_PUBLIC_URL` is `https://`, otherwise off | Send `Strict-Transport-Security`. `true` or `false`. |

The sign-in endpoints have their own fixed limits per client address: `/healthz` 60 a minute, `/token` 30 a minute, `/authorize`, `/login` and `/consent` 20 a minute, and `/register` 10 an hour.

## 5. Connect your client

In each example, replace `https://no2sql.example.com` with your `NO2SQL_PUBLIC_URL`.

### ChatGPT

ChatGPT needs the built-in sign-in or an external identity provider.

1. Open ChatGPT on the web and add a custom MCP server (connector). Menu names change, so follow ChatGPT's help for "custom MCP connectors" or developer mode if you don't see it.
2. Enter `https://no2sql.example.com/mcp` as the URL and choose **OAuth** as the authentication.
3. ChatGPT opens No2SQL's sign-in page (built-in sign-in) or your identity provider's. With the built-in sign-in, check that the page shows the address `chatgpt.com`, then type your owner password and approve.

Plans: custom MCP servers are available on the web only. On Business, Enterprise and Edu, an admin or owner adds them. Pro can use them because No2SQL's tools are all read-only. Free and Go can't add them. Check OpenAI's current help for other plans.

### claude.ai

claude.ai needs the built-in sign-in or an external identity provider.

1. Go to **Settings → Connectors → Add custom connector**. On Team and Enterprise plans, an Owner adds it for the organization.
2. Enter a name and `https://no2sql.example.com/mcp` as the URL.
3. Click **Connect**. claude.ai opens No2SQL's sign-in page or your identity provider's. With the built-in sign-in, check that the page shows the address `claude.ai`, then type your owner password and approve.

Plans: Free (one custom connector), Pro, Max, Team and Enterprise.

### OpenAI Responses API

Use the static token. OpenAI sends the `authorization` value as `Authorization: Bearer` on every request to your server.

```python
import os
from openai import OpenAI

client = OpenAI()
response = client.responses.create(
    model="gpt-5",  # any model that supports the mcp tool
    tools=[{
        "type": "mcp",
        "server_label": "no2sql",
        "server_url": "https://no2sql.example.com/mcp",
        "authorization": os.environ["NO2SQL_HTTP_TOKEN"],
        "require_approval": "never",
    }],
    input="List my MongoDB databases with No2SQL.",
)
print(response.output_text)
```

`require_approval: "never"` is reasonable here because every No2SQL tool only reads. The Responses API works with any API account.

### Claude Code over HTTP

Claude Code can also connect to a remote No2SQL. With a static token, send it as a header. Claude Code expands `${NO2SQL_HTTP_TOKEN}` from your shell, so this `.mcp.json` holds no secret:

```json
{
  "mcpServers": {
    "no2sql": {
      "type": "http",
      "url": "https://no2sql.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${NO2SQL_HTTP_TOKEN}"
      }
    }
  }
}
```

With the built-in sign-in or an identity provider, leave out `headers`, and Claude Code runs the sign-in in your browser.

## 6. Troubleshooting

| You see | Cause and fix |
|---|---|
| No2SQL exits at start saying the address is reachable from other machines | You set `NO2SQL_HTTP_URLS` (or use the container image) without sign-in. Configure sign-in (section 2). |
| No2SQL exits at start about the data directory | The built-in sign-in can't write to `NO2SQL_DATA_DIR`. In a container, create `data/` yourself and `chown 1654:1654` it. |
| Claude Code: "Dynamic Client Registration rejected (HTTP 404)" | The server has only a static token, so there is no OAuth server to register with. Add the `Authorization` header (section 5), or turn on the built-in sign-in. |
| 400 from your public URL | The `Host` isn't allowed. Set `NO2SQL_PUBLIC_URL`, or list the host in `NO2SQL_HTTP_ALLOWED_HOSTS`. |
| ChatGPT or claude.ai can't finish signing in | `NO2SQL_PUBLIC_URL` must match the URL you entered in the client exactly (scheme, host and port), and the URL must end in `/mcp`. |
| The sign-in page says the password is wrong after a few tries, or is slow | Login attempts are rate-limited per address. Wait and try again. Behind a tunnel or proxy, set `NO2SQL_HTTP_TRUSTED_PROXIES` so other callers don't share your address. |
| 401 on every call with a token from your identity provider | Check that `iss` matches `NO2SQL_OAUTH_AUTHORITY` exactly (trailing slash included), `aud` is `<NO2SQL_PUBLIC_URL>/mcp`, `typ` is `at+jwt` or `JWT`, and the token hasn't expired. The server log gives the reason for each 401. |
| 403 `insufficient_scope` | The token lacks `NO2SQL_OAUTH_SCOPE` (default `mcp:tools`). |
| 403 on a request from a browser page | The page's `Origin` isn't allowed. Add it to `NO2SQL_HTTP_ALLOWED_ORIGINS`. |
| 429 | A rate limit was hit. The response's `Retry-After` says when to try again. Raise `NO2SQL_HTTP_RATE_LIMIT_PER_MINUTE` for a legitimate busy client. |
| A tool answers "NO2SQL_MONGO is not set" | Set `NO2SQL_MONGO` or `NO2SQL_MONGO_FILE` in the server's environment, not in the client. |
