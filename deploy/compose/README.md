# No2SQL behind Caddy with Docker Compose

This example runs the No2SQL image (`ghcr.io/ptalati015/no2sql`) in HTTP mode behind
[Caddy](https://caddyserver.com/), which provides TLS. Only Caddy publishes ports. No2SQL listens
only on a private Compose network, and it won't start on `0.0.0.0` without auth.

## Before the first start

You need a DNS name that points at this machine, with ports 80 and 443 open to it.

```sh
cp env.example .env                     # set NO2SQL_DOMAIN (and optionally NO2SQL_ALLOWED_DATABASES)
cp no2sql.env.example no2sql.env        # set NO2SQL_HTTP_TOKEN (openssl rand -base64 48) or the OAuth settings
chmod 600 .env no2sql.env
mkdir -p secrets data
```

Run this line **on its own**, then type or paste the connection string at the prompt. It stays
out of your shell history and off the screen. The subshell's umask creates the file as 0600 from
the start, and the line works in bash and zsh. (If you paste it together with other lines, `read`
would take the next pasted line as the connection string.)

```sh
printf 'MongoDB connection string: '; stty -echo; IFS= read -r conn; stty echo; echo; (umask 077 && printf '%s' "$conn" > secrets/mongo.txt); unset conn
```

Then:

```sh
sudo chown 1654:1654 secrets/mongo.txt data      # 1654 is the image's non-root "app" user
sudo chmod 0400 secrets/mongo.txt
sudo chmod 0700 data
docker compose up -d
```

- **Use a read-only MongoDB user.** No2SQL only reads, so a user with the `read` role on the
  databases you list in `NO2SQL_ALLOWED_DATABASES` is enough.
- **The connection string is a secret file**, not an environment variable. No2SQL reads it from
  `NO2SQL_MONGO_FILE` and warns if other users can read it. Compose mounts the file with the host's
  owner and mode, so set them on the host as shown above.
- **`data/` must belong to UID 1654.** The container's root filesystem is read-only. `/data` is the
  only writable path (the image sets `NO2SQL_DATA_DIR=/data` for the built-in sign-in's state), and
  a directory Docker creates for a bind mount belongs to root.
- **`.env`, `no2sql.env`, `secrets/` and `data/` are git-ignored here.** Never commit them.
- **Port 8080 in `docker inspect`** comes from the .NET base image (`ASPNETCORE_HTTP_PORTS`).
  No2SQL ignores it and listens only on `NO2SQL_HTTP_URLS` (8787 in the image).

## Clients

Point MCP clients at `https://<NO2SQL_DOMAIN>/mcp` and send the token as
`Authorization: Bearer <token>`.

## Running it

- **Health check.** `GET https://<NO2SQL_DOMAIN>/healthz` returns 200 and needs no auth. Probe it
  2 s or more apart, because it is rate-limited like everything else. The image has no
  HEALTHCHECK.
- **Stopping.** By default, `docker stop` kills the container 10 s after SIGTERM. The example sets
  `stop_grace_period: 30s` so that tool calls in flight can finish.
- **Updates.** Pin a version tag (for example `:1.2.0`) instead of `latest`. Update when a new
  release ships: it carries .NET runtime patches.
- **Stdio from the same image.** `docker run -i --rm -e NO2SQL_TRANSPORT=stdio -e NO2SQL_MONGO ghcr.io/ptalati015/no2sql:<version>`
  gives a local stdio server, with no ports and no Caddy.
