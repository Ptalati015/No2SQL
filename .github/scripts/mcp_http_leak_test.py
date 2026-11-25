#!/usr/bin/env python3
"""HTTP-mode leak test for No2SQL (P2-7).

Starts the built server in HTTP mode on a free loopback port and checks that no
secret reaches its logs (stdout and stderr) or any HTTP response (status line,
headers and body):

Run 1 reads the connection string from NO2SQL_MONGO_FILE (a valid string for an
unreachable server, with a secret password and a trailing newline) while
NO2SQL_MONGO holds a different, malformed secret: the file must win. The
NO2SQL_HTTP_TOKEN and NO2SQL_OWNER_PASSWORD variables hold canaries. Every
request carries an Authorization and a Cookie canary, and some carry a canary
in tool arguments that are not audited, in an unknown tool, an unknown method
and a body that is not JSON. Each tool call must write exactly one audit line.

Run 2 repeats a tool call for each malformed NO2SQL_MONGO the stdio smoke test
uses (the driver's parse error can quote the whole string).

Run 3 points NO2SQL_MONGO_FILE at a missing file: the server must refuse to
start with exit code 2, naming the variable and not the NO2SQL_MONGO value.

Usage:
  mcp_http_leak_test.py [--timeout SECONDS] -- <server command...>
"""

import argparse
import http.client
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

PROTOCOL_VERSION = "2025-06-18"
AUDIT_MARKER = "No2SQL.Audit"

# Same strings as MALFORMED_MONGO_VARIANTS in mcp_smoke_test.py (kept in step by hand; the
# scripts run with python -I, so one cannot import the other).
MALFORMED_MONGO_VARIANTS = [
    ("bad scheme", "mongo://no2sql_smoke:{pw}@127.0.0.1:9/"),
    ("invalid option value", "mongodb://no2sql_smoke:{pw}@127.0.0.1:9/?connectTimeoutMS=notanumber"),
    ("missing colon after scheme", "mongodb//no2sql_smoke:{pw}@127.0.0.1:9/"),
    ("bare value, not a URI", "{pw}"),
]


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def canary(name):
    return f"no2sql-{name}-canary-{secrets.token_hex(10)}"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def base_env():
    env = dict(os.environ)
    for name in ("NO2SQL_MONGO", "NO2SQL_MONGO_FILE", "NO2SQL_HTTP_TOKEN", "NO2SQL_OWNER_PASSWORD"):
        env.pop(name, None)
    env["NO2SQL_TRANSPORT"] = "http"
    return env


class HttpServer:
    def __init__(self, command, env, timeout):
        self.timeout = timeout
        self.port = free_port()
        env = dict(env)
        env["NO2SQL_HTTP_URLS"] = f"http://127.0.0.1:{self.port}"
        self.proc = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True, encoding="utf-8", errors="replace", start_new_session=True)
        self.stdout_lines = []
        self.stderr_lines = []
        self.responses = []
        self.next_id = 1
        self._pumps = [
            threading.Thread(target=self._pump, args=(self.proc.stdout, self.stdout_lines), daemon=True),
            threading.Thread(target=self._pump, args=(self.proc.stderr, self.stderr_lines), daemon=True),
        ]
        for pump in self._pumps:
            pump.start()

    @staticmethod
    def _pump(stream, lines):
        for line in stream:
            lines.append(line.rstrip("\n"))

    def output(self):
        return "\n".join(self.stdout_lines + self.stderr_lines)

    def die(self, message):
        print("--- server stdout (last 40 lines) ---", file=sys.stderr)
        print("\n".join(self.stdout_lines[-40:]), file=sys.stderr)
        print("--- server stderr (last 20 lines) ---", file=sys.stderr)
        print("\n".join(self.stderr_lines[-20:]), file=sys.stderr)
        self.kill()
        fail(message)

    def kill(self):
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait(timeout=10)

    def wait_until_up(self):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self.die(f"server exited with code {self.proc.returncode} before it answered /healthz")
            try:
                status, _, body = self.send("GET", "/healthz", record=False)
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.25)
        self.die(f"/healthz did not answer within {self.timeout}s")

    def send(self, method, path, body=None, headers=None, record=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            text = response.read().decode("utf-8", "replace")
            header_text = "\n".join(f"{k}: {v}" for k, v in response.getheaders())
            if record:
                self.responses.append(f"{response.status} {response.reason}\n{header_text}\n\n{text}")
            return response.status, header_text, text
        finally:
            conn.close()

    def rpc(self, method, params=None, headers=None, raw_body=None):
        request_id = self.next_id
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        all_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        all_headers.update(headers or {})
        body = raw_body if raw_body is not None else json.dumps(message)
        status, _, text = self.send("POST", "/mcp", body=body.encode("utf-8"), headers=all_headers)
        return status, find_message(text, request_id)

    def stop(self):
        """SIGTERM, like a container stop, and require a clean exit."""
        if self.proc.poll() is not None:
            self.die(f"server crashed (exit code {self.proc.returncode}) during the test")
        os.killpg(self.proc.pid, signal.SIGTERM)
        try:
            code = self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.die("server did not exit within 20s after SIGTERM")
        for pump in self._pumps:
            pump.join(timeout=5)
        if code != 0:
            self.die(f"server exited with code {code} after SIGTERM")


def find_message(text, request_id):
    """The JSON-RPC message for request_id, from a JSON body or a one-message event stream."""
    candidates = [line[5:] for line in text.splitlines() if line.startswith("data:")] or [text]
    for candidate in candidates:
        try:
            message = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict) and message.get("id") == request_id:
            return message
    return None


def tool_text(message):
    content = ((message or {}).get("result") or {}).get("content") or []
    return " ".join(block.get("text", "") for block in content if isinstance(block, dict))


def check_no_leak(server, secrets_to_hide, run_name):
    places = {"server output": server.output()}
    for index, response in enumerate(server.responses):
        places[f"HTTP response {index + 1}"] = response
    for label, value in secrets_to_hide.items():
        for place, text in places.items():
            if value in text:
                server.die(f"{run_name}: {label} appeared in {place}")
    print(f"{run_name}: no secret in server output or in {len(server.responses)} HTTP responses")


def run_with_secret_file(command, args):
    file_pw = secrets.token_hex(16)
    env_pw = secrets.token_hex(16)
    file_conn = (f"mongodb://no2sql_smoke:{file_pw}@127.0.0.1:9/"
                 "?serverSelectionTimeoutMS=2000&connectTimeoutMS=2000")
    env_conn = f"mongodb//no2sql_smoke:{env_pw}@127.0.0.1:9/"   # malformed: would fail parsing
    hidden = {
        "MongoDB password (file)": file_pw,
        "MongoDB connection string (file)": file_conn,
        "MongoDB password (NO2SQL_MONGO)": env_pw,
        "MongoDB connection string (NO2SQL_MONGO)": env_conn,
        "NO2SQL_HTTP_TOKEN": canary("token"),
        "NO2SQL_OWNER_PASSWORD": canary("owner"),
        "Authorization header": canary("bearer"),
        "Cookie header": canary("cookie"),
        "unaudited tool argument": canary("argument"),
        "unknown method parameter": canary("method"),
        "body that is not JSON": canary("body"),
    }

    with tempfile.TemporaryDirectory() as directory:
        secret_file = os.path.join(directory, "mongo")
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(file_conn + "\n")
        os.chmod(secret_file, 0o600)

        env = base_env()
        env["NO2SQL_MONGO"] = env_conn
        env["NO2SQL_MONGO_FILE"] = secret_file
        env["NO2SQL_HTTP_TOKEN"] = hidden["NO2SQL_HTTP_TOKEN"]
        env["NO2SQL_OWNER_PASSWORD"] = hidden["NO2SQL_OWNER_PASSWORD"]

        server = HttpServer(command, env, args.timeout)
        server.wait_until_up()
        headers = {
            "Authorization": f"Bearer {hidden['Authorization header']}",
            "Cookie": f"session={hidden['Cookie header']}",
        }

        status, init = server.rpc("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "no2sql-ci-http-leak", "version": "1.0"},
        }, headers)
        if status != 200 or not (init or {}).get("result", {}).get("serverInfo"):
            server.die(f"initialize failed: HTTP {status}, {json.dumps(init)[:300]}")
        status, tools = server.rpc("tools/list", headers=headers)
        if status != 200 or len((tools or {}).get("result", {}).get("tools", [])) < 10:
            server.die(f"tools/list failed: HTTP {status}")
        print("initialize and tools/list OK")

        tool_calls = 0
        status, result = server.rpc("tools/call", {"name": "list_databases", "arguments": {}}, headers)
        tool_calls += 1
        text = tool_text(result)
        if not (result or {}).get("result", {}).get("isError"):
            server.die(f"list_databases against an unreachable server must fail, got {json.dumps(result)[:300]}")
        # The file's string is valid, NO2SQL_MONGO's is not: a parse error here means the file lost.
        if "not a valid MongoDB connection string" in text or "Unable to complete listing databases" not in text:
            server.die(f"NO2SQL_MONGO_FILE did not win over NO2SQL_MONGO: {text[:300]}")
        print("NO2SQL_MONGO_FILE wins over NO2SQL_MONGO")

        status, result = server.rpc("tools/call", {
            "name": "generate_sql_schema_advanced",
            "arguments": {
                "databaseName": "shop",
                "overrides": [{"note": hidden["unaudited tool argument"]}],
                "unknown": hidden["unaudited tool argument"],
            },
        }, headers)
        tool_calls += 1
        server.rpc("tools/call", {"name": "test_connectivity", "arguments": {"x": hidden["unaudited tool argument"]}}, headers)
        tool_calls += 1
        server.rpc("tools/call", {"name": "no_such_tool", "arguments": {"x": hidden["unaudited tool argument"]}}, headers)
        server.rpc("no2sql/unknown-method", {"x": hidden["unknown method parameter"]}, headers)
        server.rpc("tools/call", headers=headers, raw_body="{not json " + hidden["body that is not JSON"])
        server.send("GET", "/healthz", headers=headers)
        server.send("GET", "/no-such-path?q=" + hidden["unknown method parameter"], headers=headers)

        server.stop()
        print("run 1 (secret file): clean exit after SIGTERM")

    audit = [line for line in server.stdout_lines if AUDIT_MARKER in line]
    known_tool_audits = [line for line in audit if 'tool="no_such_tool"' not in line]
    if len(known_tool_audits) != tool_calls:
        server.die(f"expected {tool_calls} audit lines for tool calls, found {len(known_tool_audits)}:\n" + "\n".join(audit))
    for line in audit:
        if "duration_ms=" not in line or "caller=" not in line:
            server.die(f"audit line without duration or caller: {line}")
    print(f"audit: one line per tool call ({tool_calls})")
    check_no_leak(server, hidden, "run 1")


def run_with_malformed_mongo(command, args):
    for label, template in MALFORMED_MONGO_VARIANTS:
        fake_pw = secrets.token_hex(16)
        conn = template.format(pw=fake_pw)
        env = base_env()
        env["NO2SQL_MONGO"] = conn

        server = HttpServer(command, env, args.timeout)
        server.wait_until_up()
        status, result = server.rpc("tools/call", {"name": "list_databases", "arguments": {}})
        if status != 200 or not (result or {}).get("result", {}).get("isError"):
            server.die(f"{label}: expected an isError tool result, got HTTP {status} {json.dumps(result)[:300]}")
        server.stop()
        check_no_leak(server, {"MongoDB password": fake_pw, "MongoDB connection string": conn},
                      f"run 2 (malformed NO2SQL_MONGO, {label})")


def run_with_missing_file(command, args):
    env_pw = secrets.token_hex(16)
    env = base_env()
    env["NO2SQL_MONGO"] = f"mongodb://no2sql_smoke:{env_pw}@127.0.0.1:9/"
    env["NO2SQL_MONGO_FILE"] = os.path.join(tempfile.gettempdir(), "no2sql-missing-" + secrets.token_hex(8))
    server = HttpServer(command, env, args.timeout)
    try:
        code = server.proc.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        server.die("a missing NO2SQL_MONGO_FILE must stop the server at start-up")
    for pump in server._pumps:
        pump.join(timeout=5)
    if code != 2:
        server.die(f"a missing NO2SQL_MONGO_FILE must exit with code 2, got {code}")
    if "NO2SQL_MONGO_FILE is set, but" not in server.output():
        server.die("the start-up error does not name NO2SQL_MONGO_FILE")
    check_no_leak(server, {"MongoDB password (NO2SQL_MONGO)": env_pw}, "run 3 (missing NO2SQL_MONGO_FILE, exit 2)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=45, help="seconds to wait for start-up and each response")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("missing server command after --")

    run_with_secret_file(command, args)
    run_with_malformed_mongo(command, args)
    run_with_missing_file(command, args)
    print("MCP HTTP leak test passed")


if __name__ == "__main__":
    main()
