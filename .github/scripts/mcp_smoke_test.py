#!/usr/bin/env python3
"""MCP stdio smoke test for No2SQL.

Run 1 starts the server with no MongoDB configured, sends `initialize`, the
`notifications/initialized` notification and `tools/list` over stdio, then
exercises the error paths (a tool that needs MongoDB and an unknown method).
Run 2 starts it with a fake, unreachable connection string that carries a
secret password and calls the same tool.

The test fails if the handshake fails, if fewer tools than expected are listed,
if (with --require-annotations) a tool lacks the MCP-3 annotations, if the
server crashes or writes non-MCP text to stdout, or if a canary environment
value or the fake password shows up in any stdout or stderr output. With
--require-tool-errors, the MongoDB tool calls that must fail have to come back as
tool results with `isError: true`, so clients can tell they failed, and
test_connectivity must succeed without MongoDB. Run 3 uses a malformed connection
string (fails parsing) carrying a secret password, which must not leak either.

Usage:
  mcp_smoke_test.py [--expected-tools N] [--require-annotations] [--require-tool-errors]
                    -- <server command...>
"""

import argparse
import json
import os
import queue
import secrets
import subprocess
import sys
import threading
import time

PROTOCOL_VERSION = "2025-06-18"
# Clients on this revision skip initialize: server/discover first, then _meta on every request.
DISCOVER_PROTOCOL_VERSION = "2026-07-28"
CLIENT_INFO = {"name": "no2sql-ci-smoke", "version": "1.0"}

# Annotation values every No2SQL tool must declare (spec MCP-3).
REQUIRED_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}

# A tool that needs MongoDB, used to drive the error path.
MONGO_TOOL = "list_databases"


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


class StdioServer:
    def __init__(self, command, env, timeout):
        self.timeout = timeout
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.lines = queue.Queue()
        self.stdout_lines = []
        self.stderr_lines = []
        self.next_id = 1
        self.meta = None  # set by discover(); then sent as params._meta on every request
        self._stdout_done = threading.Thread(target=self._pump_stdout, daemon=True)
        self._stderr_done = threading.Thread(target=self._pump_stderr, daemon=True)
        self._stdout_done.start()
        self._stderr_done.start()

    def _pump_stdout(self):
        for line in self.proc.stdout:
            self.stdout_lines.append(line)
            self.lines.put(line)
        self.lines.put(None)

    def _pump_stderr(self):
        for line in self.proc.stderr:
            self.stderr_lines.append(line.rstrip("\n"))

    def output(self):
        return "".join(self.stdout_lines) + "\n".join(self.stderr_lines)

    def dump_stderr(self):
        if self.stderr_lines:
            print("--- server stderr (last 50 lines) ---", file=sys.stderr)
            print("\n".join(self.stderr_lines[-50:]), file=sys.stderr)

    def die(self, message):
        self.dump_stderr()
        fail(message)

    def send(self, message):
        try:
            self.proc.stdin.write(json.dumps(message) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            self.proc.wait(timeout=5)
            self.die(f"server exited (code {self.proc.returncode}) before it could be sent '{message.get('method')}'")

    def request(self, method, params=None, allow_error=False):
        request_id = self.next_id
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if self.meta is not None:
            params = dict(params or {}, _meta=self.meta)
        if params is not None:
            message["params"] = params
        self.send(message)
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.die(f"no response to '{method}' within {self.timeout}s")
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty:
                continue
            if line is None:
                self.proc.wait(timeout=5)
                self.die(f"server exited (code {self.proc.returncode}) before answering '{method}'")
            line = line.strip()
            if not line:
                continue
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                self.die(f"non-JSON line on stdout (stdout must carry only MCP messages): {line[:200]}")
            # Skip server-initiated notifications/requests; wait for our id.
            if response.get("id") != request_id:
                continue
            if "error" in response:
                if allow_error:
                    return response
                self.die(f"'{method}' returned an error: {json.dumps(response['error'])}")
            return response

    def handshake(self):
        init = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })["result"]
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return init

    def discover(self):
        """Talk like a 2026-07-28 client: server/discover, no initialize, _meta on every request."""
        self.meta = {
            "io.modelcontextprotocol/protocolVersion": DISCOVER_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        result = self.request("server/discover")["result"]
        if DISCOVER_PROTOCOL_VERSION not in result.get("supportedVersions", []):
            self.die(f"server/discover does not offer {DISCOVER_PROTOCOL_VERSION}: {json.dumps(result)[:300]}")
        return result

    def shutdown(self):
        """Close stdin like a client would and require a clean exit."""
        if self.proc.poll() is not None:
            self.die(f"server crashed (exit code {self.proc.returncode}) during the test")
        self.proc.stdin.close()
        try:
            code = self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.die("server did not exit within 15s after stdin was closed")
        self._stdout_done.join(timeout=5)
        self._stderr_done.join(timeout=5)
        if code != 0:
            self.die(f"server exited with code {code} after stdin was closed")


def check_no_leak(server, secrets_to_hide, run_name):
    output = server.output()
    for label, value in secrets_to_hide.items():
        if value in output:
            server.die(f"{run_name}: {label} appeared in server output")
    print(f"{run_name}: no environment leak in stdout or stderr")


def check_tools(tools, expected_tools, require_annotations):
    names = sorted(t.get("name", "?") for t in tools)
    print(f"tools/list OK: {len(tools)} tools")
    for name in names:
        print(f"  - {name}")
    if len(tools) < expected_tools:
        fail(f"expected at least {expected_tools} tools, got {len(tools)}")
    if MONGO_TOOL not in names:
        fail(f"expected tool '{MONGO_TOOL}' is missing")

    if require_annotations:
        problems = []
        for tool in tools:
            annotations = tool.get("annotations") or {}
            if not (tool.get("title") or annotations.get("title")):
                problems.append(f"{tool.get('name')}: missing title")
            for key, expected in REQUIRED_ANNOTATIONS.items():
                if annotations.get(key) is not expected:
                    problems.append(
                        f"{tool.get('name')}: {key} is {annotations.get(key)!r}, expected {expected!r}")
        if problems:
            fail("tool annotations incomplete:\n  " + "\n  ".join(problems))
        print("annotations OK")


def check_tool_error(server, result, label, require_tool_errors):
    """A call that must fail: report how it answered, and enforce isError when asked."""
    if "error" in result:
        kind = "JSON-RPC error"
    else:
        kind = "tool result, isError=" + str(bool(result.get("result", {}).get("isError")))
    print(f"{label} answered ({kind})")
    if require_tool_errors and not result.get("result", {}).get("isError"):
        server.die(f"{label}: expected a tool result with isError: true, got {kind}")


def base_env():
    env = dict(os.environ)
    # The server must not pick up a developer's or runner's real database.
    env.pop("NO2SQL_MONGO", None)
    return env


def run_without_mongo(command, args):
    canary = "no2sql-canary-" + secrets.token_hex(12)
    env = base_env()
    env["NO2SQL_SMOKE_CANARY"] = canary

    server = StdioServer(command, env, args.timeout)
    init = server.handshake()
    server_info = init.get("serverInfo", {})
    if not server_info.get("name"):
        server.die(f"initialize result has no serverInfo.name: {json.dumps(init)}")
    if "tools" not in init.get("capabilities", {}):
        server.die("initialize result does not advertise the tools capability")
    if canary in json.dumps(init):
        server.die("initialize result contains an environment value")
    print(f"initialize OK: {server_info.get('name')} {server_info.get('version')} "
          f"(protocol {init.get('protocolVersion')})")

    check_tools(server.request("tools/list")["result"].get("tools", []),
                args.expected_tools, args.require_annotations)

    # Error paths must answer, not crash.
    result = server.request("tools/call", {"name": MONGO_TOOL, "arguments": {}}, allow_error=True)
    check_tool_error(server, result, f"tools/call {MONGO_TOOL} without MongoDB", args.require_tool_errors)
    if args.require_tool_errors:
        result = server.request("tools/call", {"name": "test_connectivity", "arguments": {}}, allow_error=True)
        if "error" in result or result.get("result", {}).get("isError"):
            server.die(f"test_connectivity without MongoDB must succeed, got {json.dumps(result)[:300]}")
        print("tools/call test_connectivity without MongoDB answered (tool result, isError=False)")
    result = server.request("no2sql/smoke-unknown-method", allow_error=True)
    if "error" not in result:
        server.die("unknown method did not return a JSON-RPC error")
    print("unknown method answered with a JSON-RPC error")

    server.shutdown()
    print("run 1 (no MongoDB): clean exit")
    check_no_leak(server, {"canary environment value": canary}, "run 1")


def run_with_fake_mongo(command, args):
    # Random throwaway credential, generated per run (never a real secret).
    fake_pw = secrets.token_hex(16)
    # Port 9 (discard) on loopback refuses quickly; short timeouts keep CI fast.
    conn = (f"mongodb://no2sql_smoke:{fake_pw}@127.0.0.1:9/"
            "?serverSelectionTimeoutMS=2000&connectTimeoutMS=2000")
    env = base_env()
    env["NO2SQL_MONGO"] = conn

    server = StdioServer(command, env, args.timeout)
    server.handshake()
    result = server.request("tools/call", {"name": MONGO_TOOL, "arguments": {}}, allow_error=True)
    check_tool_error(server, result, f"tools/call {MONGO_TOOL} with unreachable MongoDB", args.require_tool_errors)
    server.shutdown()
    print("run 2 (unreachable MongoDB): clean exit")
    check_no_leak(server, {"MongoDB password": fake_pw, "MongoDB connection string": conn}, "run 2")


# Strings the driver rejects while parsing (MongoConfigurationException). That exception's
# message can quote the whole connection string, password included. The last two leaked the
# password to stderr in 1.1.1 (fixed by BL-1); keep them as the regression guard.
MALFORMED_MONGO_VARIANTS = [
    ("bad scheme", "mongo://no2sql_smoke:{pw}@127.0.0.1:9/"),
    ("invalid option value", "mongodb://no2sql_smoke:{pw}@127.0.0.1:9/?connectTimeoutMS=notanumber"),
    ("missing colon after scheme", "mongodb//no2sql_smoke:{pw}@127.0.0.1:9/"),
    ("bare value, not a URI", "{pw}"),
]


def run_with_malformed_mongo(command, args):
    for label, template in MALFORMED_MONGO_VARIANTS:
        fake_pw = secrets.token_hex(16)
        conn = template.format(pw=fake_pw)
        env = base_env()
        env["NO2SQL_MONGO"] = conn

        server = StdioServer(command, env, args.timeout)
        server.handshake()
        result = server.request("tools/call", {"name": MONGO_TOOL, "arguments": {}}, allow_error=True)
        check_tool_error(server, result, f"tools/call {MONGO_TOOL} with malformed NO2SQL_MONGO ({label})",
                         args.require_tool_errors)
        server.shutdown()
        print(f"run 3 (malformed NO2SQL_MONGO, {label}): clean exit")
        check_no_leak(server, {"MongoDB password": fake_pw, "MongoDB connection string": conn},
                      f"run 3 ({label})")


def run_with_discover(command, args):
    """Run 4: the server/discover path that current clients (Claude Code, OpenAI Agents SDK) use.
    No MongoDB first, then each malformed NO2SQL_MONGO, with the same error and leak checks."""
    canary = "no2sql-canary-" + secrets.token_hex(12)
    env = base_env()
    env["NO2SQL_SMOKE_CANARY"] = canary
    server = StdioServer(command, env, args.timeout)
    found = server.discover()
    name = found.get("_meta", {}).get("io.modelcontextprotocol/serverInfo", {}).get("name")
    print(f"server/discover OK: {name} ({DISCOVER_PROTOCOL_VERSION})")
    tools = server.request("tools/list")["result"]["tools"]
    check_tools(tools, args.expected_tools, args.require_annotations)
    result = server.request("tools/call", {"name": "test_connectivity", "arguments": {}}, allow_error=True)
    if "error" in result or result["result"].get("isError"):
        server.die(f"test_connectivity failed on the discover path: {json.dumps(result)[:300]}")
    result = server.request("tools/call", {"name": MONGO_TOOL, "arguments": {}}, allow_error=True)
    check_tool_error(server, result, f"discover: tools/call {MONGO_TOOL} without MongoDB", args.require_tool_errors)
    server.shutdown()
    print("run 4 (discover, no MongoDB): clean exit")
    check_no_leak(server, {"canary environment value": canary}, "run 4 (discover, no MongoDB)")

    for label, template in MALFORMED_MONGO_VARIANTS:
        fake_pw = secrets.token_hex(16)
        conn = template.format(pw=fake_pw)
        env = base_env()
        env["NO2SQL_MONGO"] = conn
        server = StdioServer(command, env, args.timeout)
        server.discover()
        result = server.request("tools/call", {"name": MONGO_TOOL, "arguments": {}}, allow_error=True)
        check_tool_error(server, result, f"discover: tools/call {MONGO_TOOL} with malformed NO2SQL_MONGO ({label})",
                         args.require_tool_errors)
        server.shutdown()
        print(f"run 4 (discover, malformed NO2SQL_MONGO, {label}): clean exit")
        check_no_leak(server, {"MongoDB password": fake_pw, "MongoDB connection string": conn},
                      f"run 4 (discover, {label})")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-tools", type=int, default=10)
    parser.add_argument("--require-annotations", action="store_true")
    parser.add_argument("--require-tool-errors", action="store_true",
                        help="failing MongoDB tool calls must return isError: true")
    parser.add_argument("--require-discover", action="store_true",
                        help=f"also run the server/discover ({DISCOVER_PROTOCOL_VERSION}) path")
    parser.add_argument("--timeout", type=float, default=45, help="seconds to wait for each response")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("missing server command after --")

    run_without_mongo(command, args)
    run_with_fake_mongo(command, args)
    run_with_malformed_mongo(command, args)
    if args.require_discover:
        run_with_discover(command, args)
    print("MCP smoke test passed")


if __name__ == "__main__":
    main()
