#!/usr/bin/env python3
"""Registry metadata gate for No2SQL.

Validates server.json against the schema named in its own `$schema`, checks that an
`io.github.` name uses the GitHub owner's login with its exact casing (the MCP Registry
rejected 1.1.0's lowercase `io.github.ptalati015`), and checks that every README contains
the `mcp-name: <server.json name>` marker exactly (the Registry matches it
case-sensitively against the NuGet package README).

Usage:
  check_registry_metadata.py [--server-json PATH] [--readme PATH ...] [--schema-file PATH]
                             [--github-owner LOGIN]

--github-owner defaults to $GITHUB_REPOSITORY_OWNER (set in GitHub Actions); the owner
check is skipped when neither is given.

--schema-file validates against a local copy instead of downloading `$schema`
(for offline runs); the file's `$id` must still match `$schema`.
"""

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request

import jsonschema

# Only official MCP schemas are fetched; anything else in $schema is an error.
ALLOWED_SCHEMA_HOST = "static.modelcontextprotocol.io"


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def load_schema(schema_url, schema_file):
    parsed = urllib.parse.urlparse(schema_url)
    if parsed.scheme != "https" or parsed.hostname != ALLOWED_SCHEMA_HOST:
        fail(f"$schema must be an https URL on {ALLOWED_SCHEMA_HOST}, got {schema_url!r}")

    if schema_file:
        with open(schema_file, encoding="utf-8") as f:
            schema = json.load(f)
        if schema.get("$id") != schema_url:
            fail(f"{schema_file} has $id {schema.get('$id')!r}, expected {schema_url!r}")
        return schema

    with urllib.request.urlopen(schema_url, timeout=30) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-json", default="No2SQL/.mcp/server.json")
    parser.add_argument("--readme", action="append", default=None)
    parser.add_argument("--schema-file")
    parser.add_argument("--github-owner", default=os.environ.get("GITHUB_REPOSITORY_OWNER"))
    args = parser.parse_args()
    readmes = args.readme or ["README.md", "No2SQL/README.md"]

    with open(args.server_json, encoding="utf-8") as f:
        server = json.load(f)

    schema_url = server.get("$schema")
    if not schema_url:
        fail(f"{args.server_json} has no $schema")
    schema = load_schema(schema_url, args.schema_file)

    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    errors = sorted(validator_cls(schema).iter_errors(server), key=lambda e: list(e.path))
    if errors:
        for error in errors:
            location = "/".join(str(p) for p in error.path) or "(root)"
            print(f"  {location}: {error.message}", file=sys.stderr)
        fail(f"{args.server_json} has {len(errors)} schema error(s) against {schema_url}")
    print(f"server.json OK against {schema_url}")

    name = server.get("name")
    if not name:
        fail(f"{args.server_json} has no name")
    if args.github_owner and name.lower().startswith("io.github."):
        expected_prefix = f"io.github.{args.github_owner}/"
        if not name.startswith(expected_prefix):
            fail(f"server.json name {name!r} must start with {expected_prefix!r} "
                 "(the Registry matches the GitHub login case-sensitively)")
        print(f"name namespace OK: {expected_prefix}")

    marker = f"mcp-name: {name}"
    for readme in readmes:
        with open(readme, encoding="utf-8") as f:
            text = f.read()
        if marker not in text:
            # Point at a near miss (wrong case or old name) when there is one.
            near = [line.strip() for line in text.splitlines() if "mcp-name:" in line]
            hint = f" (found: {near})" if near else ""
            fail(f"{readme} does not contain '{marker}' exactly{hint}")
        print(f"{readme}: '{marker}' found")

    print("Registry metadata gate passed")


if __name__ == "__main__":
    main()
