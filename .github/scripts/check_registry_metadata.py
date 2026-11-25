#!/usr/bin/env python3
"""Registry metadata gate for No2SQL.

Validates server.json against the schema named in its own `$schema`, checks that an
`io.github.` name uses the GitHub owner's login with its exact casing (the MCP Registry
rejected 1.1.0's lowercase `io.github.ptalati015`), and checks that every README contains
the `mcp-name: <server.json name>` marker exactly (the Registry matches it
case-sensitively against the NuGet package README).

With --package-version (CI passes the csproj's PackageVersion) it also checks the packages
(P2-9): the server version, the NuGet entry's version and the OCI image tag all equal it; the
OCI identifier is exactly ghcr.io/<--container-repository>:<version> with no separate version;
the OCI entry runs the image as a stdio server (-i, -e NO2SQL_TRANSPORT=stdio) and passes every
environment variable in with -e, never with a value; both entries declare the same environment
variables; and there is no `remotes` entry.

Usage:
  check_registry_metadata.py [--server-json PATH] [--readme PATH ...] [--schema-file PATH]
                             [--github-owner LOGIN]
                             [--package-version VERSION [--container-repository REPO]]

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


def check_packages(server, version, container_repository):
    """P2-9: the NuGet and OCI entries agree with the csproj and with each other."""
    if server.get("version") != version:
        fail(f"server.json version is {server.get('version')!r}, the csproj PackageVersion is {version!r}")
    if "remotes" in server:
        fail("server.json has a remotes entry; No2SQL is self-hosted only")

    packages = server.get("packages", [])
    by_type = {}
    for package in packages:
        registry_type = package.get("registryType")
        if registry_type in by_type:
            fail(f"server.json has more than one {registry_type!r} package")
        by_type[registry_type] = package
    if set(by_type) != {"nuget", "oci"}:
        fail(f"server.json packages are {sorted(by_type)}, expected ['nuget', 'oci']")

    nuget, oci = by_type["nuget"], by_type["oci"]
    if nuget.get("identifier") != "No2SQL" or nuget.get("version") != version:
        fail(f"NuGet entry is {nuget.get('identifier')!r} {nuget.get('version')!r}, expected 'No2SQL' {version!r}")

    expected_image = f"ghcr.io/{container_repository}:{version}"
    if oci.get("identifier") != expected_image:
        fail(f"OCI identifier is {oci.get('identifier')!r}, expected {expected_image!r}")
    if "version" in oci or "registryBaseUrl" in oci:
        fail("the OCI entry carries the version in its tag only; remove version and registryBaseUrl")
    if oci.get("transport", {}).get("type") != "stdio" or oci.get("runtimeHint") != "docker":
        fail("the OCI entry must be a stdio transport with runtimeHint 'docker'")

    names = [variable.get("name") for variable in nuget.get("environmentVariables", [])]
    if oci.get("environmentVariables") != nuget.get("environmentVariables"):
        fail("the OCI and NuGet entries must declare the same environmentVariables")

    arguments = oci.get("runtimeArguments", [])
    flags = [argument.get("name") for argument in arguments]
    if "-i" not in flags:
        fail("the OCI entry must pass -i so the client can talk to the container over stdin")
    passed = []
    for argument in arguments:
        if argument.get("name") != "-e":
            continue
        value = argument.get("value", "")
        if value == "NO2SQL_TRANSPORT=stdio":
            continue
        if "=" in value or "{" in value:
            fail(f"-e {value!r} puts a value on the docker command line; pass the variable by name only")
        passed.append(value)
    if not any(argument.get("value") == "NO2SQL_TRANSPORT=stdio" for argument in arguments):
        fail("the OCI entry must pass -e NO2SQL_TRANSPORT=stdio (the image defaults to HTTP mode)")
    if sorted(passed) != sorted(names):
        fail(f"the OCI entry passes {sorted(passed)} with -e, expected every environment variable {sorted(names)}")

    print(f"packages OK: NuGet No2SQL {version}, OCI {expected_image}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-json", default="No2SQL/.mcp/server.json")
    parser.add_argument("--readme", action="append", default=None)
    parser.add_argument("--schema-file")
    parser.add_argument("--github-owner", default=os.environ.get("GITHUB_REPOSITORY_OWNER"))
    parser.add_argument("--package-version", help="the csproj PackageVersion; enables the package checks")
    parser.add_argument("--container-repository", default="ptalati015/no2sql")
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

    if args.package_version:
        check_packages(server, args.package_version, args.container_repository)

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
