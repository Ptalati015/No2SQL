#!/usr/bin/env python3
"""Checks the No2SQL container image (P2-8) before it is pushed.

Reads the OCI archive that `dotnet publish -t:PublishContainer -p:ContainerArchiveOutputPath=...`
writes, without Docker and without unpacking it, and fails if any of these is wrong:

- the image index has exactly linux/amd64 and linux/arm64, and both tags point at it
- each image runs as the non-root "app" user and has no HEALTHCHECK
- the .NET and ASP.NET Core runtime in each image is at least --min-runtime
- NO2SQL_TRANSPORT=http and NO2SQL_HTTP_URLS=http://0.0.0.0:8787 are intact (an SDK bug once cut
  values at the first colon), port 8787 is exposed
- no secret or auth bypass is baked in: no NO2SQL_HTTP_TOKEN, NO2SQL_OWNER_PASSWORD, NO2SQL_MONGO,
  NO2SQL_MONGO_FILE variable, no --allow-anonymous in the entrypoint or command
- the MCP name label and the OCI source, revision and version labels are present and whole

Usage: container_image_gate.py ARCHIVE --version 1.2.0 [--min-runtime 10.0.15] [--require-revision]
"""

import argparse
import json
import sys
import tarfile

EXPECTED_PLATFORMS = {("linux", "amd64"), ("linux", "arm64")}
EXPECTED_ENV = {
    "NO2SQL_TRANSPORT": "http",
    "NO2SQL_HTTP_URLS": "http://0.0.0.0:8787",
    "DOTNET_EnableDiagnostics": "0",
    "NO2SQL_DATA_DIR": "/data",
}
FORBIDDEN_ENV = {"NO2SQL_HTTP_TOKEN", "NO2SQL_OWNER_PASSWORD", "NO2SQL_MONGO", "NO2SQL_MONGO_FILE"}
MCP_NAME = "io.github.Ptalati015/no2sql"
SOURCE = "https://github.com/Ptalati015/No2SQL"
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}


def version_tuple(text):
    return tuple(int(part) for part in text.split("-")[0].split("."))


class Archive:
    def __init__(self, path):
        self._tar = tarfile.open(path)
        self._names = set(self._tar.getnames())

    def json(self, name):
        if name not in self._names:
            raise SystemExit(f"FAIL: {name} is missing from the archive")
        return json.load(self._tar.extractfile(name))

    def blob(self, digest):
        algorithm, _, value = digest.partition(":")
        return self.json(f"blobs/{algorithm}/{value}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    parser.add_argument("--version", required=True)
    parser.add_argument("--min-runtime", default="10.0.15")
    parser.add_argument("--require-revision", action="store_true",
                        help="fail when org.opencontainers.image.revision is missing (CI builds from git)")
    args = parser.parse_args()

    archive = Archive(args.archive)
    failures = []

    def check(condition, message):
        if not condition:
            failures.append(message)

    top = archive.json("index.json")
    refs = {}
    for entry in top.get("manifests", []):
        name = entry.get("annotations", {}).get("org.opencontainers.image.ref.name")
        refs[name] = entry["digest"]
    check(set(refs) == {args.version, "latest"}, f"tags are {sorted(refs)}, expected [{args.version!r}, 'latest']")
    check(len(set(refs.values())) == 1, "the version tag and latest point at different images")

    index_digest = next(iter(refs.values()))
    index = archive.blob(index_digest)
    check(index.get("mediaType") in INDEX_TYPES, f"{index_digest} is not an image index")

    platforms = set()
    for manifest_ref in index.get("manifests", []):
        platform = manifest_ref.get("platform", {})
        arch = (platform.get("os"), platform.get("architecture"))
        platforms.add(arch)
        label = "/".join(str(part) for part in arch)
        manifest = archive.blob(manifest_ref["digest"])
        image = archive.blob(manifest["config"]["digest"])
        config = image.get("config", {})

        check((image.get("os"), image.get("architecture")) == arch, f"{label}: config says {image.get('os')}/{image.get('architecture')}")
        check(config.get("User") == "app", f"{label}: runs as {config.get('User')!r}, expected 'app'")
        check("Healthcheck" not in config, f"{label}: has a HEALTHCHECK; probe /healthz from outside instead")

        env = dict(item.split("=", 1) for item in config.get("Env", []))
        for key, value in EXPECTED_ENV.items():
            check(env.get(key) == value, f"{label}: {key}={env.get(key)!r}, expected {value!r}")
        for key in sorted(FORBIDDEN_ENV & env.keys()):
            failures.append(f"{label}: {key} is baked into the image")

        for key in ("DOTNET_VERSION", "ASPNET_VERSION"):
            found = env.get(key)
            if found is None:
                failures.append(f"{label}: {key} is not set, cannot check the runtime version")
            elif version_tuple(found) < version_tuple(args.min_runtime):
                failures.append(f"{label}: {key}={found} is older than {args.min_runtime}")
            else:
                print(f"{label}: {key}={found}")

        command = (config.get("Entrypoint") or []) + (config.get("Cmd") or [])
        check(not any("allow-anonymous" in part for part in command), f"{label}: the command line contains --allow-anonymous")
        check("8787/tcp" in config.get("ExposedPorts", {}), f"{label}: port 8787 is not exposed")

        labels = config.get("Labels", {})
        check(labels.get("io.modelcontextprotocol.server.name") == MCP_NAME, f"{label}: MCP name label is {labels.get('io.modelcontextprotocol.server.name')!r}")
        check(labels.get("org.opencontainers.image.source") == SOURCE, f"{label}: source label is {labels.get('org.opencontainers.image.source')!r}")
        check(labels.get("org.opencontainers.image.version") == args.version, f"{label}: version label is {labels.get('org.opencontainers.image.version')!r}")
        revision = labels.get("org.opencontainers.image.revision", "")
        if args.require_revision:
            check(len(revision) == 40, f"{label}: revision label is {revision!r}, expected a commit SHA")
        for key, value in labels.items():
            if key.endswith((".url", ".documentation", ".source")):
                check("://" in value, f"{label}: label {key}={value!r} looks cut off")
        print(f"{label}: user={config.get('User')} entrypoint={command} revision={revision or '-'}")

    check(platforms == EXPECTED_PLATFORMS, f"platforms are {sorted(platforms)}, expected {sorted(EXPECTED_PLATFORMS)}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(f"OK: image index {index_digest} passes the container gate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
