#!/usr/bin/env python3
"""Fail when a shipped No2SQL build bundles a .NET runtime with a known vulnerability.

`dotnet list package --vulnerable` checks PackageReferences only. The .NET runtime and ASP.NET Core
that a self-contained build carries come from framework runtime packs
(Microsoft.NETCore.App.Runtime.<rid>, Microsoft.AspNetCore.App.Runtime.<rid>). Their patch level is
chosen by the SDK that built the exe, and that check cannot see them. This gate reads the packs and
versions recorded in the build's deps.json and looks them up in the nuget.org vulnerability feed, the
same data `dotnet list package --vulnerable` uses.

usage: runtime_vuln_gate.py [--feed-file FILE] [--allow GHSA-...]... PATH...
       runtime_vuln_gate.py --self-test

--allow GHSA-xxxx-xxxx-xxxx accepts one advisory (for an emergency release only; say why in the workflow).

Each PATH can be one of:
  - a single-file exe (No2SQL, No2SQL.exe): deps.json is read from the bundle
  - a .zip or .nupkg: every single-file exe inside it is checked
  - a *.deps.json file, or a directory: every *.deps.json and single-file exe in it (not recursive)

Exit codes: 0 = no known advisory; 1 = an advisory applies (or --allow was needed and not given);
2 = usage error, unreadable input, or a PATH with no runtime pack in it (fails closed, so a layout
change cannot make the gate pass by finding nothing). The feed is fetched from api.nuget.org unless
--feed-file is given; a feed that cannot be fetched also exits 2.

Python 3 standard library only. Run with python3 -I.
"""
import gzip
import io
import json
import os
import re
import struct
import sys
import urllib.request
import zipfile

FEED_INDEX = "https://api.nuget.org/v3/vulnerabilities/index.json"
SEVERITY = {0: "low", 1: "moderate", 2: "high", 3: "critical"}

# SHA-256 of ".net core bundle": the marker the .NET single-file host searches for. The 8 bytes in front
# of it hold the offset of the bundle header.
BUNDLE_SIGNATURE = bytes([
    0x8B, 0x12, 0x02, 0xB9, 0x6A, 0x61, 0x20, 0x38, 0x72, 0x7B, 0x93, 0x02, 0x14, 0xD7, 0xA0, 0x32,
    0x13, 0xF5, 0xB9, 0xE6, 0xEF, 0xAE, 0x33, 0x18, 0xEE, 0x3B, 0x2D, 0xCE, 0x24, 0xB3, 0x6A, 0xAE,
])

# Framework runtime packs that a self-contained build can carry. deps.json lists each one as a
# library "runtimepack.<pack id>/<version>".
RUNTIME_PACK = re.compile(r"^runtimepack\.(Microsoft\.(?:NETCore|AspNetCore)\.App\.Runtime\.[A-Za-z0-9.\-]+)/(\S+)$")


class GateError(Exception):
    pass


# ---------------------------------------------------------------------------------------------- versions

def parse_version(text):
    """NuGet/SemVer 2 version -> sortable key. Release sorts after every prerelease of the same number."""
    text = text.strip().split("+", 1)[0]
    core, dash, pre = text.partition("-")
    try:
        nums = [int(p) for p in core.split(".")]
    except ValueError:
        raise GateError(f"not a version: {text!r}") from None
    if not 1 <= len(nums) <= 4:
        raise GateError(f"not a version: {text!r}")
    nums += [0] * (4 - len(nums))
    if not dash:
        return (tuple(nums), 1, ())
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p.lower()) for p in pre.split("."))
    return (tuple(nums), 0, ids)


def in_range(version, rng):
    """True when version is inside a NuGet version range such as "[10.0.0, 10.0.14)", "(, 0.48.0)" or "1.2.3"."""
    v = parse_version(version)
    rng = rng.strip()
    if rng[0] not in "[(":
        return v >= parse_version(rng)            # a bare version means "this or higher"
    lo_incl, hi_incl = rng[0] == "[", rng[-1] == "]"
    body = rng[1:-1]
    if "," not in body:                           # "[1.2.3]" is an exact match
        return v == parse_version(body)
    lo, hi = (p.strip() for p in body.split(",", 1))
    if lo and (v < parse_version(lo) or (v == parse_version(lo) and not lo_incl)):
        return False
    if hi and (v > parse_version(hi) or (v == parse_version(hi) and not hi_incl)):
        return False
    return True


# ---------------------------------------------------------------------------------------------- inputs

def deps_from_bundle(data):
    """Returns the deps.json text embedded in a .NET single-file exe, or None when data is not a bundle."""
    at = data.rfind(BUNDLE_SIGNATURE)
    if at < 8:
        return None
    (header_offset,) = struct.unpack_from("<q", data, at - 8)
    if header_offset <= 0 or header_offset >= len(data):
        return None
    major, _minor, _count = struct.unpack_from("<IIi", data, header_offset)
    if major < 2:
        raise GateError(f"single-file bundle version {major} has no deps.json offset")
    pos = header_offset + 12
    # bundle id: a string with a 7-bit encoded length
    length, shift = 0, 0
    while True:
        b = data[pos]
        pos += 1
        length |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            break
    pos += length
    deps_offset, deps_size = struct.unpack_from("<qq", data, pos)
    if deps_size <= 0 or deps_offset + deps_size > len(data):
        raise GateError("single-file bundle has no deps.json")
    raw = data[deps_offset:deps_offset + deps_size]
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    elif raw[:1] not in (b"{", b"\xef"):
        raise GateError("the bundled deps.json is compressed (EnableCompressionInSingleFile); this gate cannot read it")
    return raw.decode("utf-8-sig")


def packs_from_deps(text):
    """{pack id: version} for every framework runtime pack listed in a deps.json."""
    deps = json.loads(text)
    found = {}
    for name in deps.get("libraries", {}):
        m = RUNTIME_PACK.match(name)
        if m:
            found[m.group(1)] = m.group(2)
    return found


def collect(path):
    """Yields (label, {pack: version}) for each build found at path."""
    if os.path.isdir(path):
        any_found = False
        for entry in sorted(os.listdir(path)):
            full = os.path.join(path, entry)
            if os.path.isfile(full) and (entry.endswith(".deps.json") or _is_bundle_file(full)):
                any_found = True
                yield from collect(full)
        if not any_found:
            yield path, {}
        return
    if path.endswith(".deps.json"):
        with open(path, encoding="utf-8-sig") as f:
            yield path, packs_from_deps(f.read())
        return
    if zipfile.is_zipfile(path):
        any_found = False
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir() or info.file_size < 1_000_000:
                    continue
                text = deps_from_bundle(z.read(info))
                if text is not None:
                    any_found = True
                    yield f"{path}!{info.filename}", packs_from_deps(text)
        if not any_found:
            yield path, {}
        return
    with open(path, "rb") as f:
        text = deps_from_bundle(f.read())
    yield path, packs_from_deps(text) if text is not None else {}


def _is_bundle_file(path):
    if os.path.getsize(path) < 1_000_000:
        return False
    with open(path, "rb") as f:
        return f.read().rfind(BUNDLE_SIGNATURE) >= 8


# ---------------------------------------------------------------------------------------------- feed

def _get_json(url):
    req = urllib.request.Request(url, headers={"Accept-Encoding": "gzip", "User-Agent": "no2sql-ci-runtime-gate"})
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read()
    return json.loads(gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw)


def load_feed(feed_file):
    """{lowercase package id: [advisory, ...]}, merged from the feed's base and update pages."""
    if feed_file:
        with open(feed_file, encoding="utf-8") as f:
            return {k.lower(): v for k, v in json.load(f).items()}
    try:
        merged = {}
        for page in _get_json(FEED_INDEX):
            for pkg, advisories in _get_json(page["@id"]).items():
                merged.setdefault(pkg.lower(), []).extend(advisories)
        return merged
    except Exception as ex:  # noqa: BLE001 - any failure here must fail the gate, not pass it
        raise GateError(f"could not read the nuget.org vulnerability feed ({ex})") from ex


# ---------------------------------------------------------------------------------------------- self-test

SELF_TEST_RANGES = [
    ("10.0.13", "[10.0.0, 10.0.14)", True), ("10.0.14", "[10.0.0, 10.0.14)", False),
    ("10.0.14", "[10.0.0, 10.0.14]", True), ("10.0.15", "[10.0.0-0, 10.0.14]", False),
    ("10.0.0-rc.1.25451.107", "[10.0.0-rc.1.25451.107, 10.0.0-rc.1.25451.107]", True),
    ("10.0.0", "[10.0.0-rc.1.25451.107, 10.0.0-rc.1.25451.107]", False),
    ("10.0.0-preview.1", "[10.0.0, 10.0.3]", False), ("10.0.0-preview.1", "[10.0.0-0, 10.0.3]", True),
    ("0.47.4", "(, 0.48.0)", True), ("0.48.0", "(, 0.48.0)", False),
    ("10.0.0", "(10.0.0, 10.0.3)", False), ("10.0.2", "(10.0.0, 10.0.3)", True),
    ("2.0", "1.5", True), ("1.4", "1.5", False), ("1.2.3", "[1.2.3]", True), ("1.2.4", "[1.2.3]", False),
    ("10.0.15+abc", "[10.0.0, 10.0.15)", False),
]


def self_test():
    bad = [c for c in SELF_TEST_RANGES if in_range(c[0], c[1]) != c[2]]
    deps = json.dumps({"libraries": {
        "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/10.0.14": {},
        "runtimepack.Microsoft.AspNetCore.App.Runtime.linux-x64/10.0.14": {},
        "MongoDB.Driver/3.8.0": {}}})
    packs = packs_from_deps(deps)
    if packs != {"Microsoft.NETCore.App.Runtime.linux-x64": "10.0.14", "Microsoft.AspNetCore.App.Runtime.linux-x64": "10.0.14"}:
        bad.append(("packs_from_deps", packs))
    for case in bad:
        print(f"::error::self-test failed: {case}")
    print(f"self-test: {len(SELF_TEST_RANGES) + 1 - len(bad)}/{len(SELF_TEST_RANGES) + 1} ok")
    return 1 if bad else 0


# ---------------------------------------------------------------------------------------------- main

def main(argv):
    feed_file, allowed, paths = None, set(), []
    it = iter(argv)
    for a in it:
        if a == "--feed-file":
            feed_file = next(it, None)
        elif a == "--allow":
            allowed.add(next(it, "").strip().upper())
        elif a == "--self-test":
            return self_test()
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        elif a.startswith("--"):
            raise GateError(f"unknown option {a}")
        else:
            paths.append(a)
    if not paths:
        raise GateError("no PATH given")

    builds = []
    for p in paths:
        if not os.path.exists(p):
            raise GateError(f"{p} does not exist")
        builds.extend(collect(p))

    empty = [label for label, packs in builds if not packs]
    if empty:
        for label in empty:
            print(f"::error::{label}: no framework runtime pack found (not a self-contained build?)")
        return 2

    feed = load_feed(feed_file)
    hits, used_allow = 0, set()
    for label, packs in builds:
        print(f"{label}")
        for pack, version in sorted(packs.items()):
            advisories = [a for a in feed.get(pack.lower(), []) if in_range(version, a["versions"])]
            if not advisories:
                print(f"  ok    {pack} {version}")
                continue
            for a in advisories:
                ghsa = a["url"].rstrip("/").rsplit("/", 1)[-1].upper()
                sev = SEVERITY.get(a.get("severity"), str(a.get("severity")))
                if ghsa in allowed:
                    used_allow.add(ghsa)
                    print(f"  allow {pack} {version}: {sev} {a['url']} (affected {a['versions']})")
                else:
                    hits += 1
                    print(f"::error::{label}: {pack} {version} has a {sev} advisory {a['url']} (affected {a['versions']})")
    for ghsa in sorted(allowed - used_allow):
        print(f"::warning::--allow {ghsa} matched nothing; remove it")

    if hits:
        print(f"FAIL: {hits} advisory match(es). Build with an SDK whose runtime is patched "
              f"(setup-dotnet 10.0.x picks the newest SDK), or pin RuntimeFrameworkVersion.")
        return 1
    print(f"PASS: {sum(len(p) for _, p in builds)} runtime pack(s) in {len(builds)} build(s), no known advisory")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except GateError as e:
        print(f"::error::{e}")
        sys.exit(2)
