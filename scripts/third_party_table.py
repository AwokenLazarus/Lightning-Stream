#!/usr/bin/env python3
"""The dependency table of THIRD_PARTY_NOTICES.md ("Rust libraries"), from `cargo tree`.

  scripts/third_party_table.py           rewrite the table in place
  scripts/third_party_table.py --check   exit 1 (and print the difference) if the file's table is stale
  scripts/third_party_table.py --print   print the table and leave the file alone

One row for each crate and version the workspace links (normal and build dependencies, every
target), sorted by name and then by version, so the same Cargo.lock always gives the same bytes.
The workspace's own crates are left out; a crate vendored under `vendor/` says so in its version
cell. Runs cargo with --offline --locked: it reads the lock file and the local registry, and
changes neither.
"""
import difflib
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTICES = os.path.join(ROOT, "THIRD_PARTY_NOTICES.md")
HEAD = "| crate | version | licence |\n|---|---|---|\n"
TREE = ["cargo", "tree", "--offline", "--locked", "--workspace", "--target", "all", "-e", "normal,build", "--prefix", "none",
        "--format", "{p}|{l}|{r}"]


def version_key(v):
    """1.10.0 after 1.9.0; a pre-release before its release."""
    core, _, pre = v.partition("-")
    nums = tuple(int(x) if x.isdigit() else 0 for x in core.split("."))
    return (nums, pre == "", pre)


def rows():
    out = subprocess.run(TREE, cwd=ROOT, capture_output=True, text=True, check=False)
    if out.returncode != 0:
        sys.exit(f"cargo tree failed:\n{out.stderr}")
    seen = {}
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        pkg, licence, repo = (line.split("|") + ["", ""])[:3]
        repo = repo.replace("(*)", "").strip()
        m = re.match(r"^(\S+) v(\S+)(?: \((.*?)\))?(?: \(proc-macro\))?", pkg.strip())
        if not m:
            sys.exit(f"cannot read a cargo tree line: {line!r}")
        name, version, source = m.group(1), m.group(2), m.group(3) or ""
        vendored = ""
        if source.startswith("/"):
            rel = os.path.relpath(source, ROOT)
            if not rel.startswith("vendor" + os.sep):
                continue                       # one of the workspace's own crates
            vendored = f", vendored with a patch (`{rel}`)"
        elif source == "proc-macro":
            source = ""
        seen[(name, version)] = (repo, vendored, licence.strip())
    table = []
    for (name, version), (repo, vendored, licence) in sorted(seen.items(), key=lambda kv: (kv[0][0], version_key(kv[0][1]))):
        crate = f"[{name}]({repo})" if repo else name
        table.append(f"| {crate} | {version}{vendored} | {licence} |\n")
    return "".join(table)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode not in ("", "--check", "--print"):
        sys.exit(__doc__)
    table = HEAD + rows()
    if mode == "--print":
        sys.stdout.write(table)
        return 0
    with open(NOTICES, encoding="utf-8") as f:
        text = f.read()
    start = text.find(HEAD)
    if start < 0:
        sys.exit(f"{NOTICES}: no dependency table (its header row is missing)")
    end = text.find("\n\n", start)
    end = len(text) if end < 0 else end + 1
    new = text[:start] + table + text[end:]
    if new == text:
        print("THIRD_PARTY_NOTICES.md: the dependency table is current")
        return 0
    if mode == "--check":
        sys.stdout.writelines(difflib.unified_diff(text.splitlines(True), new.splitlines(True), "THIRD_PARTY_NOTICES.md", "regenerated"))
        print("THIRD_PARTY_NOTICES.md: the dependency table is stale (run scripts/third_party_table.py)")
        return 1
    with open(NOTICES, "w", encoding="utf-8") as f:
        f.write(new)
    print("THIRD_PARTY_NOTICES.md: dependency table rewritten")
    return 0


if __name__ == "__main__":
    sys.exit(main())
