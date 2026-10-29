#!/usr/bin/env python3
"""Regenerate the supported vendor patch from the actual simpleredis checkout."""
import difflib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
source = Path(sys.argv[1]).resolve()
base = json.loads(subprocess.check_output(
    ["go", "mod", "download", "-json", "github.com/maxlerebourg/simpleredis@v1.0.12"],
    cwd=root, text=True,
))
if base.get("Error"):
    raise SystemExit(base["Error"])
patch = []
for name in ("simpleredis.go", "pool.go"):
    original = Path(base["Dir"]) / name
    before = original.read_text().splitlines(keepends=True) if original.exists() else []
    after = (source / name).read_text().splitlines(keepends=True)
    target = "vendor/github.com/maxlerebourg/simpleredis/" + name
    patch.append(f"diff --git a/{target} b/{target}\n")
    if not original.exists():
        patch.append("new file mode 100644\n")
    patch.extend(difflib.unified_diff(before, after, fromfile="a/"+target if original.exists() else "/dev/null", tofile="b/"+target))
(root / "patches/simpleredis-acl.patch").write_text("".join(patch))
