#!/usr/bin/env python3
"""Rebuild the evidence store index from the run folders present.

Usage:
    reindex.py STORE_ROOT

STORE_ROOT holds one subdirectory per machine, each holding one
subdirectory per run. Rewrites, per machine:
    STORE_ROOT/<machine>/index.json   append-only-shaped run list
    STORE_ROOT/<machine>/latest       symlink -> newest run dir
and:
    STORE_ROOT/index.json             machine list + newest run each

Self-heals: run folders deleted by hand just drop out on the next run.
A run folder counts only if it has a run.json.
"""
import json
import os
import sys
from pathlib import Path

SKIP = {"index.json", "latest"}


def machine_index(mdir):
    runs = []
    for entry in sorted(mdir.iterdir()):
        if entry.name in SKIP or entry.is_symlink() or not entry.is_dir():
            continue
        run_json = entry / "run.json"
        if not run_json.is_file():
            continue
        try:
            meta = json.loads(run_json.read_text())
        except json.JSONDecodeError:
            continue
        meta["id"] = meta.get("id", entry.name)
        runs.append(meta)

    runs.sort(key=lambda r: r.get("generated", ""), reverse=True)
    (mdir / "index.json").write_text(json.dumps({"runs": runs}, indent=2) + "\n")

    latest = mdir / "latest"
    if latest.is_symlink() or latest.exists():
        latest.unlink()
    if runs:
        os.symlink(runs[0]["id"], latest)
    return runs


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = Path(sys.argv[1])
    if not root.is_dir():
        sys.exit(f"not a directory: {root}")

    machines = []
    for mdir in sorted(root.iterdir()):
        if mdir.name in SKIP or not mdir.is_dir() or mdir.is_symlink():
            continue
        runs = machine_index(mdir)
        if runs:
            machines.append({"machine": mdir.name, "runs": len(runs),
                             "latest": runs[0]["id"],
                             "generated": runs[0].get("generated", "")})

    root_index = {"machines": machines}
    (root / "index.json").write_text(json.dumps(root_index, indent=2) + "\n")
    print(f"reindexed {len(machines)} machine(s): "
          + ", ".join(f"{m['machine']}({m['runs']})" for m in machines))


if __name__ == "__main__":
    main()
