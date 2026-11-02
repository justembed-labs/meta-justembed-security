#!/usr/bin/env python3
"""Hashes every real input a triage run depends on, so a later run against
the same frozen inputs can be checked for identical output (docs/cve-triage.md
rule 1: reproducibility proven, not assumed). The model ID and prompt
revision count as inputs too, same as a source file or a CVE-DB snapshot --
a changed prompt is a new generation of the pipeline, not an invisible
change to "the same" one.

Usage:
    freeze_triage_inputs.py OUT_JSON [--spdx FILE] [--kernel-ref REF]
        [--linux-vulns-dir DIR] [--kev-file FILE] [--epss-file FILE]
        [--model MODEL] [--prompt-revision REV]

Every input is best-effort: a missing file/dir hashes as null, not a
hard failure -- this stage's whole job is recording what was actually
used for this run, including "nothing", not gatekeeping whether the run
proceeds.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def sha256_file(path):
    if not path or not Path(path).is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git_head(path):
    if not path or not Path(path, ".git").exists():
        return None
    r = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                        capture_output=True, text=True, timeout=10)
    return r.stdout.strip() if r.returncode == 0 else None


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("out_json")
    p.add_argument("--spdx")
    p.add_argument("--kernel-ref")
    p.add_argument("--linux-vulns-dir")
    p.add_argument("--kev-file")
    p.add_argument("--epss-file")
    p.add_argument("--model")
    p.add_argument("--prompt-revision")
    args = p.parse_args()

    manifest = {
        "spdx_sha256": sha256_file(args.spdx),
        "kernel_ref": args.kernel_ref,
        "linux_vulns_commit": git_head(args.linux_vulns_dir),
        "kev_file_sha256": sha256_file(args.kev_file),
        "epss_file_sha256": sha256_file(args.epss_file),
        "ai_model": args.model,
        "ai_prompt_revision": args.prompt_revision,
    }
    manifest["generation_hash"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True).encode()
    ).hexdigest()[:16]

    Path(args.out_json).write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"froze triage inputs -> generation {manifest['generation_hash']} ({args.out_json})")


if __name__ == "__main__":
    main()
