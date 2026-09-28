#!/usr/bin/env python3
"""Real source-level backport verification for kernel CVEs
kernel_cve_triage.py couldn't resolve via ancestor-check alone.

For every needs_human_review entry that has candidate_commits (a
same-subject commit was found upstream, but wasn't confirmed as an
ancestor of our build): tries `git apply --check` (forward) and
`git apply --check --reverse` for each candidate, directly against
KERNEL_GIT_DIR -- the real checkout a build already has at OUR_REF, no
separate worktree needed.

  - forward applies cleanly  -> our source is byte-for-byte (modulo
    context git itself tolerates) the PRE-fix state -> vulnerable,
    high confidence.
  - reverse applies cleanly  -> our source already matches the
    POST-fix state -> patched, high confidence.
  - neither applies for any candidate -> the vendor tree has diverged
    at that location (reformatted equivalent fix, or genuinely
    unrelated) -> diverged, not guessed either way.

Exact match only, no fuzzing -- a reformatted-but-equivalent backport
correctly falls into "diverged", not a false "patched". See
docs/cve-triage.md for why this matters and how it was validated.

Usage:
    kernel_backport_check.py KERNEL_GIT_DIR OUR_REF TRIAGE_JSON OUT_PREFIX
        [--spdx SPDX_FILE] [--max-candidates N]

KERNEL_GIT_DIR   the real kernel source checkout (e.g.
                 ${TMPDIR}/work-shared/${MACHINE}/kernel-source),
                 already at OUR_REF -- nothing is modified, only
                 `git apply --check` (dry-run).
OUR_REF          that tree's checked-out commit (same one
                 kernel_cve_triage.py was given).
TRIAGE_JSON      kernel_cve_triage.py's own OUT_PREFIX.json (reads its
                 needs_human_review bucket).
OUT_PREFIX       writes OUT_PREFIX.json/.md.
--spdx           optional kernel SPDX doc (recipe-<PN>.spdx.json) with
                 compiled-sources data, for the not-applicable-config
                 path. Without it, only vulnerable/patched/diverged.
"""
import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kernel_cve_triage import write_report  # noqa: E402

DEFAULT_MAX_CANDIDATES = 3


def git(kernel_dir, *args, input_text=None):
    r = subprocess.run(["git", "-C", kernel_dir] + list(args), capture_output=True,
                        text=True, errors="replace", input=input_text, timeout=30)
    return r.returncode, r.stdout, r.stderr


def files_touched(kernel_dir, commit):
    rc, out, _ = git(kernel_dir, "show", "--stat", "--format=", commit)
    if rc != 0:
        return []
    files = []
    for line in out.splitlines():
        if "|" not in line:
            continue
        path = line.split("|", 1)[0].strip()
        if path:
            files.append(path)
    return files


def get_patch(kernel_dir, commit):
    rc, out, _ = git(kernel_dir, "show", commit)
    return out if rc == 0 else None


def check_apply(kernel_dir, patch, reverse=False):
    args = ["apply", "--check", "-p1"]
    if reverse:
        args.append("--reverse")
    rc, _, _ = git(kernel_dir, *args, input_text=patch)
    return rc == 0


def compiled_files(spdx_path):
    if not spdx_path:
        return None
    d = json.loads(Path(spdx_path).read_text(encoding="ISO-8859-1"))
    names = set()
    for f in d.get("files", []):
        fn = f.get("fileName", "")
        names.add(fn.split("/", 1)[1] if "/" in fn else fn)
    return names


def verify_one(kernel_dir, our_ref, candidates, compiled, max_candidates):
    for candidate in candidates[:max_candidates]:
        patch = get_patch(kernel_dir, candidate)
        if patch is None:
            continue
        touched = files_touched(kernel_dir, candidate)
        if compiled is not None and touched and not any(p in compiled for p in touched):
            return "not-applicable-config", candidate
        if check_apply(kernel_dir, patch, reverse=True):
            return "patched", candidate
        if check_apply(kernel_dir, patch, reverse=False):
            return "vulnerable", candidate
    return "diverged", candidates[0] if candidates else None


def rebucket(results):
    """Same 4-bucket shape as kernel_cve_triage.py/kernel_cve_upstream_triage.py
    -- a drop-in third triage_jsons source for prioritize_cves.py, no
    changes needed there. "vulnerable" stays in needs_human_review
    (confirmed, not noise -- still needs a human decision on remediation)
    but is tagged so the viewer can show it distinctly from a genuine
    unknown."""
    inapplicable, fixed, mismatch, review = [], [], [], []
    for r in results:
        cve, commit, verdict = r["cve"], r.get("commit") or "", r["verdict"]
        short = commit[:12]
        if verdict == "not-applicable-config":
            inapplicable.append({
                "cve": cve, "source": "backport-check",
                "config_symbol": "backport-check", "file": f"fix commit {short} touches file(s) not compiled in",
                "reason": f"Candidate fix {short} touches only files not present in the SPDX compiled-sources list",
                "suggested_cve_status": f'CVE_STATUS[{cve}] = "not-applicable-config: not compiled (backport-check, {short})"',
            })
        elif verdict == "patched":
            fixed.append({
                "cve": cve, "source": "backport-check", "commit": short,
                "subject": f"backport confirmed present (git apply --check --reverse against {short})",
                "suggested_cve_status": f'CVE_STATUS[{cve}] = "fixed-version: backport confirmed present, {short}"',
            })
        elif verdict == "vulnerable":
            review.append({
                "cve": cve, "source": "backport-check", "confirmed": True,
                "reason": f"CONFIRMED vulnerable: fix {short} absent from source (git apply --check, exact match), file compiled in",
            })
        else:  # diverged
            review.append({
                "cve": cve, "source": "backport-check", "confirmed": False,
                "reason": f"source diverged from both pre- and post-fix state at candidate {short} -- needs a human diff",
            })
    return inapplicable, fixed, mismatch, review


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("kernel_git_dir")
    p.add_argument("our_ref")
    p.add_argument("triage_json")
    p.add_argument("out_prefix")
    p.add_argument("--spdx")
    p.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    args = p.parse_args()

    triage = json.loads(Path(args.triage_json).read_text())
    package = triage.get("package", "unknown")
    targets = [e for e in triage.get("needs_human_review", []) if e.get("candidate_commits")]
    compiled = compiled_files(args.spdx)

    results = []
    for t in targets:
        verdict, commit = verify_one(args.kernel_git_dir, args.our_ref, t["candidate_commits"],
                                      compiled, args.max_candidates)
        results.append({"cve": t["cve"], "commit": commit, "verdict": verdict})

    inapplicable, fixed, mismatch, review = rebucket(results)
    write_report(args.out_prefix, package, args.our_ref, len(results), inapplicable, fixed, mismatch, review)
    counts = Counter(r["verdict"] for r in results)
    print(f"backport check: {len(results)} checked -- " +
          ", ".join(f"{v}={counts.get(v, 0)}" for v in
                     ("vulnerable", "patched", "not-applicable-config", "diverged")))


if __name__ == "__main__":
    main()
