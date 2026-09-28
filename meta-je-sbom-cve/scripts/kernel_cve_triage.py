#!/usr/bin/env python3
"""Triage kernel CVEs flagged "unpatched" by cve-check (yocto-bsp#22).

Version-range matching can't see stable/vendor-tree backports already
merged, or catch a CPE mismatch onto an unrelated CVE entirely -- on a
typical embedded target, the kernel alone can account for the
overwhelming majority of "unpatched" hits. This automates what's
tractable and flags the rest for human review; it never edits a
recipe itself.

Not kernel-only despite the name -- PACKAGE and the CPE-mismatch
keyword list are both parameters (see DEFAULT_KEYWORDS), same script
works against u-boot's own git tree/.config, or in principle any
Kconfig-driven package. The ancestor-check and config-inapplicable
buckets need a commit reference quoted in the CVE summary (the kernel's
auto-CNA style) to have anything to check -- packages with traditional
prose advisories (u-boot) only get the CPE-mismatch check for now.

Usage:
    kernel_cve_triage.py PARSED_DIR KERNEL_GIT_DIR OUR_REF KCONFIG [PACKAGE] [OUT_PREFIX] [KEYWORDS]

PARSED_DIR    a parse_cve.py output dir (has unpatched.csv)
KERNEL_GIT_DIR path to the source git tree, e.g.
              build/tmp-glibc/work-shared/<machine>/kernel-source, or
              build/tmp-glibc/work/<machine>/u-boot-*/<pv>/git
OUR_REF       the commit our build actually used (that tree's HEAD
              right after a build; do not use a branch name that may
              have moved)
KCONFIG       path to our build's actual .config
PACKAGE       cve-check package name to triage (default: linux-ti-staging)
OUT_PREFIX    output file prefix (default: kernel-cve-triage)
KEYWORDS      comma-separated CPE-mismatch keywords (default: looked up
              from PACKAGE in DEFAULT_KEYWORDS)

Writes OUT_PREFIX.json and OUT_PREFIX.md, four buckets:

  config_inapplicable_candidates -- the fix commit's own touched files
    map to a Kconfig symbol (via the governing Makefile's
    `obj-$(CONFIG_X) += file.o`) that's flat-out not set in KCONFIG --
    the vulnerable code was never even compiled in, so the CVE can't
    be reached regardless of whether the fix is present. This is
    exactly the CONFIG_TUN situation meta-je-detection's own
    CVE-2026-73283 rule hit, found manually before this check existed
    -- checked ahead of the other buckets since "the code isn't even
    built" is a stronger answer than "here's its patch status".
  fixed_version_candidates -- summary names an upstream commit we
    confirmed via `git merge-base --is-ancestor <commit> OUR_REF` (not
    --all -- that only proves the commit exists somewhere in the
    mirror, not that it's actually in our build). Safe to record as
    CVE_STATUS[<cve>] = "fixed-version: ..." -- the suggested line is
    included, but this script never writes it into a recipe itself.
  cpe_mismatch_candidates -- summary doesn't even mention "linux" or
    "kernel" (e.g. a Chrome/V8 CVE mismatched onto the linux_kernel
    CPE) -- needs a human to confirm before recording
    CVE_STATUS[...] = "not-applicable-config: ...".
  needs_human_review -- everything else: no commit-like text found, or
    a candidate commit exists upstream but isn't an ancestor of
    OUR_REF (equivalent-but-different fix vs. genuinely open -- can't
    tell from commit presence alone).
"""
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

RESOLVED_MARKER = "vulnerability has been resolved:"


def load_kernel_rows(parsed_dir, package):
    path = Path(parsed_dir) / "unpatched.csv"
    rows = []
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            if row["package"] == package:
                rows.append(row)
    return rows


def looks_like_match(summary, keywords):
    s = summary.lower()
    return any(k in s for k in keywords)


def extract_commit_subject(summary):
    idx = summary.lower().find(RESOLVED_MARKER)
    if idx == -1:
        return None
    rest = summary[idx + len(RESOLVED_MARKER):]
    for line in rest.splitlines():
        line = line.strip()
        if line:
            return line
    return None


def ensure_commit_graph(kernel_dir):
    """Without this, `git merge-base --is-ancestor` on a 2M+-commit mirror
    costs ~1.8s each -- with thousands of candidates to check, that's
    tens of minutes. `git commit-graph write` is a one-time (~30s here),
    safe, standard git operation (just an object-store cache, no tracked
    content touched) that drops it to ~3ms. Safe to call every run --
    near-instant no-op if already up to date."""
    subprocess.run(
        ["git", "-C", kernel_dir, "commit-graph", "write", "--reachable"],
        capture_output=True, timeout=120,
    )


def build_subject_index(kernel_dir):
    """One pass over the whole mirror (2M+ commits here) instead of one
    `git log --grep` per CVE -- the per-CVE-query version timed out in
    practice. Maps each commit's exact subject line (first line of the
    message, which is what kernel auto-CVE summaries quote) to every
    commit hash sharing it (subject collisions happen -- cherry-picks,
    stable backports of the same fix)."""
    # Not text=True: 2M+ commits spanning decades of the kernel's history
    # include at least one non-UTF-8 commit message (old tooling/authors)
    # -- decode ourselves with errors="replace" rather than let a single
    # bad byte crash the whole index build.
    out = subprocess.run(
        ["git", "-C", kernel_dir, "log", "--all", "--format=%H\x01%s"],
        capture_output=True, timeout=300,
    )
    index = {}
    for line in out.stdout.decode("utf-8", errors="replace").splitlines():
        h, _, subject = line.partition("\x01")
        if subject:
            index.setdefault(subject, []).append(h)
    return index


def is_ancestor(kernel_dir, commit, our_ref):
    r = subprocess.run(
        ["git", "-C", kernel_dir, "merge-base", "--is-ancestor", commit, our_ref],
        capture_output=True, timeout=60,
    )
    return r.returncode == 0


def files_touched_by_commit(kernel_dir, commit):
    out = subprocess.run(
        ["git", "-C", kernel_dir, "show", "--stat", "--format=", commit],
        capture_output=True, text=True, timeout=30,
    )
    files = []
    for line in out.stdout.splitlines():
        if "|" not in line:
            continue
        path = line.split("|", 1)[0].strip()
        if path:
            files.append(path)
    return files


_OBJ_RULE_CACHE = {}


def find_config_symbol(kernel_dir, filepath):
    """Best-effort: the Kconfig symbol gating this file's compilation,
    via the Makefile in the same directory (kbuild's
    `obj-$(CONFIG_X) += file.o` convention). None if the file doesn't
    map cleanly to one symbol -- composite objects, per-file CFLAGS,
    and subdir-y indirection all fall outside what this catches, so a
    None result means "couldn't tell", not "always built"."""
    p = Path(filepath)
    if p.suffix not in (".c", ".h"):
        return None
    makefile = Path(kernel_dir) / p.parent / "Makefile"
    key = str(makefile)
    if key not in _OBJ_RULE_CACHE:
        try:
            _OBJ_RULE_CACHE[key] = makefile.read_text(errors="replace")
        except OSError:
            _OBJ_RULE_CACHE[key] = ""
    text = _OBJ_RULE_CACHE[key]
    if not text:
        return None
    obj_name = p.stem + ".o"
    m = re.search(
        r"obj-\$\(CONFIG_([A-Z0-9_]+)\)\s*[:+]?=[^\n]*\b" + re.escape(obj_name) + r"\b",
        text,
    )
    return m.group(1) if m else None


def config_status(kconfig_text, symbol):
    """'y' / 'm' / 'not-set' / None (symbol absent from this .config
    entirely -- a different question from explicitly disabled, e.g. it
    may not exist for this architecture)."""
    m = re.search(rf"^CONFIG_{re.escape(symbol)}=([ym])\b", kconfig_text, re.MULTILINE)
    if m:
        return m.group(1)
    if re.search(rf"^# CONFIG_{re.escape(symbol)} is not set\b", kconfig_text, re.MULTILINE):
        return "not-set"
    return None


def check_config_inapplicable(kernel_dir, kconfig_text, candidates):
    """Given candidate fix commits (ancestor-confirmed or not -- the
    affected code's build status doesn't depend on whether the fix
    landed), check the first candidate's touched files against our
    actual .config. Returns (symbol, file) on the first disabled match
    found, else None."""
    if not candidates:
        return None
    for f in files_touched_by_commit(kernel_dir, candidates[0]):
        symbol = find_config_symbol(kernel_dir, f)
        if symbol and config_status(kconfig_text, symbol) == "not-set":
            return symbol, f
    return None


def triage(rows, kernel_dir, our_ref, kconfig_path, keywords):
    ensure_commit_graph(kernel_dir)
    subject_index = build_subject_index(kernel_dir)
    try:
        kconfig_text = Path(kconfig_path).read_text(errors="replace")
    except OSError:
        kconfig_text = ""
    inapplicable, fixed, mismatch, review = [], [], [], []
    for row in rows:
        cve, summary = row["cve"], row["summary"]
        subject = extract_commit_subject(summary)
        if subject:
            candidates = subject_index.get(subject, [])
            if candidates and kconfig_text:
                hit = check_config_inapplicable(kernel_dir, kconfig_text, candidates)
                if hit:
                    symbol, f = hit
                    inapplicable.append({
                        "cve": cve,
                        "config_symbol": symbol,
                        "file": f,
                        "reason": f"CONFIG_{symbol} not set -- {f} (touched by "
                                  f"the fix commit) isn't compiled into this "
                                  f"kernel, so the vulnerable code isn't either",
                        "suggested_cve_status": (
                            f'CVE_STATUS[{cve}] = "not-applicable-config: '
                            f'CONFIG_{symbol} not enabled"'
                        ),
                    })
                    continue
            confirmed = [c for c in candidates if is_ancestor(kernel_dir, c, our_ref)]
            if confirmed:
                commit = confirmed[0]
                fixed.append({
                    "cve": cve,
                    "commit": commit,
                    "subject": subject,
                    "suggested_cve_status": (
                        f'CVE_STATUS[{cve}] = "fixed-version: '
                        f'present as {commit[:12]} ({subject})"'
                    ),
                })
                continue
            if candidates:
                review.append({
                    "cve": cve,
                    "reason": (
                        f"{len(candidates)} commit(s) matched the subject "
                        f"upstream, none confirmed as an ancestor of "
                        f"{our_ref[:12]} -- equivalent-but-different fix "
                        f"vs. genuinely open, needs a source diff"
                    ),
                    "candidate_commits": candidates,
                })
                continue
        if not looks_like_match(summary, keywords):
            mismatch.append({
                "cve": cve,
                "reason": f"summary doesn't mention any of {keywords}",
                "summary": summary[:200],
                "suggested_cve_status": (
                    f'CVE_STATUS[{cve}] = "not-applicable-config: '
                    f"<confirm CPE mismatch, then state what it actually "
                    f'affects>"'
                ),
            })
            continue
        review.append({
            "cve": cve,
            "reason": "no commit-like text in summary, mentions "
                      f"one of {keywords} so not an obvious CPE mismatch either",
        })
    return inapplicable, fixed, mismatch, review


def write_report(out_prefix, package, our_ref, total, inapplicable, fixed, mismatch, review):
    report = {
        "package": package,
        "our_ref": our_ref,
        "total_scanned": total,
        "config_inapplicable_candidates": inapplicable,
        "fixed_version_candidates": fixed,
        "cpe_mismatch_candidates": mismatch,
        "needs_human_review": review,
    }
    Path(f"{out_prefix}.json").write_text(json.dumps(report, indent=2))

    lines = [
        f"# Kernel CVE triage: {package} @ {our_ref[:12]}",
        "",
        f"{total} unpatched CVEs scanned -- "
        f"**{len(inapplicable)} config-inapplicable**, "
        f"**{len(fixed)} fixed-version candidates**, "
        f"**{len(mismatch)} likely CPE mismatches**, "
        f"{len(review)} need human review.",
        "",
        "## Config-inapplicable (affected code not compiled in)",
        "",
    ]
    if inapplicable:
        lines.append("| cve | config symbol | file |")
        lines.append("|---|---|---|")
        for c in inapplicable:
            lines.append(f"| {c['cve']} | CONFIG_{c['config_symbol']} | {c['file']} |")
    else:
        lines.append("(none)")
    lines += ["", "## Fixed-version candidates (commit confirmed in our build)", ""]
    if fixed:
        lines.append("| cve | commit | subject |")
        lines.append("|---|---|---|")
        for f in fixed:
            lines.append(f"| {f['cve']} | {f['commit'][:12]} | {f['subject']} |")
    else:
        lines.append("(none)")
    lines += ["", "## Likely CPE mismatches (confirm before recording)", ""]
    if mismatch:
        lines.append("| cve | reason |")
        lines.append("|---|---|")
        for m in mismatch:
            lines.append(f"| {m['cve']} | {m['reason']} |")
    else:
        lines.append("(none)")
    lines += ["", "## Needs human review", ""]
    if review:
        lines.append("| cve | reason |")
        lines.append("|---|---|")
        for r in review:
            lines.append(f"| {r['cve']} | {r['reason']} |")
    else:
        lines.append("(none)")
    Path(f"{out_prefix}.md").write_text("\n".join(lines) + "\n")


DEFAULT_KEYWORDS = {
    "linux-ti-staging": ["linux", "kernel"],
    "u-boot-ti-staging": ["u-boot", "uboot", "das u-boot"],
    "busybox": ["busybox"],
}


def main():
    if len(sys.argv) < 5:
        sys.exit(__doc__)
    parsed_dir, kernel_dir, our_ref, kconfig_path = sys.argv[1:5]
    package = sys.argv[5] if len(sys.argv) > 5 else "linux-ti-staging"
    out_prefix = sys.argv[6] if len(sys.argv) > 6 else "kernel-cve-triage"
    keywords = sys.argv[7].split(",") if len(sys.argv) > 7 else \
        DEFAULT_KEYWORDS.get(package, [package.split("-")[0]])

    rows = load_kernel_rows(parsed_dir, package)
    inapplicable, fixed, mismatch, review = triage(rows, kernel_dir, our_ref, kconfig_path, keywords)
    write_report(out_prefix, package, our_ref, len(rows), inapplicable, fixed, mismatch, review)
    print(f"{len(rows)} scanned: {len(inapplicable)} config-inapplicable, "
          f"{len(fixed)} fixed-version, {len(mismatch)} cpe-mismatch, "
          f"{len(review)} needs-review -> {out_prefix}.json/.md")


if __name__ == "__main__":
    main()
