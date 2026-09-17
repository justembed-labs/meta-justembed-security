#!/usr/bin/env python3
"""Diff two parsed cve-check runs.

Usage:
    diff_cve.py CURRENT_DIR PREVIOUS_DIR OUT_PREFIX

CURRENT_DIR / PREVIOUS_DIR are parse_cve.py output dirs. Writes
OUT_PREFIX.json and OUT_PREFIX.md:

  new             unpatched now, not unpatched (or absent) before
  resolved        unpatched before, patched or gone now
  still_unpatched carried over
  score_changed   same CVE+package, effective score moved

Kernel CVEs (package linux-*) are split out -- they dominate the count
and move on every kernel bump, so a separate section keeps the
non-kernel signal readable.

Exits non-zero with a warning if the current run has >50% fewer total
records than the previous one (a broken scan looks like "everything got
fixed").
"""
import csv
import json
import sys
from pathlib import Path

MD_ROW_CAP = 50


def load_unpatched(d):
    path = Path(d) / "unpatched.csv"
    out = {}
    if not path.is_file():
        return out
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            out[(row["cve"], row["package"])] = row
    return out


def load_total(d):
    path = Path(d) / "cve_summary.json"
    if not path.is_file():
        return 0
    data = json.loads(path.read_text())
    return sum(data.get("by_status", {}).values())


def is_kernel(pkg):
    return pkg.startswith(("linux-", "linux")) and "firmware" not in pkg


def _score(row):
    try:
        return float(row.get("cvss") or 0)
    except ValueError:
        return 0.0


def split(rows):
    kern = [r for r in rows if is_kernel(r["package"])]
    other = [r for r in rows if not is_kernel(r["package"])]
    kern.sort(key=lambda r: (-_score(r), r["package"], r["cve"]))
    other.sort(key=lambda r: (-_score(r), r["package"], r["cve"]))
    return {"kernel": kern, "non_kernel": other}


def md_table(rows):
    if not rows:
        return "_none_\n"
    lines = ["| CVE | package | version | CVSS | severity | summary |",
             "|---|---|---|---|---|---|"]
    for r in rows[:MD_ROW_CAP]:
        summary = (r.get("summary") or "").replace("|", "\\|")
        summary = " ".join(summary.split())[:120]
        lines.append(f"| [{r['cve']}]({r.get('link','')}) | {r['package']} | "
                     f"{r.get('version','')} | {r.get('cvss','')} | "
                     f"{r.get('severity','')} | {summary} |")
    if len(rows) > MD_ROW_CAP:
        lines.append(f"| … | _{len(rows) - MD_ROW_CAP} more_ | | | | |")
    return "\n".join(lines) + "\n"


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    cur_dir, prev_dir, out_prefix = sys.argv[1:4]

    cur = load_unpatched(cur_dir)
    prev = load_unpatched(prev_dir)

    new = [v for k, v in cur.items() if k not in prev]
    resolved = [v for k, v in prev.items() if k not in cur]
    still = [v for k, v in cur.items() if k in prev]

    score_changed = []
    for k in cur.keys() & prev.keys():
        if (cur[k].get("cvss") or "") != (prev[k].get("cvss") or ""):
            row = dict(cur[k])
            row["previous_cvss"] = prev[k].get("cvss", "")
            score_changed.append(row)

    cur_total, prev_total = load_total(cur_dir), load_total(prev_dir)
    scan_warning = None
    if prev_total and cur_total < prev_total * 0.5:
        scan_warning = (f"current run has {cur_total} CVE records vs "
                        f"{prev_total} previously (>50% drop) -- scan may be broken")

    result = {
        "current": cur_dir, "previous": prev_dir,
        "counts": {"new": len(new), "resolved": len(resolved),
                   "still_unpatched": len(still), "score_changed": len(score_changed)},
        "scan_warning": scan_warning,
        "new": split(new), "resolved": split(resolved),
        "still_unpatched": split(still), "score_changed": split(score_changed),
    }
    Path(out_prefix + ".json").write_text(json.dumps(result, indent=2) + "\n")

    md = ["# CVE diff\n",
          f"- new unpatched: **{len(new)}**",
          f"- resolved: **{len(resolved)}**",
          f"- still unpatched: **{len(still)}**",
          f"- score changed: **{len(score_changed)}**\n"]
    if scan_warning:
        md.append(f"> ⚠️ {scan_warning}\n")
    for title, key in (("New unpatched", "new"), ("Resolved", "resolved"),
                       ("Score changed", "score_changed"),
                       ("Still unpatched", "still_unpatched")):
        md.append(f"## {title}\n")
        md.append("### Non-kernel\n")
        md.append(md_table(result[key]["non_kernel"]))
        md.append("### Kernel\n")
        md.append(md_table(result[key]["kernel"]))
    Path(out_prefix + ".md").write_text("\n".join(md))

    print(f"cve diff: +{len(new)} new  -{len(resolved)} resolved  "
          f"={len(still)} carried  ~{len(score_changed)} rescored")
    if scan_warning:
        print("WARNING:", scan_warning, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
