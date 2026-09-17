#!/usr/bin/env python3
"""Normalise one or more Yocto cve-check manifests into a stable set of
files the diff and the viewer consume.

Usage:
    parse_cve.py OUT_DIR MANIFEST [MANIFEST ...]

Each MANIFEST is a cve-check image manifest -- JSON (CVE_CHECK_FORMAT_JSON=1)
or the legacy text format. Multiple are merged (e.g. the rootfs image
manifest plus a separate `bitbake virtual/bootloader -c cve_check`).

Writes into OUT_DIR:
    cve_summary.json         counts by severity and status
    unpatched.csv            one row per unpatched (id,package,version,layer,score,severity,...)
    unpatched_by_package.csv package rollup
    packages.json            full normalised {package: {version, layer, issues:[...]}}

Scarthgap cve-check JSON schema (per package):
    {"name","layer","version","products":[...],
     "issue":[{"id","summary","scorev2","scorev3","scorev4",
               "vector","vectorString","status","link",...}]}
The effective score is v4 -> v3 -> v2 (first non-zero).
"""
import csv
import json
import re
import sys
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]


def severity_of(score):
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def _score(issue):
    for key in ("scorev4", "scorev3", "scorev2"):
        raw = issue.get(key)
        try:
            val = float(raw)
        except (TypeError, ValueError):
            continue
        if val > 0.0:
            return val
    return None


def load_json(path, text):
    data = json.loads(text)
    out = []
    for pkg in data.get("package", []):
        issues = []
        for iss in pkg.get("issue", []):
            score = _score(iss)
            issues.append({
                "id": iss.get("id", ""),
                "status": (iss.get("status") or "Unpatched"),
                "score": score,
                "severity": severity_of(score),
                "vector": iss.get("vectorString") or iss.get("vector") or "",
                "summary": (iss.get("summary") or "").strip(),
                "link": iss.get("link", ""),
            })
        out.append({
            "name": pkg.get("name", ""),
            "version": pkg.get("version", ""),
            "layer": pkg.get("layer", ""),
            "issues": issues,
        })
    return out


_TEXT_PKG = re.compile(r"^PACKAGE NAME:\s*(.+)$")
_TEXT_VER = re.compile(r"^PACKAGE VERSION:\s*(.+)$")
_TEXT_CVE = re.compile(r"^CVE:\s*(\S+)")
_TEXT_STATUS = re.compile(r"^CVE STATUS:\s*(.+)$")
_TEXT_SCORE3 = re.compile(r"^CVSS v3 BASE SCORE:\s*([0-9.]+)")
_TEXT_SCORE2 = re.compile(r"^CVSS v2 BASE SCORE:\s*([0-9.]+)")
_TEXT_LINK = re.compile(r"^LINK:\s*(.+)$")


def load_text(path, text):
    """Best-effort parse of the legacy text manifest (no layer field)."""
    pkgs = {}
    cur_pkg = cur_ver = None
    iss = None
    for line in text.splitlines():
        m = _TEXT_PKG.match(line)
        if m:
            cur_pkg = m.group(1).strip()
            pkgs.setdefault(cur_pkg, {"name": cur_pkg, "version": "", "layer": "", "issues": []})
            continue
        m = _TEXT_VER.match(line)
        if m and cur_pkg:
            pkgs[cur_pkg]["version"] = m.group(1).strip()
            continue
        m = _TEXT_CVE.match(line)
        if m and cur_pkg:
            if iss:
                pkgs[cur_pkg]["issues"].append(iss)
            iss = {"id": m.group(1), "status": "Unpatched", "score": None,
                   "severity": "unknown", "vector": "", "summary": "", "link": ""}
            continue
        if iss is None:
            continue
        m = _TEXT_STATUS.match(line)
        if m:
            iss["status"] = m.group(1).strip().title()
            continue
        m = _TEXT_SCORE3.match(line) or _TEXT_SCORE2.match(line)
        if m:
            try:
                s = float(m.group(1))
                if s > 0 and (iss["score"] is None or s > iss["score"]):
                    iss["score"] = s
                    iss["severity"] = severity_of(s)
            except ValueError:
                pass
            continue
        m = _TEXT_LINK.match(line)
        if m:
            iss["link"] = m.group(1).strip()
    if iss and cur_pkg:
        pkgs[cur_pkg]["issues"].append(iss)
    return list(pkgs.values())


def merge(a, b):
    by_name = {p["name"]: p for p in a}
    for p in b:
        if p["name"] in by_name:
            existing = by_name[p["name"]]
            seen = {i["id"] for i in existing["issues"]}
            existing["issues"].extend(i for i in p["issues"] if i["id"] not in seen)
            if not existing["layer"] and p["layer"]:
                existing["layer"] = p["layer"]
        else:
            by_name[p["name"]] = p
    return list(by_name.values())


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    out_dir = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)

    packages = []
    for arg in sys.argv[2:]:
        path = Path(arg)
        if not path.is_file():
            print(f"warning: {path} not found, skipping", file=sys.stderr)
            continue
        text = path.read_text(errors="replace").lstrip()
        loader = load_json if text.startswith(("{", "[")) else load_text
        packages = merge(packages, loader(path, text))

    packages.sort(key=lambda p: p["name"])

    counts = {"by_severity": {s: 0 for s in SEVERITY_ORDER},
              "by_status": {}, "packages": len(packages),
              "packages_with_unpatched": 0}
    unpatched_rows = []
    pkg_rollup = []
    for p in packages:
        n_unpatched = 0
        highest = 0.0
        for iss in p["issues"]:
            counts["by_status"][iss["status"]] = counts["by_status"].get(iss["status"], 0) + 1
            if iss["status"] != "Unpatched":
                continue
            n_unpatched += 1
            counts["by_severity"][iss["severity"]] += 1
            if iss["score"] and iss["score"] > highest:
                highest = iss["score"]
            unpatched_rows.append({
                "cve": iss["id"], "package": p["name"], "version": p["version"],
                "layer": p["layer"], "cvss": iss["score"] if iss["score"] else "",
                "severity": iss["severity"], "vector": iss["vector"],
                "summary": iss["summary"][:300], "link": iss["link"],
            })
        if n_unpatched:
            counts["packages_with_unpatched"] += 1
            pkg_rollup.append({
                "package": p["name"], "version": p["version"], "layer": p["layer"],
                "unpatched": n_unpatched,
                "highest_score": highest if highest else "",
                "highest_severity": severity_of(highest if highest else None),
            })

    unpatched_rows.sort(key=lambda r: (-(r["cvss"] or 0), r["package"], r["cve"]))
    pkg_rollup.sort(key=lambda r: (-(r["highest_score"] or 0), -r["unpatched"], r["package"]))

    (out_dir / "cve_summary.json").write_text(json.dumps(counts, indent=2) + "\n")
    (out_dir / "packages.json").write_text(json.dumps(packages, indent=2) + "\n")

    with (out_dir / "unpatched.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["cve", "package", "version", "layer",
                                          "cvss", "severity", "vector", "summary", "link"])
        w.writeheader()
        w.writerows(unpatched_rows)

    with (out_dir / "unpatched_by_package.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["package", "version", "layer", "unpatched",
                                          "highest_score", "highest_severity"])
        w.writeheader()
        w.writerows(pkg_rollup)

    print(f"parsed {len(packages)} packages, "
          f"{len(unpatched_rows)} unpatched CVEs "
          f"({counts['by_severity']['critical']} critical, "
          f"{counts['by_severity']['high']} high)")


if __name__ == "__main__":
    main()
