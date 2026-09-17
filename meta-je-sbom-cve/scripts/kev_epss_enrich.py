#!/usr/bin/env python3
"""Cross-reference a scan's CVE list against CISA KEV + FIRST.org EPSS.

NVD/CVSS (what parse_cve.py already reports) says how bad a CVE could
be. KEV says it is being exploited right now (CISA's curated, binary
catalog). EPSS estimates the probability of exploitation in the next
30 days (FIRST.org's daily-scored model). Neither needs an API key.

This turns a raw "N unpatched CVEs" count into a short, actionable
list: confirmed-exploited first, then ranked by exploitation
likelihood -- the input meta-je-detection needs, not the full NVD
firehose.

Usage:
    kev_epss_enrich.py UNPATCHED_CSV OUT_PREFIX
        [--kev-file FILE] [--epss-file FILE] [--offline]

UNPATCHED_CSV   parsed/unpatched.csv from parse_cve.py (needs at least
                a `cve` column; `package`/`severity` are carried
                through if present).
OUT_PREFIX      writes OUT_PREFIX.json and OUT_PREFIX.md.

Network (skipped entirely with --offline, in which case the report
says so rather than failing): fetches CISA KEV as JSON and the FIRST.org
EPSS bulk CSV. --kev-file/--epss-file point at already-downloaded
copies instead (or if you'd rather run this outside a build's network
sandbox and feed the files in).
"""
import argparse
import csv
import gzip
import json
import sys
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
TIMEOUT = 30


def fetch(url):
    with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
        return r.read()


def load_kev(path=None):
    """Returns {cve: {date_added, ransomware}}."""
    try:
        data = Path(path).read_bytes() if path else fetch(KEV_URL)
        catalog = json.loads(data)
    except Exception as e:
        return None, f"KEV fetch/parse failed: {e}"
    kev = {}
    for v in catalog.get("vulnerabilities", []):
        kev[v["cveID"]] = {
            "date_added": v.get("dateAdded"),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown") == "Known",
            "due_date": v.get("dueDate"),
        }
    return kev, None


def load_epss(path=None):
    """Returns {cve: {score, percentile}}."""
    try:
        if path:
            raw = Path(path).read_bytes()
        else:
            raw = fetch(EPSS_URL)
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        text = raw.decode()
    except Exception as e:
        return None, f"EPSS fetch/parse failed: {e}"
    epss = {}
    # EPSS CSVs start with a `#model_version:...` comment line before the header.
    lines = [l for l in text.splitlines() if l and not l.startswith("#")]
    for row in csv.DictReader(lines):
        epss[row["cve"]] = {
            "score": float(row["epss"]),
            "percentile": float(row["percentile"]),
        }
    return epss, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("unpatched_csv", type=Path)
    ap.add_argument("out_prefix", type=Path)
    ap.add_argument("--kev-file", type=Path)
    ap.add_argument("--epss-file", type=Path)
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args()

    rows = []
    if args.unpatched_csv.is_file():
        with args.unpatched_csv.open(newline="") as f:
            rows = list(csv.DictReader(f))
    cves = sorted({r["cve"] for r in rows if r.get("cve")})

    warnings = []
    kev, epss = {}, {}
    if args.offline:
        warnings.append("--offline: KEV/EPSS not fetched, all rows unenriched")
    else:
        kev, err = load_kev(args.kev_file)
        if err:
            warnings.append(err)
            kev = {}
        epss, err = load_epss(args.epss_file)
        if err:
            warnings.append(err)
            epss = {}

    by_cve = {r["cve"]: r for r in rows if r.get("cve")}
    triage = []
    for cve in cves:
        row = by_cve.get(cve, {})
        k = kev.get(cve)
        e = epss.get(cve)
        triage.append({
            "cve": cve,
            "package": row.get("package"),
            "severity": row.get("severity"),
            "in_kev": k is not None,
            "kev_date_added": (k or {}).get("date_added"),
            "kev_ransomware": (k or {}).get("ransomware", False),
            "epss_score": (e or {}).get("score"),
            "epss_percentile": (e or {}).get("percentile"),
        })

    # Priority: confirmed-exploited (KEV) first, then by EPSS score
    # descending, unscored last.
    triage.sort(key=lambda t: (
        0 if t["in_kev"] else 1,
        -(t["epss_score"] or -1),
    ))

    result = {
        "total_cves": len(cves),
        "kev_hits": sum(1 for t in triage if t["in_kev"]),
        "epss_scored": sum(1 for t in triage if t["epss_score"] is not None),
        "warnings": warnings,
        "triage": triage,
    }

    args.out_prefix.parent.mkdir(parents=True, exist_ok=True)
    args.out_prefix.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n")

    md = [
        "# KEV/EPSS triage",
        "",
        f"{result['total_cves']} unpatched CVEs scanned -- "
        f"**{result['kev_hits']} confirmed exploited (KEV)**, "
        f"{result['epss_scored']} EPSS-scored.",
        "",
    ]
    for w in warnings:
        md.append(f"> **warning:** {w}")
    if warnings:
        md.append("")
    md.append("| cve | package | severity | KEV | EPSS | ransomware |")
    md.append("|---|---|---|---|---|---|")
    for t in triage:
        if not t["in_kev"] and (t["epss_score"] or 0) < 0.1:
            continue  # low-signal tail, full data is still in the JSON
        epss_str = f"{t['epss_score']:.3f}" if t["epss_score"] is not None else ""
        md.append(
            f"| {t['cve']} | {t['package'] or ''} | {t['severity'] or ''} | "
            f"{'YES' if t['in_kev'] else ''} | {epss_str} | "
            f"{'ransomware' if t['kev_ransomware'] else ''} |"
        )
    args.out_prefix.with_suffix(".md").write_text("\n".join(md) + "\n")

    print(
        f"kev/epss triage: {result['kev_hits']} KEV hits, "
        f"{result['epss_scored']}/{result['total_cves']} EPSS-scored"
        + (f" ({len(warnings)} warning(s))" if warnings else ""),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
