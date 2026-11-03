#!/usr/bin/env python3
"""Records a human's decision on a CVE as an OpenVEX statement -- the
audit trail Honda's own pipeline insists on: no default approver, every
record that reaches a person logs who decided, what they decided, and
why (docs/cve-triage.md rule 3). This is the ONLY way a CVE that reached
needs_human_review (AI-drafted or not) gets marked resolved in the
evidence store -- nothing upstream of this script ever claims that on
its own.

Usage:
    record_vex_decision.py RUN_DIR CVE --status STATUS --justification TEXT
        --decided-by NAME [--product PURL]

RUN_DIR         a run's evidence-store directory (same one holding
                triage.json) -- appends to RUN_DIR/vex-decisions.json,
                creating an OpenVEX document on first use.
STATUS          not_affected | affected | fixed | under_investigation
                (OpenVEX's own status vocabulary).
--justification free text: cite the actual evidence (a commit, a
                Kconfig symbol, a source diff) -- this is read by anyone
                auditing the decision later, not a formality.
--decided-by    a real name/handle -- there is no default approver.
--product       optional purl/CPE for the affected component; defaults
                to "linux-yocto" (the kernel is what this pipeline's
                human-review queue is almost entirely made of).
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

VALID_STATUSES = ("not_affected", "affected", "fixed", "under_investigation")


def load_or_init(path):
    if path.is_file():
        return json.loads(path.read_text())
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://justembed.nl/vex/{path.parent.name}",
        "author": "JustEmbed meta-je-sbom-cve evidence pipeline",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": 1,
        "statements": [],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("run_dir")
    p.add_argument("cve")
    p.add_argument("--status", required=True, choices=VALID_STATUSES)
    p.add_argument("--justification", required=True)
    p.add_argument("--decided-by", required=True)
    p.add_argument("--product", default="linux-yocto")
    args = p.parse_args()

    out_path = Path(args.run_dir) / "vex-decisions.json"
    doc = load_or_init(out_path)

    doc["statements"] = [s for s in doc["statements"] if s["vulnerability"]["name"] != args.cve]
    doc["statements"].append({
        "vulnerability": {"name": args.cve},
        "products": [{"@id": args.product}],
        "status": args.status,
        "impact_statement": args.justification,
        "decided_by": args.decided_by,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    doc["version"] += 1

    out_path.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"recorded {args.cve}: {args.status} (decided by {args.decided_by}) -> {out_path}")


if __name__ == "__main__":
    main()
