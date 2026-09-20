#!/usr/bin/env python3
"""Structural validation of a je-detection-agent event against the real
OCSF Security Finding (class_uid 2001) class definition, vendored
locally (ocsf-security-finding-<version>.json, fetched once from
schema.ocsf.io) so this runs offline and reproducibly -- not a network
call at test/CI time.

This checks structure and type of the base-class required fields
(profile-conditional fields like "cloud"/"osint" are correctly excluded
-- je-detection-agent doesn't declare those OCSF profiles) plus the two
fields the agent specifically claims to populate correctly
(vulnerabilities[].cve.uid, attacks[].technique.uid). It is NOT full
JSON-Schema conformance checking against every OCSF constraint -- see
docs/evidence/ocsf-validation.md for the exact scope.

Usage: validate_ocsf_event.py <event.jsonl> [--schema SCHEMA_JSON]
Exit 0 if every event in the file passes, 1 otherwise.
"""
import argparse
import json
import os
import sys

DEFAULT_SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "ocsf-security-finding-1.4.0.json",
)

# Base-class (profile: None) required fields, taken directly from the
# vendored schema's own "requirement": "required" attributes that
# aren't gated behind a profile -- not hand-guessed.
REQUIRED_BASE_FIELDS = {
    "state_id": int,
    "category_uid": int,
    "class_uid": int,
    "activity_id": int,
    "type_uid": int,
    "severity_id": int,
    "time": int,
    "metadata": dict,
    "finding": dict,
}


def load_schema(path):
    with open(path) as f:
        return json.load(f)


def enum_values(schema, field):
    for entry in schema["attributes"]:
        if field in entry:
            enum = entry[field].get("enum")
            if enum:
                return {int(k) for k in enum}
    return None


def validate_event(event, schema, errors):
    ok = True
    for field, expected_type in REQUIRED_BASE_FIELDS.items():
        if field not in event:
            errors.append(f"missing required field: {field}")
            ok = False
        elif not isinstance(event[field], expected_type):
            errors.append(
                f"field {field} has type {type(event[field]).__name__}, "
                f"expected {expected_type.__name__}"
            )
            ok = False

    if event.get("class_uid") != schema.get("uid"):
        errors.append(
            f"class_uid {event.get('class_uid')} does not match schema's "
            f"own uid {schema.get('uid')} (security_finding)"
        )
        ok = False

    for field in ("category_uid", "activity_id", "state_id"):
        allowed = enum_values(schema, field)
        if allowed is not None and field in event and event[field] not in allowed:
            errors.append(
                f"field {field}={event[field]} is not one of the schema's "
                f"declared enum values {sorted(allowed)}"
            )
            ok = False

    # je-detection-agent-specific fields: real OCSF structured fields,
    # not ad hoc strings (per meta-je-detection/README.md's own claim).
    vulns = event.get("vulnerabilities")
    if vulns is not None:
        if not isinstance(vulns, list) or not all(
            isinstance(v, dict) and isinstance(v.get("cve"), dict)
            and isinstance(v["cve"].get("uid"), str)
            for v in vulns
        ):
            errors.append(
                "vulnerabilities[] present but not shaped as "
                "[{cve: {uid: str}}, ...]"
            )
            ok = False

    attacks = event.get("attacks")
    if attacks is not None:
        if not isinstance(attacks, list) or not all(
            isinstance(a, dict) and isinstance(a.get("technique"), dict)
            and isinstance(a["technique"].get("uid"), str)
            for a in attacks
        ):
            errors.append(
                "attacks[] present but not shaped as "
                "[{technique: {uid: str, name: str}}, ...]"
            )
            ok = False

    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("events_file")
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    args = ap.parse_args()

    schema = load_schema(args.schema)
    all_ok = True
    count = 0
    with open(args.events_file) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            count += 1
            event = json.loads(line)
            errors = []
            if not validate_event(event, schema, errors):
                all_ok = False
                print(f"line {lineno}: FAIL")
                for e in errors:
                    print(f"  - {e}")
            else:
                print(f"line {lineno}: OK")

    print(f"\n{count} event(s) checked against "
          f"{schema.get('name')} (uid={schema.get('uid')})")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
