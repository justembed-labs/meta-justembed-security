# Claim

`je-detection-agent`'s OCSF Security Finding output is structurally
checked against the real, vendored OCSF 1.4.0 `security_finding` class
definition -- not hand-eyeballed against the spec -- and real events
captured from a live trigger pass that check. The scope of what this
check does and does not verify is stated explicitly below; it is not
full JSON-Schema conformance.

## Environment

- OCSF version: 1.4.0, `security_finding` class (`class_uid` 2001)
- Schema source: `https://schema.ocsf.io/api/1.4.0/classes/security_finding`,
  fetched once and vendored at
  `meta-je-detection/scripts/ocsf-security-finding-1.4.0.json` for
  offline, reproducible use (no network call at test/CI time)
- Validator: `meta-je-detection/scripts/validate_ocsf_event.py`
  (stdlib-only Python 3, no new dependency)

## Setup

None beyond the vendored schema file and the validator script, both
checked into `meta-je-detection/scripts/`.

## Test

```
python3 meta-je-detection/scripts/validate_ocsf_event.py events.jsonl
```

Run four ways: (1) against a synthetic, deliberately correct event;
(2) against a synthetic, deliberately malformed event; (3) against 5
real events captured from the live QEMU trigger in
`docs/evidence/detection-event.md` (pre-stabilization); (4) **rerun**
against the real post-correlation-fix event from that same evidence
file, to confirm the audit-event grouping/context-aggregation change
(see `docs/evidence/detection-event.md`'s "Previously observed
issue") introduced no schema regression.

## Expected result

(1) passes, (2) fails with specific, actionable errors, (3) passes,
(4) still passes after the correlation fix -- confirming the
validator both accepts real agent output and actually rejects broken
input, and that the stabilization fix didn't change the event shape
in a way that breaks validation.

## Actual result

**(1) Synthetic valid event:** `line 1: OK`, exit 0.

**(2) Synthetic malformed event:** `line 1: FAIL`, 9 distinct error
lines, exit 1 (e.g. missing `state_id`, `time` as a string instead of
an int, `class_uid` not matching the schema's own `uid`, an
`activity_id` outside the schema's declared enum, a
`vulnerabilities[]` entry not shaped as `{cve: {uid: str}}`).

**(3) Five real captured events (pre-stabilization):** all 5 passed
(`line N: OK` for each, exit 0).

**(4) Post-correlation-fix regression check:** the real single-finding
event from `docs/evidence/detection-event.md` (with the new
`unmapped.audit_context` structure -- syscall/exe/pid/ppid/uid/comm/
cwd/path/proctitle/audit_event_id/audit_record_types, all inside
`unmapped`, which this validator doesn't specifically inspect but
which must coexist with the required top-level fields it does check)
-- `line 1: OK`, exit 0. No regression.

## Raw evidence

Console output from all four runs is copied directly from the actual
script executions described above.

## Exact scope -- what this validator checks

- **Presence and Python type** of the base-class required fields that
  have no profile condition: `state_id`, `category_uid`, `class_uid`,
  `activity_id`, `type_uid`, `severity_id`, `time` (int), `metadata`
  (dict), `finding` (dict). These are read directly from the vendored
  schema's own `"requirement": "required"` attributes -- not
  hand-guessed from documentation.
- `class_uid` matches the schema's own declared `uid`.
- `category_uid`, `activity_id`, `state_id` values are members of the
  schema's own declared enum, when the schema declares one for that
  field.
- The two OCSF *structured* fields `je-detection-agent` specifically
  claims to populate correctly (`meta-je-detection/README.md`):
  `vulnerabilities[].cve.uid` (string) and
  `attacks[].technique.uid` (string) -- shape-checked when present.

## What this validator does NOT check

- **Not full JSON-Schema conformance.** It does not walk every
  attribute in the OCSF class definition, does not check `$ref`-style
  nested object schemas beyond the two structured fields above, and
  does not enforce field-level string patterns/formats OCSF may
  declare.
- **Not profile-specific attributes.** Fields gated behind an OCSF
  profile (e.g. `osint`, `cloud`) are correctly excluded from the
  required-field check, since `je-detection-agent` doesn't declare
  those profiles as active -- but this also means the validator would
  not catch a profile-scoped field being malformed if one were ever
  added.
- **Not enum validation beyond the three fields listed above.**
  `severity_id`, `type_uid`, and any other enumerated field are only
  type-checked (must be `int`), not range/membership-checked.
- **Not semantic/business-logic validation** -- e.g. it does not check
  that `type_uid` is the correct derived value for the given
  `class_uid`/`activity_id` pair (OCSF's own composition rule), only
  that each individually-required field is present and the right
  Python type.

## Limitations

- Checked against OCSF 1.4.0 only, fetched once; a schema update
  upstream would need the vendored copy refreshed by hand.
- Validated only against `security_finding` (`class_uid` 2001) --
  `je-detection-agent` does not emit any other OCSF class today, so no
  other class was checked.
- The three OCSF-structured fields checked (`vulnerabilities`,
  `attacks`, base required fields) reflect what
  `meta-je-detection/README.md` specifically claims the agent
  populates correctly -- other optional OCSF fields the agent may also
  emit are not separately checked.

## Reproduction

```
python3 meta-je-detection/scripts/validate_ocsf_event.py \
  /var/log/je-detection/events.jsonl \
  --schema meta-je-detection/scripts/ocsf-security-finding-1.4.0.json
```
Run against any `events.jsonl` produced per `docs/evidence/detection-event.md`.
