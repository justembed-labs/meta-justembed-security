#!/usr/bin/env python3
"""AI-escalation stage: a model drafts an OpenVEX not_affected justification
for whatever every deterministic triage stage before it couldn't resolve.
Never on the critical path -- only ever sees the genuine remainder, never
the raw CVE list -- and never terminal on its own: every draft is
independently re-checked using the exact same Makefile/.config mapping
kernel_cve_triage.py's own config_inapplicable_candidates bucket already
relies on, before anything counts as resolved. Same 4-bucket
OUT_PREFIX.json/.md shape as every other triage stage -- drops straight
into prioritize_cves.py's triage_jsons, no changes needed there.

This stage never tries to confirm a CVE is *fixed* -- that stays
kernel_backport_check.py's job, deterministic, no AI. The first version of
this script asked the model to cite a commit hash and git-apply-checked it
against the kernel tree; a real pilot run against the Nov 1 qemuarm64 data
resolved 0 of 219 CVEs that way, because a model has no reliable way to
know whether an arbitrary upstream hash is even an object in *this*
tree -- unlike kernel_cve_triage.py's own candidates, which come from
searching the local tree's own git log by commit subject, a cited commit
from the model's training data has no such guarantee. This version only
ever asks the model to name a real *source file* and pick one of OpenVEX's
five standard not_affected justifications (Honda R&D's OSS Summit EU 2026
talk, "AI-Assisted CVE Triage in Yocto-Based Supply Chains", Appendix C) --
evidence that's always locally computable from this build's own Makefiles
and .config, never dependent on upstream git history being complete.

Prompt framing still matters: ask the model to find evidence the code is
unreachable, not to clear the CVE outright -- asking it to prove a CVE
doesn't apply invites a reassuring false negative. The model's own stated
confidence carries *zero* scoring weight (see kev_epss_enrich.py) --
hardcoded policy, not learned, same discipline as docs/responsible-ai.md.

Usage:
    ai_cve_escalation.py UNPATCHED_CSV TRIAGE_JSONS OUT_PREFIX \\
        KERNEL_GIT_DIR OUR_REF --kconfig KCONFIG
        [--model MODEL] [--prompt-revision REV] [--max-cves N]
        [--response-cache DIR] [--offline]

UNPATCHED_CSV   parsed/unpatched.csv from parse_cve.py.
TRIAGE_JSONS    comma-separated reports from every stage already run
                (same list prioritize_cves.py would get) -- used to
                compute the true cumulative remainder via
                triage_common.compute_remainder(), not just one stage's
                own needs_human_review.
KERNEL_GIT_DIR / OUR_REF   same real kernel checkout every other kernel
                stage uses -- for reading each named file's governing
                Makefile, not for resolving commits.
--kconfig       the build's real .config -- whether a named file's
                Kconfig symbol is actually set.
--response-cache DIR   cache each CVE's raw model response under DIR,
                keyed by (cve, model, prompt revision) -- lets the
                reproducibility test (docs/cve-triage.md) run the
                pipeline twice without paying for the API call twice,
                and confirms the same frozen inputs give the same
                output.
--offline       don't call the API at all -- everything stays in
                needs_human_review, undrafted. For CI dry-runs/tests.

Needs ANTHROPIC_API_KEY in the environment (unless --offline or every
CVE is already cached). Network, real API cost -- CI-only, same
reasoning as JE_EVIDENCE_ENABLE_KEV_EPSS.
"""
import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from triage_common import compute_remainder, latest_review_context  # noqa: E402
from kernel_cve_triage import find_config_symbol, config_status, write_report  # noqa: E402

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-5"
# Bump this when the prompt text below changes -- it's an input to the
# reproducibility hash (docs/cve-triage.md rule 1: the prompt revision is
# an input, not just the CVE data), not a free-text comment.
PROMPT_REVISION = "ai-escalation-v3-division-of-labor"
TIMEOUT = 60

# OpenVEX's standard not_affected justification vocabulary. Only the two
# code-reachability ones are ever reverified here -- the other three
# describe facts about deployment/mitigation policy, not this build's
# compiled code, so there's nothing in the source tree to independently
# check them against; they always stay with a human.
REACHABILITY_JUSTIFICATIONS = ("vulnerable_code_not_present", "vulnerable_code_not_in_execute_path")
ALL_JUSTIFICATIONS = REACHABILITY_JUSTIFICATIONS + (
    "component_not_present",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
    "insufficient_evidence",
)

TOOL_SCHEMA = {
    "name": "submit_cve_justification",
    "description": "Propose an OpenVEX not_affected justification for this CVE against this exact kernel build, or say the evidence is insufficient.",
    "input_schema": {
        "type": "object",
        "properties": {
            "justification": {
                "type": "string",
                "enum": [
                    "component_not_present",
                    "vulnerable_code_not_present",
                    "vulnerable_code_not_in_execute_path",
                    "vulnerable_code_cannot_be_controlled_by_adversary",
                    "inline_mitigations_already_exist",
                    "insufficient_evidence",
                ],
            },
            "affected_files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Real source file path(s) in this exact kernel tree where the vulnerable code lives. Required for vulnerable_code_not_present/vulnerable_code_not_in_execute_path; leave empty otherwise.",
            },
            "justification_text": {
                "type": "string",
                "description": "Why -- cite the specific evidence found, not a restatement of the CVE summary.",
            },
            "confidence": {
                "type": "string",
                "enum": ["low", "medium", "high"],
            },
        },
        "required": ["justification", "justification_text", "confidence"],
    },
}

SYSTEM_PROMPT = (
    "You are triaging a single Linux kernel CVE against one real, specific "
    "kernel build. Deterministic tools already tried and failed to resolve "
    "it. Your job is NOT to decide whether the CVE applies in general -- "
    "asking you to clear a CVE produces reassuring guesses. Instead: "
    "determine whether you can support one of OpenVEX's standard "
    "not_affected justifications with evidence specific to THIS build. "
    "The only justifications worth attempting here are "
    "vulnerable_code_not_present and vulnerable_code_not_in_execute_path -- "
    "for either, name the REAL source file path(s) in this kernel tree "
    "where the vulnerable code lives (not a commit hash -- you have no "
    "reliable way to know whether an arbitrary upstream commit exists in "
    "this exact tree, so never cite one). "
    "You are NOT expected to know this build's actual .config state or to "
    "have read this tree's live source yourself -- that confirmation is not "
    "your job. A separate, independent, deterministic check reads this "
    "build's real Makefiles and .config and will confirm or reject your "
    "claim after you submit it. Your only job is to identify, from the CVE "
    "description and your own knowledge of where this kind of code "
    "normally lives in the kernel, which real file(s) the vulnerable code "
    "would be in. State your justification and name the file(s) even "
    "though you can't personally verify the build's state -- that's "
    "expected and fine, the independent check handles it. Only say "
    "insufficient_evidence when you can't identify which real file(s) the "
    "vulnerable code lives in at all, not merely because you lack access "
    "to confirm the build's config or runtime state. "
    "A wrong or invented path is caught, not acted on, but wastes the "
    "human reviewer's time, so only name files you have real reason to "
    "believe exist and are relevant."
)


def build_user_prompt(cve, summary, context):
    lines = [f"CVE: {cve}", f"NVD/CNA summary: {summary}"]
    if context:
        reason = context.get("reason")
        if reason:
            lines.append(f"Prior deterministic triage note: {reason}")
        candidates = context.get("candidate_commits")
        if candidates:
            lines.append(f"Candidate commit(s) a prior stage found but couldn't confirm as an ancestor: {', '.join(candidates[:5])}")
    lines.append(
        "Which OpenVEX not_affected justification, if any, applies to this "
        "exact kernel build? Name the real source file(s) involved."
    )
    return "\n".join(lines)


def cache_key(cve, model, prompt_revision):
    h = hashlib.sha256(f"{cve}|{model}|{prompt_revision}".encode()).hexdigest()[:16]
    return f"{cve}-{h}.json"


def call_model(api_key, model, system, user, timeout=TIMEOUT):
    body = json.dumps({
        "model": model,
        "max_tokens": 1024,
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "tools": [TOOL_SCHEMA],
        "tool_choice": {"type": "tool", "name": "submit_cve_justification"},
    }).encode()
    req = urllib.request.Request(
        ANTHROPIC_URL, data=body, method="POST",
        headers={
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        resp = json.loads(r.read())
    for block in resp.get("content", []):
        if block.get("type") == "tool_use" and block.get("name") == "submit_cve_justification":
            return block["input"]
    raise RuntimeError(f"no tool_use block in response: {resp}")


def draft_one(cve, summary, context, api_key, model, prompt_revision, cache_dir):
    cached = None
    cache_path = None
    if cache_dir:
        cache_path = Path(cache_dir) / cache_key(cve, model, prompt_revision)
        if cache_path.is_file():
            cached = json.loads(cache_path.read_text())
    if cached is not None:
        return cached
    draft = call_model(api_key, model, SYSTEM_PROMPT, build_user_prompt(cve, summary, context))
    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(draft, indent=2))
    return draft


def valid_draft(draft):
    """A real pilot run surfaced a malformed tool call: the model's
    chosen justification was structurally plausible, but required fields
    were missing/wrong-typed and stray tool-call-looking text (e.g.
    "</parameter><parameter name=\"confidence\">low") had leaked into
    justification_text -- evidence the generation itself went wrong, not
    just that the model was uncertain. reverify() must never evaluate a
    draft like that; a malformed draft is never evidence, no matter what
    its file/Kconfig claims look like."""
    if draft.get("justification") not in ALL_JUSTIFICATIONS:
        return False
    if draft.get("confidence") not in ("low", "medium", "high"):
        return False
    if not isinstance(draft.get("justification_text"), str) or not draft["justification_text"].strip():
        return False
    files = draft.get("affected_files")
    if files is not None and (not isinstance(files, list) or not all(isinstance(f, str) for f in files)):
        return False
    return True


def reverify(kernel_dir, kconfig_text, draft):
    """The model never resolves anything on its own -- independently
    re-check every file it named using the exact same Makefile/.config
    mapping kernel_cve_triage.py's own config_inapplicable_candidates
    bucket already relies on. Returns (justification, [confirmed files],
    [resolved symbols]) on success, or (None, None, None) if anything
    named can't be confirmed.

    Requires every named file to exist for real in this checkout (catches
    an invented/hallucinated path outright) -- partial existence always
    fails the whole claim, matching OpenVEX's own evidence-completeness
    expectation (see docs/cve-triage.md). Beyond existence, only .c files
    need to map to a Kconfig symbol that's explicitly not-set: headers
    (.h) are never gated by their own `obj-$(CONFIG_X)` Makefile rule --
    they're declarations, pulled in by whichever .c file includes them,
    not compiled objects in their own right -- so requiring one to
    resolve a symbol would always fail by construction and poison any
    claim that (correctly) cites a header alongside its .c file. At
    least one .c file must still resolve, so a claim naming only headers
    stays unverified. Any justification other than the two reachability
    ones is never attempted here -- they describe deployment/mitigation
    facts this source tree has no way to confirm or refute. A
    structurally malformed draft (missing/bad-typed required fields,
    e.g. a response-generation glitch) is rejected before any of this --
    see valid_draft()."""
    if not valid_draft(draft):
        return None, None, None
    justification = draft.get("justification")
    if justification not in REACHABILITY_JUSTIFICATIONS:
        return None, None, None
    files = [f.strip() for f in (draft.get("affected_files") or []) if f.strip()]
    if not files or not kconfig_text:
        return None, None, None
    confirmed = []
    symbols = []
    for f in files:
        if not (Path(kernel_dir) / f).is_file():
            return None, None, None
        if f.endswith(".h"):
            confirmed.append(f)
            continue
        symbol = find_config_symbol(kernel_dir, f)
        if not symbol or config_status(kconfig_text, symbol) != "not-set":
            return None, None, None
        confirmed.append(f)
        symbols.append(symbol)
    if not symbols:
        return None, None, None
    return justification, confirmed, symbols


def rebucket(results):
    inapplicable, fixed, mismatch, review = [], [], [], []
    for r in results:
        cve, draft, verified, evidence, symbols = (
            r["cve"], r["draft"], r["verified"], r["evidence"], r["symbols"])
        if verified in REACHABILITY_JUSTIFICATIONS:
            inapplicable.append({
                "cve": cve, "source": "ai-escalation",
                "config_symbol": "+".join(symbols), "file": ", ".join(evidence),
                "reason": f"OpenVEX justification '{verified}' independently confirmed -- "
                          f"named file(s) {evidence} exist in this kernel tree and map to a "
                          f"Kconfig symbol that's not-set -- model justification: {draft['justification_text']}",
                "suggested_cve_status": f'CVE_STATUS[{cve}] = "not-applicable-config: {verified} (ai-escalation, re-verified)"',
            })
        else:
            review.append({
                "cve": cve, "source": "ai-escalation", "confirmed": False,
                "reason": "AI draft could not be independently re-verified -- still needs a human",
                "ai_draft": draft,
            })
    return inapplicable, fixed, mismatch, review


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("unpatched_csv")
    p.add_argument("triage_jsons")
    p.add_argument("out_prefix")
    p.add_argument("kernel_git_dir")
    p.add_argument("our_ref")
    p.add_argument("--kconfig")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--prompt-revision", default=PROMPT_REVISION)
    p.add_argument("--max-cves", type=int, default=0, help="0 = no cap")
    p.add_argument("--response-cache")
    p.add_argument("--offline", action="store_true")
    args = p.parse_args()

    triage_json_paths = [pth for pth in args.triage_jsons.split(",") if pth]
    remainder, _ = compute_remainder(args.unpatched_csv, triage_json_paths)
    context_by_cve = latest_review_context(triage_json_paths)

    kernel_rows = [r for r in remainder if r.get("package") and "linux" in r["package"]]
    if args.max_cves:
        kernel_rows = kernel_rows[: args.max_cves]

    kconfig_text = Path(args.kconfig).read_text(errors="replace") if args.kconfig else ""

    api_key = None
    if not args.offline:
        import os
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key and not args.response_cache:
            sys.exit("ai_cve_escalation: ANTHROPIC_API_KEY not set and no --response-cache to fall back on")

    results = []
    for row in kernel_rows:
        cve, summary = row["cve"], row.get("summary", "")
        context = context_by_cve.get(cve)
        if args.offline:
            draft = {"justification": "insufficient_evidence", "justification_text": "--offline: not drafted", "confidence": "low"}
        else:
            try:
                draft = draft_one(cve, summary, context, api_key, args.model,
                                   args.prompt_revision, args.response_cache)
            except Exception as e:
                draft = {"justification": "insufficient_evidence", "justification_text": f"model call failed: {e}", "confidence": "low"}
        verified, evidence, symbols = reverify(args.kernel_git_dir, kconfig_text, draft)
        results.append({"cve": cve, "draft": draft, "verified": verified, "evidence": evidence, "symbols": symbols})

    inapplicable, fixed, mismatch, review = rebucket(results)
    write_report(args.out_prefix, "ai-escalation", args.our_ref, len(results),
                  inapplicable, fixed, mismatch, review)
    print(f"ai escalation: {len(results)} drafted, {len(remainder) - len(kernel_rows)} skipped (non-kernel/over cap) -- "
          f"{len(inapplicable)} config-inapplicable (OpenVEX not_affected, re-verified), "
          f"{len(review)} still need human review (model + independent re-check, zero confidence weight in scoring)")


if __name__ == "__main__":
    main()
