#!/usr/bin/env python3
"""AI-escalation stage: a model drafts evidence for whatever every
deterministic triage stage before it couldn't resolve. Never on the
critical path -- only ever sees the genuine remainder, never the raw
CVE list -- and never terminal on its own: every draft is independently
re-checked by the same deterministic verification kernel_backport_check.py
and kernel_cve_triage.py already use, before anything counts as resolved.
Same 4-bucket OUT_PREFIX.json/.md shape as every other triage stage --
drops straight into prioritize_cves.py's triage_jsons, no changes needed
there.

Prompt framing matters: ask the model to find evidence of impact, not to
clear the CVE -- asking it to prove a CVE doesn't apply invites a
reassuring false negative. The model's own stated confidence carries
*zero* scoring weight (see kev_epss_enrich.py) -- hardcoded policy, not
learned, same discipline as docs/responsible-ai.md.

Usage:
    ai_cve_escalation.py UNPATCHED_CSV TRIAGE_JSONS OUT_PREFIX \\
        KERNEL_GIT_DIR OUR_REF [--spdx SPDX_FILE] [--kconfig KCONFIG]
        [--model MODEL] [--prompt-revision REV] [--max-cves N]
        [--response-cache DIR] [--offline]

UNPATCHED_CSV   parsed/unpatched.csv from parse_cve.py.
TRIAGE_JSONS    comma-separated reports from every stage already run
                (same list prioritize_cves.py would get) -- used to
                compute the true cumulative remainder via
                triage_common.compute_remainder(), not just one stage's
                own needs_human_review.
KERNEL_GIT_DIR / OUR_REF   same real kernel checkout every other kernel
                stage uses, for independently re-verifying any commit
                the model cites.
--spdx          kernel SPDX doc, for re-verifying any config-inapplicable
                claim the model makes (same as kernel_backport_check.py).
--kconfig       the build's real .config, needed for that same check.
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
from kernel_backport_check import verify_one, compiled_files  # noqa: E402
from kernel_cve_triage import (  # noqa: E402
    find_config_symbol, config_status, files_touched_by_commit, write_report,
)

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-5"
# Bump this when the prompt text below changes -- it's an input to the
# reproducibility hash (docs/cve-triage.md rule 1: the prompt revision is
# an input, not just the CVE data), not a free-text comment.
PROMPT_REVISION = "ai-escalation-v1"
TIMEOUT = 60

TOOL_SCHEMA = {
    "name": "submit_cve_evidence",
    "description": "Report what evidence of real-world impact exists for this CVE against this exact kernel build.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["evidence_of_impact", "evidence_against_impact", "inconclusive"],
            },
            "cited_commit": {
                "type": "string",
                "description": "A real upstream commit hash this verdict rests on, if any. Leave empty if none.",
            },
            "cited_file": {
                "type": "string",
                "description": "A specific affected source file path, if the commit is unknown. Leave empty if none.",
            },
            "justification": {
                "type": "string",
                "description": "Why -- cite the specific evidence found, not a restatement of the CVE summary.",
            },
            "confidence": {
                "type": "string",
                "enum": ["low", "medium", "high"],
            },
        },
        "required": ["verdict", "justification", "confidence"],
    },
}

SYSTEM_PROMPT = (
    "You are triaging a single Linux kernel CVE against one real, specific "
    "kernel build. Deterministic tools already tried and failed to resolve "
    "it from commit ancestry and Kconfig alone. Your job is NOT to decide "
    "whether the CVE applies -- asking you to clear a CVE produces "
    "reassuring guesses. Instead: search for concrete EVIDENCE OF IMPACT -- "
    "a specific commit that fixes it, or a specific source file the "
    "vulnerable code lives in. If you can't find real evidence either way, "
    "say so plainly (inconclusive) rather than guessing. Every claim you "
    "make gets independently re-verified against the real source tree "
    "before anyone trusts it -- a wrong guess is caught, not acted on, but "
    "wastes the human reviewer's time, so only cite evidence you actually "
    "have reason to believe is real."
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
    lines.append("Find evidence of impact (or its absence) for this exact kernel build.")
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
        "tool_choice": {"type": "tool", "name": "submit_cve_evidence"},
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
        if block.get("type") == "tool_use" and block.get("name") == "submit_cve_evidence":
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


def reverify(kernel_dir, our_ref, kconfig_text, compiled, draft):
    """The model never resolves anything on its own -- independently
    re-check whatever evidence it cited using the exact same deterministic
    checks kernel_backport_check.py / kernel_cve_triage.py already use.
    Returns one of 'patched', 'vulnerable', 'not-applicable-config',
    or None (nothing the model cited could be independently confirmed).
    An 'inconclusive' verdict is never reverified, even if a file/commit
    name appears in the justification text -- the model is explicitly
    not claiming that as real evidence, so citing it must not be
    mechanically treated as if it were."""
    if draft.get("verdict") not in ("evidence_of_impact", "evidence_against_impact"):
        return None, None
    commit = (draft.get("cited_commit") or "").strip()
    if commit:
        verdict, _ = verify_one(kernel_dir, our_ref, [commit], compiled, 1)
        if verdict in ("patched", "not-applicable-config"):
            return verdict, commit
        return None, commit
    filepath = (draft.get("cited_file") or "").strip()
    if filepath and kconfig_text:
        symbol = find_config_symbol(kernel_dir, filepath)
        if symbol and config_status(kconfig_text, symbol) == "not-set":
            return "not-applicable-config", filepath
    return None, None


def rebucket(results):
    inapplicable, fixed, mismatch, review = [], [], [], []
    for r in results:
        cve, draft, verified, evidence = r["cve"], r["draft"], r["verified"], r["evidence"]
        if verified == "not-applicable-config":
            inapplicable.append({
                "cve": cve, "source": "ai-escalation",
                "config_symbol": "ai-escalation", "file": str(evidence),
                "reason": f"AI-cited evidence ({evidence}) independently re-verified as not compiled in -- model justification: {draft['justification']}",
                "suggested_cve_status": f'CVE_STATUS[{cve}] = "not-applicable-config: not compiled (ai-escalation, re-verified)"',
            })
        elif verified == "patched":
            fixed.append({
                "cve": cve, "source": "ai-escalation", "commit": str(evidence)[:12],
                "subject": f"AI-cited fix commit independently re-verified present (git apply --check --reverse) -- model justification: {draft['justification']}",
                "suggested_cve_status": f'CVE_STATUS[{cve}] = "fixed-version: AI-escalation cite, re-verified present, {str(evidence)[:12]}"',
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
    p.add_argument("--spdx")
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

    compiled = compiled_files(args.spdx) if args.spdx else None
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
            draft = {"verdict": "inconclusive", "justification": "--offline: not drafted", "confidence": "low"}
        else:
            try:
                draft = draft_one(cve, summary, context, api_key, args.model,
                                   args.prompt_revision, args.response_cache)
            except Exception as e:
                draft = {"verdict": "inconclusive", "justification": f"model call failed: {e}", "confidence": "low"}
        verified, evidence = reverify(args.kernel_git_dir, args.our_ref, kconfig_text, compiled, draft)
        results.append({"cve": cve, "draft": draft, "verified": verified, "evidence": evidence})

    inapplicable, fixed, mismatch, review = rebucket(results)
    write_report(args.out_prefix, "ai-escalation", args.our_ref, len(results),
                  inapplicable, fixed, mismatch, review)
    print(f"ai escalation: {len(results)} drafted, {len(remainder) - len(kernel_rows)} skipped (non-kernel/over cap) -- "
          f"{len(inapplicable)} config-inapplicable, {len(fixed)} fixed-version, "
          f"{len(review)} still need human review (model + independent re-check, zero confidence weight in scoring)")


if __name__ == "__main__":
    main()
