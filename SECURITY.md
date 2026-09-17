# Security policy

This project ships detection and update-integrity tooling for embedded
Linux. A vulnerability here has outsized impact -- report privately,
not via a public issue.

## Reporting

Email **security@justembed.nl** with:

- affected layer/recipe and version (git commit or tag),
- what's wrong and why it's exploitable (a PoC helps but isn't
  required to make a report valid),
- impact as you see it (e.g. "bypasses `meta-je-detection`'s rule
  bundle verification", not just "this looks off").

Expect an acknowledgment within 5 business days. We'll agree a
disclosure timeline with you before anything is made public; 90 days
from acknowledgment is our default if we don't agree on something
else.

## Scope

In scope: any recipe, script, or `bbclass` under
`meta-je-hygiene`/`meta-je-sbom-cve`/`meta-je-detection`/
`meta-je-boot-update` in this repository. Board-specific integration
code living downstream (e.g. in an adopter's own BSP repo) is that
repo's own security process, not this one.

Out of scope: vulnerabilities in upstream dependencies this project
consumes but doesn't author (the kernel, swupdate, auditd, Fluent Bit,
OpenSSH, etc.) -- report those to the upstream project. If an upstream
CVE affects how one of these layers is configured or shipped, that's
still useful for us to know about here.

## Supported versions

Pre-1.0, `main` only -- no separate maintained release branches yet.
