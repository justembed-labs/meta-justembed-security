# Contributing

Pre-1.0. External contributions aren't being accepted yet -- this file
documents the standard the project already holds itself to, so it's
in place before that changes.

## The one rule: prove it on real hardware

A clean build proves a recipe is well-formed. It proves nothing about
whether the layer works. Every claim in this project's docs that
something is "verified" or "hardware-proven" means it was actually
run against a real target and the result was observed directly (a
real exploit reproduced, a real signed update flashed and rebooted,
a real audit rule firing on a real syscall) -- not inferred from a
successful build log. New rules, recipes, or `bbclass` changes are
expected to meet the same bar before being described as done.

## Style

- **Docs are terse and command-first.** State what's true and how to
  reproduce it; skip the narrative. See any `README.md` in this repo
  for the target density.
- **No customer/project-specific identifiers.** These layers are
  meant to be adoptable by any Yocto BSP. Board-specific work stays
  downstream in the adopting project until it's proven and ready to
  be promoted here (see each layer's own "staying hardware-agnostic"
  or equivalent section).
- **Comments explain non-obvious constraints, not history.** No "why
  we chose X over Y" in code comments -- that belongs in the commit
  message or `docs/decisions.md` of the consuming project.
- **Honest gaps over aspirational claims.** A "not yet demonstrated" or
  "known limitation" note that's actually true is worth more than a
  roadmap bullet nobody will hold to.

## Commit messages

Explain *why*, not just *what* -- the diff already shows what changed.
Reference the real motivating constraint (a CVE, a bug found on
hardware, a spec line from the source plan) rather than restating the
change.

## Reporting a vulnerability

Don't open a public issue -- see `SECURITY.md`.
