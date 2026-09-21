# Getting started (with AI)

Adding these layers to a new BSP target is a short, concrete sequence
-- not a research problem. An implementer (human or an AI coding
agent) can follow this directly:

1. **Add the kas dependency** -- real `url:`/`branch:`, `layers:` naming
   whichever of `meta-je-hygiene` / `meta-je-sbom-cve` /
   `meta-je-detection` you're adopting.
2. **`meta-je-detection` only** -- add two kernel config fragments via
   a `.bbappend` on your kernel recipe: `CONFIG_AUDIT=y` +
   `CONFIG_AUDITSYSCALL=y` (always), plus whichever kernel feature the
   specific CVE rule you're using needs (e.g. `CONFIG_TUN=y` for the
   sample tunnel-forwarding rule) -- check per rule, per target, don't
   assume.
3. **Set `RDEPENDS`/service exec paths exactly** as documented -- two
   package names and one binary path that look right but aren't
   (`auditd` not `audit`, `python3-modules` not a single stdlib split
   package, `/usr/bin/td-agent-bit` not `/usr/bin/fluent-bit`).
4. **Build and deploy.**
5. **Validate on real hardware** -- confirm every service is actually
   `active (running)` (not just `enabled`), the audit rule is loaded,
   and triggering the real condition produces a real event that
   actually lands wherever it's shipped to. A clean build proves the
   recipe is well-formed; it proves nothing about whether the layer
   works.

This project has been built and run against Yocto **scarthgap**;
other releases haven't been tested and aren't claimed to work.

Full detail, exact commands, and the reasoning behind each gotcha:
`.claude/skills/meta-je-bootstrap/SKILL.md`. It ships with the layers
so it travels to any adopter -- to activate it in a *consuming*
project, copy or symlink the skill directory into that project's own
`.claude/skills/` (Claude Code only discovers skills relative to the
working directory it's invoked in, not across repos).

For a from-scratch, no-hardware walkthrough, start from
[`meta-je-example-bsp`](https://github.com/justembed-labs/meta-je-example-bsp)
instead -- it's a complete, working `kas.yml` you can build directly.
