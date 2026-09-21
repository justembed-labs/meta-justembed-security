# Platform-specific evidence

`docs/platform-validation-matrix.md` is the central index -- what has
actually been built, tested, and evidenced per platform, and what's
still `Planned`. This directory holds the detailed evidence document
for each platform once real validation work on it begins.

A platform document here (once one exists) covers:

- Board / SoC.
- Yocto release and branch.
- BSP layers used (name, revision/commit).
- `MACHINE`.
- Kernel version.
- U-Boot version.
- Secure boot root (what's verified, by what, anchored where -- same
  stage-by-stage framing as `docs/update-boot.md`, specific to this
  board's actual boot ROM/SPL/U-Boot chain).
- Test results, linked to `docs/evidence/` entries where applicable.
- Known limitations specific to this platform.

No placeholder documents exist yet for platforms still marked
`Planned` in the matrix -- an empty template with nothing real to put
in it is worse than no document, per this project's own evidence
standard (`docs/evidence/README.md`: "Only add an entry for something
that was actually run and observed").
