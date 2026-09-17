# SPDX SBOM generation, wrapping create-spdx.bbclass with JE defaults.
# `inherit` (not `INHERIT +=`) so this actually pulls create-spdx in
# when *this* class is loaded via a global `INHERIT += "je-sbom"` --
# nesting `INHERIT +=` inside a class only appends to the variable's
# text, it does not trigger a second real class-loading pass.

inherit create-spdx
SPDX_PRETTY ??= "1"
