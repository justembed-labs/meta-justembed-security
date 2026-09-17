#!/usr/bin/env python3
"""Diff two SBOM component lists.

Usage:
    diff_sbom.py CURRENT_TSV PREVIOUS_TSV OUT_PREFIX

Each TSV is spdx_components.py output (name<TAB>version<TAB>license<TAB>spdxid).
Writes OUT_PREFIX.json and OUT_PREFIX.md:

  added            name present now, not before
  removed          name present before, not now
  version_changed  same name, versionInfo moved
  license_changed  same name, declared license moved

An AUTOINC/SRCREV version like "1.0+git0+abcdef1234" is normalised for
the comparison to "1.0+git<7hex>" so a plain source-rev bump on an
otherwise-pinned recipe still shows as a version change (with the real
before/after strings kept in the row) rather than noise on every build.
"""
import json
import re
import sys
from pathlib import Path

_SRCREV = re.compile(r"(\+git)[0-9]*\+?[0-9a-f]{7,40}", re.I)


def norm_version(v):
    return _SRCREV.sub(r"\1<rev>", v)


def load(path):
    out = {}
    p = Path(path)
    if not p.is_file():
        return out
    for line in p.read_text().splitlines():
        parts = line.split("\t")
        if not parts or not parts[0]:
            continue
        name = parts[0]
        out[name] = {
            "version": parts[1] if len(parts) > 1 else "",
            "license": parts[2] if len(parts) > 2 else "",
        }
    return out


def _cell(v):
    # A raw newline or unescaped "|" splits a table row across lines --
    # breaks any markdown table parser, not just a strict one.
    return " ".join(str(v).split()).replace("|", "\\|")


def md_table(rows, cols):
    if not rows:
        return "_none_\n"
    header = "| " + " | ".join(cols) + " |"
    sep = "|" + "|".join(["---"] * len(cols)) + "|"
    lines = [header, sep]
    for r in rows:
        lines.append("| " + " | ".join(_cell(r.get(c, "")) for c in cols) + " |")
    return "\n".join(lines) + "\n"


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    cur_p, prev_p, out_prefix = sys.argv[1:4]
    cur, prev = load(cur_p), load(prev_p)

    added = [{"name": n, "version": cur[n]["version"], "license": cur[n]["license"]}
             for n in sorted(cur.keys() - prev.keys())]
    removed = [{"name": n, "version": prev[n]["version"], "license": prev[n]["license"]}
              for n in sorted(prev.keys() - cur.keys())]

    version_changed, license_changed = [], []
    for n in sorted(cur.keys() & prev.keys()):
        if norm_version(cur[n]["version"]) != norm_version(prev[n]["version"]):
            version_changed.append({"name": n, "from": prev[n]["version"],
                                    "to": cur[n]["version"]})
        if cur[n]["license"] != prev[n]["license"]:
            license_changed.append({"name": n, "from": prev[n]["license"],
                                    "to": cur[n]["license"]})

    result = {
        "current": cur_p, "previous": prev_p,
        "counts": {"added": len(added), "removed": len(removed),
                   "version_changed": len(version_changed),
                   "license_changed": len(license_changed)},
        "added": added, "removed": removed,
        "version_changed": version_changed, "license_changed": license_changed,
    }
    Path(out_prefix + ".json").write_text(json.dumps(result, indent=2) + "\n")

    md = ["# SBOM diff\n",
          f"- added: **{len(added)}**",
          f"- removed: **{len(removed)}**",
          f"- version changed: **{len(version_changed)}**",
          f"- license changed: **{len(license_changed)}**\n",
          "## Added\n", md_table(added, ["name", "version", "license"]),
          "## Removed\n", md_table(removed, ["name", "version", "license"]),
          "## Version changed\n", md_table(version_changed, ["name", "from", "to"]),
          "## License changed\n", md_table(license_changed, ["name", "from", "to"])]
    Path(out_prefix + ".md").write_text("\n".join(md))

    print(f"sbom diff: +{len(added)} -{len(removed)} "
          f"~{len(version_changed)}ver ~{len(license_changed)}lic")


if __name__ == "__main__":
    main()
