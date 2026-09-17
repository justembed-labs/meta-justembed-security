#!/usr/bin/env python3
"""Per-layer license / origin inventory of the image's components.

Usage:
    layer_inventory.py CVE_PACKAGES_JSON COMPONENTS_TSV OUT_PREFIX

CVE_PACKAGES_JSON  parse_cve.py packages.json -- the recipes that
                   contribute content to the image, each with its "layer"
                   (from the scarthgap cve-check manifest).
COMPONENTS_TSV     spdx_components.py output -- adds licenseDeclared and
                   the SPDX version string per recipe.

Driven by the cve-check package set (what ships), enriched with the SPDX
license. Build-only recipes (-native / -cross / nativesdk-) never appear
in the cve-check manifest, so they're excluded by construction.

Writes:
    OUT_PREFIX.json   {layer: {origin, component_count, components, licenses}}
    OUT_PREFIX.md     summary table + a per-layer component table

meta-justembed-* = JustEmbed-authored; everything else upstream/vendor.
Structural inventory only, NOT a legal determination -- patches and
build glue in the "upstream" layers can still raise derivative-work
questions (see docs/decisions.md, general-company context/open-source.md).
"""
import json
import sys
from collections import defaultdict
from pathlib import Path


def load_spdx(path):
    out = {}
    p = Path(path)
    if not p.is_file():
        return out
    for line in p.read_text().splitlines():
        parts = line.split("\t")
        if parts and parts[0]:
            out[parts[0]] = {
                "version": parts[1] if len(parts) > 1 else "",
                "license": parts[2] if len(parts) > 2 else "NOASSERTION",
            }
    return out


def origin(layer):
    return "justembed" if layer.startswith("meta-justembed") else "upstream"


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    cve_p, comp_p, out_prefix = sys.argv[1:4]

    spdx = load_spdx(comp_p)
    packages = json.loads(Path(cve_p).read_text())

    by_layer = defaultdict(lambda: {"origin": "", "components": [], "licenses": defaultdict(int)})
    for pkg in sorted(packages, key=lambda p: p["name"]):
        name = pkg["name"]
        layer = pkg.get("layer") or "unknown"
        enrich = spdx.get(name, {})
        lic = enrich.get("license", "NOASSERTION")
        version = pkg.get("version") or enrich.get("version", "")
        entry = by_layer[layer]
        entry["origin"] = origin(layer)
        entry["components"].append({"name": name, "version": version, "license": lic})
        entry["licenses"][lic] += 1

    result = {}
    for layer, entry in sorted(by_layer.items()):
        result[layer] = {
            "origin": entry["origin"],
            "component_count": len(entry["components"]),
            "components": entry["components"],
            "licenses": dict(sorted(entry["licenses"].items(), key=lambda kv: (-kv[1], kv[0]))),
        }
    Path(out_prefix + ".json").write_text(json.dumps(result, indent=2) + "\n")

    total = sum(d["component_count"] for d in result.values())
    je = sum(d["component_count"] for d in result.values() if d["origin"] == "justembed")
    md = ["# Per-layer license / origin inventory\n",
          f"{total} image components across {len(result)} layers "
          f"({je} from `meta-justembed-*`, {total - je} upstream/vendor).\n",
          "Structural inventory only -- not a legal determination. "
          "Patches and build glue in the upstream layers can still raise "
          "derivative-work questions (see `docs/decisions.md`).\n",
          "## Summary\n",
          "| layer | origin | components | top licenses |",
          "|---|---|---|---|"]
    for layer, data in result.items():
        lic = ", ".join(f"{k} ({v})" for k, v in list(data["licenses"].items())[:6])
        md.append(f"| `{layer}` | {data['origin']} | {data['component_count']} | {lic} |")
    md.append("")
    for layer, data in result.items():
        md.append(f"## `{layer}`  _({data['origin']}, {data['component_count']} components)_\n")
        md.append("| component | version | license |")
        md.append("|---|---|---|")
        for c in data["components"]:
            md.append(f"| {c['name']} | {c['version']} | {c['license']} |")
        md.append("")
    Path(out_prefix + ".md").write_text("\n".join(md) + "\n")

    print(f"layer inventory: {len(result)} layers, {total} components ({je} justembed)")


if __name__ == "__main__":
    main()
