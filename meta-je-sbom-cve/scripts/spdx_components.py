#!/usr/bin/env python3
"""Extract a stable recipe-level component list from a Yocto SPDX 2.2 bundle.

Usage:
    spdx_components.py SPDX_SOURCE OUT_TSV

SPDX_SOURCE is either:
  - a *.spdx.tar.zst bundle (the per-image SBOM in the deploy dir), or
  - a directory containing *.spdx.json

OUT_TSV gets one row per recipe:
    name<TAB>version<TAB>license<TAB>spdxid

Scarthgap create-spdx (SPDX 2.2) layout inside the bundle:
  <image>.spdx.json        the image doc (one package: the image itself)
  recipe-<name>.spdx.json  one per recipe -- packages[] has a
                           SPDXID "SPDXRef-Recipe-<name>" entry with
                           name / versionInfo / licenseDeclared, plus a
                           "SPDXRef-Download-*" entry (null version, skipped)
  <name>.spdx.json         one per runtime package (not used here)

Only the SPDXRef-Recipe-* entries in recipe-*.spdx.json are taken --
that's the stable SBOM-diff / license-inventory shape; the runtime
package set churns on every build.

Shells out to `zstd -dc | tar` -- python tarfile zst support is 3.14+.
"""
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path


def _recipe_docs_from_tar_zst(path):
    proc = subprocess.run(["sh", "-c", f'zstd -dc -- "{path}"'],
                          capture_output=True, check=True)
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as tf:
        for member in tf.getmembers():
            base = Path(member.name).name
            if not member.isfile() or not base.startswith("recipe-") \
                    or not base.endswith(".spdx.json"):
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            try:
                yield json.loads(fh.read())
            except json.JSONDecodeError:
                continue


def _recipe_docs_from_dir(path):
    for p in sorted(Path(path).rglob("recipe-*.spdx.json")):
        try:
            yield json.loads(p.read_text())
        except json.JSONDecodeError:
            continue


def recipe_docs(source):
    src = Path(source)
    if src.is_dir():
        yield from _recipe_docs_from_dir(src)
    elif ".tar.zst" in src.name:
        yield from _recipe_docs_from_tar_zst(src)
    else:
        sys.exit(f"unrecognised SPDX source: {source}")


def _license(pkg):
    for key in ("licenseDeclared", "licenseConcluded"):
        val = pkg.get(key)
        if val and val != "NOASSERTION":
            return val
    return "NOASSERTION"


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    source, out_tsv = sys.argv[1], sys.argv[2]

    components = {}
    for doc in recipe_docs(source):
        for pkg in doc.get("packages", []):
            spdxid = pkg.get("SPDXID", "")
            if not spdxid.startswith("SPDXRef-Recipe-"):
                continue
            name = pkg.get("name")
            if not name:
                continue
            components[name] = (pkg.get("versionInfo") or "",
                                _license(pkg), spdxid)

    rows = sorted(components.items())
    with open(out_tsv, "w") as f:
        for name, (version, lic, spdxid) in rows:
            f.write(f"{name}\t{version}\t{lic}\t{spdxid}\n")

    print(f"extracted {len(rows)} recipe components -> {out_tsv}")


if __name__ == "__main__":
    main()
