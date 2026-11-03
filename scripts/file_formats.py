"""Write FILE_FORMATS.md: every format the current build extracts, grouped
by type.

    cargo build --release --features full --bin whiff
    target/release/whiff formats --json > formats.json
    python3 scripts/file_formats.py formats.json > File_FORMATS.md

The list comes from the registry (`whiff formats --json`, all features);
the type (category) and Cargo feature of each family come from
data/families.tsv. A format is unreleased when the latest release tag has
no fixtures for it (every format has fixtures under tests/fixtures/<id>/).
When preparing a release, set WHIFF_RELEASE to its tag (WHIFF_RELEASE=v0.7.0)
so every format counts as released in it.
"""

import collections
import json
import os
import subprocess
import sys

ORDER = ["Text", "Web", "Document", "Personal", "Data", "Scientific", "Code", "Image", "Media", "Font", "Archive", "Package",
         "Executable", "Security", "Database", "Platform", "Disk", "Forensics", "Geospatial", "3D", "CAD", "Fallback"]

TITLES = {
    "Personal": "E-mail, calendars and contacts",
    "Platform": "Apple platform formats",
    "Security": "Certificates, keys and signatures",
    "Disk": "Disk images and file systems",
    "Forensics": "Forensic artefacts",
    "Fallback": "Generic binaries",
    "3D": "3D models and scenes",
    "CAD": "CAD, engineering and electronics",
    "Scientific": "Scientific and medical data",
}


LABELS = {
    "text.plain": "Plain text", "text.markdown": "Markdown", "text.lightmarkup": "Light markup",
    "text.html": "HTML", "text.feed": "Feeds", "text.xml": "XML", "text.calendar": "Calendars",
    "text.contact": "Contacts", "text.subtitle": "Subtitles", "email": "E-mail",
    "data.json": "JSON", "data.yaml": "YAML", "data.toml": "TOML", "data.ini": "INI", "data.csv": "CSV / TSV",
    "data.sql": "SQL", "data.binser": "Binary serialisations", "columnar": "Columnar data and models",
    "code.source": "Source code", "code.manifest": "Package manifests", "code.notebook": "Notebooks",
    "code.infra": "Build and infrastructure files",
    "doc.pdf": "PDF", "doc.ooxml": "Office Open XML", "doc.ole": "Office 97–2003 (OLE)", "doc.odf": "OpenDocument",
    "doc.rtf": "RTF", "doc.ebook": "E-books", "doc.other": "Other documents",
    "image.raster": "Raster images", "image.raw": "Camera raw", "image.vector": "Vector images",
    "image.layered": "Layered images", "image.texture": "GPU textures",
    "audio": "Audio", "video": "Video", "audio.playlist": "Playlists", "audio.score": "Music scores",
    "font": "Fonts", "archive": "Archives", "compress": "Compressed files", "package": "Packages and installers",
    "exec": "Executables", "bytecode": "Bytecode", "crypto": "Certificates, keys and signatures",
    "db": "Databases", "apple": "Apple formats", "disk": "Disk images and file systems",
    "forensic": "Forensic artefacts", "geo": "Geospatial", "binary.unknown": "Generic binaries",
}


def family_label(fid):
    return LABELS.get(fid, fid)


def released_ids():
    """Format ids with fixtures in the latest release tag (empty if none)."""
    tags = subprocess.run(["git", "tag", "--sort=-v:refname"], capture_output=True, text=True).stdout.split()
    if not tags:
        return None, set()
    names = subprocess.run(["git", "ls-tree", "--name-only", tags[0], "tests/fixtures/"],
                           capture_output=True, text=True).stdout.split()
    return tags[0], {n.rsplit("/", 1)[-1] for n in names}


def esc(s):
    return s.replace("|", "\\|")


def main():
    formats = json.load(open(sys.argv[1]))
    fams = {}
    for line in open("data/families.tsv"):
        if line.startswith("#") or not line.strip():
            continue
        c = line.rstrip("\n").split("\t")
        fams[c[0]] = {"category": c[1], "feature": c[2], "stage": c[4]}

    tag, released = released_ids()
    if os.environ.get("WHIFF_RELEASE"):
        tag, released = os.environ["WHIFF_RELEASE"], {f["id"] for f in formats}

    by_cat = collections.defaultdict(lambda: collections.defaultdict(list))
    for f in formats:
        by_cat[fams[f["family"]]["category"]][f["family"]].append(f)

    cats = [c for c in ORDER if c in by_cat] + sorted(c for c in by_cat if c not in ORDER)
    out = ["# File formats", ""]
    out.append(f"whiff extracts metadata from the **{len(formats)} formats** below (a build with every feature). "
               "Formats it does not list are still identified by signature and get the universal sections "
               "(identification, system, temporal, security, physical, integrity).")
    out.append("")
    out.append("The **Feature** column is the Cargo feature that enables a format; `common` is on by default. "
               f"*Unreleased* formats are on `main` but not in the latest release ({tag or 'none yet'}). "
               "[`docs/metadata-extracted.md`](docs/metadata-extracted.md) lists every format planned and what is "
               "extracted from each; [`docs/known-gaps.md`](docs/known-gaps.md) lists what is deliberately left out.")
    out.append("")
    out.append("Generated by `scripts/file_formats.py` from `whiff formats --json` and `data/families.tsv`.")
    out.append("")
    out.append("## Contents")
    out.append("")
    out.append("| Type | Formats |")
    out.append("|---|---|")
    for c in cats:
        n = sum(len(v) for v in by_cat[c].values())
        title = TITLES.get(c, c)
        anchor = title.lower().replace(",", "").replace(" ", "-")
        out.append(f"| [{title}](#{anchor}) | {n} |")
    for c in cats:
        out.append("")
        out.append(f"## {TITLES.get(c, c)}")
        families = sorted(by_cat[c], key=lambda k: family_label(k).lower())
        for fam in families:
            items = sorted(by_cat[c][fam], key=lambda f: f["name"].lower())
            # A type with one family needs no sub-heading.
            if len(families) > 1:
                out.append("")
                out.append(f"### {family_label(fam)}")
            out.append("")
            out.append("| Format | ID | Extensions | Feature | Extractor |")
            out.append("|---|---|---|---|---|")
            for f in items:
                exts = " ".join(f"`.{e}`" for e in f["extensions"]) or "—"
                new = " *(unreleased)*" if released and f["id"] not in released else ""
                out.append(f"| {esc(f['name'])}{new} | `{f['id']}` | {exts} | `{fams[fam]['feature']}` | `{f['extractor']}` |")
    print("\n".join(out))


if __name__ == "__main__":
    main()
