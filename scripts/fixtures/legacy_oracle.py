#!/usr/bin/env python3
"""Oracle for the stage 8 long-tail fixtures (batch 4): independent tools
read each fixture and their facts are compared with whiff's report.

    # in the whiff-legacy container (see legacy.sh):
    python3 scripts/fixtures/legacy_oracle.py expect tests/fixtures > target/legacy-expect.json
    # on the host:
    python3 scripts/fixtures/legacy_oracle.py check target/legacy-expect.json [path/to/whiff]

Tools: `nomarch` (ARC), `lsar` from The Unarchiver (Zoo, ALZip, StuffIt,
MacBinary), the `acefile` module (ACE), `zpaq l` (ZPAQ), `wimlib-imagex info` (WIM), macutils `hexbin`
(BinHex), sharutils `uudecode` and coreutils `base64`, the shar scripts
themselves (run in a scratch folder) and Makeself's `--info`, `jmod list`,
Python's zipfile and json (zip applications, PEX-INFO), `restore -t` (dump),
configparser (Borg), zlib and tarfile (Android backups), libmagic
`file`, and the Python standard library where the format is plain text
(the KGB header; yEnc, decoded separately from whiff).
Each expectation is (fixture, report path, value).
"""

import json
import re
import subprocess
import sys
from pathlib import Path

EXPECT = []


def want(fixture, path, value, tool):
    if value is None:
        return
    EXPECT.append({"file": str(fixture), "path": path, "value": value, "tool": tool})


def out(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", check=True).stdout


def entries(fx, fmt, f, rows, tool):
    """`rows`: (path, size) in archive order."""
    want(fx / f, f"format.{fmt}.files", len(rows), tool)
    for i, (path, size) in enumerate(rows):
        want(fx / f, f"format.{fmt}.entries.{i}.path", path, tool)
        want(fx / f, f"format.{fmt}.entries.{i}.size_bytes", size, tool)


def libmagic(fx, f, needle):
    desc = out("file", "-b", str(fx / f))
    want(fx / f, "_libmagic", needle if needle.lower() in desc.lower() else f"MISSING {needle}: {desc.strip()}", "file")


def dos(fx):
    for f in sorted((fx / "arc").glob("*.arc")):
        rows = []
        for line in out("nomarch", "-l", str(f)).splitlines():
            name, size = line.split("\t")[0].strip(), int(line.split("\t")[1].split()[0])
            rows.append((name.upper(), size))
        entries(fx, "arc", f.relative_to(fx), rows, "nomarch")
        libmagic(fx, f.relative_to(fx), "ARC archive")
    for f in sorted((fx / "alz").glob("*.alz")):
        j = json.loads(out("lsar", "-j", str(f)))
        rows = [(e["XADFileName"].replace("/", "\\"), e["XADFileSize"]) for e in j["lsarContents"]]
        entries(fx, "alz", f.relative_to(fx), rows, "lsar")
        libmagic(fx, f.relative_to(fx), "ALZ archive")
    for f in sorted((fx / "zoo").glob("*.zoo")):
        j = json.loads(out("lsar", "-j", str(f)))
        rows = [(e["XADFileName"], e["XADFileSize"]) for e in j["lsarContents"]]
        entries(fx, "zoo", f.relative_to(fx), rows, "lsar")
        libmagic(fx, f.relative_to(fx), "Zoo archive")
    import acefile

    for f in sorted((fx / "ace").glob("*.ace")):
        with acefile.open(str(f)) as a:
            rows = [(m.filename.replace("/", "\\"), m.size) for m in a.getmembers()]
        entries(fx, "ace", f.relative_to(fx), rows, "acefile")
        libmagic(fx, f.relative_to(fx), "ACE archive")
    for f in sorted((fx / "zpaq").glob("*.zpaq")):
        listing = out("zpaq", "l", str(f), "-all")
        versions = int(re.search(r": (\d+) versions", listing).group(1))
        frags = int(re.search(r"(\d+) fragments", listing).group(1))
        mb = float(re.search(r"([\d.]+) MB \(\d+ refs", listing).group(1))
        want(fx / f.relative_to(fx), "format.zpaq.transactions", versions, "zpaq l")
        want(fx / f.relative_to(fx), "format.zpaq.fragments", frags, "zpaq l")
        want(fx / f.relative_to(fx), "format.zpaq.deduplicated_bytes", round(mb * 1_000_000), "zpaq l")
        libmagic(fx, f.relative_to(fx), "ZPAQ")
    for f in sorted((fx / "kgb").glob("*.kgb")):
        lines = f.read_bytes().split(b"\r\n")
        rows = []
        for line in lines[1:]:
            m = re.fullmatch(rb"(\d+)\t(.+)", line)
            if not m:
                break
            rows.append((m.group(2).decode(), int(m.group(1))))
        entries(fx, "kgb", f.relative_to(fx), rows, "header text")
        libmagic(fx, f.relative_to(fx), "KGB Archiver")


def mac(fx):
    for f in sorted((fx / "stuffit").glob("*.sit")):
        j = json.loads(out("lsar", "-j", str(f)))
        rows = [
            (e["XADFileName"], e.get("XADFileSize", 0))
            for e in j["lsarContents"]
            if not e.get("XADIsResourceFork") and not e.get("XADIsDirectory")
        ]
        want(fx / f.relative_to(fx), "format.stuffit.files", len(rows), "lsar")
        libmagic(fx, f.relative_to(fx), "StuffIt")
    for f in sorted((fx / "macbinary").glob("*.bin")):
        j = json.loads(out("lsar", "-j", str(f)))
        for e in j["lsarContents"]:
            key = "resource_fork_bytes" if e.get("XADIsResourceFork") else "data_fork_bytes"
            want(fx / f.relative_to(fx), f"format.macbinary.{key}", e["XADFileSize"], "lsar")
            want(fx / f.relative_to(fx), "format.macbinary.name", e["XADFileName"], "lsar")
        libmagic(fx, f.relative_to(fx), "MacBinary")
    for f in sorted((fx / "binhex").glob("*.hqx")):
        p = subprocess.run(["hexbin", "-i", str(f.resolve())], capture_output=True, text=True, cwd="/tmp")
        info = p.stdout + p.stderr
        m = re.search(r'name="([^"]*)", type=(\S+), author=(\S+), data=(\d+), rsrc=(\d+)', info)
        want(fx / f.relative_to(fx), "format.binhex.name", m.group(1).replace("_", " "), "hexbin")
        want(fx / f.relative_to(fx), "format.binhex.file_type", m.group(2), "hexbin")
        want(fx / f.relative_to(fx), "format.binhex.creator", m.group(3), "hexbin")
        want(fx / f.relative_to(fx), "format.binhex.data_fork_bytes", int(m.group(4)), "hexbin")
        want(fx / f.relative_to(fx), "format.binhex.resource_fork_bytes", int(m.group(5)), "hexbin")


def ydecode(text):
    """yEnc, decoded independently of whiff: (name, data, crc32)."""
    lines = text.split(b"\r\n")
    head = lines[0].decode()
    name = head.split(" name=", 1)[1]
    data, crc = bytearray(), None
    for line in lines[1:]:
        if line.startswith(b"=yend"):
            crc = int(line.split(b"crc32=")[1].split()[0], 16)
            break
        it = iter(line)
        for c in it:
            if c == 0x3D:
                c = (next(it) - 64) & 0xFF
            data.append((c - 42) & 0xFF)
    return name, bytes(data), crc


def encoded(fx):
    import tempfile
    import zlib

    for f in sorted((fx / "uuencode").glob("*.uue")):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["uudecode", "-o", f"{d}/out", str(f.resolve())], check=True)
            name = re.search(rb"^begin(?:-base64)? \d+ (.+)$", f.read_bytes(), re.M).group(1).decode()
            entries(fx, "uuencode", f.relative_to(fx), [(name, Path(f"{d}/out").stat().st_size)], "uudecode")
    for f in sorted((fx / "base64").glob("*.b64")):
        n = len(subprocess.run(["base64", "-d", str(f)], check=True, capture_output=True).stdout)
        want(fx / f.relative_to(fx), "format.base64.decoded_bytes", n, "base64 -d")
    for f in sorted((fx / "yenc").glob("*.yenc")):
        name, data, crc = ydecode(f.read_bytes())
        want(fx / f.relative_to(fx), "format.yenc.name", name, "python")
        want(fx / f.relative_to(fx), "format.yenc.decoded_bytes", len(data), "python")
        want(fx / f.relative_to(fx), "format.yenc.crc32_ok", zlib.crc32(data) == crc, "python zlib")
    for f in sorted((fx / "shar").glob("*.shar")):
        # Unpack it the way it is meant to be: run it.
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["sh", str(f.resolve())], cwd=d, check=True, capture_output=True)
            rows = sorted((str(p.relative_to(d)), p.stat().st_size) for p in Path(d).rglob("*") if p.is_file())
        want(fx / f.relative_to(fx), "format.shar.files", len(rows), "sh")
        for path, size in rows:
            want(fx / f.relative_to(fx), "_shar_member", [path, size], "sh")
        libmagic(fx, f.relative_to(fx), "shell archive")
    for f in sorted((fx / "makeself").glob("*.run")):
        info = subprocess.run(["sh", str(f.resolve()), "--info"], capture_output=True, text=True).stdout
        want(fx / f.relative_to(fx), "format.makeself.label", re.search(r"Identification: (.*)", info).group(1).strip(), "makeself --info")
        want(fx / f.relative_to(fx), "format.makeself.compression", re.search(r"Compression: (\S+)", info).group(1), "makeself --info")
        want(fx / f.relative_to(fx), "format.makeself.startup_script", re.search(r"Script run after extraction:\s*\n?\s*(\S+)", info).group(1), "makeself --info")
        want(fx / f.relative_to(fx), "format.makeself.makeself_version", re.search(r"Built with Makeself version (\S+)", info).group(1), "makeself --info")
        libmagic(fx, f.relative_to(fx), "Makeself")


def wim(fx):
    for f in sorted((fx / "wim").glob("*")):
        if f.name == "SOURCE.md":
            continue
        info = out("wimlib-imagex", "info", str(f))
        rel = f.relative_to(fx)
        want(fx / rel, "format.wim.images", int(re.search(r"Image Count:\s+(\d+)", info).group(1)), "wimlib-imagex")
        want(fx / rel, "format.wim.compression", re.search(r"Compression:\s+(\S+)", info).group(1), "wimlib-imagex")
        for i, block in enumerate(re.split(r"\nIndex:", info)[1:]):
            field = lambda k: re.search(rf"{k}:\s+(.*)", block).group(1).strip()
            want(fx / rel, f"format.wim.image_list.{i}.name", field("Name"), "wimlib-imagex")
            want(fx / rel, f"format.wim.image_list.{i}.files", int(field("File Count")), "wimlib-imagex")
            want(fx / rel, f"format.wim.image_list.{i}.directories", int(field("Directory Count")), "wimlib-imagex")
            want(fx / rel, f"format.wim.image_list.{i}.total_bytes", int(field("Total Bytes")), "wimlib-imagex")
        libmagic(fx, rel, "Windows imaging")


def bundles(fx):
    import struct
    import zipfile

    for kind, pattern in (("zipapp", "*.pyz"), ("pex", "*.pex")):
        for f in sorted((fx / kind).glob(pattern)):
            with zipfile.ZipFile(f) as z:
                files = [i for i in z.infolist() if not i.is_dir()]
                want(fx / f.relative_to(fx), f"format.{kind}.files", len(files), "zipfile")
                if kind == "pex":
                    info = json.loads(z.read("PEX-INFO"))
                    want(fx / f.relative_to(fx), "format.pex.entry_point", info["entry_point"], "PEX-INFO")
                    want(fx / f.relative_to(fx), "format.pex.pex_version", info["build_properties"]["pex_version"], "PEX-INFO")
    for f in sorted((fx / "jmod").glob("*.jmod")):
        listed = [l for l in out("jmod", "list", str(f)).splitlines() if l.strip()]
        want(fx / f.relative_to(fx), "format.jmod.files", len(listed), "jmod list")
        for i, name in enumerate(listed):
            want(fx / f.relative_to(fx), f"format.jmod.entries.{i}.path", name, "jmod list")
    for f in sorted((fx / "obb").glob("*.obb")):
        b = f.read_bytes()
        size, sig = struct.unpack("<LL", b[-8:])
        assert sig == 0x01059983
        footer = b[-8 - size : -8]
        _, pver, _, _, n = struct.unpack("<LLL8sL", footer[:24])
        want(fx / f.relative_to(fx), "format.obb.package", footer[24 : 24 + n].decode(), "struct")
        want(fx / f.relative_to(fx), "format.obb.package_version", pver, "struct")


def backups(fx):
    import configparser
    import io
    import tarfile
    import zlib

    for f in sorted((fx / "unix_dump").glob("*.dump")):
        listing = subprocess.run(["restore", "-t", "-f", str(f)], capture_output=True, text=True).stdout
        m = re.search(r"Level (\d+) dump of (.*) on [^:]*:(\S+)", listing)
        want(fx / f.relative_to(fx), "format.unix_dump.level", int(m.group(1)), "restore -t")
        want(fx / f.relative_to(fx), "format.unix_dump.file_system", m.group(2), "restore -t")
        want(fx / f.relative_to(fx), "format.unix_dump.device", m.group(3), "restore -t")
        want(fx / f.relative_to(fx), "format.unix_dump.label", re.search(r"Label: (\S+)", listing).group(1), "restore -t")
    for f in sorted((fx / "android_backup").glob("*.ab")):
        lines = f.read_bytes().split(b"\n", 4)
        want(fx / f.relative_to(fx), "format.android_backup.encryption", lines[3].decode(), "header")
        if lines[3] == b"none":
            tar = zlib.decompress(lines[4])
            want(fx / f.relative_to(fx), "format.android_backup.tar_bytes", len(tar), "zlib")
            with tarfile.open(fileobj=io.BytesIO(tar)) as t:
                want(fx / f.relative_to(fx), "embedded.0.format.tar.files", len(t.getmembers()), "tarfile")
    for f in sorted((fx / "borg_repository").glob("config")):
        c = configparser.ConfigParser()
        c.read(f)
        r = c["repository"]
        want(fx / f.relative_to(fx), "format.borg_repository.segments_per_dir", int(r["segments_per_dir"]), "configparser")
        want(fx / f.relative_to(fx), "format.borg_repository.repository_id", r["id"], "configparser")


def executables(fx):
    for f in sorted((fx / "ms_pdb").glob("*.pdb")):
        summary = out("llvm-pdbutil", "dump", "-summary", str(f))
        want(fx / f.relative_to(fx), "format.ms_pdb.age", int(re.search(r"Age: (\d+)", summary).group(1)), "llvm-pdbutil")
        want(fx / f.relative_to(fx), "format.ms_pdb.guid", re.search(r"GUID: (\{[^}]+\})", summary).group(1), "llvm-pdbutil")
        want(fx / f.relative_to(fx), "format.ms_pdb.signature", int(re.search(r"Signature: (\d+)", summary).group(1)), "llvm-pdbutil")
        mods = re.findall(r"Mod \d+ \| `([^`]*)`", out("llvm-pdbutil", "dump", "-modules", str(f)))
        want(fx / f.relative_to(fx), "format.ms_pdb.module_count", len(mods), "llvm-pdbutil")
        for i, m in enumerate(mods):
            want(fx / f.relative_to(fx), f"format.ms_pdb.modules.{i}.module", m, "llvm-pdbutil")
    for f in sorted((fx / "split_dwarf").glob("*.dwo")):
        info = out("llvm-dwarfdump", "--debug-info", str(f))
        want(fx / f.relative_to(fx), "format.split_dwarf.producer", re.search(r'DW_AT_producer\s+\("([^"]*)"\)', info).group(1), "llvm-dwarfdump")
        want(fx / f.relative_to(fx), "format.split_dwarf.unit_list.0.dwo_id", re.search(r"DWO_id = 0x([0-9a-f]+)", info).group(1), "llvm-dwarfdump")
    for f in sorted((fx / "split_dwarf").glob("*.dwp")):
        idx = out("llvm-dwarfdump", "--debug-cu-index", str(f))
        want(fx / f.relative_to(fx), "format.split_dwarf.units", int(re.search(r"units = (\d+)", idx).group(1)), "llvm-dwarfdump")
    for f in sorted((fx / "xcoff").glob("*.o")):
        heads = re.findall(r"^\s*\d+ (\S+)\s+([0-9a-f]+)", out("llvm-objdump", "-h", str(f)), re.M)
        for i, (name, size) in enumerate(heads):
            want(fx / f.relative_to(fx), f"format.xcoff.sections.{i}.name", name, "llvm-objdump")
            want(fx / f.relative_to(fx), f"format.xcoff.sections.{i}.size_bytes", int(size, 16), "llvm-objdump")
    for f in sorted((fx / "fdt").glob("*.dtb")):
        want(fx / f.relative_to(fx), "format.fdt.model", out("fdtget", "-t", "s", str(f), "/", "model").strip(), "fdtget")
        compat = out("fdtget", "-t", "s", str(f), "/", "compatible").split()
        want(fx / f.relative_to(fx), "format.fdt.compatible", ", ".join(compat), "fdtget")
    for f in sorted((fx / "fdt").glob("*.dtb*")):
        v = re.search(r"version (\d+)", out("file", "-b", str(f))).group(1)
        want(fx / f.relative_to(fx), "format.fdt.version", int(v), "file")
    for f in sorted((fx / "linux_kernel").glob("vmlinuz*")):
        m = re.search(r"version (\S+)", out("file", "-b", str(f)))
        want(fx / f.relative_to(fx), "format.linux_kernel.release", m.group(1), "file")
    for f in sorted((fx / "linux_kernel").glob("Image*")):
        libmagic(fx, f.relative_to(fx), "Linux kernel ARM64 boot executable")
    for f in sorted((fx / "android_vdex").glob("*.vdex")):
        v = re.search(r"version: (\d+)", out("file", "-b", str(f))).group(1)
        want(fx / f.relative_to(fx), "format.android_vdex.vdex_version", v, "file")


def writing(fx):
    import gzip
    from xml.etree import ElementTree as ET

    def rel(f):
        return fx / f.relative_to(fx)

    for kind, tool, pattern in (("ris", "ris2xml", "*.ris"), ("endnote", "end2xml", "*.enw")):
        for f in sorted((fx / kind).glob(pattern)):
            mods = subprocess.run([tool, str(f)], capture_output=True, text=True).stdout
            want(rel(f), f"format.{kind}.entries", mods.count("<mods ID=") or mods.count("<mods "), tool)
    for f in sorted((fx / "medline").glob("*.nbib")):
        want(rel(f), "format.medline.entries", f.read_text().count("PMID- "), "text")
    ns = {"csl": "http://purl.org/net/xbiblio/csl"}
    for f in sorted((fx / "csl_style").glob("*.csl")):
        want(rel(f), "format.csl_style.title", ET.parse(f).find("csl:info/csl:title", ns).text, "ElementTree")
    for f in sorted((fx / "enex").glob("*.enex")):
        root = ET.parse(f).getroot()
        want(rel(f), "format.enex.notes", len(root.findall("note")), "ElementTree")
        want(rel(f), "format.enex.titles", [n.findtext("title") for n in root.findall("note")], "ElementTree")
    for f in sorted((fx / "obsidian_canvas").glob("*.canvas")):
        j = json.loads(f.read_text())
        want(rel(f), "format.obsidian_canvas.nodes", len(j["nodes"]), "json")
        want(rel(f), "format.obsidian_canvas.edges", len(j["edges"]), "json")
    for f in sorted((fx / "final_draft").glob("*.fdx")):
        heads = [p.findtext("Text") for p in ET.parse(f).getroot().iter("Paragraph") if p.get("Type") == "Scene Heading"]
        want(rel(f), "format.final_draft.scene_headings", heads, "ElementTree")
    for f in sorted((fx / "scrivener").glob("*.scrivx")):
        titles = [b.findtext("Title") for b in ET.parse(f).getroot().iter("BinderItem")]
        want(rel(f), "format.scrivener.titles", titles, "ElementTree")
    for f in sorted((fx / "scribus").glob("*.sla")):
        want(rel(f), "format.scribus.pages", len(ET.parse(f).getroot().findall("DOCUMENT/PAGE")), "ElementTree")
    for f in sorted((fx / "abiword").glob("*.abw")):
        sections = len(ET.parse(f).getroot().findall("{http://www.abisource.com/awml.dtd}section"))
        want(rel(f), "format.abiword.sections", sections, "ElementTree")
    for f in sorted((fx / "gnumeric").glob("*.gnumeric")):
        root = ET.fromstring(gzip.decompress(f.read_bytes()))
        g = "{http://www.gnumeric.org/v10.dtd}"
        names = [s.findtext(f"{g}Name") for s in root.iter(f"{g}Sheet")]
        want(rel(f), "format.gnumeric.sheets", len(names), "ElementTree")
        want(rel(f), "format.gnumeric.sheet_list.0.name", names[0], "ElementTree")
    for f in sorted((fx / "lyx").glob("*.lyx")):
        libmagic(fx, f.relative_to(fx), "LyX")


def books(fx):
    import zipfile
    from xml.etree import ElementTree as ET

    for kind in ("sxw", "sxc", "sxi", "sxd"):
        for f in sorted((fx / kind).glob(f"*.{kind}")):
            with zipfile.ZipFile(f) as z:
                want(fx / f.relative_to(fx), f"format.{kind}.mimetype", z.read("mimetype").decode(), "zipfile")
                meta = ET.fromstring(z.read("meta.xml"))
            title = meta.find(".//{http://purl.org/dc/elements/1.1/}title").text
            want(fx / f.relative_to(fx), "content.title", title, "ElementTree")
            libmagic(fx, f.relative_to(fx), "OpenOffice.org 1.x")
    for f in sorted((fx / "ncx").glob("*.ncx")):
        root = ET.parse(f).getroot()
        ns = "{http://www.daisy.org/z3986/2005/ncx/}"
        want(fx / f.relative_to(fx), "format.ncx.nav_points", len(list(root.iter(f"{ns}navPoint"))), "ElementTree")
        want(fx / f.relative_to(fx), "content.title", root.findtext(f"{ns}docTitle/{ns}text"), "ElementTree")
    for f in sorted((fx / "opf").glob("*.opf")):
        root = ET.parse(f).getroot()
        ns = "{http://openebook.org/namespaces/oeb-package/1.0/}"
        want(fx / f.relative_to(fx), "format.opf.manifest_items", len(root.findall(f"{ns}manifest/{ns}item")), "ElementTree")
    for f in sorted((fx / "ibooks").glob("*.ibooks")):
        with zipfile.ZipFile(f) as z:
            want(fx / f.relative_to(fx), "format.ibooks.entries", len(z.infolist()), "zipfile")


def packages(fx):
    import plistlib
    import zipfile
    from xml.etree import ElementTree as ET

    def rel(f):
        return fx / f.relative_to(fx)

    for f in sorted((fx / "xps").glob("*.xps")):
        with zipfile.ZipFile(f) as z:
            pages = [n for n in z.namelist() if n.endswith(".fpage")]
            title = ET.fromstring(z.read("docProps/core.xml")).findtext("{http://purl.org/dc/elements/1.1/}title")
        want(rel(f), "physical.document.pages", len(pages), "zipfile")
        want(rel(f), "content.title", title, "ElementTree")
    for f in sorted((fx / "idml").glob("*.idml")):
        with zipfile.ZipFile(f) as z:
            want(rel(f), "format.idml.stories", len([n for n in z.namelist() if n.startswith("Stories/")]), "zipfile")
        libmagic(fx, f.relative_to(fx), "InDesign")
    for f in sorted((fx / "hwpx").glob("*.hwpx")):
        with zipfile.ZipFile(f) as z:
            want(rel(f), "format.hwpx.sections", len([n for n in z.namelist() if n.startswith("Contents/section")]), "zipfile")
        libmagic(fx, f.relative_to(fx), "Hancom")
    for kind in ("iwork_pages", "iwork_numbers", "iwork_keynote"):
        for f in sorted((fx / kind).glob("*")):
            if f.name == "SOURCE.md":
                continue
            with zipfile.ZipFile(f) as z:
                hist = plistlib.loads(z.read("Metadata/BuildVersionHistory.plist"))
            want(rel(f), f"format.{kind}.saved_with", hist[-1], "plistlib")
    for f in sorted((fx / "wiki_export").glob("*.zip")):
        with zipfile.ZipFile(f) as z:
            pages = [n for n in z.namelist() if n.endswith(".md") or (n.endswith(".html") and not n.endswith("index.html"))]
        want(rel(f), "format.wiki_export.pages", len(pages), "zipfile")
    for f in sorted((fx / "flat_opc").glob("*.xml")):
        root = ET.parse(f).getroot()
        want(rel(f), "format.flat_opc.parts", len(root.findall("{http://schemas.microsoft.com/office/2006/xmlPackage}part")), "ElementTree")
    for kind, needle in (("indesign", "InDesign"), ("framemaker", "FrameMaker"), ("framemaker_mif", "FrameMaker MIF")):
        for f in sorted((fx / kind).glob("*")):
            if f.name != "SOURCE.md":
                libmagic(fx, f.relative_to(fx), needle)
    for f in sorted((fx / "pdf").glob("*.ai")):
        libmagic(fx, f.relative_to(fx), "PDF document")


def legacy_docs(fx):
    import csv
    import io

    def rel(f):
        return fx / f.relative_to(fx)

    for f in sorted((fx / "lotus123").glob("*.wk1")):
        rows = list(csv.reader(io.StringIO(out("wks2csv", str(f)))))[1:]
        numbers = sum(1 for r in rows for c in r if c.replace(".", "", 1).isdigit())
        labels = sum(1 for r in rows for c in r if c and not c.replace(".", "", 1).isdigit())
        want(rel(f), "format.lotus123.cells.label", labels, "wks2csv")
        want(rel(f), "format.lotus123.cells.number", numbers, "wks2csv")
    for f in sorted((fx / "chm").glob("*.chm")):
        listing = out("enum_chmLib", str(f))
        topics = [l.split()[-1].lstrip("/") for l in listing.splitlines() if "normal file" in l and l.rstrip().endswith((".html", ".htm"))]
        want(rel(f), "format.chm.topic_list", topics, "enum_chmLib")
        libmagic(fx, f.relative_to(fx), "HtmlHelp")
    for f in sorted((fx / "winhelp").glob("*.hlp")):
        m = re.search(r'title "([^"]*)"', out("file", "-b", str(f)))
        want(rel(f), "content.title", m.group(1), "file")
    for kind, needle in (("wordperfect", "WordPerfect"), ("clarisworks", "AppleWorks"), ("ms_write", "Microsoft Write"),
                         ("onenote", "OneNote"), ("pcl", "Printer Job Language")):
        for f in sorted((fx / kind).glob("*")):
            if f.name != "SOURCE.md":
                libmagic(fx, f.relative_to(fx), needle)


def records(fx):
    import io

    def rel(f):
        return fx / f.relative_to(fx)

    import ofxparse
    for f in sorted((fx / "ofx").glob("*.ofx")):
        o = ofxparse.OfxParser.parse(open(f, "rb"))
        want(rel(f), "format.ofx.transactions", len(o.account.statement.transactions), "ofxparse")
        want(rel(f), "format.ofx.currency", o.account.statement.currency.upper(), "ofxparse")
        want(rel(f), "format.ofx.accounts.0", "•" * 8 + o.account.account_id[-4:], "ofxparse")
    import mt940
    for f in sorted((fx / "mt940").glob("*.sta")):
        t = mt940.parse(str(f))
        want(rel(f), "format.mt940.transactions", len(t), "mt-940")
    from gedcom.parser import Parser
    for f in sorted((fx / "gedcom").glob("*.ged")):
        p = Parser()
        p.parse_file(str(f), False)
        root = p.get_root_child_elements()
        want(rel(f), "format.gedcom.records.individuals", sum(1 for e in root if e.get_tag() == "INDI"), "python-gedcom")
        want(rel(f), "format.gedcom.records.families", sum(1 for e in root if e.get_tag() == "FAM"), "python-gedcom")
    import contextlib

    # tap.py warns on stdout about an optional YAML dependency.
    with contextlib.redirect_stdout(io.StringIO()):
        from tap.parser import Parser as TapParser
    for f in sorted((fx / "tap").glob("*")):
        if f.name == "SOURCE.md":
            continue
        with contextlib.redirect_stdout(io.StringIO()):
            lines = list(TapParser().parse_text(f.read_text()))
        results = [l for l in lines if l.category == "test"]
        want(rel(f), "format.tap.passed", sum(1 for r in results if r.ok and not r.skip and not r.todo), "tap.py")
        want(rel(f), "format.tap.skipped", sum(1 for r in results if r.skip), "tap.py")
        want(rel(f), "format.tap.todo", sum(1 for r in results if r.todo), "tap.py")
    from prometheus_client.parser import text_string_to_metric_families
    for f in sorted((fx / "prometheus").glob("*.prom")):
        fams = list(text_string_to_metric_families(f.read_text()))
        want(rel(f), "format.prometheus.metric_families", len(fams), "prometheus_client")
        # The client names counters without `_total` (OpenMetrics); the
        # file's `# TYPE` line has it.
        text = f.read_text()
        names = [m.name + "_total" if m.type == "counter" and f"# TYPE {m.name}_total" in text else m.name for m in fams]
        want(rel(f), "format.prometheus.metric_names", sorted(names), "prometheus_client")
    from beancount import loader
    for f in sorted((fx / "ledger").glob("*.beancount")):
        entries, errors, _ = loader.load_file(str(f))
        txns = [e for e in entries if type(e).__name__ == "Transaction"]
        want(rel(f), "format.ledger.transactions", len(txns), "beancount")


def batch5c(fx):
    import subprocess
    import xml.etree.ElementTree as ET

    def rel(f):
        return fx / f.relative_to(fx)

    def local(t):
        return t.rsplit("}", 1)[-1]

    def count(f, name):
        return sum(1 for e in ET.parse(f).iter() if local(e.tag) == name)

    # TNEF attachments, by the tnef tool.
    for f in sorted((fx / "tnef").glob("*.dat")):
        listing = subprocess.run(["tnef", "-t", str(f)], capture_output=True, text=True).stdout
        names = [line.split("\t")[0] for line in listing.splitlines() if line.strip()]
        want(rel(f), "format.tnef.attachments.*.name", sorted(names), "tnef")
        libmagic(fx, f.relative_to(fx), "Transport Neutral Encapsulation Format")
    for f, needle in ((fx / "pst" / "saltmere-archive.pst", "Microsoft Outlook"), (fx / "dbx" / "Inbox.dbx", "Outlook Express")):
        libmagic(fx, f.relative_to(fx), needle)
    # Web bundle, decoded with cbor2.
    import cbor2
    for f in sorted((fx / "web_bundle").glob("*.wbn")):
        top = cbor2.loads(f.read_bytes())
        names = cbor2.loads(top[2])[::2]
        sections = dict(zip(names, top[3]))
        want(rel(f), "format.web_bundle.resources", len(sections["index"]), "cbor2")
        want(rel(f), "format.web_bundle.primary_url", sections["primary"], "cbor2")
    # XML vocabularies: counts recomputed with ElementTree.
    for f in sorted((fx / "qt_ts").glob("*.ts")):
        want(rel(f), "format.qt_ts.messages", count(f, "message"), "ElementTree")
        want(rel(f), "format.qt_ts.contexts", count(f, "context"), "ElementTree")
    for f in sorted((fx / "onix").glob("*.xml")):
        want(rel(f), "format.onix.products", count(f, "Product"), "ElementTree")
    for f in sorted((fx / "apple_health").glob("*.xml")):
        want(rel(f), "format.apple_health.records", count(f, "Record"), "ElementTree")
    for f in sorted((fx / "android_manifest").glob("*.xml")):
        ns = "{http://schemas.android.com/apk/res/android}name"
        want(rel(f), "format.android_manifest.permissions",
             [e.get(ns) for e in ET.parse(f).iter() if local(e.tag) == "uses-permission"], "ElementTree")
    for f in sorted((fx / "opendrive").glob("*.xodr")):
        want(rel(f), "format.opendrive.counts.roads", count(f, "road"), "ElementTree")
        want(rel(f), "format.opendrive.road_length_m",
             round(sum(float(e.get("length")) for e in ET.parse(f).iter() if local(e.tag) == "road"), 1), "ElementTree")
    for f in sorted((fx / "openscenario").glob("*.xosc")):
        want(rel(f), "format.openscenario.entities",
             [e.get("name") for e in ET.parse(f).iter() if local(e.tag) == "ScenarioObject"], "ElementTree")


def batch5e(fx):
    """Batch 5e: libmagic, ElementTree and zipfile on the long-tail 3D / CAD,
    science, database and system fixtures that exist."""
    import xml.etree.ElementTree as ET
    import zipfile

    def rel(f):
        return fx / f.relative_to(fx)

    for f, needle in (("sketchup/saltmere-office.skp", "SketchUp Model"), ("u3d/buoy.u3d", "Universal 3D"),
                      ("pcd/buoy-light.pcd", "Point Cloud Data"), ("revit/saltmere-office.rvt", "Composite Document File"),
                      ("hdf4/saltmere-depths.hdf", "Hierarchical Data Format (version 4)")):
        if (fx / f).exists():
            libmagic(fx, f, needle)
    for f in sorted((fx / "materialx").glob("*.mtlx")):
        root = ET.parse(f).getroot()
        want(rel(f), "format.materialx.version", root.get("version"), "ElementTree")
        want(rel(f), "format.materialx.materials", [e.get("name") for e in root.iter("surfacematerial")], "ElementTree")
        want(rel(f), "format.materialx.node_graphs", [e.get("name") for e in root.iter("nodegraph")], "ElementTree")
    ns = {"h": "urn:hl7-org:v3"}
    for f in sorted((fx / "aecg").glob("*.xml")):
        codes = [c.get("code") for c in ET.parse(f).getroot().iterfind(".//h:sequence/h:code", ns)]
        want(rel(f), "format.aecg.leads", [c.removeprefix("MDC_ECG_LEAD_") for c in codes if c.startswith("MDC_ECG_LEAD_")], "ElementTree")
    for f in sorted((fx / "dwf").glob("*.dwfx")):
        want(rel(f), "format.dwf.entries", len(zipfile.ZipFile(f).namelist()), "zipfile")


def expect(root):
    fx = Path(root)
    batch5e(fx)
    batch5c(fx)
    records(fx)
    legacy_docs(fx)
    packages(fx)
    books(fx)
    writing(fx)
    executables(fx)
    dos(fx)
    mac(fx)
    encoded(fx)
    wim(fx)
    bundles(fx)
    backups(fx)
    print(json.dumps(EXPECT, indent=1))


def lookup(r, path):
    """A dotted path into the report; `*` maps the rest over a list and sorts."""
    cur = r
    parts = path.split(".")
    for i, part in enumerate(parts):
        if part == "*" and isinstance(cur, list):
            rest = ".".join(parts[i + 1:])
            return sorted(lookup(x, rest) if rest else x for x in cur)
        if isinstance(cur, list):
            cur = cur[int(part)] if part.isdigit() and int(part) < len(cur) else None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def check(path, whiff="target/debug/whiff"):
    exp = json.load(open(path))
    cache = {}
    ok = bad = 0
    for e in exp:
        f = e["file"].replace("/whiff/", "")
        if f not in cache:
            line = subprocess.run([whiff, "--jsonl", f], capture_output=True, text=True, check=True).stdout.splitlines()[0]
            cache[f] = json.loads(line)
        r = cache[f]
        if e["path"] == "_libmagic":
            got = e["value"]
            good = not got.startswith("MISSING")
        elif e["path"] == "_shar_member":
            members = [[x["path"], x.get("size_bytes")] for x in lookup(r, "format.shar.entries") or []]
            got = members
            good = e["value"] in members
        else:
            got = lookup(r, e["path"])
            good = got == e["value"]
        if good:
            ok += 1
        else:
            bad += 1
            print(f"DIFF {f} {e['path']}: whiff {got!r}, {e['tool']} {e['value']!r}")
    print(f"{ok}/{ok + bad} agree")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    if sys.argv[1] == "expect":
        expect(sys.argv[2])
    else:
        check(sys.argv[2], *sys.argv[3:])
