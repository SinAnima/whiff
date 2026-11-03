"""Compare whiff's font reports with independent readers.

Two halves, like the other oracles:

    # in the `whiff-font-corpus` container: write the expected facts
    python3 font_oracle.py expect OUT.jsonl HOST_PREFIX=CONTAINER_ROOT ... [--copy DIR]

    # on the host: run whiff on every file and compare
    python3 font_oracle.py check OUT.jsonl WHIFF_BINARY

`expect` reads each font with fontTools (sfnt, collections, WOFF, WOFF2,
Type 1, AFM), pcf2bdf (PCF), psfgettable (PSF), wrestool and FontForge
(Windows FON). Each `HOST_PREFIX=CONTAINER_ROOT` pair maps a read-only
host folder mounted in the container back to the host path whiff reads.
With `--copy DIR`, fonts found under the container's own /usr/share are
copied (gzipped PCF and PSF decompressed) into DIR, which must be a host
folder mounted in the container, so the host can read them too.

Nothing here is shipped with whiff.
"""

import gzip
import json
import os
import re
import shutil
import subprocess
import sys

SFNT = (".ttf", ".otf", ".ttc", ".otc", ".woff", ".woff2", ".dfont")
TYPE1 = (".pfb", ".pfa", ".t1")
OTHER = (".afm", ".pcf", ".psf", ".fon")


def name(font, nid):
    """The name record whiff prefers: Windows English, Windows, Unicode, Mac Roman."""
    best = None
    for rec in font["name"].names:
        if rec.nameID != nid:
            continue
        p, e, lang = rec.platformID, rec.platEncID, rec.langID
        if p == 3 and e in (1, 10) and lang == 0x409:
            rank = 0
        elif p == 3 and e in (0, 1, 10):
            rank = 1
        elif p == 0:
            rank = 2
        elif p == 1 and e == 0 and lang == 0:
            rank = 3
        else:
            continue
        try:
            text = rec.toUnicode().strip().strip("\0").strip()
        except Exception:
            continue
        if text and (best is None or rank < best[0]):
            best = (rank, text)
    return best[1] if best else None


def coverage(font):
    """Mapped code points of the subtable whiff picks (glyph 0 excluded)."""
    if "cmap" not in font:
        return None
    ranked = []
    for t in font["cmap"].tables:
        p, e, f = t.platformID, t.platEncID, t.format
        if (p, e) in ((3, 10), (0, 4), (0, 6)) and f in (12, 13):
            r = 0
        elif (p, e) in ((3, 1), (0, 3)) and f == 4:
            r = 1
        elif p == 0 and f in (4, 6):
            r = 2
        elif (p, e) == (3, 0) and f == 4:
            r = 3
        elif (p, e) == (1, 0) and f in (0, 6):
            r = 4
        else:
            continue
        ranked.append((r, t))
    if not ranked:
        return None
    ranked.sort(key=lambda x: x[0])
    t = ranked[0][1]
    notdef = font.getGlyphOrder()[0]
    return sum(1 for g in t.cmap.values() if g != notdef)


def sfnt_facts(font):
    from fontTools.misc.timeTools import timestampToString  # noqa: F401

    f = {}
    for nid, key in [(1, "family"), (2, "subfamily"), (4, "full_name"), (6, "postscript_name"), (5, "version")]:
        v = name(font, nid) if "name" in font else None
        if v:
            f[key] = v[:200]
    if "maxp" in font:
        f["glyph_count"] = font["maxp"].numGlyphs
    if "head" in font:
        h = font["head"]
        f["units_per_em"] = h.unitsPerEm
        f["font_revision"] = round(round(h.fontRevision * 65536) / 65536, 3)
    if "OS/2" in font:
        o = font["OS/2"]
        f["fs_type"] = o.fsType
        f["weight_class"] = o.usWeightClass
        f["width_class"] = o.usWidthClass
        f["italic"] = bool(o.fsSelection & 1)
        f["bold"] = bool(o.fsSelection & 0x20)
        v = (o.achVendID or "").strip().strip("\0")
        if v and all(32 <= ord(c) < 127 for c in v):
            f["vendor_id"] = v
    if "post" in font:
        f["monospace"] = font["post"].isFixedPitch != 0
    cp = coverage(font)
    if cp:
        f["codepoints"] = cp
    feats, scripts = set(), set()
    for tag in ("GSUB", "GPOS"):
        if tag in font and font[tag].table:
            t = font[tag].table
            if t.FeatureList:
                feats |= {r.FeatureTag.rstrip() for r in t.FeatureList.FeatureRecord}
            if t.ScriptList:
                scripts |= {r.ScriptTag.rstrip() for r in t.ScriptList.ScriptRecord}
    if feats:
        f["features"] = sorted(feats)[:200]
    if scripts:
        f["layout_scripts"] = sorted(scripts)[:200]
    if "fvar" in font:
        f["axes"] = [[a.axisTag, round(a.minValue, 3), round(a.defaultValue, 3), round(a.maxValue, 3)] for a in font["fvar"].axes]
        f["instance_count"] = len(font["fvar"].instances)
    if "CPAL" in font:
        f["palettes"] = len(font["CPAL"].palettes)
    f["tables"] = sorted(t.strip() for t in font.reader.keys())
    return f


def expect_sfnt(path):
    from fontTools.ttLib import TTCollection, TTFont

    ext = os.path.splitext(path)[1].lower()
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head == b"ttcf" or (ext == ".woff2" and _woff2_collection(path)):
        tc = TTCollection(path, lazy=True)
        fonts = tc.fonts
        facts = sfnt_facts(fonts[0])
        facts["fonts"] = len(fonts)
        facts["members"] = [name(f, 4) for f in fonts[:256]]
        return facts
    if ext == ".dfont":
        from fontTools.misc.macRes import ResourceReader

        rr = ResourceReader(path)
        n = len(rr.get("sfnt", []))
        fonts = [TTFont(path, res_name_or_index=i + 1, lazy=True) for i in range(n)]
        facts = sfnt_facts(fonts[0])
        facts["fonts"] = n
        facts["members"] = [name(f, 4) for f in fonts]
        return facts
    return sfnt_facts(TTFont(path, lazy=True, fontNumber=0))


def _woff2_collection(path):
    with open(path, "rb") as fh:
        b = fh.read(8)
    return b[4:8] == b"ttcf"


def expect_type1(path):
    from fontTools.t1Lib import T1Font

    t = T1Font(path)
    t.parse()
    d = t.font
    info = d.get("FontInfo", {})
    f = {"postscript_name": d.get("FontName"), "glyph_count": len(d.get("CharStrings", {}))}
    for k, out in [("FullName", "full_name"), ("FamilyName", "family"), ("Weight", "weight"), ("version", "version")]:
        if k in info:
            f[out] = str(info[k]).strip()
    subrs = d.get("Private", {}).get("Subrs")
    if subrs is not None:
        f["subroutines"] = len(subrs)
    return f


def expect_afm(path):
    from fontTools.afmLib import AFM

    a = AFM(path)
    f = {}
    for k, out in [("FontName", "postscript_name"), ("FullName", "full_name"), ("FamilyName", "family"), ("Weight", "weight")]:
        try:
            f[out] = str(getattr(a, k)).strip()
        except AttributeError:
            pass
    f["glyph_count"] = len(a.chars())
    if a.kernpairs():
        f["kern_pairs"] = len(a.kernpairs())
    return f


def expect_pcf(path):
    out = subprocess.run(["pcf2bdf", path], capture_output=True, check=True).stdout.decode("latin-1")
    f = {}
    for line in out.splitlines():
        if line.startswith("FONT "):
            f["font"] = line[5:].strip()
        elif line.startswith("CHARS "):
            f["encoded_characters"] = int(line.split()[1])
            break
        else:
            m = re.match(r'(FAMILY_NAME|FOUNDRY|COPYRIGHT) "?(.*?)"?$', line)
            if m:
                f["prop_" + m.group(1).lower()] = m.group(2).replace('""', '"')
    return f


def expect_psf(path):
    out = subprocess.run(["psfgettable", path], capture_output=True).stdout.decode()
    with open(path, "rb") as fh:
        b = fh.read(32)
    if b[:2] == b"\x36\x04":
        glyphs = 512 if b[2] & 1 else 256
    else:
        glyphs = int.from_bytes(b[16:20], "little")
    f = {"glyph_count": glyphs}
    codes = sum(len(re.findall(r"U\+[0-9a-fA-F]+", l.split(";")[0])) for l in out.splitlines() if not l.startswith("#"))
    if codes:
        f["codepoints"] = codes
    return f


def expect_fon(path):
    import fontforge

    out = subprocess.run(["wrestool", "-l", path], capture_output=True).stdout.decode()
    f = {"fonts": sum(1 for l in out.splitlines() if "--type=8 " in l)}
    try:
        font = fontforge.open(path)
        f["face"] = font.familyname
    except Exception:
        pass
    return f


def expect(path):
    low = path.lower()
    if low.endswith(SFNT):
        return expect_sfnt(path)
    if low.endswith(TYPE1):
        return expect_type1(path)
    if low.endswith(".afm"):
        return expect_afm(path)
    if low.endswith(".pcf"):
        return expect_pcf(path)
    if low.endswith(".psf"):
        return expect_psf(path)
    if low.endswith(".fon"):
        return expect_fon(path)
    return None


def walk(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if not x.startswith(".")]
        for n in files:
            yield os.path.join(d, n)


def cmd_expect(out, pairs, copy):
    mapping = [p.split("=", 1) for p in pairs]
    jobs = []
    for host, croot in mapping:
        for p in walk(croot):
            if p.lower().endswith(SFNT + TYPE1 + OTHER):
                jobs.append((p, host + p[len(croot):]))
    if copy:
        os.makedirs(copy, exist_ok=True)
        host_copy = os.environ.get("HOST_COPY", copy)
        for p in walk("/usr/share"):
            low = p.lower()
            plain = low.endswith(SFNT + TYPE1 + OTHER)
            gz = low.endswith((".pcf.gz", ".psf.gz"))
            if not (plain or gz):
                continue
            flat = p.strip("/").replace("/", "__")
            if gz:
                flat = flat[:-3]
                with gzip.open(p) as src, open(os.path.join(copy, flat), "wb") as dst:
                    shutil.copyfileobj(src, dst)
            else:
                shutil.copy(p, os.path.join(copy, flat))
            jobs.append((os.path.join(copy, flat), os.path.join(host_copy, flat)))
    n = 0
    with open(out, "w") as fh:
        for cpath, hpath in jobs:
            try:
                facts = expect(cpath)
            except Exception as e:  # unreadable for the oracle: recorded, not compared
                facts = {"oracle_error": f"{type(e).__name__}: {e}"[:200]}
            if facts is None:
                continue
            fh.write(json.dumps({"path": hpath, "facts": facts}) + "\n")
            n += 1
    print(f"{n} fonts written to {out}")


def whiff_facts(report):
    fmt = report.get("format", {})
    if not fmt:
        return None, {}
    fid, d = next(iter(fmt.items()))
    return fid, d


def compare(exp, got):
    """Mismatched keys (an absent oracle value is not compared)."""
    bad = []
    for k, v in exp.items():
        if k == "oracle_error":
            continue
        if k.startswith("prop_"):
            g = got.get("properties", {}).get(k[5:])
            g = str(g) if g is not None else None
        elif k == "axes":
            g = [[a["tag"], a["min"], a["default"], a["max"]] for a in got.get("axes", [])]
        elif k == "tables":
            g = sorted(got.get("tables", []))
            # whiff lists at most 200 tables
            v = v[:200] if len(v) > 200 else v
        else:
            g = got.get(k)
        if k in ("full_name", "family", "subfamily", "postscript_name", "version", "weight", "face") and g is not None:
            g = str(g)[:200]
            v = str(v)[:200]
        if k == "members":
            v = [x[:200] if x else None for x in v]
            g = [m.get("full_name") for m in got.get("members", [])]
        if g != v:
            bad.append((k, v, g))
    return bad


def cmd_check(out, whiff):
    rows = [json.loads(l) for l in open(out)]
    totals, fails, oracle_errors = {}, {}, 0
    paths = [r["path"] for r in rows]
    reports = {}
    for i in range(0, len(paths), 100):
        batch = paths[i:i + 100]
        res = subprocess.run([whiff, "--profile", "standard", *batch], capture_output=True)
        # Not splitlines(): JSON strings may hold U+2028 or \x1c raw.
        for line in res.stdout.decode().split("\n"):
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            reports[r.get("source", {}).get("path")] = r
    for p in paths:
        if p not in reports:
            res = subprocess.run([whiff, "--profile", "standard", p], capture_output=True)
            try:
                reports[p] = json.loads(res.stdout)
            except json.JSONDecodeError:
                print(f"  whiff gave no report for {p}: {res.stderr.decode()[:200]}")
    for row in rows:
        if "oracle_error" in row["facts"]:
            oracle_errors += 1
            continue
        r = reports.get(row["path"])
        ext = os.path.splitext(row["path"])[1].lower()
        totals[ext] = totals.get(ext, 0) + 1
        if r is None:
            fails.setdefault(ext, []).append((row["path"], [("report", "present", None)]))
            continue
        fid, got = whiff_facts(r)
        bad = compare(row["facts"], got)
        if bad:
            fails.setdefault(ext, []).append((row["path"], bad))
    for ext in sorted(totals):
        n, f = totals[ext], len(fails.get(ext, []))
        print(f"{ext:8} {n - f:5}/{n:<5} agree")
    print(f"oracle could not read {oracle_errors} files")
    for ext, items in sorted(fails.items()):
        for path, bad in items[:8]:
            print(f"  {path}")
            for k, v, g in bad[:6]:
                print(f"      {k}: oracle {json.dumps(v)[:160]} whiff {json.dumps(g)[:160]}")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "expect":
        args = sys.argv[3:]
        copy = None
        if "--copy" in args:
            i = args.index("--copy")
            copy = args[i + 1]
            args = args[:i] + args[i + 2:]
        cmd_expect(sys.argv[2], args, copy)
    else:
        cmd_check(sys.argv[2], sys.argv[3])
