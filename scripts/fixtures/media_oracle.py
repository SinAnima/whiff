#!/usr/bin/env python3
"""Oracle for the stage 8 image long-tail fixtures (batch 3): independent
tools read each fixture and their facts are compared with whiff's report.

    # in the whiff-media container (see media.sh):
    python3 scripts/fixtures/media_oracle.py expect tests/fixtures > target/media-expect.json
    # on the host:
    python3 scripts/fixtures/media_oracle.py check target/media-expect.json [path/to/whiff]

Tools: exiftool, ImageMagick `identify`, Pillow, ffprobe, djvulibre
`djvudump`, Graphviz `gc`, `fig2dev`, psd-tools (Photoshop descriptors and
patterns), libmagic `file`, and the Python standard library (zipfile,
ElementTree, plistlib, configparser, json) for the package and XML formats.
Each expectation is (fixture, report path, value); numbers compare with a
small tolerance.
"""

import configparser
import io
import json
import re
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path
from urllib.parse import unquote
from xml.etree import ElementTree as ET

EXPECT = []


def want(fixture, path, value, tool):
    if value is None:
        return
    EXPECT.append({"file": str(fixture), "path": path, "value": value, "tool": tool})


def out(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", check=True).stdout


def exif(f, *tags):
    p = subprocess.run(["exiftool", "-j", "-n", *[f"-{t}" for t in tags], str(f)], capture_output=True, text=True)
    j = json.loads(p.stdout or "[{}]")[0]
    return {t: j.get(t) for t in tags}


def identify(f):
    """(width, height, scenes) of the first image."""
    lines = out("identify", "-format", "%w %h\n", str(f)).split()
    return int(lines[0]), int(lines[1]), len(lines) // 2


def size(fx, f, tool, w, h):
    want(fx / f, "physical.image.width", w, tool)
    want(fx / f, "physical.image.height", h, tool)


def magic(fx, f, needle):
    desc = out("file", "-b", str(fx / f))
    want(fx / f, "_libmagic", needle if needle.lower() in desc.lower() else f"MISSING in: {desc.strip()}", "libmagic")


def ln(tag):
    """An ElementTree tag without its `{namespace}`."""
    return tag.rsplit("}", 1)[-1]


def expect(fx):
    from PIL import Image

    fx = Path(fx)
    # --- ImageMagick: sizes of the legacy rasters.
    for f in ["sgi/harbour.sgi", "sun_raster/harbour.ras", "xbm/check.xbm", "xpm/harbour.xpm", "wbmp/check.wbmp", "farbfeld/harbour.ff", "pict/harbour.pict", "utah_rle/harbour.rle", "dpx/reel1_000100.dpx", "cineon/reel1_000100.cin", "cineon/reel2_000200.cin"]:
        w, h, _ = identify(fx / f)
        size(fx, f, "ImageMagick", w, h)
    w, h, n = identify(fx / "dcx/pages.dcx")
    size(fx, "dcx/pages.dcx", "ImageMagick", w, h)
    want(fx / "dcx/pages.dcx", "physical.document.pages", n, "ImageMagick")
    # MacPaint through ImageMagick's MAC coder.
    w, h, _ = identify("MAC:" + str(fx / "macpaint/check.mac"))
    size(fx, "macpaint/check.mac", "ImageMagick", w, h)
    # --- Pillow: ICNS, SGI name, XPM colours, Photo CD, FlashPix.
    im = Image.open(fx / "icns/harbour.icns")
    largest = max(s[0] * s[2] for s in im.info.get("sizes", []) or [(im.size[0], im.size[1], 1)])
    want(fx / "icns/harbour.icns", "physical.image.width", largest, "Pillow")
    im = Image.open(fx / "sgi/harbour.sgi")
    want(fx / "sgi/harbour.sgi", "physical.image.channels", len(im.getbands()), "Pillow")
    im = Image.open(fx / "photo_cd/img0001.pcd")
    # Pillow decodes the Base image (768x512) and reads the orientation byte.
    want(fx / "photo_cd/img0001.pcd", "_pcd_base", list(im.size), "Pillow")
    raw = (fx / "photo_cd/img0001.pcd").read_bytes()
    want(fx / "photo_cd/img0001.pcd", "format.photo_cd.rotation", (raw[2048 + 1538] & 3) * 90, "Pillow PcdImagePlugin offset")
    import olefile

    prop = olefile.OleFileIO(str(fx / "fpx/ferry.fpx")).getproperties(["Data Object Store 000001", "\x05Image Contents"])
    size(fx, "fpx/ferry.fpx", "olefile", prop[0x1000002], prop[0x1000003])
    want(fx / "fpx/ferry.fpx", "format.fpx.resolutions", prop[0x1000000], "olefile")
    # --- exiftool.
    for f in ["ilbm/lighthouse.lbm", "ilbm/harbour-netpbm.iff"]:
        p = json.loads(out("ffprobe", "-v", "error", "-show_streams", "-of", "json", str(fx / f)))["streams"][0]
        size(fx, f, "ffprobe", p["width"], p["height"])
    e = exif(fx / "ani/tide-spinner.ani", "Title", "Artist")
    want(fx / "ani/tide-spinner.ani", "content.title", e["Title"], "exiftool")
    want(fx / "ani/tide-spinner.ani", "content.authors.0", e["Artist"], "exiftool")
    e = exif(fx / "dpx/reel1_000100.dpx", "ImageWidth", "ImageHeight", "BitDepth", "Creator", "Project", "Copyright", "Originator", "InputDeviceName", "FrameRate", "TimeCode", "FrameID")
    want(fx / "dpx/reel1_000100.dpx", "format.dpx.creator", e["Creator"], "exiftool")
    want(fx / "dpx/reel1_000100.dpx", "format.dpx.project", e["Project"], "exiftool")
    want(fx / "dpx/reel1_000100.dpx", "rights.copyright", e["Copyright"], "exiftool")
    want(fx / "dpx/reel1_000100.dpx", "physical.image.bit_depth", e["BitDepth"], "exiftool")
    if e.get("InputDeviceName"):
        want(fx / "dpx/reel1_000100.dpx", "format.dpx.input_device", e["InputDeviceName"], "exiftool")
    e = exif(fx / "xisf/saltmere-nebula.xisf", "ImageWidth", "ImageHeight", "Object", "Telescope", "CreatorApplication")
    size(fx, "xisf/saltmere-nebula.xisf", "exiftool", e["ImageWidth"], e["ImageHeight"])
    if e.get("Object"):
        want(fx / "xisf/saltmere-nebula.xisf", "content.title", e["Object"], "exiftool")
    e = exif(fx / "jxr/harbour.jxr", "ImageWidth", "ImageHeight", "PixelFormat")
    size(fx, "jxr/harbour.jxr", "exiftool", e["ImageWidth"], e["ImageHeight"])
    for f in ["flif/quay.flif", "flif/waves-anim.flif", "bpg/ferry.bpg"]:
        e = exif(fx / f, "ImageWidth", "ImageHeight")
        size(fx, f, "exiftool", e["ImageWidth"], e["ImageHeight"])
    e = exif(fx / "flif/quay.flif", "Title")
    want(fx / "flif/quay.flif", "content.title", e["Title"], "exiftool (eXmp)")
    e = exif(fx / "bpg/ferry.bpg", "BitDepth", "ColorSpace", "Title")
    want(fx / "bpg/ferry.bpg", "physical.image.bit_depth", e["BitDepth"], "exiftool")
    want(fx / "bpg/ferry.bpg", "content.title", e["Title"], "exiftool (XMP extension)")
    for f in ["dcr/sample.dcr", "kdc/sample.kdc", "erf/sample.erf", "mef/sample.mef", "mos/sample.mos", "iiq/sample.iiq", "gpr/sample.gpr", "mrw/sample.mrw", "x3f/sample.x3f"]:
        e = exif(fx / f, "Make", "Model")
        fid = f.split("/")[0]
        # MRW keeps make and model only in its EXIF block (TTW).
        base = "metadata.exif." if fid == "mrw" else f"format.{fid}.raw."
        want(fx / f, base + ("Make" if fid == "mrw" else "make"), e["Make"], "exiftool")
        want(fx / f, base + ("Model" if fid == "mrw" else "model"), e["Model"], "exiftool")
    e = exif(fx / "x3f/sample.x3f", "ImageWidth", "ImageHeight", "ISO")
    size(fx, "x3f/sample.x3f", "exiftool", e["ImageWidth"], e["ImageHeight"])
    e = exif(fx / "mrw/sample.mrw", "SensorWidth", "SensorHeight", "ISOSetting")
    want(fx / "mrw/sample.mrw", "format.mrw.raw.sensor_size", [e["SensorWidth"], e["SensorHeight"]], "exiftool")
    e = exif(fx / "psp/breakwater.pspimage", "ImageWidth", "ImageHeight", "LayerCount", "Title", "Artist", "Copyright", "Description")
    size(fx, "psp/breakwater.pspimage", "exiftool", e["ImageWidth"], e["ImageHeight"])
    want(fx / "psp/breakwater.pspimage", "format.psp.layer_count_header", e["LayerCount"], "exiftool")
    want(fx / "psp/breakwater.pspimage", "content.title", e["Title"], "exiftool")
    want(fx / "psp/breakwater.pspimage", "content.authors.0", e["Artist"], "exiftool")
    want(fx / "psp/breakwater.pspimage", "rights.copyright", e["Copyright"], "exiftool")
    e = exif(fx / "xmp/IMG_0042.xmp", "Title", "Creator", "Rating")
    want(fx / "xmp/IMG_0042.xmp", "content.title", e["Title"], "exiftool")
    want(fx / "xmp/IMG_0042.xmp", "metadata.xmp.xmp.Rating", str(e["Rating"]), "exiftool")
    for f in ["exv/harbour.exv", "exif/harbour.exif"]:
        e = exif(fx / f, "Make", "Model", "Artist")
        want(fx / f, "metadata.exif.Make", e["Make"], "exiftool")
        want(fx / f, "metadata.exif.Model", e["Model"], "exiftool")
    e = exif(fx / "exv/harbour.exv", "Title", "ObjectName")
    want(fx / "exv/harbour.exv", "content.title", e["Title"], "exiftool")
    e = exif(fx / "icc/whiff-test.icc", "ProfileDescription", "ProfileClass", "ColorSpaceData")
    want(fx / "icc/whiff-test.icc", "metadata.icc.description", e["ProfileDescription"], "exiftool")
    e = exif(fx / "fpx/ferry.fpx", "Title", "Author")
    if e.get("Title"):
        want(fx / "fpx/ferry.fpx", "content.title", e["Title"], "exiftool")
    for f in ["djvu/tide-tables.djvu", "djvu/tide-tables-2p.djvu"]:
        e = exif(fx / f, "ImageWidth", "ImageHeight", "XResolution")
        size(fx, f, "exiftool", e["ImageWidth"], e["ImageHeight"])
    for f in ["svs/harbour-1.svs", "ndpi/harbour-2.ndpi", "scn/harbour-3.scn", "avci/harbour.avci", "hej2/harbour.hej2"]:
        e = exif(fx / f, "ImageWidth", "ImageHeight", "Make", "Model")
        size(fx, f, "exiftool", e["ImageWidth"], e["ImageHeight"])
        fid = f.split("/")[0]
        if fid in ("svs", "ndpi"):
            want(fx / f, f"format.{fid}.slide.make", e["Make"], "exiftool")
    # --- djvudump: pages.
    for f in ["djvu/tide-tables.djvu", "djvu/tide-tables-2p.djvu"]:
        d = out("djvudump", str(fx / f))
        want(fx / f, "physical.document.pages", max(1, d.count("FORM:DJVU")), "djvudump")
        m = re.search(r"DjVu (\d+)x(\d+), v(\d+), (\d+) dpi", d)
        want(fx / f, "physical.image.dpi.0", float(m.group(4)), "djvudump")
    # --- ffprobe: JPEG-LS.
    p = json.loads(out("ffprobe", "-v", "error", "-show_streams", "-of", "json", str(fx / "jls/harbour.jls")))["streams"][0]
    size(fx, "jls/harbour.jls", "ffprobe", p["width"], p["height"])
    want(fx / "jls/harbour.jls", "format.jls.process", "JPEG-LS" if p["codec_name"] == "jpegls" else p["codec_name"], "ffprobe")
    # --- Graphviz gc.
    for f in ["graphviz/ferries.gv", "graphviz/moorings.dot"]:
        nums = [int(x) for x in out("gc", "-n", "-e", str(fx / f)).split()[:2]]
        want(fx / f, f"format.graphviz.nodes", nums[0], "gc")
        want(fx / f, f"format.graphviz.edges", nums[1], "gc")
    # --- fig2dev: text objects in the SVG it renders.
    svg = out("fig2dev", "-L", "svg", str(fx / "xfig/quay.fig"))
    want(fx / "xfig/quay.fig", "format.xfig.objects.text", svg.count("<text"), "fig2dev")
    # --- psd-tools: descriptors and patterns.
    from psd_tools.psd.descriptor import Descriptor
    from psd_tools.psd.patterns import Pattern

    def names(desc, acc):
        for k, v in desc.items():
            key = k.decode() if isinstance(k, bytes) else str(k)
            if hasattr(v, "items"):
                names(v, acc)
            elif isinstance(v, list) or type(v).__name__ == "List":
                for x in v:
                    if hasattr(x, "items"):
                        names(x, acc)
            elif key.strip() in ("Nm", "Nm  ", "Name") or "Nm" in key:
                acc.append(str(v.value if hasattr(v, "value") else v).rstrip("\0"))
        return acc

    grd = (fx / "photoshop_gradients/harbour.grd").read_bytes()
    d = Descriptor.read(io.BytesIO(grd[10:]))
    want(fx / "photoshop_gradients/harbour.grd", "format.photoshop_gradients.names", names(d, []), "psd-tools")
    abr = (fx / "photoshop_brushes/harbour.abr").read_bytes()
    i = abr.index(b"desc") + 8
    d = Descriptor.read(io.BytesIO(abr[i + 4 :]))
    want(fx / "photoshop_brushes/harbour.abr", "format.photoshop_brushes.names", names(d, []), "psd-tools")
    pat = io.BytesIO((fx / "photoshop_patterns/harbour.pat").read_bytes()[10:])
    got = []
    for _ in range(2):
        p = Pattern.read(pat)
        got.append({"name": p.name.rstrip("\0"), "width": p.point[1], "height": p.point[0]})
    want(fx / "photoshop_patterns/harbour.pat", "_patterns", got, "psd-tools")
    # --- libmagic: format identification.
    for f, needle in [("sgi/harbour.sgi", "SGI image"), ("sun_raster/harbour.ras", "Sun raster"), ("xpm/harbour.xpm", "X pixmap"), ("farbfeld/harbour.ff", "farbfeld"), ("dcx/pages.dcx", "DCX"), ("icns/harbour.icns", "Mac OS X icon"), ("ani/tide-spinner.ani", "animated cursor"), ("dpx/reel1_000100.dpx", "DPX"), ("cineon/reel1_000100.cin", "Cineon"), ("jxr/harbour.jxr", "JPEG-XR"), ("photo_cd/img0001.pcd", "Photo CD"), ("djvu/tide-tables.djvu", "DjVu"), ("cgm/harbour-cleartext.cgm", "Computer Graphics Metafile"), ("ai/harbour-sign.ai", "PostScript"), ("freehand/harbour.fh9", "Freehand 9"), ("psp/breakwater.pspimage", "Paint Shop Pro"), ("vtf/buoy.vtf", "Valve"), ("ilbm/lighthouse.lbm", "ILBM"), ("xfig/quay.fig", "FIG image"), ("astc/harbour.astc", "ASTC"), ("pvr/harbour-etc2.pvr", "PowerVR"), ("mrw/sample.mrw", "Minolta"), ("x3f/sample.x3f", "Foveon"), ("bpg/ferry.bpg", "BPG"), ("flif/quay.flif", "FLIF"), ("utah_rle/harbour.rle", "RLE")]:
        magic(fx, f, needle)
    # --- Standard library: packages, XML, INI, plists.
    z = zipfile.ZipFile(fx / "krita/lighthouse.kra")
    root = ET.fromstring(z.read("maindoc.xml"))
    layers = [e for e in root.iter() if ln(e.tag) in ("layer", "mask")]
    want(fx / "krita/lighthouse.kra", "format.krita.layer_count", len(layers), "ElementTree")
    want(fx / "krita/lighthouse.kra", "format.krita.hidden_layers", sum(1 for e in layers if e.get("visible") == "0"), "ElementTree")
    img = next(e for e in root.iter() if ln(e.tag) == "IMAGE")
    size(fx, "krita/lighthouse.kra", "ElementTree", int(img.get("width")), int(img.get("height")))
    z = zipfile.ZipFile(fx / "openraster/boats.ora")
    root = ET.fromstring(z.read("stack.xml"))
    n = sum(1 for e in root.iter() if ln(e.tag) == "layer") + sum(1 for e in root.iter() if ln(e.tag) == "stack") - 1
    want(fx / "openraster/boats.ora", "format.openraster.layer_count", n, "ElementTree")
    size(fx, "openraster/boats.ora", "ElementTree", int(root.get("w")), int(root.get("h")))
    z = zipfile.ZipFile(fx / "procreate/gull-island.procreate")
    import plistlib

    a = plistlib.loads(z.read("Document.archive"))
    objs = a["$objects"]
    docd = objs[a["$top"]["root"].data]
    w, h = [int(float(x)) for x in objs[docd["size"].data].strip("{}").split(",")]
    size(fx, "procreate/gull-island.procreate", "plistlib", w, h)
    want(fx / "procreate/gull-island.procreate", "format.procreate.layer_count", len(objs[docd["layers"].data]["NS.objects"]), "plistlib")
    z = zipfile.ZipFile(fx / "sketch/ferry-app.sketch")
    m = json.loads(z.read("meta.json"))
    want(fx / "sketch/ferry-app.sketch", "format.sketch.artboards", sum(len(p["artboards"]) for p in m["pagesAndArtboards"].values()), "json")
    want(fx / "sketch/ferry-app.sketch", "format.sketch.app_version", m["appVersion"], "json")
    # draw.io: inflate compressed pages.
    root = ET.fromstring((fx / "drawio/harbour.drawio").read_bytes())
    cells = []
    for dgm in root.iter("diagram"):
        if len(dgm):
            cells += list(dgm.iter("mxCell"))
        else:
            xml = unquote(zlib.decompress(__import__("base64").b64decode(dgm.text), -15).decode())
            cells += list(ET.fromstring(xml).iter("mxCell"))
    want(fx / "drawio/harbour.drawio", "format.drawio.vertices", sum(1 for c in cells if c.get("vertex") == "1"), "ElementTree + zlib")
    want(fx / "drawio/harbour.drawio", "format.drawio.edges", sum(1 for c in cells if c.get("edge") == "1"), "ElementTree + zlib")
    root = ET.fromstring((fx / "vdx/harbour.vdx").read_bytes())
    pages = [e for e in root.iter() if ln(e.tag) == "Page"]
    want(fx / "vdx/harbour.vdx", "format.vdx.pages", [p.get("NameU") for p in pages], "ElementTree")
    want(fx / "vdx/harbour.vdx", "format.vdx.shapes", sum(1 for p in pages for e in p.iter() if ln(e.tag) == "Shape"), "ElementTree")
    want(fx / "vdx/harbour.vdx", "format.vdx.connections", sum(1 for e in root.iter() if ln(e.tag) == "Connect"), "ElementTree")
    root = ET.fromstring((fx / "vra/breakwater-vra.xml").read_bytes())
    want(fx / "vra/breakwater-vra.xml", "format.vra.records", sum(1 for e in root if ln(e.tag) in ("work", "image", "collection")), "ElementTree")
    c = configparser.ConfigParser(strict=False, interpolation=None)
    c.optionxform = str
    c.read_string((fx / "pp3/IMG_0042.CR2.pp3").read_text())
    want(fx / "pp3/IMG_0042.CR2.pp3", "format.pp3.app_version", c["Version"]["AppVersion"], "configparser")
    want(fx / "pp3/IMG_0042.CR2.pp3", "format.pp3.sections", c.sections(), "configparser")
    want(fx / "pp3/IMG_0042.CR2.pp3", "format.pp3.settings", sum(len(c[s]) for s in c.sections()), "configparser")
    c = configparser.ConfigParser(strict=False, interpolation=None)
    c.optionxform = str
    c.read_string((fx / "vms/harbour-4.vms").read_text())
    s = c["Virtual Microscope Specimen"]
    want(fx / "vms/harbour-4.vms", "format.vms.slide.tile_columns", float(s["NoJpegColumns"]), "configparser")
    want(fx / "vms/harbour-4.vms", "format.vms.slide.magnification", float(s["SourceLens"]), "configparser")
    json.dump(EXPECT, sys.stdout, indent=1)


def lookup(r, path):
    cur = r
    for p in path.split("."):
        if isinstance(cur, list):
            p = int(p)
            cur = cur[p] if p < len(cur) else None
        elif isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def same(a, b):
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool):
        return abs(a - b) <= max(1e-6, 1e-4 * abs(b))
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return a == b


def check(path, whiff="target/debug/whiff"):
    exp = json.load(open(path))
    cache = {}
    ok = bad = 0
    for e in exp:
        f = e["file"].replace("/whiff/", "")
        if f not in cache:
            cache[f] = json.loads(subprocess.run([whiff, "--jsonl", f], capture_output=True, text=True, check=True).stdout.splitlines()[0])
        r = cache[f]
        if e["path"] == "_pcd_base":
            # Pillow opens the Base resolution; whiff reports the highest (4Base = 2x) after rotation.
            w, h = lookup(r, "physical.image.width"), lookup(r, "physical.image.height")
            got = sorted([w // 2, h // 2]) if w and h else None
            good = got == sorted(e["value"])
        elif e["path"] == "_libmagic":
            got = e["value"]
            good = not got.startswith("MISSING")
            got = r["identification"]["format"] if good else got
        elif e["path"] == "_patterns":
            items = lookup(r, "format.photoshop_patterns.items") or []
            got = [{"name": i["name"], "width": i["width"], "height": i["height"]} for i in items]
            good = got == e["value"]
        else:
            got = lookup(r, e["path"])
            good = same(got, e["value"])
        if good:
            ok += 1
        else:
            bad += 1
            print(f"DIFF {f} {e['path']} ({e['tool']}): oracle {e['value']!r}, whiff {got!r}")
    files = len({e["file"] for e in exp})
    print(f"{ok}/{ok + bad} checks agree over {files} files")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    if sys.argv[1] == "expect":
        expect(sys.argv[2])
    else:
        check(sys.argv[2], *sys.argv[3:])
