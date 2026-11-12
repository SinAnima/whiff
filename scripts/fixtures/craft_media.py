#!/usr/bin/env python3
"""Write the stage 8 image long-tail fixtures (batch 3): legacy rasters,
film / LUT / XISF, Photoshop assets, FLIF / BPG / JPEG XR / JPEG-LS /
Photo CD / FlashPix, HEIF variants, GPU textures, camera raws, vector and
text diagrams, layered documents, metadata sidecars, DjVu, thumbcache,
whole-slide images and an Unreal texture package.

    python3 scripts/fixtures/craft_media.py OUT [STEP ...]

Runs in the `whiff-media` container (see media.sh), which supplies netpbm,
ImageMagick, ffmpeg, exiftool, JxrEncApp, djvulibre, Pillow and psd-tools.
Formats no installed tool writes are built here from their specifications.
Pixels are synthetic gradients; every name, place and caption is
fictitious (Saltmere Harbour), CC0-1.0. Output is deterministic.
"""

import base64
import io
import json
import os
import plistlib
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = Path(sys.argv[1])
STEPS = sys.argv[2:] or ["raster", "film", "assets", "codecs", "textures", "raw", "diagram", "layered", "sidecar", "misc"]
sys.argv = [sys.argv[0], str(OUT)]  # craft_images reads its output folder from argv
sys.path.insert(0, str(HERE))
import craft_images as ci  # noqa: E402
import office  # noqa: E402

WORK = OUT / "_work"
WORK.mkdir(parents=True, exist_ok=True)
ENV = dict(os.environ, SOURCE_DATE_EPOCH="1714592530", TZ="UTC")


def write(rel, data):
    p = OUT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    print(f"{rel}: {len(data)} bytes")


def run(*cmd, stdin=None, cwd=None):
    return subprocess.run(cmd, input=stdin, capture_output=True, check=True, env=ENV, cwd=cwd).stdout


def ppm(w=64, h=48):
    """A deterministic RGB gradient as binary PPM."""
    px = bytearray()
    for y in range(h):
        for x in range(w):
            px += bytes(((x * 255) // (w - 1), (y * 255) // (h - 1), 128))
    return b"P6\n%d %d\n255\n" % (w, h) + bytes(px)


def pbm(w=64, h=48):
    rows = bytearray()
    for y in range(h):
        bits = 0
        row = bytearray()
        for x in range(w):
            bits = (bits << 1) | (1 if (x // 8 + y // 8) % 2 else 0)
            if x % 8 == 7:
                row.append(bits)
                bits = 0
        rows += row
    return b"P4\n%d %d\n" % (w, h) + bytes(rows)


def png_bytes(w=32, h=24):
    from PIL import Image

    im = Image.frombytes("RGB", (w, h), bytes(((x * 255) // max(w - 1, 1), (y * 255) // max(h - 1, 1), 128)[i] for y in range(h) for x in range(w) for i in range(3)))
    b = io.BytesIO()
    im.save(b, "PNG", optimize=False)
    return b.getvalue()


def be(f, *v):
    return struct.pack(">" + f, *v)


def le(f, *v):
    return struct.pack("<" + f, *v)


def chunk_iff(cid, body):
    return cid + be("I", len(body)) + body + (b"\0" if len(body) & 1 else b"")


def chunk_riff(cid, body):
    return cid + le("I", len(body)) + body + (b"\0" if len(body) & 1 else b"")


def utf16be(s, nul=True):
    """A Photoshop Unicode string: count (with the NUL) + UTF-16BE."""
    units = s.encode("utf-16-be") + (b"\0\0" if nul else b"")
    return be("I", len(units) // 2) + units


# --------------------------------------------------------------------------
# Legacy rasters


def raster():
    src = WORK / "gradient.ppm"
    src.write_bytes(ppm())
    bw = WORK / "check.pbm"
    bw.write_bytes(pbm())
    write("ilbm/harbour-netpbm.iff", run("ppmtoilbm", str(src)))
    # A hand-made ILBM with the text chunks, palette and display mode.
    w, h, planes = 32, 16, 4
    bmhd = be("HHhhBBBBHBBhh", w, h, 0, 0, planes, 0, 1, 0, 0, 10, 11, 320, 256)
    cmap = bytes(c for i in range(16) for c in (i * 16, i * 8, 255 - i * 16))
    body = b"\xfd\x00" * (h * planes)  # ByteRun1: each plane row is 4 zero bytes
    form = b"ILBM" + chunk_iff(b"BMHD", bmhd) + chunk_iff(b"CMAP", cmap) + chunk_iff(b"CAMG", be("I", 0x8004))
    form += chunk_iff(b"NAME", b"Saltmere lighthouse") + chunk_iff(b"AUTH", b"Mira Castell")
    form += chunk_iff(b"(c) ", b"(c) 2024 Mira Castell, CC0") + chunk_iff(b"ANNO", b"Painted on an imaginary Amiga")
    form += chunk_iff(b"BODY", body)
    write("ilbm/lighthouse.lbm", b"FORM" + be("I", len(form)) + form)
    write("macpaint/check.mac", run("pbmtomacp", str(bw)))
    write("sun_raster/harbour.ras", run("pnmtorast", str(src)))
    write("sgi/harbour.sgi", run("pnmtosgi", "-imagename", "Saltmere harbour", "-rle", str(src)))
    write("xbm/check.xbm", run("pbmtoxbm", str(bw)).replace(b"noname", b"harbour_check"))
    small = WORK / "small.ppm"
    small.write_bytes(ppm(8, 6))
    write("xpm/harbour.xpm", run("ppmtoxpm", "-name", "harbour", str(small)))
    write("wbmp/check.wbmp", run("pbmtowbmp", str(bw)))
    write("farbfeld/harbour.ff", run("magick", str(src), "farbfeld:-"))
    q = WORK / "quant.ppm"
    q.write_bytes(run("pnmquant", "64", str(src)))
    write("pict/harbour.pict", run("ppmtopict", str(q)))
    run("magick", str(src), str(small), "-strip", str(WORK / "pages.dcx"))
    write("dcx/pages.dcx", (WORK / "pages.dcx").read_bytes())
    # From stdin, so no path is recorded in the RLE comments.
    rle = run("pnmtorle", stdin=src.read_bytes())
    # pnmtorle records the time it ran: pin it (same length, so the header stays valid).
    rle = re.sub(rb"HISTORY=pnmtorle on [^\0]{24}", b"HISTORY=pnmtorle on Wed May  1 19:42:10 2024", rle)
    write("utah_rle/harbour.rle", rle)
    # CompuServe RLE: ESC G H, runs of alternating colour, ESC G N.
    write("compuserve_rle/check.rle", b"\x1bGH" + bytes([0x20 + 64, 0x20 + 64] * 96) + b"\x1bGN")
    icns()
    ani()


def icns():
    from PIL import Image

    im = Image.open(io.BytesIO(png_bytes(256, 256)))
    b = io.BytesIO()
    im.save(b, "ICNS", sizes=[(16, 16), (32, 32), (128, 128), (256, 256)])
    write("icns/harbour.icns", b.getvalue())


def ico_frame(size, colour):
    from PIL import Image

    im = Image.new("RGBA", (size, size), colour)
    b = io.BytesIO()
    im.save(b, "ICO", sizes=[(size, size)])
    return b.getvalue()


def ani():
    frames = [ico_frame(32, c) for c in ((20, 60, 140, 255), (40, 120, 200, 255), (80, 160, 220, 255))]
    anih = le("9I", 36, 3, 4, 0, 0, 0, 0, 10, 1)
    info = b"INFO" + chunk_riff(b"INAM", b"Tide spinner\0") + chunk_riff(b"IART", b"Mira Castell\0")
    fram = b"fram" + b"".join(chunk_riff(b"icon", f) for f in frames)
    body = b"ACON" + chunk_riff(b"LIST", info) + chunk_riff(b"anih", anih) + chunk_riff(b"seq ", le("4I", 0, 1, 2, 1)) + chunk_riff(b"LIST", fram)
    write("ani/tide-spinner.ani", b"RIFF" + le("I", len(body)) + body)


# --------------------------------------------------------------------------
# Film scans, LUTs, XISF


def film():
    src = WORK / "gradient.ppm"
    src.write_bytes(ppm())
    props = [
        "-set", "dpx:file.creator", "whiff fixture generator",
        "-set", "dpx:file.project", "Saltmere Harbour restoration",
        "-set", "dpx:file.copyright", "(c) 2024 Castell Studio, CC0",
        "-set", "dpx:file.create_date", "2024:05:01:19:42:10:+02",
        "-set", "dpx:file.filename", "reel1_000100.dpx",
        "-set", "dpx:film.frame_rate", "24",
        "-set", "dpx:film.frame_position", "100",
        "-set", "dpx:film.format", "Academy",
        "-set", "dpx:television.time.code", "01:00:04:04",
        "-set", "dpx:television.frame_rate", "24",
        "-set", "dpx:orientation.device", "Example film scanner",
    ]
    write("dpx/reel1_000100.dpx", run("magick", str(src), "-strip", *props, "-depth", "10", "dpx:-"))
    cprops = ["-set", "cin:file.create_date", "2024:05:01", "-set", "cin:file.create_time", "19:42:10Z", "-set", "cin:file.filename", "reel1_000100.cin", "-set", "cin:origination.device", "Example film scanner", "-set", "cin:film.format", "Academy", "-set", "cin:film.frame_rate", "24"]
    # Written by its bare name in the work folder: Cineon records the output file name.
    run("magick", "gradient.ppm", "-strip", *cprops, "reel1_000100.cin", cwd=WORK)
    write("cineon/reel1_000100.cin", (WORK / "reel1_000100.cin").read_bytes())
    write("cineon/reel2_000200.cin", cineon_by_hand())
    # A 2-point 3D cube and a 1D cube.
    lines = ['# Saltmere warm grade', 'TITLE "Saltmere warm"', "LUT_3D_SIZE 2", "DOMAIN_MIN 0.0 0.0 0.0", "DOMAIN_MAX 1.0 1.0 1.0"]
    for b_ in (0, 1):
        for g in (0, 1):
            for r in (0, 1):
                lines.append(f"{min(1, r * 1.05):.6f} {g * 0.98:.6f} {b_ * 0.9:.6f}")
    write("cube_lut/saltmere-warm.cube", ("\n".join(lines) + "\n").encode())
    oned = ['TITLE "Lift"', "LUT_1D_SIZE 4"] + [f"{v:.4f} {v:.4f} {v:.4f}" for v in (0.05, 0.35, 0.68, 1.0)]
    write("cube_lut/lift-1d.cube", ("\n".join(oned) + "\n").encode())
    mesh = [0, 341, 682, 1023]
    rows = [" ".join(map(str, mesh))]
    for r in range(4):
        for g in range(4):
            for b_ in range(4):
                rows.append(f"{r * 1365} {g * 1365} {b_ * 1365}")
    write("lut_3dl/saltmere.3dl", ("# Autodesk 3D LUT\n" + "\n".join(rows) + "\n").encode())
    xisf()


def cineon_by_hand():
    h = bytearray(2048)
    def put(at, b):
        h[at : at + len(b)] = b
    put(0, be("IIIIII", 0x802A5FD7, 2048, 1024, 1024, 0, 2048 + 64 * 48 * 4))
    put(24, b"V4.5")
    put(32, b"reel2_000200.cin")
    put(132, b"2024:05:01")
    put(144, b"19:42:10UTC")
    h[192], h[193] = 0, 3
    for i in range(3):
        put(196 + 28 * i, bytes([0, i + 1, 10, 0]) + be("II", 64, 48) + be("4f", 0.0, 0.0, 1023.0, 2.047))
    put(452, b"Saltmere Harbour, reel 2")
    put(720, b"reel2_000200.cin")
    put(820, b"2024:05:01")
    put(832, b"19:42:10UTC")
    put(844, b"Example film scanner")
    put(908, b"FS-2")
    put(940, b"000000")
    put(1036, b"Academy")
    put(1068, be("I", 200))
    put(1072, be("f", 24.0))
    put(1076, b"Reel 2 frame 200")
    put(1108, b"Saltmere Harbour / scene 4 / take 1")
    return bytes(h) + bytes(64 * 48 * 4)


def xisf():
    w, h = 16, 12
    data = bytes(w * h * 2)
    def header(offset):
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<xisf version="1.0" xmlns="http://www.pixinsight.com/xisf">'
            f'<Image geometry="{w}:{h}:1" sampleFormat="UInt16" colorSpace="Gray" location="attachment:{offset}:{len(data)}">'
            '<FITSKeyword name="OBJECT" value="\'Saltmere Nebula\'" comment="Target"/>'
            '<FITSKeyword name="TELESCOP" value="\'Harbour 80mm refractor\'" comment=""/>'
            '<FITSKeyword name="DATE-OBS" value="\'2024-05-01T22:10:00\'" comment=""/>'
            '<FITSKeyword name="EXPTIME" value="300." comment="seconds"/>'
            '<FITSKeyword name="FILTER" value="\'Ha\'" comment=""/>'
            '<Property id="Observation:Object:Name" type="String" value="Saltmere Nebula"/>'
            '</Image>'
            '<Metadata><Property id="XISF:CreatorApplication" type="String" value="whiff fixture generator"/>'
            '<Property id="XISF:CreationTime" type="TimePoint" value="2024-05-02T08:00:00Z"/></Metadata>'
            '</xisf>'
        ).encode()
    hdr = header(0)
    offset = (16 + len(hdr) + 64 + 4095) // 4096 * 4096
    hdr = header(offset)
    out = b"XISF0100" + le("II", len(hdr), 0) + hdr
    write("xisf/saltmere-nebula.xisf", out.ljust(offset, b"\0") + data)


# --------------------------------------------------------------------------
# Photoshop assets


def key(k):
    return be("I", 0) + k if len(k) == 4 else be("I", len(k)) + k


def descriptor(cls, items):
    """items: list of (key, ostype, payload bytes)."""
    out = utf16be("") + key(cls) + be("I", len(items))
    for k, t, payload in items:
        out += key(k) + t + payload
    return out


def text(s):
    return utf16be(s)


def assets():
    # Gradients (version 5): GrdL list of gradient descriptors named by "Nm  ".
    grads = []
    for name in ("Harbour dusk", "Sea glass"):
        clr = descriptor(b"RGBC", [(b"Rd  ", b"doub", be("d", 200.0)), (b"Grn ", b"doub", be("d", 120.0)), (b"Bl  ", b"doub", be("d", 60.0))])
        stop = descriptor(b"Clrt", [(b"Clr ", b"Objc", clr), (b"Type", b"enum", key(b"Clry") + key(b"UsrS")), (b"Lctn", b"long", be("i", 0)), (b"Mdpn", b"long", be("i", 50))])
        grd = descriptor(b"Grdn", [(b"Nm  ", b"TEXT", text(name)), (b"GrdF", b"enum", key(b"GrdF") + key(b"CstS")), (b"Intr", b"doub", be("d", 4096.0)), (b"Clrs", b"VlLs", be("I", 1) + b"Objc" + stop)])
        grads.append(b"Objc" + descriptor(b"Grdn", [(b"Grad", b"Objc", grd)]))
    top = descriptor(b"null", [(b"GrdL", b"VlLs", be("I", len(grads)) + b"".join(grads))])
    write("photoshop_gradients/harbour.grd", b"8BGR" + be("HI", 5, 16) + top)
    # Patterns: two RGB patterns.
    pats = b""
    for name, pid, (w, h) in (("Rope weave", "4d1a0c2e-0000-4000-8000-000000000001", (4, 4)), ("Sail cloth", "4d1a0c2e-0000-4000-8000-000000000002", (2, 3))):
        # Virtual memory array list: rectangle, then each channel's array (not written here).
        arrays = be("4I", 0, 0, h, w) + be("I", 3) + be("I", 0) * 5  # 3 channels + user and sheet masks
        vma = be("I", 3) + be("I", len(arrays)) + arrays
        pats += be("I", 1) + be("I", 3) + be("HH", h, w) + utf16be(name) + bytes([len(pid)]) + pid.encode() + vma
    write("photoshop_patterns/harbour.pat", b"8BPT" + be("HI", 1, 2) + pats)
    # Swatches: version 1 then version 2 with names.
    cols = [(0, (65535, 32768, 0, 0), "Buoy orange"), (0, (0, 26214, 52428, 0), "Harbour blue"), (8, (5000, 0, 0, 0), "Slate")]
    v1 = be("HH", 1, len(cols)) + b"".join(be("H4H", s, *v) for s, v, _ in cols)
    v2 = be("HH", 2, len(cols)) + b"".join(be("H4H", s, *v) + utf16be(n) for s, v, n in cols)
    write("photoshop_swatches/harbour.aco", v1 + v2)
    # Adobe Swatch Exchange: a group with two colours, then a lone CMYK colour.
    def ase_name(n):
        u = (n + "\0").encode("utf-16-be")
        return be("H", len(u) // 2) + u
    blocks = [
        (0xC001, ase_name("Harbour")),
        (0x0001, ase_name("Buoy orange") + b"RGB " + be("3f", 1.0, 0.5, 0.0) + be("H", 2)),
        (0x0001, ase_name("Harbour blue") + b"RGB " + be("3f", 0.0, 0.4, 0.8) + be("H", 0)),
        (0xC002, b""),
        (0x0001, ase_name("Net black") + b"CMYK" + be("4f", 0.0, 0.0, 0.0, 1.0) + be("H", 1)),
    ]
    write("ase_swatches/harbour.ase", b"ASEF" + be("HHI", 1, 0, len(blocks)) + b"".join(be("HI", t, len(b_)) + b_ for t, b_ in blocks))
    # Brushes (version 6.2): a sampled brush and the descriptor naming it.
    samp = be("I", 8) + bytes(8)
    brush = descriptor(b"null", [(b"Brsh", b"VlLs", be("I", 1) + b"Objc" + descriptor(b"brushPreset", [(b"Nm  ", b"TEXT", text("Spray foam")), (b"Dmtr", b"UntF", b"#Pxl" + be("d", 30.0))]))])
    desc = be("I", 16) + brush
    def section(k, b_):
        return b"8BIM" + k + be("I", len(b_)) + b_ + (b"\0" if len(b_) & 1 else b"")
    write("photoshop_brushes/harbour.abr", be("HH", 6, 2) + section(b"samp", samp) + section(b"desc", desc))
    # Actions: one set, two actions, three commands.
    def command(event, label, desc_items=None):
        out = bytes([0, 1, 0, 0]) + b"TEXT" + be("I", len(event)) + event + be("I", len(label)) + label
        if desc_items is None:
            return out + be("i", 0)
        return out + be("i", -1) + be("I", 16) + descriptor(b"null", desc_items)
    act1 = be("HBBH", 0, 0, 0, 0) + utf16be("Harbour toning") + b"\0" + be("I", 2)
    act1 += command(b"convertMode", b"Convert Mode", [(b"T   ", b"type", utf16be("") + key(b"Grys"))])
    act1 += command(b"save", b"Save")
    act2 = be("HBBH", 1, 0, 0, 0) + utf16be("Flatten for print") + b"\0" + be("I", 1) + command(b"flattenImage", b"Flatten Image")
    write("photoshop_actions/harbour.atn", be("I", 16) + utf16be("Saltmere actions") + b"\0" + be("I", 2) + act1 + act2)


# --------------------------------------------------------------------------
# Codecs


def varint(n):
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.append(0x80 | (n & 0x7F))
        n >>= 7
    return bytes(reversed(out))


def raw_deflate(b):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(b) + c.flush()


def xmp_packet(title):
    return (
        '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f'<dc:title><rdf:Alt><rdf:li xml:lang="x-default">{title}</rdf:li></rdf:Alt></dc:title>'
        '<dc:creator><rdf:Seq><rdf:li>Mira Castell</rdf:li></rdf:Seq></dc:creator>'
        '</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
    ).encode()


def codecs():
    # FLIF: non-interlaced RGBA, 8-bit, 40x30, with an XMP chunk.
    x = raw_deflate(xmp_packet("Saltmere quay"))
    write("flif/quay.flif", b"FLIF" + bytes([0x34, ord("1")]) + varint(39) + varint(29) + b"eXmp" + varint(len(x)) + x + b"\0" + bytes(16))
    # FLIF animation: interlaced, RGB, 3 frames.
    write("flif/waves-anim.flif", b"FLIF" + bytes([0x63, ord("1")]) + varint(19) + varint(14) + varint(1) + b"\0" + bytes(8))
    # BPG: 4:2:0, 8-bit, YCbCr BT.709, alpha, extensions (XMP, animation control).
    xmp = xmp_packet("Saltmere ferry")
    ext = varint(3) + varint(len(xmp)) + xmp + varint(5) + varint(3) + varint(0) + varint(1) + varint(25)
    a = (1 << 5) | 0x10 | 0
    b_ = (3 << 4) | 8 | 0 | 0 | 1
    write("bpg/ferry.bpg", b"BPG\xfb" + bytes([a, b_]) + varint(48) + varint(32) + varint(16) + varint(len(ext)) + ext + bytes(16))
    # JPEG-LS and lossless JPEG via ffmpeg.
    src = WORK / "gradient.ppm"
    src.write_bytes(ppm())
    write("jls/harbour.jls", run("ffmpeg", "-v", "error", "-i", str(src), "-c:v", "jpegls", "-f", "image2pipe", "-"))
    # JPEG XR via JxrEncApp (24-bit BGR from a BMP).
    bmp = WORK / "gradient.bmp"
    run("magick", str(src), "-strip", "-define", "bmp:format=bmp3", str(bmp))
    run("JxrEncApp", "-i", str(bmp), "-o", str(WORK / "harbour.jxr"), "-q", "1")
    write("jxr/harbour.jxr", (WORK / "harbour.jxr").read_bytes())
    photo_cd()
    flashpix()
    heif_variants()


def photo_cd():
    ipi = bytearray(2048)
    ipi[0:7] = b"PCD_IPI"
    ipi[7:9] = bytes([1, 0])
    ipi[9:11] = bytes([2, 0])
    ipi[0x0B:0x0F] = be("I", 1714592530)
    ipi[0x0F:0x13] = be("I", 1714592530)
    ipi[0x13] = 1
    ipi[0x14:0x28] = b"Example Photo CD".ljust(20)
    ipi[0x28:0x3C] = b"Example Scanners".ljust(20)
    ipi[0x3C:0x4C] = b"Film Scanner 1".ljust(16)
    ipi[0xA3:0xDF] = b"Saltmere Photo Lab".ljust(60)
    ipi[0x602] = 0x01 | (1 << 2)  # rotated 90 degrees, 4Base
    write("photo_cd/img0001.pcd", bytes(2048) + bytes(ipi) + bytes(4096))


def flashpix():
    fmtid_image = "56616000-C154-11CE-8553-00AA00A1F95B"
    contents = office.property_set([(fmtid_image, [(0x01000000, office.VT_I4, 2), (0x01000002, office.VT_I4, 640), (0x01000003, office.VT_I4, 480)])])
    summary = office.property_set([("F29F85E0-4FF9-1068-AB91-08002B27B3D9", [(2, office.VT_LPSTR, "Saltmere ferry"), (4, office.VT_LPSTR, "Mira Castell")])])
    streams = [
        ("\x05SummaryInformation", summary),
        ("Data Object Store 000001/\x05Image Contents", contents),
        ("Data Object Store 000001/Resolution 0000/Subimage 0000 Header", bytes(64)),
        ("Data Object Store 000001/Resolution 0000/Subimage 0000 Data", bytes(64)),
        ("Data Object Store 000001/Resolution 0001/Subimage 0000 Header", bytes(64)),
    ]
    write("fpx/ferry.fpx", office.cfb_bytes(streams, root_clsid=office.guid_bytes("56616700-C154-11CE-8553-00AA00A1F95B")))


def box(kind, body):
    return be("I", len(body) + 8) + kind + body


def fullbox(kind, v, flags, body):
    return box(kind, bytes([v]) + flags.to_bytes(3, "big") + body)


def heif_still(brand, compat, item_type, config_kind, config):
    ftyp = box(b"ftyp", brand + be("I", 0) + b"mif1" + compat)
    hdlr = fullbox(b"hdlr", 0, 0, be("I", 0) + b"pict" + bytes(12) + b"\0")
    pitm = fullbox(b"pitm", 0, 0, be("H", 1))
    infe = fullbox(b"infe", 2, 0, be("HH", 1, 0) + item_type + b"\0")
    iinf = fullbox(b"iinf", 0, 0, be("H", 1) + infe)
    ispe = fullbox(b"ispe", 0, 0, be("II", 64, 48))
    ipco = box(b"ipco", ispe + box(config_kind, config))
    ipma = fullbox(b"ipma", 0, 0, be("I", 1) + be("HB", 1, 2) + bytes([0x81, 0x82]))
    iprp = box(b"iprp", ipco + ipma)
    mdat_body = bytes(32)
    meta_wo_iloc = hdlr + pitm + iinf + iprp
    # iloc: version 0, offset/length sizes 4/4, one extent; offset patched below.
    def iloc(offset):
        return fullbox(b"iloc", 0, 0, bytes([0x44, 0x00]) + be("H", 1) + be("HHH", 1, 0, 1) + be("II", offset, len(mdat_body)))
    meta = fullbox(b"meta", 0, 0, meta_wo_iloc + iloc(0))
    offset = len(ftyp) + len(meta) + 8
    meta = fullbox(b"meta", 0, 0, meta_wo_iloc + iloc(offset))
    return ftyp + meta + box(b"mdat", mdat_body)


def heif_variants():
    avcc = bytes([1, 0x42, 0xC0, 0x1E, 0xFF, 0xE0, 0x00])
    write("avci/harbour.avci", heif_still(b"avci", b"avci", b"avc1", b"avcC", avcc))
    write("hej2/harbour.hej2", heif_still(b"j2ki", b"j2ki", b"j2k1", b"j2kH", box(b"ihdr", be("IIHBBBB", 48, 64, 3, 7, 7, 0, 0))))


# --------------------------------------------------------------------------
# GPU textures


def textures():
    # ASTC 6x6, 64x48x1.
    blocks = ((64 + 5) // 6) * ((48 + 5) // 6)
    write("astc/harbour.astc", b"\x13\xab\xa1\x5c" + bytes([6, 6, 1]) + (64).to_bytes(3, "little") + (48).to_bytes(3, "little") + (1).to_bytes(3, "little") + bytes(16 * blocks))
    # Basis Universal: ETC1S 2D, two mip levels, alpha.
    slices = [(0, 0, 64, 48), (0, 1, 32, 24)]
    header_size = 77
    slice_ofs = header_size
    data_ofs = slice_ofs + 23 * len(slices)
    sd = b""
    for img, lvl, w, h in slices:
        sd += (img).to_bytes(3, "little") + bytes([lvl, 0]) + le("HHHH", w, h, (w + 3) // 4, (h + 3) // 4) + le("II", data_ofs, 8) + le("H", 0)
    hdr = b"sB" + le("HHH", 0x13, header_size, 0) + le("I", 0) + le("H", 0)
    hdr += (len(slices)).to_bytes(3, "little") + (1).to_bytes(3, "little") + bytes([0]) + le("H", 1 | 4) + bytes([0]) + (0).to_bytes(3, "little")
    hdr += le("III", 0, 0, 0) + le("H", 0) + le("I", 0) + (0).to_bytes(3, "little") + le("H", 0) + le("I", 0) + (0).to_bytes(3, "little")
    hdr += le("II", 0, 0) + le("I", slice_ofs) + le("II", 0, 0)
    assert len(hdr) == header_size, len(hdr)
    write("basis/harbour.basis", hdr + sd + bytes(8))
    # PVR v3: ETC2 RGB, sRGB, 64x48, 1 mip, orientation metadata.
    meta = b"PVR\x03" + le("II", 3, 3) + bytes([0, 0, 0])
    v3 = b"PVR\x03" + le("I", 0) + le("Q", 22) + le("IIIIIIIII", 1, 0, 48, 64, 1, 1, 1, 1, len(meta)) + meta + bytes(64 * 48 // 2)
    write("pvr/harbour-etc2.pvr", v3)
    # PVR v3 uncompressed RGBA8888.
    fmt = int.from_bytes(b"rgba", "little") | (int.from_bytes(bytes([8, 8, 8, 8]), "little") << 32)
    write("pvr/harbour-rgba.pvr", b"PVR\x03" + le("I", 2) + le("Q", fmt) + le("IIIIIIIII", 0, 0, 8, 8, 1, 1, 1, 1, 0) + bytes(8 * 8 * 4))
    # PVR v2 legacy header: PVRTC 4bpp, 32x32.
    v2 = le("IIIIIIIIIIIII", 52, 32, 32, 0, 0x19, 512, 4, 0, 0, 0, 0, 0x21525650, 1)
    write("pvr/legacy-pvrtc.pvr", v2 + bytes(512))
    # VTF 7.3: DXT5 64x64, 1 frame, low-res DXT1 16x16, 2 resources.
    lo = 16 * 16 // 2
    hi = 64 * 64
    hsize = 80 + 2 * 8
    hdr = b"VTF\0" + le("II", 7, 3) + le("I", hsize) + le("HH", 64, 64) + le("I", 0x2000 | 0x0004) + le("HH", 1, 0) + bytes(4)
    hdr += le("3f", 0.25, 0.4, 0.55) + bytes(4) + le("f", 1.0) + le("i", 15) + bytes([1]) + le("i", 13) + bytes([16, 16]) + le("H", 1) + bytes(3)
    hdr += le("I", 2) + bytes(8)
    hdr += b"\x01\0\0\0" + le("I", hsize) + b"\x30\0\0\0" + le("I", hsize + lo)
    assert len(hdr) == hsize, len(hdr)
    write("vtf/buoy.vtf", hdr + bytes(lo) + bytes(hi))


# --------------------------------------------------------------------------
# Camera raw


def raw():
    write("dcr/sample.dcr", ci.tiff_raw(True, "Kodak", "DCS Pro Example"))
    write("kdc/sample.kdc", ci.tiff_raw(True, "EASTMAN KODAK COMPANY", "KODAK EXAMPLE DIGITAL CAMERA"))
    write("erf/sample.erf", ci.tiff_raw(True, "SEIKO EPSON CORP.", "R-D1 Example"))
    write("mef/sample.mef", ci.tiff_raw(False, "Mamiya-OP Co.,Ltd.", "ZD Example"))
    write("mos/sample.mos", ci.tiff_raw(False, "Leaf", "Aptus Example"))
    write("iiq/sample.iiq", ci.tiff_raw(True, "Phase One", "IQ Example", artist="Ines Halvorsen"))
    write("gpr/sample.gpr", ci.tiff_raw(True, "GoPro", "HERO Example", ifd0_extra={50706: ci.byte(1, 4, 0, 0), 50708: ci.ascii_("GoPro HERO Example")}, lat=43.2951, lon=5.3739))
    # Minolta MRW: PRD, RIF, WBG, TTW (an EXIF TIFF), then the image data.
    ifd0, exif, _ = ci.camera("Minolta Co., Ltd.", "DiMAGE Example")
    ttw = ci.tiff(False, {"ifd0": (ifd0, None), "exif": (exif, None)})
    prd = b"21810002" + be("HHHH", 48, 64, 48, 64) + bytes([12, 12, 0x52, 0]) + be("H", 0) + be("H", 1)
    rif = bytes([0, 0, 0, 0, 0, 0, 48, 0]) + bytes(8)
    wbg = bytes(4) + be("4H", 256, 256, 256, 256)
    blocks = b"\0PRD" + be("I", len(prd)) + prd + b"\0WBG" + be("I", len(wbg)) + wbg + b"\0RIF" + be("I", len(rif)) + rif + b"\0TTW" + be("I", len(ttw)) + ttw
    write("mrw/sample.mrw", b"\0MRM" + be("I", len(blocks)) + blocks + bytes(64 * 48 * 12 // 8))
    # Sigma X3F 2.1: header, PROP section, IMAG preview, directory.
    head = b"FOVb" + le("I", 0x00020001) + bytes(16) + le("I", 0) + le("III", 64, 48, 0) + b"Daylight".ljust(32, b"\0")
    head = head.ljust(256, b"\0")
    props = [("CAMMANUF", "SIGMA"), ("CAMMODEL", "SIGMA DP Example"), ("ISO", "100"), ("EXPTIME", "8000"), ("APERTURE", "5.600"), ("TIME", "1714592530"), ("CAMSERIAL", "0000000")]
    chars = ""
    entries = b""
    for k, v in props:
        entries += le("II", len(chars), len(chars) + len(k) + 1)
        chars += k + "\0" + v + "\0"
    cdata = chars.encode("utf-16-le")
    prop = b"SECp" + le("IIIII", 0x00020000, len(props), 0, 0, len(chars)) + entries + cdata
    imag = b"SECi" + le("IIIIII", 0x00020000, 2, 3, 16, 12, 48) + bytes(16 * 12 * 3)
    prop_at = len(head)
    imag_at = prop_at + len(prop)
    dir_at = imag_at + len(imag)
    directory = b"SECd" + le("II", 0x00020000, 2) + le("II", prop_at, len(prop)) + b"PROP" + le("II", imag_at, len(imag)) + b"IMAG"
    write("x3f/sample.x3f", head + prop + imag + directory + le("I", dir_at))


# --------------------------------------------------------------------------
# Vector and text diagrams


def cgm_cmd(cls, eid, params=b""):
    n = len(params)
    if n < 31:
        out = be("H", (cls << 12) | (eid << 5) | n) + params
    else:
        out = be("HH", (cls << 12) | (eid << 5) | 31, n) + params
    return out + (b"\0" if n & 1 else b"")


def cgm_str(s):
    b_ = s.encode("latin-1")
    return bytes([len(b_)]) + b_


def diagram():
    body = cgm_cmd(0, 1, cgm_str("Saltmere chart"))
    body += cgm_cmd(1, 1, be("h", 1))
    body += cgm_cmd(1, 2, cgm_str("whiff fixture: tide chart"))
    body += cgm_cmd(1, 13, cgm_str("Helvetica") + cgm_str("Times-Roman"))
    body += cgm_cmd(0, 3, cgm_str("Tides"))
    body += cgm_cmd(2, 6, be("4h", 0, 0, 1000, 800))
    body += cgm_cmd(0, 4)
    body += cgm_cmd(4, 1, be("4h", 10, 10, 900, 700))
    body += cgm_cmd(4, 4, be("hhh", 100, 100, 1) + cgm_str("High water 06:12"))
    body += cgm_cmd(4, 4, be("hhh", 100, 200, 1) + cgm_str("Low water 12:30"))
    body += cgm_cmd(0, 5)
    body += cgm_cmd(0, 2)
    write("cgm/tides.cgm", body)
    write("cgm/harbour-cleartext.cgm", b"BEGMF 'Harbour plan';\nMFVERSION 1;\nMFDESC 'whiff fixture';\nFONTLIST 'Helvetica';\nBEGPIC 'Quay';\nVDCEXT 0,0 100,100;\nBEGPICBODY;\nLINE 0,0 100,100;\nTEXT 10,10 final 'North quay';\nENDPIC;\nENDMF;\n")
    # CorelDRAW (RIFF, version 13): vrsn, a doc list with two pages, a DISP thumbnail.
    disp = bytes(40)
    pages = chunk_riff(b"LIST", b"page" + chunk_riff(b"flgs", bytes(4))) * 2
    doc = chunk_riff(b"LIST", b"doc " + chunk_riff(b"mcfg", bytes(16)))
    body = b"CDRD" + chunk_riff(b"vrsn", le("H", 1300)) + chunk_riff(b"DISP", disp) + doc + pages
    write("cdr/harbour.cdr", b"RIFF" + le("I", len(body)) + body)
    # draw.io: one plain page, one compressed page.
    page2 = '<mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/><mxCell id="a" value="Ferry terminal" vertex="1" parent="1"/><mxCell id="b" value="Car park" vertex="1" parent="1"/><mxCell id="e" edge="1" source="a" target="b" parent="1"/></root></mxGraphModel>'
    from urllib.parse import quote
    comp = base64.b64encode(raw_deflate(quote(page2, safe="").encode())).decode()
    drawio = (
        '<mxfile host="app.diagrams.net" modified="2024-05-01T17:42:10.000Z" agent="whiff fixture" version="24.4.0" type="device">'
        '<diagram id="p1" name="Harbour"><mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
        '<mxCell id="2" value="&lt;b&gt;Lighthouse&lt;/b&gt;" vertex="1" parent="1"/>'
        '<mxCell id="3" value="Breakwater" vertex="1" parent="1"/>'
        '<mxCell id="4" value="guides" edge="1" source="2" target="3" parent="1"/></root></mxGraphModel></diagram>'
        f'<diagram id="p2" name="Landside">{comp}</diagram></mxfile>'
    )
    write("drawio/harbour.drawio", drawio.encode())
    ai = (
        "%!PS-Adobe-3.0\n%%Creator: Adobe Illustrator(R) 8.0\n%%AI8_CreatorVersion: 8.0.1\n%%For: (Mira Castell) ()\n"
        "%%Title: (Harbour sign)\n%%CreationDate: (5/1/24) (7:42 PM)\n%%BoundingBox: 0 0 200 100\n%%DocumentProcessColors: Black\n"
        "%AI5_FileFormat 4.0\n%AI3_ColorUsage: Black&White\n%AI5_ArtSize: 612 792\n%%EndComments\n%%BeginProlog\n%%EndProlog\n"
        "%%BeginSetup\n%%EndSetup\n0 A\n0 O\n0 g\n10 10 m\n190 10 L\n190 90 L\n10 90 L\nf\n%%PageTrailer\n%%Trailer\n%%EOF\n"
    )
    write("ai/harbour-sign.ai", ai.encode())
    write("freehand/harbour.fh9", b"AGD4\xbe\xb8\xbb\xcb" + bytes(120))
    write("mermaid/ferry.mmd", b"---\ntitle: Ferry crossing\n---\nflowchart LR\n    %% route\n    A[Saltmere quay] --> B{Weather ok?}\n    B -->|yes| C[Sail to Gull Island]\n    B -->|no| D[Wait in harbour]\n    C --> E[Gull Island pier]\n")
    write("mermaid/tides.mermaid", b"sequenceDiagram\n    participant Harbourmaster\n    participant Pilot\n    Harbourmaster->>Pilot: High water at 06:12\n    Pilot-->>Harbourmaster: Bringing the ferry in\n")
    write("plantuml/booking.puml", b"@startuml booking\ntitle Ferry booking\nactor Passenger\nparticipant \"Ticket office\" as T\ndatabase Schedule\nPassenger -> T : ask for a crossing\nT -> Schedule : check tides\nSchedule --> T : 06:12\nT --> Passenger : ticket\n@enduml\n")
    vdx = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<VisioDocument xmlns="http://schemas.microsoft.com/visio/2003/core">'
        '<DocumentProperties><Title>Harbour layout</Title><Subject>Berths and moorings</Subject><Creator>Mira Castell</Creator>'
        '<Company>Saltmere Harbour</Company><Keywords>harbour, berths</Keywords><TimeCreated>2024-05-01T17:42:10</TimeCreated><TimeSaved>2024-05-02T08:00:00</TimeSaved></DocumentProperties>'
        '<Masters><Master ID="1" NameU="Rectangle"><Shapes><Shape ID="1"/></Shapes></Master><Master ID="2" NameU="Dynamic connector"/></Masters>'
        '<Pages><Page ID="0" NameU="Berths"><Shapes><Shape ID="1" Master="1"><Text>Berth 1</Text></Shape><Shape ID="2" Master="1"><Text>Berth 2</Text></Shape>'
        '<Shape ID="3" Master="2"/></Shapes><Connects><Connect FromSheet="3" ToSheet="1"/><Connect FromSheet="3" ToSheet="2"/></Connects></Page>'
        '<Page ID="1" NameU="Moorings"><Shapes><Shape ID="1"><Text>Buoy A</Text></Shape></Shapes></Page></Pages></VisioDocument>'
    )
    write("vdx/harbour.vdx", vdx.encode())
    fig = (
        "#FIG 3.2  Produced by whiff fixture generator\nLandscape\nCenter\nMetric\nA4\n100.00\nSingle\n-2\n# Saltmere quay sketch\n1200 2\n"
        "2 2 0 1 0 7 50 -1 -1 0.000 0 0 -1 0 0 5\n\t 1000 1000 4000 1000 4000 3000 1000 3000 1000 1000\n"
        "1 3 0 1 0 7 50 -1 -1 0.000 1 0.0000 2500 2000 300 300 2500 2000 2800 2000\n"
        "4 0 0 50 -1 0 12 0.0000 4 135 1200 1200 2500 North quay\\001\n"
        "4 0 0 50 -1 0 12 0.0000 4 135 900 1200 2800 Caf\\351 \\\\ bar\\001\n"
    )
    write("xfig/quay.fig", fig.encode("latin-1"))
    dot = (
        "// ferry network\n"
        'digraph "Saltmere ferries" {\n  label="Saltmere ferry network";\n  rankdir=LR;\n  node [shape=box];\n'
        '  quay [label="Saltmere quay"];\n  gull [label="Gull Island"];\n  quay -> gull -> heron;\n  quay -> {lamb, otter};\n'
        "  subgraph cluster_north { label=\"North\"; heron; puffin; heron -> puffin }\n}\n"
    )
    write("graphviz/ferries.gv", dot.encode())
    write("graphviz/moorings.dot", b"strict graph moorings {\n  a -- b;\n  b -- c;\n  a -- b;\n}\n")


# --------------------------------------------------------------------------
# Layered documents


def layered():
    png = png_bytes(32, 24)
    maindoc = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE DOC PUBLIC "-//KDE//DTD krita 2.0//EN" "http://www.calligra.org/DTD/krita-2.0.dtd">\n'
        '<DOC xmlns="http://www.calligra.org/DTD/krita" editor="Krita" syntaxVersion="2.0" kritaVersion="5.2.2">'
        '<IMAGE name="Saltmere lighthouse" width="640" height="480" colorspacename="RGBA" profile="sRGB-elle-V2-srgbtrc.icc" x-res="300" y-res="300" description="">'
        '<layers><layer name="Sky" nodetype="paintlayer" visible="1" filename="layer2"/>'
        '<layer name="Lighthouse" nodetype="grouplayer" visible="1"><layers><layer name="Tower" nodetype="paintlayer" visible="1" filename="layer3"/>'
        '<layer name="Old sketch" nodetype="paintlayer" visible="0" filename="layer4"/></layers></layer>'
        '<layer name="Background" nodetype="paintlayer" visible="1" filename="layer1"/></layers></IMAGE></DOC>'
    )
    info = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<document-info xmlns="http://www.calligra.org/DTD/document-info">'
        '<about><title>Saltmere lighthouse</title><description>Study of the harbour light at dusk</description><subject></subject>'
        '<keyword>lighthouse harbour</keyword><initial-creator>Mira Castell</initial-creator><editing-cycles>12</editing-cycles>'
        '<date>2024-05-02T08:00:00</date><creation-date>2024-05-01T17:42:10</creation-date><language>en</language><license>CC0-1.0</license></about>'
        '<author><full-name>Mira Castell</full-name></author></document-info>'
    )
    write("krita/lighthouse.kra", office.zip_bytes([("mimetype", b"application/x-krita"), ("maindoc.xml", maindoc.encode()), ("documentinfo.xml", info.encode()), ("preview.png", png), ("mergedimage.png", png)], stored=("mimetype",)))
    stack = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<image version="0.0.6" w="320" h="240" xres="72" yres="72">'
        '<stack><layer name="Gulls" src="data/gulls.png" x="0" y="0" opacity="1.0" visibility="visible"/>'
        '<stack name="Boats" visibility="visible"><layer name="Red sail" src="data/red.png" visibility="visible"/><layer name="Rigging" src="data/rig.svg" visibility="hidden"/></stack>'
        '<layer name="Water" src="data/water.png" visibility="visible"/></stack></image>'
    )
    write("openraster/boats.ora", office.zip_bytes([("mimetype", b"image/openraster"), ("stack.xml", stack.encode()), ("Thumbnails/thumbnail.png", png), ("mergedimage.png", png), ("data/water.png", png)], stored=("mimetype",)))
    psp()
    pdn(png)
    procreate(png)
    sketch(png)
    figma(png)
    write("affinity/harbour.afphoto", b"\x00\xffKA" + le("I", 10) + b"Prsn" + bytes(52) + png + bytes(64))


def psp():
    gia = le("I", 46) + le("ii", 64, 48) + le("d", 300.0) + bytes([1]) + le("HHH", 2, 24, 3) + le("I", 0) + bytes([0]) + le("I", 64 * 48 * 3) + le("i", 0) + le("H", 2) + le("I", 0)
    def field(kw, data):
        return b"~FL\0" + le("HI", kw, len(data)) + data
    creator = field(0, b"Saltmere breakwater") + field(1, le("I", 1714592530)) + field(3, b"Mira Castell") + field(4, b"(c) 2024 Mira Castell, CC0") + field(5, b"Breakwater at low tide") + field(6, le("I", 1)) + field(7, le("I", 0x08000000))
    def block(bid, body):
        return b"~BK\0" + le("HI", bid, len(body)) + body
    def layer(name):
        n = name.encode()
        return block(4, le("I", 4 + 2 + len(n) + 1) + le("H", len(n)) + n + bytes([1]))
    bank = layer("Background") + layer("Rocks")
    out = b"Paint Shop Pro Image File\n\x1a\0\0\0\0\0" + le("HH", 5, 0) + block(0, gia) + block(1, creator) + block(3, bank)
    write("psp/breakwater.pspimage", out)


def pdn(png):
    hdr = f'<pdnImage width="800" height="600" layers="3" savedWithVersion="5.0.13.0"><custom><thumb png="{base64.b64encode(png).decode()}" /></custom></pdnImage>'.encode()
    write("pdn/gulls.pdn", b"PDN3" + len(hdr).to_bytes(3, "little") + hdr + b"\x00\x01" + bytes(32))


def procreate(png):
    U = plistlib.UID
    objects = [
        "$null",
        {"$class": U(9), "size": U(2), "name": U(3), "layers": U(4), "SilicaDocumentArchiveDPIKey": 264.0, "SilicaDocumentTrackedTimeKey": 5400.5, "orientation": 1, "SilicaDocumentVideoPurged": False},
        "{2048, 1536}",
        "Gull Island",
        {"$class": U(10), "NS.objects": [U(5), U(7)]},
        {"$class": U(11), "name": U(6), "hidden": False},
        "Sketch",
        {"$class": U(11), "name": U(8), "hidden": True},
        "Colour flats",
        {"$classname": "SilicaDocument", "$classes": ["SilicaDocument", "NSObject"]},
        {"$classname": "NSArray", "$classes": ["NSArray", "NSObject"]},
        {"$classname": "SilicaLayer", "$classes": ["SilicaLayer", "NSObject"]},
    ]
    archive = plistlib.dumps({"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": U(1)}, "$objects": objects}, fmt=plistlib.FMT_BINARY, sort_keys=True)
    write("procreate/gull-island.procreate", office.zip_bytes([("Document.archive", archive), ("QuickLook/Thumbnail.png", png), ("video/segments/segment-1.mp4", bytes(16))]))


def sketch(png):
    meta = {
        "commit": "0000000", "appVersion": "99.1", "build": 180000, "app": "com.bohemiancoding.sketch3", "version": 146, "compatibilityVersion": 99,
        "created": {"app": "com.bohemiancoding.sketch3", "appVersion": "99.1", "build": 180000, "version": 146},
        "pagesAndArtboards": {"P1": {"name": "Ferry app", "artboards": {"A1": {"name": "Timetable"}, "A2": {"name": "Tickets"}}}, "P2": {"name": "Symbols", "artboards": {}}},
        "fonts": ["Inter-Regular", "Inter-Bold"],
    }
    doc = {"_class": "document", "pages": [{"_ref": "pages/P1"}, {"_ref": "pages/P2"}]}
    write("sketch/ferry-app.sketch", office.zip_bytes([("document.json", json.dumps(doc).encode()), ("meta.json", json.dumps(meta, sort_keys=True).encode()), ("user.json", b"{}"), ("pages/P1.json", b"{}"), ("pages/P2.json", b"{}"), ("previews/preview.png", png)]))


def figma(png):
    canvas = b"fig-kiwi" + le("I", 20) + le("I", 8) + bytes(8)
    write("figma/harbour-raw.fig", canvas)
    meta = {"client_meta": {"background_color": {"r": 0.9, "g": 0.9, "b": 0.9, "a": 1}}, "file_name": "Harbour signage", "exported_at": "2024-05-01T17:42:10.000Z"}
    write("figma/harbour-signage.fig", office.zip_bytes([("canvas.fig", canvas), ("meta.json", json.dumps(meta).encode()), ("thumbnail.png", png), ("images/0001", bytes(8))]))


# --------------------------------------------------------------------------
# Metadata sidecars


def sidecar():
    png = WORK / "base.png"
    png.write_bytes(png_bytes())
    tagged = WORK / "tagged.jpg"
    run("magick", str(png), "-strip", str(tagged))
    run("exiftool", "-q", "-overwrite_original", "-Make=Example Optics", "-Model=Example X100", "-Artist=Mira Castell",
        "-DateTimeOriginal=2024:05:01 19:42:10", "-Copyright=(c) 2024 Mira Castell, CC0",
        "-XMP-dc:Title=Old harbour", "-XMP-dc:Creator=Mira Castell", "-XMP-dc:Subject=harbour", "-XMP-dc:Subject=boats",
        "-IPTC:ObjectName=Old harbour", "-IPTC:Keywords=harbour", str(tagged))
    write("exv/harbour.exv", exv_from(tagged))
    exif_tiff = run("exiftool", "-b", "-EXIF", str(tagged))
    write("exif/harbour.exif", b"Exif\0\0" + exif_tiff if not exif_tiff.startswith(b"Exif") else exif_tiff)
    # An XMP sidecar with Camera Raw develop settings, as Lightroom writes next to a raw file.
    xmp = (
        '<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="whiff fixture">\n <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
        '  <rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/"\n'
        '    xmlns:crs="http://ns.adobe.com/camera-raw-settings/1.0/" xmp:Rating="4" xmp:CreatorTool="whiff fixture"\n'
        '    crs:Version="16.0" crs:WhiteBalance="Custom" crs:Temperature="5600" crs:Exposure2012="+0.35" crs:Contrast2012="+12">\n'
        '   <dc:title><rdf:Alt><rdf:li xml:lang="x-default">Breakwater at dusk</rdf:li></rdf:Alt></dc:title>\n'
        '   <dc:creator><rdf:Seq><rdf:li>Mira Castell</rdf:li></rdf:Seq></dc:creator>\n'
        '   <dc:subject><rdf:Bag><rdf:li>harbour</rdf:li><rdf:li>dusk</rdf:li></rdf:Bag></dc:subject>\n'
        '  </rdf:Description>\n </rdf:RDF>\n</x:xmpmeta>\n'
    )
    write("xmp/IMG_0042.xmp", xmp.encode())
    write("icc/whiff-test.icc", ci.icc_profile())
    vra = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<vra xmlns="http://www.vraweb.org/vracore4.htm">\n'
        ' <work id="w_1" source="Saltmere Harbour Museum">\n'
        '  <titleSet><display>The Old Breakwater</display><title type="descriptive">The Old Breakwater</title></titleSet>\n'
        '  <agentSet><display>Mira Castell (painter)</display><agent><name type="personal">Mira Castell</name><role>painter</role><dates type="life"><earliestDate>1980</earliestDate></dates></agent></agentSet>\n'
        '  <dateSet><date type="creation"><earliestDate>2024</earliestDate><latestDate>2024</latestDate></date></dateSet>\n'
        '  <subjectSet><subject><term type="descriptiveTopic">harbours</term></subject><subject><term type="geographicPlace">Saltmere</term></subject></subjectSet>\n'
        '  <rightsSet><rights type="publicDomain"><rightsHolder>Saltmere Harbour Museum</rightsHolder><text>CC0 1.0</text></rights></rightsSet>\n'
        '  <descriptionSet><description>Oil sketch of the breakwater at low tide.</description></descriptionSet>\n'
        ' </work>\n <image id="i_1"><titleSet><title>Breakwater, full view</title></titleSet><techniqueSet><technique>digital photography</technique></techniqueSet></image>\n</vra>\n'
    )
    write("vra/breakwater-vra.xml", vra.encode())
    pp3 = (
        "[Version]\nAppVersion=5.10\nVersion=351\n\n[General]\nRank=3\nColorLabel=1\nInTrash=false\n\n"
        "[Exposure]\nAuto=false\nCompensation=0.35\nContrast=12\n\n[White Balance]\nEnabled=true\nSetting=Custom\nTemperature=5600\nGreen=1.02\n\n"
        "[Crop]\nEnabled=true\nX=10\nY=10\nW=600\nH=400\n\n[Sharpening]\nEnabled=true\nAmount=200\n"
    )
    write("pp3/IMG_0042.CR2.pp3", pp3.encode())


def exv_from(jpg):
    """An exiv2 .exv: FF 01 "Exiv2" then the JPEG's APPn / COM segments and EOI."""
    d = jpg.read_bytes()
    out = b"\xff\x01Exiv2"
    at = 2
    while at + 4 <= len(d) and d[at] == 0xFF:
        m = d[at + 1]
        n = struct.unpack(">H", d[at + 2 : at + 4])[0]
        if m == 0xDA:
            break
        if 0xE0 <= m <= 0xEF or m == 0xFE:
            if m != 0xE0:
                out += d[at : at + 2 + n]
        at += 2 + n
    out += b"\xff\xfe" + be("H", 2 + 18) + b"whiff exv fixture\0"
    return out + b"\xff\xd9"


# --------------------------------------------------------------------------
# DjVu, thumbcache, whole-slide images, Unreal texture package


def misc():
    bw = WORK / "check.pbm"
    bw.write_bytes(pbm(128, 96))
    page = WORK / "page.djvu"
    run("cjb2", "-dpi", "300", str(bw), str(page))
    ann = WORK / "meta.dsed"
    ann.write_text('select; set-meta\nTitle\t"Saltmere tide tables"\nAuthor\t"Saltmere Harbour Office"\nKeywords\t"tides, harbour"\n.\n')
    run("djvused", "-s", "-f", str(ann), str(page))
    write("djvu/tide-tables.djvu", page.read_bytes())
    page2 = WORK / "page2.djvu"
    run("cjb2", "-dpi", "150", str(bw), str(page2))
    multi = WORK / "bundle.djvu"
    run("djvm", "-c", str(multi), str(page), str(page2))
    write("djvu/tide-tables-2p.djvu", multi.read_bytes())
    thumbcache()
    slides()
    # Unreal Engine 2 texture package header.
    utx = struct.pack("<IHHI", 0x9E2A83C1, 128, 29, 0x0001) + struct.pack("<6I", 12, 64, 3, 200, 2, 300) + bytes(64)
    write("uasset/harbour-textures.utx", utx)


def thumbcache():
    png = png_bytes(32, 24)
    jpg = WORK / "t.jpg"
    run("magick", "png:-", "-strip", str(jpg), stdin=png)
    def entry(ident, data, w, h):
        idu = ident.encode("utf-16-le")
        head = b"CMMM" + le("I", 0) + le("Q", 0x1122334455667788) + le("III", len(idu), 0, len(data)) + le("II", w, h) + le("I", 0) + le("QQ", 0, 0)
        e = head + idu + data
        return e[:4] + le("I", len(e)) + e[8:]
    entries = entry("9f1e7c2a5d3b4e60", png, 32, 24) + entry("1a2b3c4d5e6f7081", jpg.read_bytes(), 32, 24) + entry("0000000000000000", b"", 0, 0)
    header = b"CMMM" + le("IIIIII", 32, 1, 0, 28, 28 + len(entries), 3)
    write("thumbcache/thumbcache_32.db", header[:28] + entries)
    write("thumbcache/thumbcache_idx.db", b"IMMM" + le("IIIII", 32, 0, 0, 3, 0) + bytes(64))


def slides():
    L, S, A = ci.LONG, ci.SHORT, ci.ASCII
    def page(w, h, desc, tiled=True, extra=None):
        e = {256: (L, [w]), 257: (L, [h]), 258: (S, [8, 8, 8]), 259: (S, [7]), 262: (S, [6]), 270: ci.ascii_(desc), 277: (S, [3])}
        if tiled:
            e.update({322: (L, [256]), 323: (L, [256]), 324: (L, [0]), 325: (L, [0])})
        else:
            e.update({273: (L, [0]), 279: (L, [0])})
        e.update(extra or {})
        return e
    svs_desc = "Aperio Image Library v12.0.15 \r\n46000x32914 [0,100 46000x32914] (256x256) JPEG/RGB Q=70|AppMag = 20|StripeWidth = 2040|ScanScope ID = SS0000|Filename = HARBOUR-1|Date = 05/01/24|Time = 19:42:10|User = 00000000-0000-0000-0000-000000000000|MPP = 0.4990|ImageID = 1001"
    ifds = {
        "p0": (page(46000, 32914, svs_desc, extra={271: ci.ascii_("Aperio")}), "p1"),
        "p1": (page(1024, 732, "Aperio Image Library v12.0.15 \r\n46000x32914 -> 1024x732 - |AppMag = 20", tiled=False), "p2"),
        "p2": (page(11500, 8228, "Aperio Image Library v12.0.15 \r\n46000x32914 -> 11500x8228 |AppMag = 20"), "p3"),
        "p3": (page(400, 300, "Aperio Image Library v12.0.15\nlabel 400x300", tiled=False), "p4"),
        "p4": (page(1200, 400, "Aperio Image Library v12.0.15\nmacro 1200x400", tiled=False), None),
    }
    write("svs/harbour-1.svs", ci.tiff(True, ifds, first="p0"))
    # NDPI: Hamamatsu private tags; 65421 (source lens) is a FLOAT.
    nd = page(20480, 15360, "", extra={271: ci.ascii_("Hamamatsu"), 272: ci.ascii_("C13220"), 65420: (L, [1]), 65421: (L, [struct.unpack("<I", struct.pack("<f", 40.0))[0]]), 65422: (L, [1000]), 65423: (L, [2000]), 65424: (L, [0]), 65442: ci.ascii_("000000")})
    del nd[270]
    t = bytearray(ci.tiff(True, {"p0": (nd, "p1"), "p1": (page(5120, 3840, "", extra={65420: (L, [1])}), None)}, first="p0"))
    # Patch tag 65421's type from LONG (4) to FLOAT (11).
    n = struct.unpack("<H", t[8:10])[0]
    for i in range(n):
        o = 10 + 12 * i
        if struct.unpack("<H", t[o : o + 2])[0] == 65421:
            t[o + 2 : o + 4] = struct.pack("<H", 11)
    write("ndpi/harbour-2.ndpi", bytes(t))
    scn_xml = (
        '<?xml version="1.0" encoding="utf-8"?><scn xmlns="http://www.leica-microsystems.com/scn/2010/10/01">'
        '<collection name="HARBOUR-3" uuid="00000000-0000-0000-0000-000000000003" sizeX="25000000" sizeY="75000000">'
        '<image name="Main" uuid="00000000-0000-0000-0000-000000000004"><creationDate>2024-05-01T19:42:10.00Z</creationDate>'
        '<device model="Leica SCN400" version="1.4.0.0000"/><pixels sizeX="40000" sizeY="30000"/>'
        '<scanSettings><objectiveSettings><objective>20</objective></objectiveSettings><illuminationSettings><numericalAperture>0.4</numericalAperture><illuminationSource>brightfield</illuminationSource></illuminationSettings></scanSettings></image>'
        '<image name="Macro"><pixels sizeX="1600" sizeY="4800"/></image></collection></scn>'
    )
    write("scn/harbour-3.scn", ci.tiff(True, {"p0": (page(40000, 30000, scn_xml), "p1"), "p1": (page(1600, 4800, "", tiled=False), None)}, first="p0"))
    vms = "[Virtual Microscope Specimen]\nNoLayers=1\nNoJpegColumns=4\nNoJpegRows=3\nImageFile=harbour-4.jpg\nImageFile(1,0)=harbour-4_1_0.jpg\nImageFile(2,0)=harbour-4_2_0.jpg\nMapFile=harbour-4_map.jpg\nOptimisationFile=harbour-4.opt\nMacroImage=harbour-4_macro.jpg\nSourceLens=20\nPhysicalWidth=25000000\nPhysicalHeight=18750000\n"
    write("vms/harbour-4.vms", vms.encode())


for step in STEPS:
    globals()[step]()
