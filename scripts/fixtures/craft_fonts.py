"""Font fixtures for whiff, written with fontTools, FontForge and ufoLib2.

Run by scripts/fixtures/fonts.sh inside the `whiff-font` container:

    python3 craft_fonts.py OUT_DIR

A fictitious type foundry (Saltmere Harbour Type) and fixed timestamps; every
font is CC0-1.0. Outlines are plain boxes: the fixtures exercise the tables,
not the drawing.
"""

import os
import sys

from fontTools.feaLib.builder import addOpenTypeFeaturesFromString
from fontTools.fontBuilder import FontBuilder
from fontTools.misc.timeTools import timestampFromString
from fontTools.pens.t2CharStringPen import T2CharStringPen
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.ttLib import TTFont
from fontTools.ttLib.tables.TupleVariation import TupleVariation
from fontTools.ttLib.ttCollection import TTCollection

OUT = sys.argv[1]
CREATED = timestampFromString("Mon Sep  1 06:12:00 2025")
MODIFIED = timestampFromString("Wed Oct  1 18:31:00 2025")
GLYPHS = [".notdef", "space", "A", "B", "f", "i", "f_i", "one", "Alpha", "uni0414", "uni05D0"]
CMAP = {0x20: "space", 0x41: "A", 0x42: "B", 0x66: "f", 0x69: "i", 0x31: "one",
        0x391: "Alpha", 0x414: "uni0414", 0x5D0: "uni05D0"}
FEATURES = """
languagesystem DFLT dflt;
languagesystem latn dflt;
languagesystem cyrl dflt;
feature liga { sub f i by f_i; } liga;
feature kern { pos A B -40; } kern;
feature onum { sub one by one; } onum;
"""
LICENCE = "This font is dedicated to the public domain under CC0 1.0 Universal."
LICENCE_URL = "https://creativecommons.org/publicdomain/zero/1.0/"


def names(family, style, version="Version 1.002"):
    ps = f"{family.replace(' ', '')}-{style.replace(' ', '')}"
    return {
        "copyright": "Copyright 2025 Saltmere Harbour Type",
        "familyName": family,
        "styleName": style,
        "uniqueFontIdentifier": f"1.002;SHT;{ps}",
        "fullName": f"{family} {style}",
        "version": version,
        "psName": ps,
        "manufacturer": "Saltmere Harbour Type",
        "designer": "Ada Example",
        "description": "A harbour signage face for tide boards and berth numbers.",
        "vendorURL": "https://example.org/type",
        "designerURL": "https://example.org/type/ada",
        "licenseDescription": LICENCE,
        "licenseInfoURL": LICENCE_URL,
    }


def box(pen, x0, y0, x1, y1):
    pen.moveTo((x0, y0))
    pen.lineTo((x0, y1))
    pen.lineTo((x1, y1))
    pen.lineTo((x1, y0))
    pen.closePath()


def tt_glyphs(extra=()):
    out = {}
    for i, g in enumerate(list(GLYPHS) + list(extra)):
        pen = TTGlyphPen(None)
        if g != "space":
            box(pen, 50 + i, 0, 450 + i, 700)
        out[g] = pen.glyph()
    return out


def common(fb, family, style, fs_type, weight=400, glyphs=GLYPHS):
    fb.font.recalcTimestamp = False
    fb.setupGlyphOrder(list(glyphs))
    fb.setupCharacterMap(CMAP)
    fb.setupHorizontalMetrics({g: (500, 50) for g in glyphs})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupNameTable(names(family, style))
    fb.setupOS2(achVendID="SHTY", fsType=fs_type, usWeightClass=weight, sTypoAscender=800,
                sTypoDescender=-200, usWinAscent=800, usWinDescent=200,
                ulUnicodeRange1=(1 << 0) | (1 << 7) | (1 << 9), ulUnicodeRange2=0)
    fb.setupPost()
    fb.setupHead(unitsPerEm=1000, created=CREATED, modified=MODIFIED, fontRevision=1.002)


def save(font, path):
    font.recalcTimestamp = False
    font.save(os.path.join(OUT, path))


def sans():
    fb = FontBuilder(1000, isTTF=True)
    common(fb, "Saltmere Sans", "Regular", fs_type=0)
    fb.setupGlyf(tt_glyphs())
    fb.setupMaxp()
    addOpenTypeFeaturesFromString(fb.font, FEATURES)
    fb.setupDummyDSIG()
    return fb.font


def bold():
    fb = FontBuilder(1000, isTTF=True)
    common(fb, "Saltmere Sans", "Bold", fs_type=4, weight=700)
    fb.setupGlyf(tt_glyphs())
    fb.setupMaxp()
    addOpenTypeFeaturesFromString(fb.font, FEATURES)
    return fb.font


def variable():
    fb = FontBuilder(1000, isTTF=True)
    common(fb, "Saltmere Flex", "Regular", fs_type=0)
    fb.setupGlyf(tt_glyphs())
    fb.setupMaxp()
    axes = [("wght", 100, 400, 900, "Weight"), ("wdth", 75, 100, 125, "Width")]
    instances = [
        dict(location=dict(wght=100, wdth=100), stylename="Thin"),
        dict(location=dict(wght=400, wdth=100), stylename="Regular"),
        dict(location=dict(wght=900, wdth=100), stylename="Black"),
        dict(location=dict(wght=400, wdth=75), stylename="Condensed"),
    ]
    fb.setupFvar(axes, instances)
    var = TupleVariation({"wght": (0, 1, 1)}, [(40, 0), (40, 0), (-40, 0), (-40, 0), (0, 0), (0, 0), (0, 0), (0, 0)])
    fb.setupGvar({"A": [var]})
    fb.setupStat([
        dict(tag="wght", name="Weight", values=[dict(value=100, name="Thin"), dict(value=400, name="Regular", flags=2),
                                                dict(value=900, name="Black")]),
        dict(tag="wdth", name="Width", values=[dict(value=75, name="Condensed"), dict(value=100, name="Normal", flags=2)]),
    ])
    return fb.font


def colour():
    layers = ["A.layer0", "A.layer1"]
    glyphs = GLYPHS + layers
    fb = FontBuilder(1000, isTTF=True)
    common(fb, "Saltmere Flags", "Regular", fs_type=2, glyphs=glyphs)
    fb.setupGlyf(tt_glyphs(layers))
    fb.setupMaxp()
    fb.setupCPAL([[(0.8, 0.1, 0.1, 1.0), (0.1, 0.2, 0.7, 1.0)]])
    fb.setupCOLR({"A": [("A.layer0", 0), ("A.layer1", 1)]})
    return fb.font


def serif():
    fb = FontBuilder(1000, isTTF=False)
    common(fb, "Saltmere Serif", "Italic", fs_type=8)
    strings = {}
    for i, g in enumerate(GLYPHS):
        pen = T2CharStringPen(500, None)
        if g != "space":
            box(pen, 50 + i, 0, 450 + i, 700)
        strings[g] = pen.getCharString()
    fb.setupCFF("SaltmereSerif-Italic", {"FullName": "Saltmere Serif Italic", "Notice": "Saltmere Harbour Type"},
                strings, {})
    fb.setupMaxp()
    addOpenTypeFeaturesFromString(fb.font, FEATURES)
    fb.font["OS/2"].fsSelection = 0x01
    fb.font["head"].macStyle = 0x02
    fb.font["post"].italicAngle = -12
    return fb.font


def main():
    os.makedirs(OUT, exist_ok=True)
    save(sans(), "saltmere-sans.ttf")
    save(variable(), "saltmere-flex-variable.ttf")
    save(colour(), "saltmere-flags-colr.ttf")
    save(serif(), "saltmere-serif-italic.otf")
    for flavor in ("woff", "woff2"):
        f = TTFont(os.path.join(OUT, "saltmere-sans.ttf"))
        f.flavor = flavor
        save(f, f"saltmere-sans.{flavor}")
    f = TTFont(os.path.join(OUT, "saltmere-flex-variable.ttf"))
    f.flavor = "woff2"
    save(f, "saltmere-flex-variable.woff2")
    tc = TTCollection()
    tc.fonts = [sans(), bold()]
    for f in tc.fonts:
        f.recalcTimestamp = False
    tc.save(os.path.join(OUT, "saltmere-sans.ttc"), shareTables=True)
    ufo()


def ufo():
    import glyphsLib
    import ufoLib2

    u = ufoLib2.Font()
    i = u.info
    i.familyName, i.styleName = "Saltmere Sans", "Regular"
    i.versionMajor, i.versionMinor = 1, 2
    i.copyright = "Copyright 2025 Saltmere Harbour Type"
    i.openTypeNameDesigner = "Ada Example"
    i.openTypeNameManufacturer = "Saltmere Harbour Type"
    i.openTypeNameLicense = LICENCE
    i.openTypeNameLicenseURL = LICENCE_URL
    i.openTypeOS2VendorID = "SHTY"
    i.openTypeOS2Type = []
    i.unitsPerEm, i.ascender, i.descender, i.capHeight, i.xHeight = 1000, 800, -200, 700, 500
    i.openTypeHeadCreated = "2025/09/01 06:12:00"
    for g, u_ in [("A", 0x41), ("B", 0x42), ("space", 0x20)]:
        glyph = u.newGlyph(g)
        glyph.unicodes = [u_]
        glyph.width = 500
        if g != "space":
            box(glyph.getPen(), 50, 0, 450, 700)
    u.features.text = "feature kern { pos A B -40; } kern;\n"
    path = os.path.join(OUT, "SaltmereSans-Regular.ufo")
    u.save(path, overwrite=True)
    gs = glyphsLib.to_glyphs([u])
    gs.save(os.path.join(OUT, "SaltmereSans.glyphs"))


if __name__ == "__main__":
    main()
