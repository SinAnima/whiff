"""The FontForge half of the font fixtures (run after craft_fonts.py).

    python3 craft_fonts_ff.py OUT_DIR

Type 1 (PFB, PFA, AFM, PFM) from the OpenType serif, a Mac dfont from the
sans, the FontForge source (SFD), and a bitmap face: a BDF written here
(every printable ASCII character, a simple pattern) that FontForge turns
into a Windows FNT / FON.
"""

import os
import sys

import fontforge

OUT = sys.argv[1]


def bdf(path):
    """A 6x10 bitmap face covering printable ASCII."""
    chars = []
    for c in range(0x20, 0x7F):
        rows = ["00"] * 10 if c == 0x20 else [format((0x78 >> (r % 3)) & 0xFC, "02X") for r in range(10)]
        chars.append(
            f"STARTCHAR U+{c:04X}\nENCODING {c}\nSWIDTH 600 0\nDWIDTH 6 0\nBBX 6 10 0 -2\nBITMAP\n"
            + "\n".join(rows) + "\nENDCHAR\n"
        )
    head = f"""STARTFONT 2.1
COMMENT Saltmere Fixed, a tide-board bitmap face (CC0-1.0)
FONT -SHTY-Saltmere Fixed-Medium-R-Normal--10-100-75-75-C-60-ISO10646-1
SIZE 10 75 75
FONTBOUNDINGBOX 6 10 0 -2
STARTPROPERTIES 16
FOUNDRY "SHTY"
FAMILY_NAME "Saltmere Fixed"
WEIGHT_NAME "Medium"
SLANT "R"
SETWIDTH_NAME "Normal"
PIXEL_SIZE 10
POINT_SIZE 100
RESOLUTION_X 75
RESOLUTION_Y 75
SPACING "C"
AVERAGE_WIDTH 60
CHARSET_REGISTRY "ISO10646"
CHARSET_ENCODING "1"
FONT_ASCENT 8
FONT_DESCENT 2
COPYRIGHT "Copyright 2025 Saltmere Harbour Type, CC0-1.0"
ENDPROPERTIES
CHARS {len(chars)}
"""
    with open(path, "w") as f:
        f.write(head + "".join(chars) + "ENDFONT\n")


def main():
    serif = fontforge.open(os.path.join(OUT, "saltmere-serif-italic.otf"))
    serif.generate(os.path.join(OUT, "saltmere-serif-italic.pfb"), flags=("afm", "pfm"))
    serif.generate(os.path.join(OUT, "saltmere-serif-italic.pfa"))
    serif.save(os.path.join(OUT, "saltmere-serif-italic.sfd"))
    sans = fontforge.open(os.path.join(OUT, "saltmere-sans.ttf"))
    sans.generate(os.path.join(OUT, "saltmere-sans.dfont"))
    path = os.path.join(OUT, "saltmere-fixed.bdf")
    bdf(path)
    fixed = fontforge.open(path)
    fixed.generate(os.path.join(OUT, "saltmere-fixed.fnt"), bitmap_type="fnt")
    fixed.generate(os.path.join(OUT, "saltmere-fixed.fon"), bitmap_type="fon")


if __name__ == "__main__":
    main()
