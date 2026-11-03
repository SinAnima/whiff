#!/usr/bin/env bash
# Regenerate the font fixtures under tests/fixtures/<format>/.
#
# Written in a Debian container run with podman (image `whiff-font`, built
# from the Containerfile below) for a fictitious type foundry (Saltmere
# Harbour Type) with fixed timestamps; every font is CC0-1.0:
# fontTools FontBuilder (TrueType, CFF, variable, COLR, collection, WOFF,
# WOFF2) and ufoLib2 / glyphsLib (UFO, Glyphs) in craft_fonts.py; FontForge
# (Type 1 PFB / PFA / AFM / PFM, dfont, SFD, Windows FNT / FON from a BDF
# written by craft_fonts_ff.py); bdftopcf (PCF); bdf2psf (PSF 2); mkeot
# (EOT). The Metafont source is written by hand.
#
#     scripts/fixtures/fonts.sh
#
# Containerfile (`podman build -t whiff-font`):
#
#     FROM docker.io/library/debian:trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#         python3 python3-pip python3-fontforge fontforge xfonts-utils eot-utils console-setup-linux bdf2psf \
#         t1utils ca-certificates
#     RUN pip install --break-system-packages fonttools[woff,ufo]==4.60.1 glyphsLib==6.12.3 ufoLib2==0.18.1

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/font-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff -e SOURCE_DATE_EPOCH=1759343460 -e USER=saltmere -e LOGNAME=saltmere whiff-font sh -euc "
python3 scripts/fixtures/craft_fonts.py $w
python3 scripts/fixtures/craft_fonts_ff.py $w 2>/dev/null
bdftopcf -o $w/saltmere-fixed.pcf $w/saltmere-fixed.bdf
bdf2psf --fb $w/saltmere-fixed.bdf /usr/share/bdf2psf/standard.equivalents /usr/share/bdf2psf/ascii.set 256 $w/saltmere-fixed.psf
mkeot $w/saltmere-sans.ttf https://example.org/ https://type.example.org/ >$w/saltmere-sans.eot
"

cat >"$work/saltmere.mf" <<'EOF'
% Saltmere tide figures, a Metafont sketch (CC0-1.0).
% Copyright 2025 Saltmere Harbour Type
mode_setup;
font_identifier:="SALTMERE";
font_coding_scheme:="ASCII digits";
designsize:=10pt#;
input saltmere-base;
beginchar("0",5pt#,7pt#,0); pickup pencircle scaled .4pt; draw (0,0)--(w,h); endchar;
beginchar("1",5pt#,7pt#,0); pickup pencircle scaled .4pt; draw (w/2,0)--(w/2,h); endchar;
% beginchar in a comment is not counted
end
EOF

put() { mkdir -p "$fx/$1"; cp "$work/$2" "$fx/$1/${3:-$2}"; }
put ttf saltmere-sans.ttf
put ttf saltmere-flex-variable.ttf
put ttf saltmere-flags-colr.ttf
put otf saltmere-serif-italic.otf
put ttc saltmere-sans.ttc
put woff saltmere-sans.woff
put woff2 saltmere-sans.woff2
put woff2 saltmere-flex-variable.woff2
put eot saltmere-sans.eot
put dfont saltmere-sans.dfont
put pfb saltmere-serif-italic.pfb
put pfa saltmere-serif-italic.pfa
put afm saltmere-serif-italic.afm
put pfm saltmere-serif-italic.pfm
put bdf saltmere-fixed.bdf
put pcf saltmere-fixed.pcf
put fnt saltmere-fixed-10.fnt saltmere-fixed.fnt
put fon saltmere-fixed.fon
put psf saltmere-fixed.psf
put sfd saltmere-serif-italic.sfd
put glyphs SaltmereSans.glyphs
put ufo_fontinfo SaltmereSans-Regular.ufo/fontinfo.plist fontinfo.plist
put metafont saltmere.mf

source_md() {
    local id=$1 name=$2 origin=$3
    {
        echo "# Fixtures for \`$id\` ($name)"
        echo
        echo "Fonts made for whiff's tests, CC0-1.0, for a fictitious type foundry (Saltmere Harbour Type) with fixed timestamps; outlines are plain boxes. Regenerate with \`scripts/fixtures/fonts.sh\`."
        echo
        echo "| File | Origin | Licence |"
        echo "|---|---|---|"
        for f in "$fx/$id"/*; do
            [ "$(basename "$f")" = SOURCE.md ] && continue
            echo "| \`$(basename "$f")\` | $origin | CC0-1.0 |"
        done
    } >"$fx/$id/SOURCE.md"
}
source_md ttf "TrueType font" "fontTools 4.60.1 FontBuilder (static, variable with fvar / gvar / STAT, COLRv0 / CPAL)"
source_md otf "OpenType font" "fontTools 4.60.1 FontBuilder (CFF outlines)"
source_md ttc "TrueType / OpenType collection" "fontTools 4.60.1 TTCollection, shared tables"
source_md woff "WOFF web font" "fontTools 4.60.1 (flavor woff)"
source_md woff2 "WOFF2 web font" "fontTools 4.60.1 (flavor woff2, transformed glyf / loca)"
source_md eot "EOT embedded OpenType" "mkeot (eot-utils 1.1) with two root URLs"
source_md dfont "Apple dfont / suitcase" "FontForge 20230101 (Mac dfont)"
source_md pfb "PostScript Type 1 font (binary)" "FontForge 20230101 from the CFF fixture"
source_md pfa "PostScript Type 1 font (ASCII)" "FontForge 20230101 from the CFF fixture"
source_md afm "Adobe font metrics" "FontForge 20230101 from the CFF fixture"
source_md pfm "Printer font metrics" "FontForge 20230101 from the CFF fixture"
source_md bdf "BDF bitmap font" "craft_fonts_ff.py (printable ASCII, 6x10)"
source_md pcf "PCF bitmap font" "bdftopcf (xfonts-utils) from the BDF fixture"
source_md fnt "Windows bitmap font" "FontForge 20230101 from the BDF fixture"
source_md fon "Windows font library" "FontForge 20230101 from the BDF fixture"
source_md psf "PC Screen Font" "bdf2psf (console-setup) from the BDF fixture, with a Unicode table"
source_md sfd "FontForge source" "FontForge 20230101 (saved from the CFF fixture)"
source_md glyphs "Glyphs source" "glyphsLib 6.12.3 from a ufoLib2 font"
source_md ufo_fontinfo "UFO font info" "ufoLib2 0.18.1 (fontinfo.plist of a UFO 3)"
source_md metafont "Metafont source" "written by hand"
echo "fixtures written; scratch files in $work"
