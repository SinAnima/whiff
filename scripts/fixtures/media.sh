#!/usr/bin/env bash
# Regenerate the stage 8 image long-tail fixtures (batch 3) under
# tests/fixtures/<format>/: legacy rasters, film scans / LUTs / XISF,
# Photoshop assets, FLIF / BPG / JPEG XR / JPEG-LS / Photo CD / FlashPix,
# HEIF variants, GPU textures, camera raws, diagrams, layered documents,
# metadata sidecars, DjVu, thumbcache, whole-slide images.
#
# Written in a container run with podman, for the fictitious Saltmere
# Harbour, CC0-1.0: craft_media.py in `whiff-media` (the Containerfile
# below) drives netpbm, ImageMagick, ffmpeg, exiftool, JxrEncApp, djvulibre
# and Pillow, and builds the rest from each format's specification.
#
#     scripts/fixtures/media.sh [STEP ...]
#     (raster film assets codecs textures raw diagram layered sidecar misc)
#
# Containerfile (`podman build -t whiff-media`):
#
#     FROM docker.io/library/python:3.12-slim-trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#           netpbm imagemagick ffmpeg libimage-exiftool-perl graphviz fig2dev icnsutils libjxr-tools file djvulibre-bin
#     RUN pip install --no-cache-dir pillow psd-tools olefile
#
# (graphviz, fig2dev, icnsutils, file, psd-tools and olefile are for
# media_oracle.py.) The `uasset` and `vra` folders keep their own
# SOURCE.md (the `.utx` and `artwork.vra.xml` rows are kept by hand).

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/media-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff whiff-media python3 scripts/fixtures/craft_media.py "$w" "$@"

for d in "$work"/*/; do
    id=$(basename "$d")
    [ "$id" = _work ] && continue
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
done

source_md() {
    local id=$1 name=$2
    {
        echo "# Fixtures for \`$id\` ($name)"
        echo
        echo "Files made for whiff's tests, CC0-1.0, for the fictitious Saltmere Harbour. Regenerate with \`scripts/fixtures/media.sh\`."
        echo
        echo "| File | Origin | Licence |"
        echo "|---|---|---|"
        for f in "$fx/$id"/*; do
            [ "$(basename "$f")" = SOURCE.md ] && continue
            echo "| \`$(basename "$f")\` | $(origin "$id" "$(basename "$f")") | CC0-1.0 |"
        done
    } >"$fx/$id/SOURCE.md"
}

# How each file was made (the tool, or "written by hand from the specification").
origin() {
    case "$1/$2" in
        ilbm/harbour-netpbm.iff) echo "netpbm \`ppmtoilbm\`" ;;
        macpaint/*) echo "netpbm \`pbmtomacp\`" ;;
        sun_raster/*) echo "netpbm \`pnmtorast\`" ;;
        sgi/*) echo "netpbm \`pnmtosgi\`" ;;
        xbm/*) echo "netpbm \`pbmtoxbm\`" ;;
        xpm/*) echo "netpbm \`ppmtoxpm\`" ;;
        wbmp/*) echo "netpbm \`pbmtowbmp\`" ;;
        pict/*) echo "netpbm \`ppmtopict\`" ;;
        utah_rle/*) echo "netpbm \`pnmtorle\`" ;;
        farbfeld/* | dcx/* | dpx/* | cineon/reel1_000100.cin) echo "ImageMagick 7" ;;
        icns/*) echo "Pillow" ;;
        jls/*) echo "ffmpeg (\`jpegls\` encoder)" ;;
        jxr/*) echo "jxrlib \`JxrEncApp\`" ;;
        djvu/*) echo "djvulibre \`cjb2\`, \`djvused\`, \`djvm\`" ;;
        exv/* | exif/*) echo "ImageMagick + exiftool (tags), segments copied by craft_media.py" ;;
        icc/*) echo "craft_images.py (whiff's own test profile)" ;;
        *) echo "written by hand from the format's specification (craft_media.py)" ;;
    esac
}

cargo run -q --manifest-path "$root/Cargo.toml" --features full --bin whiff -- formats --json >"$work/formats.json"
for d in "$work"/*/; do
    id=$(basename "$d")
    case "$id" in _work | uasset | vra) continue ;; esac
    name=$(python3 -c 'import json,sys; print({f["id"]: f["name"] for f in json.load(open(sys.argv[1]))}[sys.argv[2]])' "$work/formats.json" "$id")
    source_md "$id" "$name"
done
echo "fixtures written; scratch files in $work"
