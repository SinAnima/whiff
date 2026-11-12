#!/usr/bin/env bash
# Regenerate the batch 5e part 2 science fixtures under tests/fixtures/<format>/:
# HDF4 from GDAL's HDF4Image driver in `whiff-geo` (see geo.sh), the rest
# (SCP-ECG, HL7 aECG, Maple, Mathcad, a MrSID signature) written by
# craft_science5e.py in `whiff-legacy` (see legacy.sh). Fictitious
# Saltmere Harbour data, CC0-1.0.
#
#     scripts/fixtures/science5e.sh

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/science5e-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff whiff-legacy python3 scripts/fixtures/craft_science5e.py "$w"
mkdir -p "$work/hdf4"
podman run --rm -e GDAL_PAM_ENABLED=NO -v "$root:/whiff" -w /whiff whiff-geo sh -c "
  gdal_create -of GTiff -outsize 24 16 -bands 1 -ot Int16 -burn 42 -a_srs EPSG:4326 -a_ullr -5.1 50.1 -4.9 49.9 /tmp/depth.tif &&
  gdal_translate -q -of HDF4Image -mo TITLE='Saltmere harbour depths' -mo INSTITUTION='Saltmere Harbour' /tmp/depth.tif $w/hdf4/saltmere-depths.hdf"
for d in "$work"/*/; do
    id=$(basename "$d")
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
done
echo "science fixtures written"
