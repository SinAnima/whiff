#!/usr/bin/env bash
# Regenerate the stage 8 code fixtures under tests/fixtures/<format>/:
# source files in ~90 more languages, SPIR-V modules and package manifests.
#
# Written in a container run with podman, for the fictitious Saltmere
# Harbour, CC0-1.0: craft_code.py in `whiff-code` (the Containerfile below)
# drives glslang 15 (SPIR-V); the sources (craft_code_src.py) and the
# manifests are written by hand from each format's documentation.
#
#     scripts/fixtures/code.sh [STEP ...]      (sources spirv manifests)
#
# Containerfile (`podman build -t whiff-code`):
#
#     FROM docker.io/library/python:3.12-slim-trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#           glslang-tools spirv-tools rpm dpkg-dev file ruby-bundler erlang-base
#     RUN pip install --no-cache-dir pygments python-debian pyyaml json5 spdx-tools cyclonedx-python-lib cffconvert python-hcl2
#
# (spirv-dis, rpmspec, dpkg-parsechangelog, Bundler, Erlang, Pygments,
# python-debian, spdx-tools, cyclonedx-python-lib, cffconvert and
# python-hcl2 are for code_oracle.py.)

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/code-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff whiff-code python3 scripts/fixtures/craft_code.py "$w" "$@"

for d in "$work"/*/; do
    id=$(basename "$d")
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
done

source_md() {
    local id=$1 name=$2 origin=$3
    {
        echo "# Fixtures for \`$id\` ($name)"
        echo
        echo "Files made for whiff's tests, CC0-1.0, for the fictitious Saltmere Harbour. Regenerate with \`scripts/fixtures/code.sh\`."
        echo
        echo "| File | Origin | Licence |"
        echo "|---|---|---|"
        for f in "$fx/$id"/*; do
            [ "$(basename "$f")" = SOURCE.md ] && continue
            echo "| \`$(basename "$f")\` | $origin | CC0-1.0 |"
        done
    } >"$fx/$id/SOURCE.md"
}
# Every format folder written by craft_code.py; `groovy` keeps its own
# SOURCE.md (its new script is added there by hand).
cargo run -q --manifest-path "$root/Cargo.toml" --bin whiff -- formats --json >"$work/formats.json"
python3 - "$root" "$work/formats.json" <<'PY' | while IFS='|' read -r id name origin; do [ -d "$fx/$id" ] && source_md "$id" "$name" "$origin"; done
import json, sys
sys.path.insert(0, sys.argv[1] + "/scripts/fixtures")
from craft_code import MANIFESTS
from craft_code_src import SOURCES
names = {f["id"]: f["name"] for f in json.load(open(sys.argv[2]))}
for fid in SOURCES:
    if fid != "groovy":
        print(f"{fid}|{names[fid]}|written by hand")
for fid in MANIFESTS:
    print(f"{fid}|{names[fid]}|written by hand from the format's documentation")
print(f"spirv|{names['spirv']}|glslang 15 from the `glsl` fixtures (`tide.comp.be.spv`: the same module with its words byte-swapped)")
PY
echo "fixtures written; scratch files in $work"
