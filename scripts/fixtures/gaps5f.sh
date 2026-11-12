#!/usr/bin/env bash
# Regenerate the batch 5f fixtures under tests/fixtures/<format>/:
# fixed-width tables, XDR data and an ONC RPC call, an ETW trace, Minitab
# worksheets and projects, Pro Tools sessions, GarageBand project data
# (and its MetaData.plist, which goes to the shared `bplist` folder), and
# Fusion designs and archives, for the fictitious Saltmere Harbour,
# CC0-1.0. craft_gaps5f.py runs in `whiff-legacy` (see legacy.sh).
#
#     scripts/fixtures/gaps5f.sh
#
# The JMP fixtures are JMPReader.jl's MIT-licensed test tables (see
# tests/fixtures/jmp/SOURCE.md); gaps5f_oracle.py checks the rest.

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/gaps5f-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff whiff-legacy python3 scripts/fixtures/craft_gaps5f.py "$w"
for d in "$work"/*/; do
    id=$(basename "$d")
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
done
echo "fixtures written"
