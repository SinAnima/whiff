#!/usr/bin/env bash
# Regenerate the batch 5e part 4 fixtures under tests/fixtures/<format>/:
# Hermes bytecode, Smalltalk images and change logs, ActionScript bytecode
# (and a SWF carrying it), TPM 2.0 keys and a tpm2-tools context, Hadoop
# SequenceFiles and Hive RCFiles, a Hudi table's properties and commit, a
# Unity package, a partial download and a backup copy, and OCI index /
# ORAS manifest JSON, all for the fictitious Saltmere Harbour, CC0-1.0.
# craft_packages5e.py runs in `whiff-legacy` (see legacy.sh).
#
#     scripts/fixtures/packages5e.sh
#
# The OCI JSON goes to the shared `json` folder and the SWF to `swf`: their
# SOURCE.md rows are kept by hand.

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/packages5e-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff whiff-legacy python3 scripts/fixtures/craft_packages5e.py "$w"
for d in "$work"/*/; do
    id=$(basename "$d")
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
done
echo "fixtures written"
