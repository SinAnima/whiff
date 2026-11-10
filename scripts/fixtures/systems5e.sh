#!/usr/bin/env bash
# Regenerate the batch 5e part 3 fixtures under tests/fixtures/<format>/:
# Realm, Firebird, SQL Server (MTF) backups, Kafka segments and indexes,
# Prometheus TSDB files, an Anki deck, a macOS unified log and ASL file,
# nfdump and IPFIX captures, Firefox and Chrome cache files, all for the
# fictitious Saltmere Harbour, CC0-1.0. craft_systems5e.py runs in
# `whiff-legacy` (see legacy.sh; kafka-python is in that image).
#
#     scripts/fixtures/systems5e.sh
#
# The TSDB block's meta.json goes to the shared `json` folder: its
# SOURCE.md row is kept by hand.

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/systems5e-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff whiff-legacy python3 scripts/fixtures/craft_systems5e.py "$w"
for d in "$work"/*/; do
    id=$(basename "$d")
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
done
echo "fixtures written"
