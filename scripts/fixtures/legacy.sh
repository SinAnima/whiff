#!/usr/bin/env bash
# Regenerate the stage 8 long-tail fixtures (batch 4) under
# tests/fixtures/<format>/: older archivers (ARC, Zoo, ACE, ZPAQ, KGB), Mac
# wrappers (StuffIt, BinHex, MacBinary), encoded files and shell archives
# (uuencode, yEnc, base64, shar, Makeself), WIM, ZIP-based bundles (zipapp,
# PEX, JMOD, OBB), backups (Android, dump, Borg, Apple Archive), debug files
# (PDB, split DWARF), kernel images, Android runtime files, XCOFF, device
# trees, Xilinx bitstreams, script hosts, compiled AppleScript and Rust
# libraries.
#
# Written in a container run with podman, for the fictitious Saltmere
# Harbour, CC0-1.0: craft_legacy.py in `whiff-legacy` (the Containerfile
# below) drives arc, kgb, zpaq, macutils, sharutils, makeself, wimlib,
# zipapp, pex, the JDK, dump and borg (under faketime where they record the
# time) and builds the rest from each format's specification. On macOS the
# Apple Archive fixtures come from `aa`.
# legacy_oracle.py then reads every fixture with an independent tool:
#
#     scripts/fixtures/legacy.sh [STEP ...]
#         (dos mac encoded wim bundles backups debug exec scripts writing books
#          packages legacy_docs configs languages records)
#     podman run --rm -v "$PWD:/whiff" -w /whiff whiff-legacy \
#         python3 scripts/fixtures/legacy_oracle.py expect tests/fixtures > target/legacy-expect.json
#     python3 scripts/fixtures/legacy_oracle.py check target/legacy-expect.json
#
# Containerfile (`podman build -t whiff-legacy`):
#
#     FROM docker.io/library/python:3.12-slim-trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#           arc nomarch kgb zpaq unar 7zip wimtools sharutils makeself binutils file cpio e2fsprogs dump \
#           openjdk-21-jdk-headless restic borgbackup macutils xxd
#     RUN apt-get install -y --no-install-recommends gcc libc6-dev && pip install --no-cache-dir acefile
#     RUN apt-get install -y --no-install-recommends faketime
#     RUN apt-get install -y --no-install-recommends clang lld llvm device-tree-compiler
#     RUN apt-get install -y --no-install-recommends bibutils abiword gnumeric lyx pandoc libchm-bin libwpd-tools libwps-tools
#     RUN apt-get install -y --no-install-recommends fp-utils ghostscript
#     RUN pip install --no-cache-dir ofxparse mt-940 python-gedcom tap.py prometheus_client beancount
#
# (nomarch, unar, file and acefile are for legacy_oracle.py; gcc builds
# acefile's optional C module.)

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
mkdir -p "$root/target"
work=$(mktemp -d "$root/target/legacy-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

# The host name ends up in dump headers.
podman run --rm --hostname saltmere-harbour -v "$root:/whiff" -w /whiff whiff-legacy \
    python3 scripts/fixtures/craft_legacy.py "$w" "$@"

# Apple Archive: macOS's `aa`, without the owner, extended attributes
# (com.apple.provenance names this Mac's apps), flags and creation times.
if [ "$(uname)" = Darwin ] && { [ $# -eq 0 ] || [[ " $* " == *" backups "* ]]; }; then
    aar="$work/aar"
    mkdir -p "$aar/harbour/charts" "$work/apple_archive"
    printf 'Saltmere harbour notes\n' >"$aar/harbour/notes.txt"
    printf 'chart\n' >"$aar/harbour/charts/bay.txt"
    for f in "$aar/harbour" "$aar/harbour/notes.txt" "$aar/harbour/charts" "$aar/harbour/charts/bay.txt"; do
        TZ=UTC touch -t 202509011200 "$f"
    done
    aa archive -d "$aar/harbour" -o "$work/apple_archive/saltmere-macos-raw.aar" -a raw -exclude-field uid,gid,xat,ctm,flg,btm
    aa archive -d "$aar/harbour" -o "$work/apple_archive/saltmere-macos-lzfse.aar" -exclude-field uid,gid,xat,ctm,flg,btm
    aa list -i "$work/apple_archive/saltmere-macos-raw.aar" -v
fi

# Compiled AppleScript (macOS) and a Rust rlib / rmeta (any host with
# rustc), built with the paths remapped so no home folder is recorded.
if [ $# -eq 0 ] || [[ " $* " == *" scripts "* ]]; then
    host="$work/host"
    mkdir -p "$host" "$work/applescript_compiled" "$work/rust_rlib" "$work/rust_rmeta"
    if command -v osacompile >/dev/null; then
        printf 'return "The Saltmere harbour bell rings at high tide."\n' >"$host/bell.applescript"
        osacompile -o "$work/applescript_compiled/harbour-bell.scpt" "$host/bell.applescript"
    fi
    if command -v rustc >/dev/null; then
        printf '//! Saltmere harbour tides.\n\n/// Hours from low to high water.\npub fn rise(low: u32, high: u32) -> u32 {\n    high - low\n}\n' >"$host/lib.rs"
        (cd "$host" && rustc --crate-type=rlib --crate-name harbour --edition 2021 -C metadata=saltmere \
            -C codegen-units=1 --remap-path-prefix="$host=/src/harbour" --emit=link,metadata lib.rs)
        cp "$host/libharbour.rlib" "$work/rust_rlib/"
        cp "$host/libharbour.rmeta" "$work/rust_rmeta/"
    fi
fi

for d in "$work"/*/; do
    id=$(basename "$d")
    [ "$id" = _work ] || [ "$id" = host ] || [ "$id" = aar ] || [ -z "$(ls -A "$d")" ] && continue
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
done

# How each file was made (the tool, or "written by hand from the specification").
origin() {
    case "$1/$2" in
        arc/*) echo "ARC 5.21 (\`arc a\`; the uninitialised bytes after each name zeroed)" ;;
        split_volume/*) echo "7-Zip 25.01 (\`7z a -v1k\`), the second volume" ;;
        kgb/*) echo "KGB Archiver 1.0b4 (\`kgb -3\`)" ;;
        zpaq/*) echo "zpaq 7.15 (\`zpaq a\`, two transactions, under faketime)" ;;
        binhex/*macutils*) echo "macutils 2.0b3 \`binhex\`, from the MacBinary fixture" ;;
        binhex/*binhex40*) echo "macutils 2.0b3 \`binhex\`, with BinHex 4.0's own comment line" ;;
        uuencode/*) echo "GNU sharutils 4.15 \`uuencode\`" ;;
        base64/*) echo "GNU coreutils \`base64\`" ;;
        shar/*) echo "GNU sharutils 4.15 \`shar\` (the user, host and folder in its header replaced)" ;;
        makeself/*) echo "Makeself 2.5.0" ;;
        wim/*) echo "wimlib-imagex 1.14 (capture, append, image properties; \`export --solid\` for the ESD)" ;;
        zipapp/*) echo "Python 3.12 \`zipapp\`" ;;
        pex/*) echo "pex 2.107.1, its \`.bootstrap/\` runtime left out" ;;
        jmod/*) echo "JDK 21 \`javac\` and \`jmod create\`" ;;
        unix_dump/*) echo "dump 0.4b49 (\`dump -0\` of an ext2 image)" ;;
        borg_repository/*) echo "Borg 1.4 (\`borg init --encryption=none\`)" ;;
        apple_archive/*) echo "macOS \`aa archive\`" ;;
        ms_pdb/*) echo "clang 19 and lld-link (\`/debug\`)" ;;
        split_dwarf/*.dwo) echo "GCC 14 (\`-gsplit-dwarf\`)" ;;
        split_dwarf/*.dwp) echo "llvm-dwp 19, from two GCC 14 units" ;;
        xcoff/*) echo "clang 19 (\`--target=powerpc*-ibm-aix\`)" ;;
        fdt/*) echo "dtc 1.7 (from saltmere-bell.dts and an overlay)" ;;
        dts/*) echo "written by hand" ;;
        hta/* | wsf/* | scriptlet/*) echo "written by hand (shows text only)" ;;
        applescript_compiled/*) echo "macOS \`osacompile\`" ;;
        rust_rlib/* | rust_rmeta/*) echo "rustc 1.97 (\`--emit=link,metadata\`, paths remapped)" ;;
        ris/*) echo "bibutils 7.2 (\`bib2xml\`, \`xml2ris\`)" ;;
        endnote/*) echo "bibutils 7.2 (\`bib2xml\`, \`xml2end\`)" ;;
        abiword/*) echo "AbiWord 3.0 (\`abiword --to=abw\`)" ;;
        gnumeric/*) echo "Gnumeric 1.12 (\`ssconvert\`)" ;;
        flat_opc/*) echo "pandoc 3.1 \`.docx\`, its parts folded into one Flat OPC file (the theme part left out)" ;;
        chm/*) echo "Free Pascal \`chmcmd\` 3.2.2" ;;
        pcl/*) echo "Ghostscript 10.05 (\`-sDEVICE=ljet4\`) in a hand-written PJL job" ;;
        *) echo "written by hand from the format's specification (craft_legacy.py)" ;;
    esac
}

source_md() {
    local id=$1 name=$2
    {
        echo "# Fixtures for \`$id\` ($name)"
        echo
        echo "Files made for whiff's tests, CC0-1.0, for the fictitious Saltmere Harbour. Regenerate with \`scripts/fixtures/legacy.sh\`."
        echo
        echo "| File | Origin | Licence |"
        echo "|---|---|---|"
        for f in "$fx/$id"/*; do
            [ "$(basename "$f")" = SOURCE.md ] && continue
            echo "| \`$(basename "$f")\` | $(origin "$id" "$(basename "$f")") | CC0-1.0 |"
        done
    } >"$fx/$id/SOURCE.md"
}

cargo run -q --manifest-path "$root/Cargo.toml" --features full --bin whiff -- formats --json >"$work/formats.json"
for d in "$work"/*/; do
    id=$(basename "$d")
    [ "$id" = _work ] || [ "$id" = host ] || [ "$id" = aar ] || [ -z "$(ls -A "$d")" ] && continue
    # Shared with other fixture scripts: its SOURCE.md is kept by hand.
    [ "$id" = pdf ] || [ "$id" = json ] || [ "$id" = yaml ] && continue
    name=$(python3 -c 'import json,sys; print({f["id"]: f["name"] for f in json.load(open(sys.argv[1]))}[sys.argv[2]])' "$work/formats.json" "$id")
    source_md "$id" "$name"
done
echo "fixtures written; scratch files in $work"
