#!/usr/bin/env bash
# Regenerate the stage 8 long-tail audio and video fixtures (batch 5d)
# under tests/fixtures/<format>/: raw AC-3 / E-AC-3 / DTS / TrueHD / MLP /
# GSM / VOX streams, Shorten, QCP, OpenMG, TwinVQ and RealAudio files,
# SoundFont / DLS / SFZ / EXS instruments, Audacity / Ableton / FL Studio /
# REAPER projects, DV, MXF, AMV, FLIC, Bink, Smacker, NSV, R3D and
# ARRIRAW headers, EDL / OTIO / FCPXML / Kdenlive / Premiere timelines and
# asciinema casts.
#
# Written in a container run with podman, for the fictitious Saltmere
# Harbour, CC0-1.0: craft_av.py in `whiff-av` (the Containerfile below)
# drives FFmpeg, SoX, OpenTimelineIO and writes the rest from each format's
# published layout. av_oracle.py checks the results with ffprobe,
# sf2utils, OpenTimelineIO and libmagic.
#
#     scripts/fixtures/av.sh [STEP ...]   (raw instruments projects video edit)
#
# Containerfile (`podman build -t whiff-av`), on top of `whiff-media`
# (see media.sh):
#
#     FROM localhost/whiff-media
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#           sox libsox-fmt-all mediainfo && rm -rf /var/lib/apt/lists/*
#     RUN pip install --no-cache-dir opentimelineio
#     RUN pip install --no-cache-dir pyaaf2 pyflp sf2utils
#
# (pyaaf2 is installed for a future AAF fixture: its smallest file is over
# the 256 KiB fixture limit. pyflp does not run on Python 3.12.)

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/av-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff whiff-av python3 scripts/fixtures/craft_av.py "$w" "$@"

for d in "$work"/*/; do
    id=$(basename "$d")
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
    {
        echo "# Fixtures for \`$id\`"
        echo
        echo "Files made for whiff's tests, CC0-1.0, for the fictitious Saltmere Harbour. Regenerate with \`scripts/fixtures/av.sh\`."
        echo
        echo "| File | Origin | Licence |"
        echo "|---|---|---|"
        for f in "$fx/$id"/*; do
            n=$(basename "$f")
            [ "$n" = SOURCE.md ] && continue
            echo "| \`$n\` | craft_av.py (whiff-av) | CC0-1.0 |"
        done
    } > "$fx/$id/SOURCE.md"
done
echo "fixtures written; check them with scripts/fixtures/av_oracle.py"
