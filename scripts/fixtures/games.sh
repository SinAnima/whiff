#!/usr/bin/env bash
# Regenerate the games fixtures under tests/fixtures/<format>/.
#
# Written in a container run with podman, for a fictitious game ("Saltmere
# Tides", set in Saltmere Harbour), CC0-1.0: craft_games.py in
# `whiff-games` (the Containerfile below) drives cc65 2.19 (the NES ROM and
# the NSF), Inform 6.42 with the 6.12 library (Z-code, Glulx), Tiled 1.11
# (TMJ and TSJ from TMX and TSX), omgifol 0.5 (Doom WADs), vgio 1.3 (Quake
# PAK, WAD2 and BSP), vpk 1.4 (Valve VPK), nbtlib 2.0 (Minecraft NBT) and
# vdf 3.4 (Steam KeyValues). The other formats are written by
# craft_games.py from their specifications; the ROMs carry only the first
# bytes of the consoles' boot logos.
#
#     scripts/fixtures/games.sh [STEP ...]   (roms consoles chiptunes archives engines minecraft tiled sprites steam fiction saves)
#
# Containerfile (`podman build -t whiff-games`):
#
#     FROM docker.io/library/python:3.12-slim-trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#           cc65 inform6-compiler inform6-library tiled file ffmpeg zip unzip xz-utils ca-certificates \
#           libqt6gui6 qt6-qpa-plugins build-essential
#     RUN pip install --no-cache-dir nbtlib vdf UnityPy lz4 vpk omgifol vgio unrpa pytmx
#
# (`file`, ffmpeg with libgme, UnityPy, unrpa and pytmx are for
# games_oracle.py.)

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/games-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff whiff-games python3 scripts/fixtures/craft_games.py "$w" "$@"

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
        echo "Files made for whiff's tests, CC0-1.0, for a fictitious game (Saltmere Tides). Regenerate with \`scripts/fixtures/games.sh\`."
        echo
        echo "| File | Origin | Licence |"
        echo "|---|---|---|"
        for f in "$fx/$id"/*; do
            [ "$(basename "$f")" = SOURCE.md ] && continue
            echo "| \`$(basename "$f")\` | $origin | CC0-1.0 |"
        done
    } >"$fx/$id/SOURCE.md"
}
while IFS='|' read -r id name origin; do
    [ -d "$fx/$id" ] && source_md "$id" "$name" "$origin"
done <<'LIST'
nes_rom|NES ROM|cc65 2.19 (NES target); the NES 2.0 header rewritten by craft_games.py
snes_rom|Super NES ROM|craft_games.py (SNESdev cartridge header and checksum)
gameboy_rom|Game Boy ROM|craft_games.py (Pan Docs header; boot logo cut to its first bytes)
gba_rom|Game Boy Advance ROM|craft_games.py (GBATEK header; boot logo cut to its first bytes)
n64_rom|Nintendo 64 ROM|craft_games.py (n64brew header, no boot code; three byte orders)
megadrive_rom|Mega Drive / Genesis ROM|craft_games.py (Sega header and checksum)
nsp|Nintendo Switch package|craft_games.py (PFS0)
xci|Nintendo Switch game card image|craft_games.py (card header, root HFS0)
cia|Nintendo 3DS CIA|craft_games.py (3dbrew CIA, TMD and SMDH)
nsf|NES Sound Format|cc65 2.19 (ca65 / ld65)
nsfe|Extended NES Sound Format|craft_games.py
spc|SNES SPC700 sound file|craft_games.py (ID666 text and binary, xid6)
vgm|Video Game Music|craft_games.py (VGM 1.71 and a gzipped 1.50, GD3)
sid|Commodore 64 SID tune|craft_games.py (PSID v2, RSID v3)
gbs|Game Boy Sound System|craft_games.py
wad|Doom / Quake WAD|omgifol 0.5 (IWAD, PWAD), vgio 1.3 (WAD2), craft_games.py (WAD3)
quake_pak|Quake PAK|vgio 1.3
bsp|BSP map|vgio 1.3 (Quake, Half-Life), craft_games.py (Quake II, Quake III, Source)
vpk|Valve VPK|vpk 1.4
bsa|Bethesda archive|craft_games.py (v104, v105)
ba2|Bethesda archive 2|craft_games.py (GNRL v1)
rgssad|RPG Maker archive|craft_games.py (RGSSAD v1, RGSS3A)
rpa|Ren'Py archive|craft_games.py (Ren'Py's layout; the index pickled by CPython)
godot_pck|Godot pack|craft_games.py (pack formats 1 and 2)
unreal_pak|Unreal Engine pak|craft_games.py (versions 3 and 11)
unity_bundle|Unity asset bundle|craft_games.py (UnityFS 6 and 7; block info compressed with python-lz4)
unity_assets|Unity serialized file|craft_games.py (versions 17 and 22)
uasset|Unreal Engine package|craft_games.py (UE 4.27 and UE 5.1 summaries)
gamemaker_project|GameMaker project|written by hand (GameMaker 2024 layout)
godot_project|Godot project|written by hand (Godot 3 and 4)
paradox_mod|Paradox mod descriptor|written by hand
mca|Minecraft region file|nbtlib 2.0 (chunks), craft_games.py (region layout)
minecraft_schematic|Minecraft schematic|nbtlib 2.0 (Sponge v2 and v3, Litematica, MCEdit)
minecraft_level|Minecraft world|nbtlib 2.0 (Java and Bedrock level.dat)
tiled_map|Tiled map|written by hand (TMX); Tiled 1.11 (TMJ)
tiled_tileset|Tiled tileset|written by hand (TSX); Tiled 1.11 (TSJ)
aseprite|Aseprite sprite|craft_games.py (Aseprite 1.3 file specification)
steam_vdf|Steam KeyValues|vdf 3.4
steam_binary_vdf|Steam binary KeyValues|vdf 3.4 (shortcuts), craft_games.py (appinfo)
twee|Twee|written by hand (Twee 3 and 1)
ink|Ink story source|written by hand
ink_json|Compiled Ink story|written by hand (ink 21 JSON layout)
zcode|Z-code story file|Inform 6.42 with the 6.12 library
glulx|Glulx story file|Inform 6.42
blorb|Blorb story package|craft_games.py around the Inform 6.42 stories
retroarch_state|RetroArch save state|craft_games.py (RetroArch 1.20 task_save.c and rzip_stream.c layouts)
mednafen_state|Mednafen save state|craft_games.py (Mednafen 1.32 state.cpp layout)
battery_save|Battery save|craft_games.py
LIST
echo "fixtures written; scratch files in $work"
