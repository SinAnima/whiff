#!/usr/bin/env bash
# Regenerate the 3D and CAD fixtures under tests/fixtures/<format>/.
#
# Written in containers run with podman, for a fictitious harbour (Saltmere
# Harbour: a navigation buoy, a pier, the lighthouse, a mooring bracket, the
# harbour office, the buoy light's board, a test chip), CC0-1.0:
# craft_cad.py in `whiff-cad` (the Containerfile below) drives trimesh
# 5.2 (OBJ, STL, PLY, OFF, 3MF, glTF, GLB, COLLADA), assimp 5.4 (COLLADA,
# 3DS, X3D, FBX binary and ASCII, MTL), Blender 4.3 (.blend, FBX, BVH),
# usd-core 26.11 (USDA, USDC, USDZ), pygltflib 1.16 (VRM metadata),
# draco_encoder (Draco), py-vox-io (MagicaVoxel), OpenVDB 10 (Debian's
# pyopenvdb), c3d 0.6 (C3D), PrusaSlicer 2.9 (G-code), cadquery 2.8 /
# OpenCASCADE 7.9 (STEP, IGES, AMF, VRML), ezdxf 1.4 (DXF, binary DXF),
# ifcopenshell 0.9 (IFC, IFC-ZIP), gerber-writer 0.4 (Gerber X2), kiutils
# 1.4 (KiCad) and KLayout 0.30 (GDSII, OASIS); IES, EULUMDAT, LDraw,
# Excellon, OpenSCAD and CNC programs are written by craft_cad.py from
# their specifications. DGN comes from GDAL 3.10 in `whiff-geo` (see
# geo.sh).
#
#     scripts/fixtures/cad.sh [STEP ...]   (meshes blender usd voxels capture photometry ldraw gcode cad eda)
#
# Containerfile (`podman build -t whiff-cad`):
#
#     FROM docker.io/library/python:3.12-slim-trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#           assimp-utils draco prusa-slicer blender python3-openvdb gmsh build-essential cmake ca-certificates zip unzip curl
#     RUN pip install --no-cache-dir numpy trimesh==5.2.0 pygltflib==1.16.5 usd-core==26.11 ezdxf==1.4.5 \
#           ifcopenshell==0.9.0.post1 klayout==0.30.12 kiutils==1.4.8 gerber-writer==0.4.3.3 DracoPy==2.2.0 \
#           pycollada==0.9.3 lxml networkx cadquery==2.8.0 c3d==0.6.0 py-vox-io==0.1

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/cad-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff whiff-cad python3 scripts/fixtures/craft_cad.py "$w" "$@"
if [ $# -eq 0 ] || [[ " $* " == *" dgn "* ]]; then
    podman run --rm -v "$root:/whiff" -w /whiff whiff-geo sh -c "mkdir -p $w/dgn && cat > /tmp/p.geojson <<'J'
{\"type\":\"FeatureCollection\",\"features\":[{\"type\":\"Feature\",\"properties\":{\"name\":\"pier\"},\"geometry\":{\"type\":\"LineString\",\"coordinates\":[[0,0],[12,0],[12,2.5],[0,2.5],[0,0]]}},{\"type\":\"Feature\",\"properties\":{\"name\":\"bollard\"},\"geometry\":{\"type\":\"Point\",\"coordinates\":[6,1.25]}}]}
J
ogr2ogr -f DGN $w/dgn/pier-plan-2d.dgn /tmp/p.geojson 2>/dev/null; ogr2ogr -f DGN -dsco 3D=YES $w/dgn/pier-plan-3d.dgn /tmp/p.geojson 2>/dev/null"
fi

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
        echo "Files made for whiff's tests, CC0-1.0, for a fictitious harbour (Saltmere Harbour). Regenerate with \`scripts/fixtures/cad.sh\`."
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
obj|Wavefront OBJ / MTL|trimesh 5.2
mtl|Wavefront material library|assimp 5.4 (OBJ export)
stl|STL|trimesh 5.2 (binary and ASCII)
ply|PLY|trimesh 5.2 (binary little-endian and ASCII)
off|OFF / AMF / Stanford|trimesh 5.2
amf|Additive Manufacturing File|cadquery 2.8 (OpenCASCADE 7.9)
3mf|3D Manufacturing Format|trimesh 5.2
collada|Collada DAE|trimesh 5.2 and assimp 5.4
x3d|X3D / VRML|assimp 5.4
vrml|VRML|cadquery 2.8 (OpenCASCADE 7.9)
draco|Draco compressed mesh|draco_encoder (mesh and point cloud)
gltf|glTF / GLB|trimesh 5.2 (embedded buffers)
glb|glTF binary|trimesh 5.2
vrm|VRM avatar|pygltflib 1.16 (VRM 1.0 and 0.x metadata on a trimesh glTF)
fbx|FBX|assimp 5.4 (binary and ASCII), Blender 4.3
blend|Blender|Blender 4.3 (zstd-compressed)
usda|USD / USDZ / USDA / USDC|usd-core 26.11
usdc|USD crate file|usd-core 26.11
usdz|USDZ package|usd-core 26.11 (UsdUtils.CreateNewUsdzPackage)
3ds|Autodesk 3DS / MAX|assimp 5.4
vox|MagicaVoxel / Qubicle|py-vox-io 0.1
openvdb|OpenVDB volume|OpenVDB 10 (pyopenvdb)
bvh|Motion capture BVH / C3D|Blender 4.3
c3d|C3D motion capture|c3d 0.6
ies|IES photometric|craft_cad.py (ANSI/IES LM-63-2002)
ldt|EULUMDAT photometric|craft_cad.py (EULUMDAT)
ldraw|LDraw brick models|craft_cad.py (LDraw 1.0.2, MPD)
gcode|3D printing G-code|PrusaSlicer 2.9
cnc_gcode|CNC / ISO G-code|craft_cad.py (RS-274NGC)
dxf|AutoCAD DXF|ezdxf 1.4 (R12, R2018)
dxf_binary|AutoCAD binary DXF|ezdxf 1.4 (R2000, R2018)
dgn|MicroStation DGN|GDAL 3.10 (DGN v7, 2D and 3D)
step|STEP|cadquery 2.8 (OpenCASCADE 7.9, AP214)
iges|IGES|OpenCASCADE 7.9 IGESControl_Writer
ifc|IFC (BIM)|ifcopenshell 0.9 (IFC4, IFC2X3)
ifczip|IFC-ZIP|ifcopenshell 0.9, zipped
gerber|Gerber / Excellon PCB|gerber-writer 0.4 (X2)
excellon|Excellon drill file|craft_cad.py
kicad_pcb|KiCad / Eagle / Altium|kiutils 1.4
kicad_sch|KiCad schematic|kiutils 1.4
openscad|OpenSCAD / FreeCAD|craft_cad.py
gdsii|GDSII / OASIS chip layout|KLayout 0.30
oasis|OASIS chip layout|KLayout 0.30 (with and without CBLOCKs)
LIST
echo "fixtures written; scratch files in $work"
