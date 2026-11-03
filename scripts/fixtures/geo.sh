#!/usr/bin/env bash
# Regenerate the geo fixtures under tests/fixtures/<format>/.
#
# Written in a container run with podman (image `whiff-geo`, built from the
# Containerfile below) by each format's own tool, for a fictitious harbour
# (Saltmere Harbour, North Sea: buoys, a dredged channel, the inner basin, a
# survey boat's track, an elevation grid, a scan of the harbour wall),
# CC0-1.0: GDAL / OGR 3.10 (GeoJSON, GeoJSONSeq, KML and LIBKML, GPX, GML,
# GeoRSS, MapInfo, FlatGeobuf, GeoPackage, shapefiles, OpenFileGDB, CSV,
# PMTiles, MBTiles, MVT, GeoTIFF and COG, AAIGrid, world files, DTED, S-57),
# osmium 1.18 (OSM XML, PBF, change files), laspy 2.7 (LAS, LAZ), PDAL 2.8.4
# (COPC), pye57 0.4.19 (E57), fit-tool 0.9.17 (FIT), aerofiles 1.5.6 (IGC),
# pynmea2 1.19.0 (NMEA), shapely 2.2.0 (WKT, WKB), topojson 2.2, czml3 4.0.0,
# py3dtiles 12.1.1 (3D Tiles tilesets and pnts) and pygltflib 1.16.5 (the
# glTF inside b3dm). Map styles, layer files, EPT, SLD, LOC, GeoRSS GML,
# QGIS projects, TCX and the b3dm / cmpt wrappers are written by
# craft_geo.py from their specifications. Two S-57 cells are NOAA
# electronic navigational charts (US Government works, public domain).
#
#     scripts/fixtures/geo.sh [STEP ...]   (vector wkt raster osm tracks points json xml s57)
#
# Containerfile (`podman build -t whiff-geo`):
#
#     FROM docker.io/library/debian:trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#           gdal-bin python3-gdal osmium-tool python3-pip python3-venv python3-numpy python3-dev ca-certificates \
#           zip unzip build-essential cmake libxerces-c-dev curl bzip2
#     RUN pip install --no-cache-dir --break-system-packages "laspy[lazrs]==2.7.0" lazrs==0.8.2 pye57==0.4.19 \
#           fit-tool==0.9.17 aerofiles==1.5.6 pynmea2==1.19.0 py3dtiles==12.1.1 topojson==2.2 czml3==4.0.0 \
#           shapely==2.2.0 mapbox-vector-tile==2.2.0
#     # PDAL (the COPC writer) from conda-forge: Debian has no package.
#     RUN curl -Ls https://micro.mamba.pm/api/micromamba/linux-aarch64/2.3.3 | tar -xj -C /usr/local bin/micromamba \
#         && micromamba create -y -p /opt/pdal -c conda-forge pdal=2.8 && micromamba clean -a -y

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/geo-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff whiff-geo python3 scripts/fixtures/craft_geo.py "$w" "$@"

for d in "$work"/*/; do
    id=$(basename "$d")
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
done

# origin_of ID FILE: a file's origin when it differs from the folder's.
origin_of() {
    case "$1/$2" in
        geopackage/saltmere-buoys.gpkg) echo "ogr2ogr -f GPKG (GDAL 3.10), from scripts/fixtures/db.sh" ;;
        mbtiles/saltmere-chart.mbtiles) echo "gdal_translate -of MBTILES (GDAL 3.10), from scripts/fixtures/db.sh" ;;
        s57/US5*) echo "NOAA electronic navigational chart ${2%.000} (charts.noaa.gov)" ;;
        georss/saltmere-notices-gml.xml) echo "craft_geo.py (GeoRSS GML in Atom)" ;;
        geojson/harbours.geojson | topojson/world.topojson) echo "Written for whiff's test suite (formerly a JSON fixture)" ;;
        *) echo "" ;;
    esac
}
licence_of() {
    case "$1/$2" in
        s57/US5*) echo "Public domain (US Government work)" ;;
        *) echo "CC0-1.0" ;;
    esac
}
source_md() {
    local id=$1 name=$2 origin=$3
    {
        echo "# Fixtures for \`$id\` ($name)"
        echo
        echo "Files made for whiff's tests for a fictitious harbour (Saltmere Harbour), CC0-1.0 unless the table says otherwise. Regenerate with \`scripts/fixtures/geo.sh\`."
        echo
        echo "| File | Origin | Licence |"
        echo "|---|---|---|"
        for f in "$fx/$id"/*; do
            local b
            b=$(basename "$f")
            [ "$b" = SOURCE.md ] && continue
            local o
            o=$(origin_of "$id" "$b")
            echo "| \`$b\` | ${o:-$origin} | $(licence_of "$id" "$b") |"
        done
    } >"$fx/$id/SOURCE.md"
}
while IFS='|' read -r id name origin; do
    [ -d "$fx/$id" ] && source_md "$id" "$name" "$origin"
done <<'LIST'
geojson|GeoJSON|ogr2ogr -f GeoJSON (GDAL 3.10; RFC 7946, and the 2008 crs member)
geojson_seq|GeoJSON-seq / NDGeoJSON|ogr2ogr -f GeoJSONSeq (GDAL 3.10)
topojson|TopoJSON|topojson 2.2 (quantized and not)
czml|CZML|czml3 4.0.0
map_style|Map styles (Mapbox style JSON / SLD / lyrx)|craft_geo.py (MapLibre style specification v8)
lyrx|ArcGIS layer file|craft_geo.py (Esri CIM CIMLayerDocument)
ept|COPC / EPT point cloud index|craft_geo.py (Entwine ept.json 1.1)
kml|KML / KMZ|ogr2ogr -f KML and -f LIBKML (GDAL 3.10)
kmz|KMZ archive|ogr2ogr -f LIBKML (GDAL 3.10)
gpx|GPX|ogr2ogr -f GPX (GDAL 3.10; waypoints, a track)
gml|GML / CityGML|ogr2ogr -f GML (GDAL 3.10; GML 3.2 and GML 2)
tcx|Garmin TCX|craft_geo.py (TrainingCenterDatabase v2)
osm_xml|OpenStreetMap PBF / XML|osmium cat 1.18 (from OPL)
osc|OSM change / diff|osmium derive-changes 1.18
sld|OGC SLD style|craft_geo.py (SLD 1.0 and 1.1)
loc|Geocaching LOC / GeoRSS|craft_geo.py
georss|GeoRSS feed|ogr2ogr -f GeoRSS (GDAL 3.10; GeoRSS Simple in RSS)
qgis|QGIS / ArcGIS project|craft_geo.py (QGIS 3.40 project layout)
qgz|QGIS project archive|craft_geo.py (a zipped .qgs)
wkt|WKT / WKB / EWKB|shapely 2.2.0 (WKT, EWKT)
wkb|WKB geometry|shapely 2.2.0 (ISO WKB in both byte orders, EWKB with an SRID)
ascii_grid|ESRI ASCII / Grid / ArcInfo coverage|gdal_translate -of AAIGrid (GDAL 3.10)
world_file|CZML / world file / .prj|gdal_translate -co TFW=YES / WORLDFILE=YES (GDAL 3.10)
prj|Projection file|ogr2ogr -f "ESRI Shapefile" (GDAL 3.10)
mapinfo|MapInfo TAB / MIF|ogr2ogr -f "MapInfo File" (GDAL 3.10; TAB and MIF)
csv_geo|CSV with coordinates (WKT/lat-lon columns)|craft_geo.py (latitude / longitude) and ogr2ogr -f CSV -lco GEOMETRY=AS_WKT
shapefile|ESRI Shapefile|ogr2ogr -f "ESRI Shapefile" (GDAL 3.10; point, 3D line, polygon in UTM)
shapefile_index|Shapefile index|ogr2ogr -f "ESRI Shapefile" (GDAL 3.10)
filegdb_table|Esri File Geodatabase / Personal GDB|ogr2ogr -f OpenFileGDB (GDAL 3.10; the layer's table)
geopackage|GeoPackage|ogr2ogr -f GPKG (GDAL 3.10)
mbtiles|MBTiles tileset|ogr2ogr / gdal_translate -f MBTILES (GDAL 3.10; vector and raster)
pmtiles|MBTiles / PMTiles|ogr2ogr -f PMTiles (GDAL 3.10)
mvt|Mapbox Vector Tile|ogr2ogr -f MVT -dsco COMPRESS=NO (GDAL 3.10)
osm_pbf|OpenStreetMap PBF|osmium cat 1.18 (dense and plain nodes)
tiles3d|OGC 3D Tiles / I3S|py3dtiles 12.1.1 (pnts); craft_geo.py (b3dm around a pygltflib glTF, cmpt)
tileset3d|3D Tiles tileset|py3dtiles 12.1.1 convert
flatgeobuf|FlatGeobuf|ogr2ogr -f FlatGeobuf (GDAL 3.10; with and without the index)
s57|S-57 / S-101 nautical charts|ogr2ogr -f S57 (GDAL 3.10; feature records only)
geotiff|GeoTIFF / COG|gdal_translate (GDAL 3.10; GTiff, COG with overviews, BigTIFF with PixelIsPoint)
dted|DTED / SRTM HGT / ASC grid|gdal_translate -of DTED (GDAL 3.10; level 0)
garmin_fit|Garmin FIT|fit-tool 0.9.17
igc|TCX / IGC / NMEA logs|aerofiles 1.5.6
nmea|NMEA 0183 log|pynmea2 1.19.0
las|LAS / LAZ point cloud|laspy 2.7.0 (LAS 1.2 and 1.4 with a WKT CRS)
laz|LAZ point cloud|laspy 2.7.0 with lazrs 0.8.2
copc|Cloud Optimized Point Cloud|PDAL 2.8.4 writers.copc
e57|E57 point cloud|pye57 0.4.19
LIST
echo "fixtures written; scratch files in $work"
