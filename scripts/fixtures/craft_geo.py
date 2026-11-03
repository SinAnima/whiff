"""Make whiff's geo fixtures (run by scripts/fixtures/geo.sh in `whiff-geo`).

    python3 craft_geo.py OUT_DIR [STEP ...]

Everything describes a fictitious Saltmere Harbour in the North Sea: four
buoys, a dredged channel, the harbour basin, a survey boat's track, a small
elevation grid and a point cloud of the harbour wall. Each format is
written by its own tool where one exists (GDAL / OGR, osmium, laspy, PDAL,
pye57, fit-tool, aerofiles, pynmea2, topojson, czml3, py3dtiles); the
others are written here from their specifications.
"""

import datetime as dt
import glob
import json
import os
import shutil
import struct
import subprocess
import sys
import zipfile

OUT = os.path.abspath(sys.argv[1])
STEPS = sys.argv[2:]
TMP = os.path.join(OUT, "_work")
os.makedirs(TMP, exist_ok=True)
os.environ["SOURCE_DATE_EPOCH"] = "1756706400"  # 2025-09-01T06:00:00Z

BUOYS = [
    ("Outer Fairway", "safe_water", 4.0950, 52.3610, 14.2),
    ("Channel Red 1", "port", 4.1105, 52.3560, 9.8),
    ("Channel Green 1", "starboard", 4.1130, 52.3575, 9.6),
    ("Kelp Bank", "isolated_danger", 4.1240, 52.3502, 3.1),
]
CHANNEL = [(4.0950, 52.3610), (4.1118, 52.3567), (4.1260, 52.3520), (4.1330, 52.3490)]
BASIN = [(4.1300, 52.3470), (4.1420, 52.3470), (4.1420, 52.3530), (4.1300, 52.3530), (4.1300, 52.3470)]
T0 = dt.datetime(2025, 9, 1, 6, 0, 0, tzinfo=dt.timezone.utc)
TRACK = [(52.3610 - i * 0.0006, 4.0950 + i * 0.0019, 1.5 + (i % 3) * 0.2, T0 + dt.timedelta(seconds=20 * i)) for i in range(20)]


def run(*cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def out(fmt, name):
    d = os.path.join(OUT, fmt)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def want(step):
    return not STEPS or step in STEPS


def base_geojson():
    feats = [
        {"type": "Feature", "properties": {"name": n, "kind": k, "depth_m": d},
         "geometry": {"type": "Point", "coordinates": [x, y]}}
        for n, k, x, y, d in BUOYS
    ]
    feats.append({"type": "Feature", "properties": {"name": "Dredged channel", "kind": "channel", "depth_m": 9.5},
                  "geometry": {"type": "LineString", "coordinates": [list(p) for p in CHANNEL]}})
    feats.append({"type": "Feature", "properties": {"name": "Inner basin", "kind": "basin", "depth_m": 6.0},
                  "geometry": {"type": "Polygon", "coordinates": [[list(p) for p in BASIN]]}})
    p = os.path.join(TMP, "harbour.geojson")
    with open(p, "w") as f:
        json.dump({"type": "FeatureCollection", "name": "saltmere", "features": feats}, f)
    pts = os.path.join(TMP, "buoys.geojson")
    with open(pts, "w") as f:
        json.dump({"type": "FeatureCollection", "name": "buoys", "features": feats[:4]}, f)
    lines = os.path.join(TMP, "channel.geojson")
    with open(lines, "w") as f:
        json.dump({"type": "FeatureCollection", "name": "channel", "features": [feats[4]]}, f)
    poly = os.path.join(TMP, "basin.geojson")
    with open(poly, "w") as f:
        json.dump({"type": "FeatureCollection", "name": "basin", "features": [feats[5]]}, f)
    return p, pts, lines, poly


def ogr(fmt, dst, src, *extra):
    run("ogr2ogr", "-f", fmt, dst, src, *extra)


def vector():
    all_, pts, lines, poly = base_geojson()
    # GeoJSON: RFC 7946, and the 2008 form with a projected `crs` member.
    ogr("GeoJSON", out("geojson", "saltmere-harbour.geojson"), all_, "-lco", "RFC7946=YES", "-nln", "saltmere")
    ogr("GeoJSON", out("geojson", "saltmere-utm.geojson"), all_, "-t_srs", "EPSG:32631", "-nln", "saltmere_utm")
    ogr("GeoJSONSeq", out("geojson_seq", "buoys.geojsons"), pts, "-lco", "RS=YES")
    ogr("GeoJSONSeq", out("geojson_seq", "harbour.geojsonl"), all_)
    ogr("KML", out("kml", "saltmere-harbour.kml"), all_, "-dsco", "NameField=name")
    ogr("LIBKML", out("kml", "saltmere-libkml.kml"), all_)
    ogr("LIBKML", out("kmz", "saltmere-harbour.kmz"), all_)
    ogr("LIBKML", out("kmz", "buoys.kmz"), pts)
    ogr("GPX", out("gpx", "buoys-waypoints.gpx"), pts, "-nln", "waypoints")
    ogr("GML", out("gml", "saltmere-gml32.gml"), all_, "-dsco", "FORMAT=GML3.2")
    ogr("GML", out("gml", "saltmere-gml2.gml"), all_, "-dsco", "FORMAT=GML2", "-t_srs", "EPSG:32631")
    rss = ("-dsco", "USE_EXTENSIONS=YES", "-dsco", "TITLE=Saltmere notices")
    ogr("GeoRSS", out("georss", "saltmere-notices.xml"), pts, "-dsco", "GEOM_DIALECT=SIMPLE", *rss)
    # GeoRSS GML, written here: GDAL 3.10 puts longitude first in gml:pos,
    # where GeoRSS defines "lat lon".
    entries = "\n".join(
        f"""  <entry><title>{n}</title><id>urn:saltmere:buoy:{i}</id><updated>2025-09-01T06:00:00Z</updated>
    <georss:where><gml:Point><gml:pos>{y} {x}</gml:pos></gml:Point></georss:where></entry>"""
        for i, (n, k, x, y, d) in enumerate(BUOYS))
    open(out("georss", "saltmere-notices-gml.xml"), "w").write(f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:georss="http://www.georss.org/georss" xmlns:gml="http://www.opengis.net/gml">
  <title>Saltmere notices</title>
  <id>urn:saltmere:notices</id>
  <updated>2025-09-01T06:00:00Z</updated>
{entries}
</feed>
""")
    ogr("MapInfo File", out("mapinfo", "buoys.tab"), pts)
    ogr("MapInfo File", out("mapinfo", "harbour.mif"), all_, "-dsco", "FORMAT=MIF")
    for f in glob.glob(out("mapinfo", "*")):
        if not f.endswith((".tab", ".mif")):
            os.remove(f)
    ogr("FlatGeobuf", out("flatgeobuf", "buoys.fgb"), pts, "-lco", "TITLE=Saltmere buoys", "-lco", "DESCRIPTION=Navigation buoys")
    ogr("FlatGeobuf", out("flatgeobuf", "channel-utm-noindex.fgb"), lines, "-t_srs", "EPSG:32631", "-lco", "SPATIAL_INDEX=NO")
    ogr("GPKG", out("geopackage", "saltmere-harbour.gpkg"), all_, "-nln", "harbour")
    ogr("GPKG", out("geopackage", "saltmere-utm.gpkg"), all_, "-t_srs", "EPSG:32631", "-nln", "harbour_utm")
    # Shapefiles: points, a 3D line, a polygon in UTM; .prj files from them.
    shp = os.path.join(TMP, "shp")
    os.makedirs(shp, exist_ok=True)
    ogr("ESRI Shapefile", os.path.join(shp, "buoys.shp"), pts)
    ogr("ESRI Shapefile", os.path.join(shp, "channel.shp"), lines, "-dim", "XYZ")
    ogr("ESRI Shapefile", os.path.join(shp, "basin.shp"), poly, "-t_srs", "EPSG:32631")
    for n in ("buoys", "channel", "basin"):
        shutil.copy(os.path.join(shp, n + ".shp"), out("shapefile", n + ".shp"))
        shutil.copy(os.path.join(shp, n + ".shx"), out("shapefile_index", n + ".shx"))
    shutil.copy(os.path.join(shp, "buoys.prj"), out("prj", "buoys-wgs84.prj"))
    shutil.copy(os.path.join(shp, "basin.prj"), out("prj", "basin-utm31n.prj"))
    # File Geodatabase: the layer's table (the highest-numbered .gdbtable).
    for name, src, extra in (("buoys", pts, []), ("basin-utm", poly, ["-t_srs", "EPSG:32631"])):
        gdb = os.path.join(TMP, name + ".gdb")
        ogr("OpenFileGDB", gdb, src, *extra)
        tables = sorted(glob.glob(os.path.join(gdb, "a*.gdbtable")))
        shutil.copy(tables[-1], out("filegdb_table", f"{name}-{os.path.basename(tables[-1])}"))
    # CSV with coordinates: latitude / longitude columns, and a WKT column.
    with open(out("csv_geo", "buoys-latlon.csv"), "w") as f:
        f.write("name,kind,latitude,longitude,depth_m\n")
        for n, k, x, y, d in BUOYS:
            f.write(f"{n},{k},{y},{x},{d}\n")
    ogr("CSV", out("csv_geo", "harbour-wkt.csv"), all_, "-lco", "GEOMETRY=AS_WKT")
    # Tiles: PMTiles and MBTiles (vector), MVT tiles.
    ogr("PMTiles", out("pmtiles", "saltmere.pmtiles"), all_, "-dsco", "MINZOOM=10", "-dsco", "MAXZOOM=13", "-dsco", "NAME=Saltmere harbour")
    ogr("PMTiles", out("pmtiles", "buoys-z14.pmtiles"), pts, "-dsco", "MINZOOM=14", "-dsco", "MAXZOOM=14")
    ogr("MBTILES", out("mbtiles", "saltmere-vector.mbtiles"), all_, "-dsco", "MINZOOM=10", "-dsco", "MAXZOOM=12", "-dsco", "NAME=Saltmere vector")
    mvt = os.path.join(TMP, "mvt")
    ogr("MVT", mvt, all_, "-dsco", "MINZOOM=12", "-dsco", "MAXZOOM=12", "-dsco", "COMPRESS=NO")
    tiles = sorted(glob.glob(os.path.join(mvt, "12", "*", "*.pbf")), key=os.path.getsize)
    shutil.copy(tiles[-1], out("mvt", "saltmere-12.mvt"))
    shutil.copy(tiles[0], out("mvt", "saltmere-12-small.pbf"))


def wkt_wkb():
    from shapely import wkb, wkt
    from shapely.geometry import LineString, MultiPoint, Point, Polygon

    geoms = [MultiPoint([(x, y) for _, _, x, y, _ in BUOYS]), LineString(CHANNEL), Polygon(BASIN)]
    with open(out("wkt", "harbour.wkt"), "w") as f:
        for g in geoms:
            f.write(wkt.dumps(g, rounding_precision=6) + "\n")
    with open(out("wkt", "buoy-z.ewkt"), "w") as f:
        f.write("SRID=4326;" + wkt.dumps(Point(4.095, 52.361, 14.2), rounding_precision=6) + "\n")
    with open(out("wkb", "channel-le.wkb"), "wb") as f:
        f.write(wkb.dumps(LineString(CHANNEL), byte_order=1))
    with open(out("wkb", "basin-be.wkb"), "wb") as f:
        f.write(wkb.dumps(Polygon(BASIN), byte_order=0))
    import shapely

    with open(out("wkb", "buoy-srid.ewkb"), "wb") as f:
        f.write(wkb.dumps(shapely.set_srid(Point(4.095, 52.361, 14.2), 4326), include_srid=True, flavor="extended"))


def rasters():
    import numpy as np
    from osgeo import gdal, osr

    gdal.UseExceptions()
    drv = gdal.GetDriverByName("MEM")

    def grid(w, h, srs, gt, dtype=gdal.GDT_Int16, bands=1):
        ds = drv.Create("", w, h, bands, dtype)
        ds.SetGeoTransform(gt)
        s = osr.SpatialReference()
        s.ImportFromEPSG(srs)
        ds.SetProjection(s.ExportToWkt())
        yy, xx = np.mgrid[0:h, 0:w]
        for b in range(bands):
            band = ds.GetRasterBand(b + 1)
            band.WriteArray((-20 + xx // 4 + yy // 5 + b).astype("int16"))
            band.SetNoDataValue(-9999)
        return ds

    utm = grid(64, 48, 32631, (595000.0, 25.0, 0.0, 5802000.0, 0.0, -25.0))
    gdal.Translate(out("geotiff", "depth-utm31n.tif"), utm, creationOptions=["COMPRESS=DEFLATE"])
    gdal.Translate(out("geotiff", "depth-cog.tif"), utm, format="COG", creationOptions=["COMPRESS=DEFLATE", "BLOCKSIZE=32", "OVERVIEWS=FORCE_USE_EXISTING"])
    utm.BuildOverviews("NEAREST", [2, 4])
    gdal.Translate(out("geotiff", "depth-cog-overviews.tif"), utm, format="COG", creationOptions=["COMPRESS=LZW", "BLOCKSIZE=32"])
    geo = grid(40, 30, 4326, (4.09, 0.0015, 0.0, 52.365, 0.0, -0.0010), gdal.GDT_Float32)
    geo.SetMetadataItem("AREA_OR_POINT", "Point")
    geo.SetMetadataItem("SURVEY", "Saltmere 2025")
    gdal.Translate(out("geotiff", "depth-wgs84-point.tif"), geo, creationOptions=["BIGTIFF=YES", "TILED=YES", "BLOCKXSIZE=16", "BLOCKYSIZE=16"])
    # ASCII grids, world files.
    gdal.Translate(out("ascii_grid", "depth-utm31n.asc"), utm, format="AAIGrid")
    gdal.Translate(out("ascii_grid", "depth-wgs84.asc"), geo, format="AAIGrid", creationOptions=["FORCE_CELLSIZE=FALSE", "DECIMAL_PRECISION=3"])
    for f in glob.glob(out("ascii_grid", "*")):
        if not f.endswith(".asc"):
            os.remove(f)
    tfw = os.path.join(TMP, "world")
    os.makedirs(tfw, exist_ok=True)
    gdal.Translate(os.path.join(tfw, "chart.tif"), utm, creationOptions=["TFW=YES"])
    gdal.Translate(os.path.join(tfw, "chart.png"), utm, format="PNG", outputType=gdal.GDT_Byte, scaleParams=[[]], creationOptions=["WORLDFILE=YES"])
    shutil.copy(os.path.join(tfw, "chart.tfw"), out("world_file", "chart.tfw"))
    shutil.copy(os.path.join(tfw, "chart.wld"), out("world_file", "chart.wld"))
    # DTED level 0: one 1° cell, 121 x 121 posts.
    dted = grid(121, 121, 4326, (3.99583333, 1 / 120, 0.0, 53.00416667, 0.0, -1 / 120))
    gdal.Translate(out("dted", "e004-n52.dt0"), dted, format="DTED")
    dted2 = grid(121, 121, 4326, (4.99583333, 1 / 120, 0.0, 53.00416667, 0.0, -1 / 120))
    gdal.Translate(out("dted", "e005-n52.dt0"), dted2, format="DTED")
    # A raster MBTiles (PNG tiles).
    rgb = grid(256, 256, 3857, (455800.0, 2.0, 0.0, 6866000.0, 0.0, -2.0), gdal.GDT_Byte, 3)
    gdal.Translate(out("mbtiles", "saltmere-chart-raster.mbtiles"), rgb, format="MBTILES", creationOptions=["NAME=Saltmere chart", "TILE_FORMAT=PNG"])


def osm():
    opl = os.path.join(TMP, "a.opl")
    lines = []
    for i, (n, k, x, y, _) in enumerate(BUOYS, 1):
        lines.append(f"n{i} v1 dV c1 t2025-09-01T06:00:0{i}Z i42 uharbourmaster Tseamark:type=buoy_{k},name={n.replace(' ', '%20%')} x{x} y{y}")
    for i, (x, y) in enumerate(CHANNEL, 11):
        lines.append(f"n{i} v1 dV c1 t2025-09-01T06:01:00Z i42 uharbourmaster T x{x} y{y}")
    lines.append("w100 v1 dV c1 t2025-09-01T06:02:00Z i42 uharbourmaster Tname=Dredged%20%channel,waterway=fairway Nn11,n12,n13,n14")
    lines.append("r200 v1 dV c1 t2025-09-01T06:03:00Z i42 uharbourmaster Ttype=route,route=ferry Mw100@")
    with open(opl, "w") as f:
        f.write("\n".join(lines) + "\n")
    b = os.path.join(TMP, "b.opl")
    with open(b, "w") as f:
        f.write("\n".join(lines[:3] + [lines[3].replace("v1", "v2").replace("06:00:04", "07:00:00")] + lines[4:]) + "\n")
    run("osmium", "cat", opl, "-o", out("osm_xml", "saltmere.osm"), "--overwrite")
    run("osmium", "cat", opl, "-o", out("osm_pbf", "saltmere.osm.pbf"), "--overwrite", "--output-header=xml_josm_upload=false",
        "--output-header=osmosis_replication_timestamp=2025-09-01T06:00:00Z")
    run("osmium", "cat", opl, "-o", out("osm_pbf", "saltmere-plain-nodes.osm.pbf"), "--overwrite", "-f", "pbf,pbf_dense_nodes=false")
    run("osmium", "derive-changes", opl, b, "-o", out("osc", "saltmere-edit.osc"), "--overwrite")
    run("osmium", "derive-changes", b, opl, "-o", out("osc", "saltmere-revert.osc"), "--overwrite")
    run("osmium", "cat", b, "-o", out("osm_xml", "saltmere-v2.osm"), "--overwrite", "--output-header=generator=osmium/saltmere")


def tracks():
    # GPX track via OGR from a points layer.
    gpx = os.path.join(TMP, "track.geojson")
    with open(gpx, "w") as f:
        json.dump({"type": "FeatureCollection", "features": [
            {"type": "Feature", "properties": {"name": "Morning survey"},
             "geometry": {"type": "MultiLineString", "coordinates": [[[lo, la, e] for la, lo, e, _ in TRACK]]}}]}, f)
    ogr("GPX", out("gpx", "survey-track.gpx"), gpx, "-nln", "tracks", "-lco", "FORCE_GPX_TRACK=YES")
    # TCX, from Garmin's TrainingCenterDatabase v2 schema.
    pts = "\n".join(
        f"""          <Trackpoint><Time>{t.strftime('%Y-%m-%dT%H:%M:%SZ')}</Time><Position><LatitudeDegrees>{la:.6f}</LatitudeDegrees><LongitudeDegrees>{lo:.6f}</LongitudeDegrees></Position><AltitudeMeters>{e:.1f}</AltitudeMeters></Trackpoint>"""
        for la, lo, e, t in TRACK)
    for name in ("survey-row.tcx", "survey-row-short.tcx"):
        tcx(name, pts if name == "survey-row.tcx" else pts.split("\n", 4)[0])
    # IGC, with aerofiles.
    from aerofiles.igc import Writer

    for name, glider in (("saltmere-flight.igc", "Kestrel 19"), ("saltmere-short.igc", "Skylark 4")):
        with open(out("igc", name), "wb") as f:
            w = Writer(f)
            w.write_headers({"manufacturer_code": "XSM", "logger_id": "SAL", "date": T0.date(), "fix_accuracy": 50,
                             "pilot": "Harbour Pilot", "glider_type": glider, "glider_id": "D-SALT", "gps_datum": "WGS-1984",
                             "firmware_version": "1.0", "hardware_version": "1.0", "logger_type": "Saltmere logger",
                             "gps_receiver": "Generic", "pressure_sensor": "Generic", "competition_id": "SM",
                             "competition_class": "Club"})
            for la, lo, e, t in TRACK[: 20 if "flight" in name else 6]:
                w.write_fix(t.time(), latitude=la, longitude=lo, valid=True, pressure_alt=int(300 + e * 10), gps_alt=int(310 + e * 10))
    # NMEA, with pynmea2.
    import pynmea2

    def sentences(n):
        rows = []
        for la, lo, e, t in TRACK[:n]:
            lat = f"{int(la):02d}{(la % 1) * 60:07.4f}"
            lon = f"{int(lo):03d}{(lo % 1) * 60:07.4f}"
            hms = t.strftime("%H%M%S.00")
            rows.append(str(pynmea2.GGA("GP", "GGA", (hms, lat, "N", lon, "E", "1", "08", "0.9", f"{e:.1f}", "M", "47.0", "M", "", ""))))
            rows.append(str(pynmea2.RMC("GP", "RMC", (hms, "A", lat, "N", lon, "E", "5.2", "112.0", t.strftime("%d%m%y"), "", ""))))
        rows.append(str(pynmea2.GSA("GN", "GSA", ("A", "3", "05", "12", "15", "", "", "", "", "", "", "", "", "", "1.4", "0.9", "1.1"))))
        return "\r\n".join(rows) + "\r\n"

    with open(out("nmea", "survey-boat.nmea"), "w") as f:
        f.write(sentences(20))
    with open(out("nmea", "survey-short.nmea"), "w") as f:
        f.write(sentences(5))
    # FIT, with fit-tool.
    from fit_tool.fit_file_builder import FitFileBuilder
    from fit_tool.profile.messages.file_id_message import FileIdMessage
    from fit_tool.profile.messages.record_message import RecordMessage
    from fit_tool.profile.messages.session_message import SessionMessage
    from fit_tool.profile.profile_type import FileType, Manufacturer, Sport

    def fit(path, n, sport):
        b = FitFileBuilder(auto_define=True, min_string_size=50)
        m = FileIdMessage()
        m.type = FileType.ACTIVITY
        m.manufacturer = Manufacturer.DEVELOPMENT.value
        m.product = 7
        m.time_created = round(T0.timestamp() * 1000)
        m.serial_number = 12345
        b.add(m)
        for la, lo, e, t in TRACK[:n]:
            r = RecordMessage()
            r.timestamp = round(t.timestamp() * 1000)
            r.position_lat = la
            r.position_long = lo
            r.altitude = e
            b.add(r)
        s = SessionMessage()
        s.start_time = round(T0.timestamp() * 1000)
        s.sport = sport
        s.total_elapsed_time = 20 * n
        s.total_distance = 160.0 * n
        b.add(s)
        b.build().to_file(path)

    fit(out("garmin_fit", "survey-row.fit"), 20, Sport.ROWING)
    fit(out("garmin_fit", "harbour-walk.fit"), 6, Sport.WALKING)


def tcx(name, pts):
    with open(out("tcx", name), "w") as f:
        f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<TrainingCenterDatabase xmlns="http://www.garmin.com/xmlschemas/TrainingCenterDatabase/v2">
  <Activities>
    <Activity Sport="Other">
      <Id>{T0.strftime('%Y-%m-%dT%H:%M:%SZ')}</Id>
      <Lap StartTime="{T0.strftime('%Y-%m-%dT%H:%M:%SZ')}">
        <TotalTimeSeconds>380</TotalTimeSeconds><DistanceMeters>3120.5</DistanceMeters><Calories>0</Calories>
        <Intensity>Active</Intensity><TriggerMethod>Manual</TriggerMethod>
        <Track>
{pts}
        </Track>
      </Lap>
      <Creator><Name>Saltmere survey logger</Name></Creator>
    </Activity>
  </Activities>
</TrainingCenterDatabase>
""")


def points():
    import laspy
    import numpy as np

    n = 400
    rng = np.random.default_rng(7)
    x = 595000 + rng.random(n) * 80
    y = 5801000 + rng.random(n) * 30
    z = 2 + rng.random(n) * 6

    def write(path, version, fmt, wkt=True, compressed=False):
        h = laspy.LasHeader(point_format=fmt, version=version)
        h.scales = [0.001, 0.001, 0.001]
        h.offsets = [595000, 5801000, 0]
        h.system_identifier = "Saltmere wall scan"
        h.generating_software = "laspy 2.7"
        h.creation_date = dt.date(2025, 9, 1)
        if wkt and version >= "1.4":
            import pyproj

            h.add_crs(pyproj.CRS.from_epsg(32631))
        las = laspy.LasData(h)
        las.x, las.y, las.z = x, y, z
        las.return_number = np.ones(n, dtype=np.uint8)
        las.number_of_returns = np.ones(n, dtype=np.uint8)
        las.write(path, laz_backend=laspy.LazBackend.Lazrs if compressed else None)

    write(out("las", "harbour-wall-1.2.las"), "1.2", 1, wkt=False)
    write(out("las", "harbour-wall-1.4.las"), "1.4", 6)
    write(out("laz", "harbour-wall-1.4.laz"), "1.4", 6, compressed=True)
    write(out("laz", "harbour-wall-1.2.laz"), "1.2", 3, wkt=False, compressed=True)
    pdal = ("micromamba", "run", "-p", "/opt/pdal", "pdal", "translate")
    run(*pdal, out("las", "harbour-wall-1.4.las"), out("copc", "harbour-wall.copc.laz"), "--writers.copc.a_srs=EPSG:32631")
    run(*pdal, out("las", "harbour-wall-1.2.las"), out("copc", "harbour-wall-small.copc.laz"), "--writers.copc.a_srs=EPSG:32631")
    # E57, with pye57.
    import pye57

    for name, m in (("harbour-wall.e57", n), ("harbour-wall-small.e57", 50)):
        e = pye57.E57(out("e57", name), mode="w")
        e.write_scan_raw({"cartesianX": x[:m] - 595000, "cartesianY": y[:m] - 5801000, "cartesianZ": z[:m]}, name="Harbour wall scan")
        e.close()
    # 3D Tiles: py3dtiles converts a LAS file into a tileset of pnts tiles.
    t = os.path.join(TMP, "3dtiles")
    shutil.rmtree(t, ignore_errors=True)
    run("py3dtiles", "convert", out("las", "harbour-wall-1.4.las"), "--out", t, "--srs_in", "32631", "--srs_out", "4978", "--overwrite")
    shutil.copy(os.path.join(t, "tileset.json"), out("tileset3d", "harbour-wall-tileset.json"))
    t2 = os.path.join(TMP, "3dtiles-small")
    run("py3dtiles", "convert", out("las", "harbour-wall-1.2.las"), "--out", t2, "--srs_in", "32631", "--srs_out", "4978", "--overwrite")
    shutil.copy(os.path.join(t2, "tileset.json"), out("tileset3d", "harbour-wall-small-tileset.json"))
    pnts = sorted(glob.glob(os.path.join(t, "**", "*.pnts"), recursive=True), key=os.path.getsize)
    shutil.copy(pnts[0], out("tiles3d", "harbour-wall.pnts"))
    tiles3d_wrappers(open(pnts[0], "rb").read())


def tiles3d_wrappers(pnts):
    """A b3dm around a tiny glTF (pygltflib), and a cmpt of both (3D Tiles 1.0)."""
    import pygltflib

    g = pygltflib.GLTF2(asset=pygltflib.Asset(version="2.0", generator="pygltflib"), scenes=[pygltflib.Scene(nodes=[0])], nodes=[pygltflib.Node()])
    glb = b"".join(g.save_to_bytes())

    def pad(b, n=8, c=b" "):
        return b + c * (-len(b) % n)

    ft = pad(json.dumps({"BATCH_LENGTH": 2, "RTC_CENTER": [3_870_000.0, 280_000.0, 5_030_000.0]}).encode(), 8)
    bt = pad(json.dumps({"name": ["Pier head", "Lighthouse"], "height_m": [6.5, 21.0]}).encode(), 8)
    body = ft + bt + glb
    b3dm = b"b3dm" + struct.pack("<6I", 1, 28 + len(body), len(ft), 0, len(bt), 0) + body
    with open(out("tiles3d", "harbour-structures.b3dm"), "wb") as f:
        f.write(b3dm)
    inner = pad(b3dm) + pad(pnts)
    with open(out("tiles3d", "harbour.cmpt"), "wb") as f:
        f.write(b"cmpt" + struct.pack("<3I", 1, 16 + len(inner), 2) + inner)


def json_formats():
    import topojson

    all_ = os.path.join(TMP, "harbour.geojson")
    gj = json.load(open(all_))
    open(out("topojson", "saltmere-quantized.topojson"), "w").write(topojson.Topology(gj, prequantize=1e5).to_json())
    open(out("topojson", "saltmere.topojson"), "w").write(topojson.Topology(gj, prequantize=False).to_json())
    from czml3 import CZML_VERSION, Document, Packet
    from czml3.properties import Billboard, Clock, Position

    packets = [Packet(id="document", name="Saltmere buoys", version=CZML_VERSION, clock=Clock(currentTime=T0))]
    for i, (n, k, x, y, d) in enumerate(BUOYS):
        packets.append(Packet(id=f"buoy{i}", name=n, position=Position(cartographicDegrees=[x, y, 0.0]),
                              billboard=Billboard(image="buoy.png")))
    open(out("czml", "saltmere-buoys.czml"), "w").write(Document(packets=packets).dumps())
    track = [v for la, lo, e, t in TRACK for v in ((t - T0).total_seconds(), lo, la, e)]
    doc = Document(packets=[Packet(id="document", name="Survey boat", version=CZML_VERSION),
                            Packet(id="boat", name="Survey boat", position=Position(epoch=T0, cartographicDegrees=track))])
    open(out("czml", "survey-boat.czml"), "w").write(doc.dumps())
    # A MapLibre style (style specification v8).
    style = {"version": 8, "name": "Saltmere nautical", "center": [4.115, 52.356], "zoom": 13,
             "sources": {"harbour": {"type": "vector", "url": "pmtiles://saltmere.pmtiles"},
                         "relief": {"type": "raster-dem", "url": "https://tiles.example.org/relief.json"}},
             "glyphs": "https://tiles.example.org/fonts/{fontstack}/{range}.pbf",
             "layers": [{"id": "water", "type": "background", "paint": {"background-color": "#a8c8e0"}},
                        {"id": "basin", "type": "fill", "source": "harbour", "source-layer": "basin"},
                        {"id": "channel", "type": "line", "source": "harbour", "source-layer": "channel"},
                        {"id": "buoys", "type": "symbol", "source": "harbour", "source-layer": "buoys"}]}
    json.dump(style, open(out("map_style", "saltmere-nautical.style.json"), "w"), indent=2)
    json.dump({**style, "name": "Saltmere plain", "layers": style["layers"][:2]}, open(out("map_style", "saltmere-plain.json"), "w"))
    # ArcGIS layer files: CIMLayerDocument (Esri CIM specification).
    for name, layers in (("buoys.lyrx", [("Buoys", "CIMFeatureLayer")]),
                         ("harbour-group.lyrx", [("Harbour", "CIMGroupLayer"), ("Basin", "CIMFeatureLayer"), ("Relief", "CIMRasterLayer")])):
        doc = {"type": "CIMLayerDocument", "version": "3.1.0", "build": 41833,
               "layers": [f"CIMPATH=map/{n.lower()}.json" for n, _ in layers],
               "layerDefinitions": [{"type": t, "name": n, "uRI": f"CIMPATH=map/{n.lower()}.json"} for n, t in layers]}
        json.dump(doc, open(out("lyrx", name), "w"), indent=2)
    # Entwine Point Tiles `ept.json` (EPT 1.1).
    for name, srs in (("ept.json", {"authority": "EPSG", "horizontal": "32631"}), ("harbour-ept.json", {"wkt": 'PROJCS["WGS 84 / UTM zone 31N",AUTHORITY["EPSG","32631"]]'})):
        ept = {"bounds": [594990, 5800990, -10, 595090, 5801090, 90], "boundsConforming": [595000, 5801000, 2, 595080, 5801030, 8],
               "dataType": "laszip", "hierarchyType": "json", "points": 400, "span": 128, "version": "1.1.0", "srs": srs,
               "schema": [{"name": "X", "type": "signed", "size": 4, "scale": 0.001, "offset": 595040},
                          {"name": "Y", "type": "signed", "size": 4, "scale": 0.001, "offset": 5801040},
                          {"name": "Z", "type": "signed", "size": 4, "scale": 0.001, "offset": 40},
                          {"name": "Intensity", "type": "unsigned", "size": 2}]}
        json.dump(ept, open(out("ept", name), "w"), indent=2)


def xml_formats():
    # OGC SLD 1.0 and 1.1.
    for name, ver, ns in (("buoys.sld", "1.0.0", 'xmlns="http://www.opengis.net/sld" xmlns:ogc="http://www.opengis.net/ogc"'),
                          ("harbour-se.sld", "1.1.0", 'xmlns="http://www.opengis.net/sld" xmlns:se="http://www.opengis.net/se"')):
        p = "se:" if ver == "1.1.0" else ""
        open(out("sld", name), "w").write(f"""<?xml version="1.0" encoding="UTF-8"?>
<StyledLayerDescriptor version="{ver}" {ns}>
  <NamedLayer>
    <{p}Name>buoys</{p}Name>
    <UserStyle>
      <{p}Name>Saltmere buoys</{p}Name>
      <{p}FeatureTypeStyle>
        <{p}Rule><{p}Name>port</{p}Name><{p}PointSymbolizer><{p}Graphic><{p}Mark><{p}WellKnownName>circle</{p}WellKnownName></{p}Mark></{p}Graphic></{p}PointSymbolizer></{p}Rule>
        <{p}Rule><{p}Name>labels</{p}Name><{p}TextSymbolizer><{p}Label>name</{p}Label></{p}TextSymbolizer></{p}Rule>
      </{p}FeatureTypeStyle>
    </UserStyle>
  </NamedLayer>
</StyledLayerDescriptor>
""")
    # Geocaching LOC.
    for name, rows in (("saltmere-caches.loc", BUOYS), ("kelp-bank.loc", BUOYS[3:])):
        wps = "\n".join(f'<waypoint><name id="GCSM{i:02d}"><![CDATA[{n} cache]]></name><coord lat="{y}" lon="{x}"/><type>Geocache</type></waypoint>'
                        for i, (n, k, x, y, d) in enumerate(rows))
        open(out("loc", name), "w").write(f'<?xml version="1.0" encoding="UTF-8"?>\n<loc version="1.0" src="Saltmere Geocaching">\n{wps}\n</loc>\n')
    # QGIS projects (.qgs; .qgz is the same document zipped).
    def qgs(title, layers):
        ml = "\n".join(f"""    <maplayer type="{t}" geometry="{g}"><id>{n}_1</id><datasource>./{n}.gpkg</datasource><layername>{n}</layername><provider encoding="UTF-8">{prov}</provider></maplayer>"""
                       for n, t, g, prov in layers)
        return f"""<!DOCTYPE qgis PUBLIC 'http://mrcc.com/qgis.dtd' 'SYSTEM'>
<qgis projectname="{title}" version="3.40.0-Bratislava">
  <homePath path=""/>
  <title>{title}</title>
  <projectCrs><spatialrefsys nativeFormat="Wkt"><authid>EPSG:32631</authid><description>WGS 84 / UTM zone 31N</description></spatialrefsys></projectCrs>
  <projectlayers>
{ml}
  </projectlayers>
</qgis>
"""
    open(out("qgis", "saltmere.qgs"), "w").write(qgs("Saltmere harbour", [("buoys", "vector", "Point", "ogr"), ("channel", "vector", "Line", "ogr"), ("relief", "raster", "", "gdal")]))
    open(out("qgis", "saltmere-small.qgs"), "w").write(qgs("Saltmere small", [("buoys", "vector", "Point", "ogr")]))
    for name, title in (("saltmere.qgz", "Saltmere harbour"), ("saltmere-small.qgz", "Saltmere small")):
        with zipfile.ZipFile(out("qgz", name), "w", zipfile.ZIP_DEFLATED) as z:
            info = zipfile.ZipInfo(name.replace(".qgz", ".qgs"), (2025, 9, 1, 6, 0, 0))
            z.writestr(info, qgs(title, [("buoys", "vector", "Point", "ogr")]), zipfile.ZIP_DEFLATED)


def s57():
    """S-57 from GDAL's S57 writer: layers named by object class."""
    src = os.path.join(TMP, "s57src.gpkg")
    pts, lines = os.path.join(TMP, "buoys.geojson"), os.path.join(TMP, "channel.geojson")
    run("ogr2ogr", "-f", "GPKG", src, pts, "-nln", "BOYLAT", "-sql", "SELECT name AS OBJNAM, 2 AS CATLAM FROM buoys", "-dialect", "SQLITE")
    run("ogr2ogr", "-update", "-f", "GPKG", src, lines, "-nln", "DEPCNT", "-sql", "SELECT 10.0 AS VALDCO FROM channel", "-dialect", "SQLITE")
    # Two real cells from NOAA's catalogue (US Government work, public
    # domain): GDAL writes feature records without spatial primitives.
    import urllib.request

    for cell in ("US5OR2XF", "US5WA4KT"):
        z = os.path.join(TMP, cell + ".zip")
        urllib.request.urlretrieve(f"https://charts.noaa.gov/ENCs/{cell}.zip", z)
        with zipfile.ZipFile(z) as zf:
            name = next(n for n in zf.namelist() if n.endswith(cell + ".000"))
            open(out("s57", cell + ".000"), "wb").write(zf.read(name))
    for name, ed in (("SM5HARB1.000", "1"),):
        run("ogr2ogr", "-f", "S57", out("s57", name), src,
            "-dsco", f"S57_EXPP=1", "-dsco", f"S57_INTU=5", "-dsco", f"S57_EDTN={ed}", "-dsco", "S57_UPDN=0",
            "-dsco", "S57_UADT=20250901", "-dsco", "S57_ISDT=20250901", "-dsco", "S57_STED=03.1", "-dsco", "S57_AGEN=540",
            "-dsco", "S57_COMT=Saltmere test cell", "-dsco", "S57_NOMR=0", "-dsco", "S57_CSCL=12000",
            "-dsco", "S57_COMF=10000000", "-dsco", "S57_SOMF=10")


if want("vector"):
    vector()
if want("wkt"):
    wkt_wkb()
if want("raster"):
    rasters()
if want("osm"):
    osm()
if want("tracks"):
    tracks()
if want("points"):
    points()
if want("json"):
    if not os.path.exists(os.path.join(TMP, "harbour.geojson")):
        base_geojson()
    json_formats()
if want("xml"):
    xml_formats()
if want("s57"):
    if not os.path.exists(os.path.join(TMP, "buoys.geojson")):
        base_geojson()
    s57()
shutil.rmtree(TMP, ignore_errors=True)
# Writers' sidecars (GDAL PAM, GML schemas) are not fixtures.
for f in glob.glob(os.path.join(OUT, "*", "*")):
    if f.endswith((".aux.xml", ".xsd", ".gfs")):
        os.remove(f)
print("geo fixtures written to", OUT)
