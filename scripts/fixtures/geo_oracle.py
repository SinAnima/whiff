"""Compare whiff's geo reports with GDAL / OGR, osmium, laspy, pye57,
fit-tool, aerofiles, pynmea2 and shapely.

    # in `whiff-geo`: build a corpus and the expected facts
    python3 geo_oracle.py expect OUT_DIR
    # on the host
    python3 geo_oracle.py check OUT_DIR WHIFF_BINARY

The corpus is generated: random features (counts, geometry types, CRSs,
extents) written with OGR to every vector format, random rasters
(sizes, bands, CRSs, compression, tiling, COG, BigTIFF) with GDAL, point
clouds (LAS versions, point formats, LAZ, COPC), tracks (FIT, IGC, NMEA),
OSM files and WKT / WKB. Nothing here ships with whiff.
"""

import glob
import json
import math
import os
import random
import shutil
import subprocess
import sys

R = random.Random(11)
CRS = [4326, 4258, 3857, 32631, 25832]


def sh(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def random_features(n, kinds):
    """GeoJSON features (WGS84) somewhere around the North Sea."""
    x0, y0 = R.uniform(2, 8), R.uniform(50, 56)
    feats = []
    for i in range(n):
        k = R.choice(kinds)
        pt = lambda: [round(x0 + R.uniform(0, 0.5), 6), round(y0 + R.uniform(0, 0.4), 6)]
        if k == "Point":
            g = {"type": "Point", "coordinates": pt()}
        elif k == "LineString":
            g = {"type": "LineString", "coordinates": [pt() for _ in range(R.randint(2, 8))]}
        else:
            c = pt()
            r = R.uniform(0.001, 0.02)
            ring = [[round(c[0] + r * math.cos(a / 6 * 2 * math.pi), 6), round(c[1] + r * math.sin(a / 6 * 2 * math.pi), 6)] for a in range(6)]
            g = {"type": "Polygon", "coordinates": [ring + [ring[0]]]}
        feats.append({"type": "Feature", "properties": {"id": i, "name": f"f{i}", "v": round(R.random(), 3)}, "geometry": g})
    return {"type": "FeatureCollection", "features": feats}


def vectors(c, work):
    for i in range(20):
        kinds = R.choice([["Point"], ["LineString"], ["Polygon"], ["Point", "LineString", "Polygon"]])
        n = R.randint(1, 300)
        src = os.path.join(work, f"v{i}.geojson")
        json.dump(random_features(n, kinds), open(src, "w"))
        single = kinds if len(kinds) == 1 else ["Point"]
        srcs = os.path.join(work, f"s{i}.geojson")
        json.dump(random_features(n, single), open(srcs, "w"))
        epsg = R.choice(CRS)
        t = ["-t_srs", f"EPSG:{epsg}"]
        jobs = [
            ("GeoJSON", f"v{i}.geojson", src, t if R.random() < 0.5 else ["-lco", "RFC7946=YES"]),
            ("GeoJSONSeq", f"v{i}.geojsons", src, ["-lco", "RS=YES"]),
            ("KML", f"v{i}.kml", src, []),
            ("LIBKML", f"v{i}.kmz", src, []),
            ("GML", f"v{i}.gml", src, ["-dsco", R.choice(["FORMAT=GML3.2", "FORMAT=GML2", "FORMAT=GML3"])] + t),
            ("FlatGeobuf", f"v{i}.fgb", srcs, t + (["-lco", "SPATIAL_INDEX=NO"] if R.random() < 0.3 else [])),
            ("GPKG", f"v{i}.gpkg", src, t),
            ("ESRI Shapefile", f"v{i}.shp", srcs, t),
            ("CSV", f"v{i}.csv", src, ["-lco", "GEOMETRY=AS_WKT"]),
            ("MapInfo File", f"v{i}.mif", src, ["-dsco", "FORMAT=MIF"]),
            ("GeoRSS", f"v{i}.georss", srcs if single == ["Point"] else src, ["-dsco", "USE_EXTENSIONS=YES"]),
        ]
        if single == ["Point"] or kinds == ["LineString"]:
            jobs.append(("GPX", f"v{i}.gpx", srcs, ["-nln", "waypoints" if single == ["Point"] else "routes"]))
        for drv, name, s, extra in jobs:
            try:
                sh("ogr2ogr", "-f", drv, os.path.join(c, name), s, *extra)
            except subprocess.CalledProcessError:
                pass
        # The FileGDB layer table.
        gdb = os.path.join(work, f"v{i}.gdb")
        try:
            sh("ogr2ogr", "-f", "OpenFileGDB", gdb, srcs, "-unsetFid", *t)
            tables = sorted(glob.glob(os.path.join(gdb, "a*.gdbtable")))
            shutil.copy(tables[-1], os.path.join(c, f"v{i}.gdbtable"))
            json.dump({"gdb": gdb}, open(os.path.join(c, f"v{i}.gdbtable.src"), "w"))
        except subprocess.CalledProcessError:
            pass
    for f in glob.glob(os.path.join(c, "*")):
        if f.endswith((".xsd", ".gfs")):
            os.remove(f)


def rasters(c):
    from osgeo import gdal, osr

    gdal.UseExceptions()
    for i in range(20):
        w, h, b = R.randint(8, 300), R.randint(8, 300), R.choice([1, 1, 3])
        epsg = R.choice(CRS)
        dt = R.choice([gdal.GDT_Byte, gdal.GDT_Int16, gdal.GDT_Float32, gdal.GDT_UInt16])
        ds = gdal.GetDriverByName("MEM").Create("", w, h, b, dt)
        s = osr.SpatialReference()
        s.ImportFromEPSG(epsg)
        if epsg in (4326, 4258):
            gt = (R.uniform(2, 8), R.uniform(0.0001, 0.01), 0, R.uniform(50, 56), 0, -R.uniform(0.0001, 0.01))
        elif epsg == 3857:
            gt = (R.uniform(2e5, 9e5), R.uniform(1, 50), 0, R.uniform(6.4e6, 7.5e6), 0, -R.uniform(1, 50))
        else:
            gt = (R.uniform(3e5, 7e5), R.uniform(1, 50), 0, R.uniform(5.5e6, 6.2e6), 0, -R.uniform(1, 50))
        ds.SetGeoTransform(gt)
        ds.SetProjection(s.ExportToWkt())
        if R.random() < 0.3:
            ds.SetMetadataItem("AREA_OR_POINT", "Point")
        kind = R.choice(["gtiff", "cog", "bigtiff", "tiled"])
        opts = {"gtiff": ["COMPRESS=" + R.choice(["NONE", "DEFLATE", "LZW"])], "bigtiff": ["BIGTIFF=YES"],
                "tiled": ["TILED=YES", "BLOCKXSIZE=16", "BLOCKYSIZE=16"], "cog": ["COMPRESS=DEFLATE", "BLOCKSIZE=64"]}[kind]
        if kind == "cog" and R.random() < 0.5:
            ds.BuildOverviews("NEAREST", [2, 4])
        gdal.Translate(os.path.join(c, f"r{i}.tif"), ds, format="COG" if kind == "cog" else "GTiff", creationOptions=opts)
        if i < 8:
            gdal.Translate(os.path.join(c, f"r{i}.asc"), ds, format="AAIGrid", bandList=[1])
    for f in glob.glob(os.path.join(c, "*.aux.xml")) + glob.glob(os.path.join(c, "*.prj")):
        os.remove(f)


def points(c):
    import laspy
    import numpy as np
    import pyproj

    for i in range(16):
        n = R.randint(1, 3000)
        version, fmt = R.choice([("1.2", 0), ("1.2", 1), ("1.2", 3), ("1.4", 6), ("1.4", 7), ("1.3", 1)])
        hdr = laspy.LasHeader(point_format=fmt, version=version)
        hdr.scales = [0.01, 0.01, 0.01]
        hdr.offsets = [500000, 5800000, 0]
        if version == "1.4" and R.random() < 0.7:
            hdr.add_crs(pyproj.CRS.from_epsg(R.choice([32631, 25832])))
        las = laspy.LasData(hdr)
        las.x = 500000 + np.random.default_rng(i).random(n) * R.uniform(10, 1000)
        las.y = 5800000 + np.random.default_rng(i + 1).random(n) * R.uniform(10, 1000)
        las.z = np.random.default_rng(i + 2).random(n) * 50
        ext = "laz" if R.random() < 0.4 else "las"
        p = os.path.join(c, f"p{i}.{ext}")
        las.write(p, laz_backend=laspy.LazBackend.Lazrs if ext == "laz" else None)
        if i < 4:
            subprocess.run(["micromamba", "run", "-p", "/opt/pdal", "pdal", "translate", p, os.path.join(c, f"p{i}.copc.laz")], check=True)
    import pye57

    for i in range(4):
        e = pye57.E57(os.path.join(c, f"e{i}.e57"), mode="w")
        for s in range(R.randint(1, 3)):
            m = R.randint(1, 500)
            rng = np.random.default_rng(i * 10 + s)
            e.write_scan_raw({"cartesianX": rng.random(m), "cartesianY": rng.random(m), "cartesianZ": rng.random(m)}, name=f"scan {s}")
        e.close()


def tracks(c):
    import datetime as dt

    from aerofiles.igc import Writer
    from fit_tool.fit_file_builder import FitFileBuilder
    from fit_tool.profile.messages.file_id_message import FileIdMessage
    from fit_tool.profile.messages.record_message import RecordMessage
    from fit_tool.profile.profile_type import FileType, Manufacturer
    import pynmea2

    t0 = dt.datetime(2025, 9, 1, 6, tzinfo=dt.timezone.utc)
    for i in range(10):
        n = R.randint(1, 400)
        pts = [(R.uniform(-60, 60), R.uniform(-170, 170)) for _ in range(1)]
        la, lo = pts[0]
        fixes = [(la + k * 1e-4, lo + k * 1e-4, R.uniform(0, 500), t0 + dt.timedelta(seconds=k)) for k in range(n)]
        b = FitFileBuilder(auto_define=True, min_string_size=50)
        m = FileIdMessage()
        m.type = FileType.ACTIVITY
        m.manufacturer = Manufacturer.DEVELOPMENT.value
        m.time_created = round(t0.timestamp() * 1000)
        b.add(m)
        for a, o, e, t in fixes:
            r = RecordMessage()
            r.timestamp = round(t.timestamp() * 1000)
            r.position_lat, r.position_long, r.altitude = a, o, e
            b.add(r)
        b.build().to_file(os.path.join(c, f"t{i}.fit"))
        with open(os.path.join(c, f"t{i}.igc"), "wb") as f:
            w = Writer(f)
            w.write_headers({"manufacturer_code": "XXX", "logger_id": "ABC", "date": t0.date(), "pilot": "P", "glider_type": "G",
                             "glider_id": "D-X", "gps_datum": "WGS-1984", "firmware_version": "1", "hardware_version": "1",
                             "logger_type": "L", "gps_receiver": "G", "pressure_sensor": "P", "fix_accuracy": 50,
                             "competition_id": "X", "competition_class": "C"})
            for a, o, e, t in fixes:
                w.write_fix(t.time(), latitude=a, longitude=o, valid=True, pressure_alt=int(e), gps_alt=int(e))
        rows = []
        for a, o, e, t in fixes:
            lat = f"{int(abs(a)):02d}{(abs(a) % 1) * 60:07.4f}"
            lon = f"{int(abs(o)):03d}{(abs(o) % 1) * 60:07.4f}"
            rows.append(str(pynmea2.GGA("GP", "GGA", (t.strftime("%H%M%S.00"), lat, "N" if a >= 0 else "S", lon, "E" if o >= 0 else "W", "1", "08", "0.9", f"{e:.1f}", "M", "", "", "", ""))))
        open(os.path.join(c, f"t{i}.nmea"), "w").write("\r\n".join(rows) + "\r\n")


def osm(c, work):
    for i in range(6):
        lines = []
        n = R.randint(1, 500)
        x0, y0 = R.uniform(-170, 170), R.uniform(-60, 60)
        for k in range(1, n + 1):
            lines.append(f"n{k} v1 dV c1 t2025-09-01T06:00:00Z i1 ua T x{x0 + R.uniform(0, 0.1):.7f} y{y0 + R.uniform(0, 0.1):.7f}")
        for w in range(R.randint(0, 20)):
            nodes = ",".join(f"n{R.randint(1, n)}" for _ in range(3))
            lines.append(f"w{w + 1} v1 dV c1 t2025-09-01T06:00:00Z i1 ua Thighway=path N{nodes}")
        opl = os.path.join(work, f"o{i}.opl")
        open(opl, "w").write("\n".join(lines) + "\n")
        sh("osmium", "cat", opl, "-o", os.path.join(c, f"o{i}.osm"), "--overwrite")
        sh("osmium", "cat", opl, "-o", os.path.join(c, f"o{i}.osm.pbf"), "--overwrite", "-f", R.choice(["pbf", "pbf,pbf_dense_nodes=false"]))


def wkx(c):
    import shapely
    from shapely import wkb, wkt

    for i in range(8):
        gj = random_features(R.randint(1, 20), ["Point", "LineString", "Polygon"])
        geoms = [shapely.geometry.shape(f["geometry"]) for f in gj["features"]]
        open(os.path.join(c, f"g{i}.wkt"), "w").write("\n".join(wkt.dumps(g) for g in geoms) + "\n")
        open(os.path.join(c, f"g{i}.wkb"), "wb").write(b"".join(wkb.dumps(g, byte_order=R.choice([0, 1])) for g in geoms))


def facts(p):
    from osgeo import gdal, ogr

    gdal.UseExceptions()
    name = os.path.basename(p)
    low = name.lower()
    if low.endswith((".tif", ".asc")):
        info = gdal.Info(p, format="json")
        info = json.loads(info) if isinstance(info, str) else info
        f = {"size": info["size"], "bands": len(info["bands"]), "geotransform": info["geoTransform"]}
        epsg = info.get("stac", {}).get("proj:epsg")
        if epsg and low.endswith(".tif"):
            f["epsg"] = epsg
        if low.endswith(".tif"):
            f["overviews"] = len(info["bands"][0].get("overviews", []))
            from osgeo_utils.samples.validate_cloud_optimized_geotiff import ValidateCloudOptimizedGeoTIFFException, validate

            try:
                _, errors, _ = validate(p, full_check=True)
                f["cog"] = not errors
            except ValidateCloudOptimizedGeoTIFFException:
                f["cog"] = False
        return f
    if low.endswith((".las", ".laz")):
        import laspy

        with laspy.open(p) as r:
            h = r.header
            f = {"points": h.point_count, "point_format": h.point_format.id, "version": f"{h.version.major}.{h.version.minor}",
                 "bbox": [round(v, 3) for v in (h.mins[0], h.mins[1], h.maxs[0], h.maxs[1])]}
            crs = h.parse_crs()
            if crs is not None and crs.to_epsg():
                f["epsg"] = crs.to_epsg()
            return f
    if low.endswith(".e57"):
        import pye57

        e = pye57.E57(p)
        return {"scans": e.scan_count, "points": sum(e.get_header(i).point_count for i in range(e.scan_count))}
    if low.endswith(".fit"):
        from fit_tool.fit_file import FitFile
        from fit_tool.profile.messages.record_message import RecordMessage

        ff = FitFile.from_file(p)
        return {"fixes": sum(1 for r in ff.records if isinstance(r.message, RecordMessage))}
    if low.endswith(".igc"):
        from aerofiles.igc import Reader

        with open(p) as fh:
            return {"fixes": len(Reader().read(fh)["fix_records"][1])}
    if low.endswith(".nmea"):
        return {"sentences": sum(1 for l in open(p) if l.startswith("$"))}
    if low.endswith((".osm", ".osm.pbf")):
        v = json.loads(sh("osmium", "fileinfo", "-e", "-j", p))
        b = v["data"]["bbox"]
        return {"elements": {"nodes": v["data"]["count"]["nodes"], "ways": v["data"]["count"]["ways"], "relations": v["data"]["count"]["relations"]},
                "bbox": [round(x, 6) for x in b]}
    if low.endswith((".wkt", ".wkb")):
        import shapely
        from shapely import wkb, wkt

        if low.endswith(".wkt"):
            geoms = [wkt.loads(l) for l in open(p) if l.strip()]
        else:
            data, geoms = open(p, "rb").read(), []
            # Concatenated WKB: shapely reads one at a time from its own length.
            while data:
                g = wkb.loads(data)
                geoms.append(g)
                data = data[len(wkb.dumps(g, byte_order=data[0])):]
        b = shapely.total_bounds(geoms)
        return {"geometries": len(geoms), "bbox": [round(v, 6) for v in b]}
    if low.endswith(".shx"):
        ds = ogr.Open(p[:-4] + ".shp")
        return {"records": ds.GetLayer(0).GetFeatureCount()}
    if low.endswith(".gdbtable"):
        src = json.load(open(p + ".src"))["gdb"]
        ds = ogr.Open(src)
        lyr = ds.GetLayer(0)
        return {"rows": lyr.GetFeatureCount(), "fields": lyr.GetLayerDefn().GetFieldCount() + 2}
    # Vector formats through OGR.
    ds = ogr.Open(p)
    if ds is None:
        return None
    count, ext, epsg = 0, None, None
    for lyr in ds:
        if low.endswith(".gpx") and lyr.GetName() in ("route_points", "track_points"):
            continue
        n = lyr.GetFeatureCount()
        count += n
        if n:
            e = lyr.GetExtent()
            ext = e if ext is None else (min(ext[0], e[0]), max(ext[1], e[1]), min(ext[2], e[2]), max(ext[3], e[3]))
            s = lyr.GetSpatialRef()
            if s is not None and s.GetAuthorityCode(None):
                epsg = int(s.GetAuthorityCode(None))
    f = {"features": count}
    if ext:
        f["bbox"] = [round(ext[0], 6), round(ext[2], 6), round(ext[1], 6), round(ext[3], 6)]
    if epsg and low.endswith((".fgb",)):
        f["epsg"] = epsg
    return f


def cmd_expect(out):
    c = os.path.join(out, "corpus")
    work = os.path.join(out, "work")
    for d in (c, work):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    vectors(c, work)
    rasters(c)
    points(c)
    tracks(c)
    osm(c, work)
    wkx(c)
    rows = []
    for name in sorted(os.listdir(c)):
        p = os.path.join(c, name)
        # Sidecars are read by OGR with their main file, not compared alone.
        if name.endswith((".src", ".dbf", ".prj", ".cpg", ".mid")) or not os.path.isfile(p):
            continue
        try:
            f = facts(p)
        except Exception as e:
            f = {"oracle_error": f"{type(e).__name__}: {e}"[:200]}
        if f is not None:
            rows.append({"path": os.path.relpath(p, out), "facts": f})
    with open(os.path.join(out, "expected.jsonl"), "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(f"{len(rows)} files written to {out}/expected.jsonl")


def close(a, b, tol):
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(close(x, y, tol) for x, y in zip(a, b))
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(a - b) <= tol * max(1.0, abs(a))
    return a == b


def got(fid, d, want):
    g = {}
    for k in want:
        if fid == "geopackage" and k in ("features", "bbox"):
            app = d.get("application", {})
            contents = [x for x in app.get("contents", []) if x.get("data_type") == "features"]
            names = {x.get("table_name") for x in contents}
            if k == "features":
                g[k] = sum(t.get("rows", 0) for t in d.get("tables", []) if t.get("name") in names)
            elif contents:
                g[k] = [min(x["min_x"] for x in contents), min(x["min_y"] for x in contents), max(x["max_x"] for x in contents), max(x["max_y"] for x in contents)]
        elif k == "features":
            g[k] = next((d[x] for x in ("features", "placemarks", "feature_members", "items", "records", "rows", "waypoints") if x in d), None)
            if fid == "mapinfo":
                g[k] = sum(d.get("objects", {}).values())
            if fid == "gpx":
                g[k] = d.get("waypoints", 0) + d.get("routes", 0) + d.get("tracks", 0)
            if fid == "shapefile":
                g[k] = d.get("records")
        elif k == "epsg":
            g[k] = d.get("crs", {}).get("epsg")
        elif k == "size":
            g[k] = [d.get("width", d.get("columns")), d.get("height", d.get("rows"))]
        elif k == "overviews":
            g[k] = len(d.get("overviews", []))
        elif k == "cog":
            g[k] = d.get("cog", {}).get("conforms")
        elif k == "version":
            g[k] = d.get("las_version")
        elif k == "fields":
            g[k] = d.get("field_count")
        elif k == "bbox" and fid in ("ascii_grid",):
            g[k] = d.get("bbox")
        else:
            g[k] = d.get(k)
    return g


def cmd_check(out, whiff):
    rows = [json.loads(l) for l in open(os.path.join(out, "expected.jsonl"))]
    totals, fails, errors = {}, {}, 0
    for row in rows:
        want = dict(row["facts"])
        if "oracle_error" in want:
            errors += 1
            continue
        path = os.path.join(out, row["path"])
        r = json.loads(subprocess.run([whiff, path], capture_output=True).stdout or "{}")
        fid = r.get("identification", {}).get("format")
        key = fid or "?"
        totals[key] = totals.get(key, 0) + 1
        d = r.get("format", {}).get(fid)
        if d is None:
            fails.setdefault(key, []).append((path, [("format", "section", fid)]))
            continue
        # Rasters: the geotransform and size give the bounds; ASCII grids
        # carry no CRS, PixelIsPoint shifts by half a pixel.
        if "geotransform" in want and "geotransform" in d:
            pass
        elif "geotransform" in want:
            gt = want.pop("geotransform")
            w, h = want["size"]
            want["bbox"] = [gt[0], gt[3] + h * gt[5], gt[0] + w * gt[1], gt[3]]
        if fid == "ascii_grid":
            want.pop("bands", None)
        if fid == "geotiff":
            want.pop("bands", None) if d.get("bands") == want.get("bands") else None
        if fid in ("kml", "kmz", "gpx", "georss", "csv_geo", "geojson_seq") or (fid == "geojson" and "epsg" not in want):
            # Formats in WGS84: OGR's extents are the same numbers.
            pass
        if fid in ("mapinfo",):
            want.pop("bbox", None)  # MIF bounds come from the objects, OGR's from the header
        g = got(fid, d, want)
        bad = [(k, v, g.get(k)) for k, v in want.items() if not close(v, g.get(k), 1e-6)]
        if bad:
            fails.setdefault(key, []).append((path, bad))
    for k in sorted(totals):
        n, f = totals[k], len(fails.get(k, []))
        print(f"{k:16} {n - f:4}/{n:<4} agree")
    print(f"oracle could not read {errors} files")
    for k, items in sorted(fails.items()):
        for path, bad in items[: int(os.environ.get("SHOW", "4"))]:
            print(f"  {path}")
            for key, v, g in bad[:4]:
                print(f"      {key}: oracle {json.dumps(v)[:160]} whiff {json.dumps(g)[:160]}")


if __name__ == "__main__":
    if sys.argv[1] == "expect":
        cmd_expect(sys.argv[2])
    else:
        cmd_check(sys.argv[2], sys.argv[3])
