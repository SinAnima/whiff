"""Compare whiff's 3D and CAD reports with each format's own library.

    # in `whiff-cad`: build a corpus and the expected facts
    python3 cad_oracle.py expect OUT_DIR
    # on the host
    python3 cad_oracle.py check OUT_DIR WHIFF_BINARY

The corpus is generated: random meshes (trimesh) in every mesh format,
assimp conversions (3DS, X3D, FBX), DXF of every release (ezdxf), STEP and
IGES solids (cadquery / OpenCASCADE), IFC models (ifcopenshell), USD
stages, chip layouts (KLayout), C3D captures, VOX models and OpenVDB
grids. Expected facts come from trimesh, assimp, ezdxf, OpenCASCADE,
ifcopenshell, usd-core, KLayout, c3d, py-vox-io and OpenVDB. Nothing here
ships with whiff.
"""

import json
import os
import random
import re
import shutil
import subprocess
import sys

R = random.Random(13)


def run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def generate(c):
    import numpy as np
    import trimesh

    for i in range(16):
        kind = R.choice(["ico", "box", "cyl", "torus"])
        if kind == "ico":
            m = trimesh.creation.icosphere(subdivisions=R.randint(0, 3), radius=R.uniform(0.5, 50))
        elif kind == "box":
            m = trimesh.creation.box(extents=[R.uniform(0.1, 100) for _ in range(3)])
        elif kind == "cyl":
            m = trimesh.creation.cylinder(radius=R.uniform(0.1, 10), height=R.uniform(0.1, 30), sections=R.randint(3, 64))
        else:
            m = trimesh.creation.torus(R.uniform(2, 10), R.uniform(0.2, 1.5), major_sections=R.randint(8, 32), minor_sections=R.randint(4, 16))
        m.apply_translation([R.uniform(-100, 100) for _ in range(3)])
        stem = os.path.join(c, f"m{i}")
        m.export(stem + ".obj")
        m.export(stem + ".stl") if i % 2 else m.export(stem + ".stl", file_type="stl_ascii")
        m.export(stem + ".ply", encoding="ascii" if i % 3 == 0 else "binary")
        m.export(stem + ".off")
        m.export(stem + ".glb")
        m.export(stem + ".3mf")
        open(stem + ".dae", "wb").write(trimesh.exchange.dae.export_collada(m))
        g = trimesh.exchange.gltf.export_gltf(trimesh.Scene(m), embed_buffers=True)
        open(stem + ".gltf", "wb").write(g["model.gltf"])
        if i < 8:
            for fmt, ext in (("3ds", "3ds"), ("x3d", "x3d"), ("fbx", "fbx"), ("fbxa", "fbx")):
                out = f"{stem}-{fmt}.{ext}"
                try:
                    run("assimp", "export", stem + ".obj", out, f"-f{fmt}")
                except subprocess.CalledProcessError:
                    pass
    for f in os.listdir(c):
        if f.endswith(".mtl"):
            os.remove(os.path.join(c, f))
    # DXF of every release.
    import ezdxf

    for i, ver in enumerate(["R12", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018"] * 2):
        doc = ezdxf.new(ver)
        msp = doc.modelspace()
        for k in range(R.randint(1, 6)):
            doc.layers.add(f"L{k}")
        for k in range(R.randint(1, 40)):
            layer = f"L{R.randint(0, 0)}"
            t = R.choice(["line", "circle", "text", "point"])
            if t == "line":
                msp.add_line((R.random(), R.random()), (R.random(), R.random()), dxfattribs={"layer": layer})
            elif t == "circle":
                msp.add_circle((R.random(), R.random()), R.random() + 0.1)
            elif t == "text":
                msp.add_text(f"label {k}")
            else:
                msp.add_point((R.random(), R.random()))
        p = os.path.join(c, f"d{i}.dxf")
        doc.saveas(p, fmt="bin" if i >= 7 and ver != "R12" else "asc")
    # STEP and IGES solids.
    import cadquery as cq
    from OCP.IGESControl import IGESControl_Controller, IGESControl_Writer

    IGESControl_Controller.Init_s()
    for i in range(8):
        w = cq.Workplane("XY").box(R.uniform(1, 50), R.uniform(1, 50), R.uniform(1, 50))
        for _ in range(R.randint(0, 3)):
            w = w.faces(">Z").workplane().hole(R.uniform(0.2, 0.9))
        cq.exporters.export(w, os.path.join(c, f"s{i}.step"))
        iw = IGESControl_Writer("MM", 1)
        iw.AddShape(w.val().wrapped)
        iw.ComputeModel()
        iw.Write(os.path.join(c, f"s{i}.igs"))
    # IFC models.
    import ifcopenshell
    import ifcopenshell.api

    for i in range(6):
        f = ifcopenshell.api.run("project.create_file", version="IFC4")
        p = ifcopenshell.api.run("root.create_entity", f, ifc_class="IfcProject", name=f"Project {i}")
        site = ifcopenshell.api.run("root.create_entity", f, ifc_class="IfcSite", name=f"Site {i}")
        ifcopenshell.api.run("aggregate.assign_object", f, relating_object=p, products=[site])
        for k in range(R.randint(0, 10)):
            ifcopenshell.api.run("root.create_entity", f, ifc_class="IfcWall", name=f"Wall {k}")
        f.write(os.path.join(c, f"b{i}.ifc"))
    # USD stages.
    from pxr import Usd, UsdGeom

    for i in range(6):
        s = Usd.Stage.CreateNew(os.path.join(c, f"u{i}.{'usda' if i % 2 else 'usdc'}"))
        UsdGeom.SetStageUpAxis(s, R.choice([UsdGeom.Tokens.y, UsdGeom.Tokens.z]))
        UsdGeom.SetStageMetersPerUnit(s, R.choice([1.0, 0.01]))
        root = UsdGeom.Xform.Define(s, "/Root")
        s.SetDefaultPrim(root.GetPrim())
        for k in range(R.randint(0, 20)):
            R.choice([UsdGeom.Cube, UsdGeom.Sphere, UsdGeom.Xform]).Define(s, f"/Root/p{k}")
        s.GetRootLayer().Save()
    # Chip layouts.
    import klayout.db as kdb

    for i in range(6):
        ly = kdb.Layout()
        ly.dbu = R.choice([0.001, 0.0005])
        top = ly.create_cell(f"TOP{i}")
        for k in range(R.randint(1, 5)):
            sub = ly.create_cell(f"C{i}_{k}")
            sub.shapes(ly.layer(R.randint(1, 10), 0)).insert(kdb.Box(0, 0, R.randint(100, 10000), R.randint(100, 10000)))
            top.insert(kdb.CellInstArray(sub.cell_index(), kdb.Trans(kdb.Point(R.randint(0, 50000), R.randint(0, 50000)))))
        ly.write(os.path.join(c, f"g{i}.gds"))
    # C3D, VOX, VDB.
    import c3d
    import numpy as np

    for i in range(6):
        n, frames, rate = R.randint(1, 30), R.randint(1, 200), R.choice([50.0, 100.0, 120.0, 250.0])
        w = c3d.Writer(point_rate=rate)
        w.set_point_labels([f"M{k}" for k in range(n)])
        for _ in range(frames):
            w.add_frames([(np.zeros((n, 5), dtype=np.float32), np.zeros((0, 0), dtype=np.float32))])
        with open(os.path.join(c, f"c{i}.c3d"), "wb") as fh:
            w.write(fh)
    from pyvox.models import Vox
    from pyvox.writer import VoxWriter

    for i in range(6):
        d = np.zeros((R.randint(1, 30), R.randint(1, 30), R.randint(1, 30)), dtype=np.uint8)
        d[np.random.default_rng(i).random(d.shape) < 0.3] = 1
        VoxWriter(os.path.join(c, f"v{i}.vox"), Vox.from_dense(d)).write()
    script = os.path.join(c, "..", "vdb.py")
    open(script, "w").write(f"""
import pyopenvdb as vdb, random
R = random.Random(5)
for i in range(4):
    grids = []
    for k in range(R.randint(1, 4)):
        g = vdb.FloatGrid(); g.name = f"g{{k}}"; grids.append(g)
    vdb.write({c!r} + f"/w{{i}}.vdb", grids=grids, metadata={{"creator": f"run {{i}}"}})
""")
    subprocess.run(["/usr/bin/python3", script], check=True)


def facts(p):
    low = p.lower()
    ext = os.path.splitext(low)[1]
    import trimesh

    if ext in (".obj", ".stl", ".ply", ".off", ".glb", ".gltf", ".3mf", ".dae") and not re.search(r"-(3ds|x3d|fbx|fbxa)\.", low):
        m = trimesh.load(p, force="mesh", process=False)
        b = m.bounds
        # OFF and PLY report faces (polygons); these meshes are triangles.
        key = "faces" if ext in (".off", ".ply") else "triangles"
        f = {"bounds": [[round(float(v), 4) for v in b[0]], [round(float(v), 4) for v in b[1]]], key: len(m.faces)}
        if ext in (".off", ".ply", ".obj", ".3mf"):
            f["vertices"] = len(m.vertices)
        return f
    if ext in (".3ds", ".x3d", ".fbx"):
        info = run("assimp", "info", p)
        g = lambda k: int(re.search(rf"{k}:\s+(\d+)", info).group(1))
        # X3D and FBX: identification only (whiff counts their nodes, not faces).
        return {"vertices": g("Vertices"), "faces": g("Faces")} if ext == ".3ds" else {}
    if ext == ".dxf":
        import ezdxf

        doc = ezdxf.readfile(p)
        counts = {}
        for e in doc.modelspace():
            counts[e.dxftype()] = counts.get(e.dxftype(), 0) + 1
        return {"acadver": doc.dxfversion, "layers": sorted(l.dxf.name for l in doc.layers), "entities": counts}
    if ext in (".step", ".igs"):
        if ext == ".step":
            from OCP.STEPControl import STEPControl_Reader

            r = STEPControl_Reader()
        else:
            from OCP.IGESControl import IGESControl_Reader

            r = IGESControl_Reader()
        r.ReadFile(p)
        return {"entities": r.WS().Model().NbEntities()}
    if ext == ".ifc":
        import ifcopenshell

        f = ifcopenshell.open(p)
        return {"schemas": [f.schema], "project": [x.Name for x in f.by_type("IfcProject")], "entities": len(list(f))}
    if ext in (".usda", ".usdc"):
        from pxr import Usd, UsdGeom

        s = Usd.Stage.Open(p)
        # USDC tokens are compressed: whiff reads its sections only.
        if ext == ".usdc":
            return {"sections_present": True}
        return {"upAxis": str(UsdGeom.GetStageUpAxis(s)), "metersPerUnit": UsdGeom.GetStageMetersPerUnit(s), "prims": len(list(s.TraverseAll()))}
    if ext == ".gds":
        import klayout.db as kdb

        ly = kdb.Layout()
        ly.read(p)
        return {"cells": ly.cells(), "layers": sorted(ly.get_info(i).layer for i in ly.layer_indexes())}
    if ext == ".c3d":
        import c3d

        with open(p, "rb") as fh:
            r = c3d.Reader(fh)
            return {"points": r.point_used, "frames": r.last_frame - r.first_frame + 1, "frame_rate": r.point_rate}
    if ext == ".vox":
        from pyvox.parser import VoxParser

        v = VoxParser(p).parse()
        return {"models": len(v.models), "voxels": sum(len(m.voxels) for m in v.models)}
    if ext == ".vdb":
        out = run("/usr/bin/python3", "-c", f"import pyopenvdb as v, json; g, m = v.readAll({p!r}); print(json.dumps([x.name for x in g]))")
        return {"grid_names": json.loads(out)}
    return None


def cmd_expect(out):
    c = os.path.join(out, "corpus")
    shutil.rmtree(c, ignore_errors=True)
    os.makedirs(c)
    generate(c)
    rows = []
    for name in sorted(os.listdir(c)):
        p = os.path.join(c, name)
        try:
            f = facts(p)
        except Exception as e:
            f = {"oracle_error": f"{type(e).__name__}: {e}"[:200]}
        if f is not None:
            rows.append({"path": os.path.relpath(p, out), "facts": f})
    with open(os.path.join(out, "expected.jsonl"), "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, default=lambda o: o.item() if hasattr(o, "item") else str(o)) + "\n")
    print(f"{len(rows)} files written to {out}/expected.jsonl")


def close(a, b, tol=1e-3):
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(close(x, y, tol) for x, y in zip(a, b))
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(a - b) <= tol * max(1.0, abs(a))
    return a == b


def got(fid, d, k, want):
    if k == "bounds":
        b = d.get("bounds") or {}
        return [b.get("min"), b.get("max")]
    if k == "acadver":
        return (d.get("header") or {}).get("acadver")
    if k == "layers" and fid in ("dxf", "dxf_binary"):
        return sorted(d.get("layers", []))
    if k == "entities" and fid in ("dxf", "dxf_binary"):
        e = d.get("entities", {})
        # ezdxf counts the model space; whiff the ENTITIES section (the same).
        return {t: n for t, n in e.items() if t not in ("SEQEND", "VERTEX")}
    if k == "layers" and fid == "gdsii":
        return d.get("layers")
    if k == "faces" and fid in ("3ds",):
        return d.get("faces")
    if k == "upAxis":
        return (d.get("layer_metadata") or {}).get("upAxis")
    if k == "metersPerUnit":
        v = (d.get("layer_metadata") or {}).get("metersPerUnit")
        return float(v) if v is not None else None
    if k == "sections_present":
        return bool(d.get("sections"))
    if k == "grid_names":
        return [g.split(" (")[0] for g in d.get("grids", [])]
    if k == "vertices" and fid == "3mf":
        return d.get("vertices")
    return d.get(k)


def cmd_check(out, whiff):
    rows = [json.loads(l) for l in open(os.path.join(out, "expected.jsonl"))]
    totals, fails, errors = {}, {}, 0
    for row in rows:
        want = row["facts"]
        if "oracle_error" in want:
            errors += 1
            continue
        path = os.path.join(out, row["path"])
        r = json.loads(subprocess.run([whiff, path], capture_output=True).stdout or "{}")
        fid = r.get("identification", {}).get("format")
        totals[fid] = totals.get(fid, 0) + 1
        d = r.get("format", {}).get(fid)
        if d is None:
            fails.setdefault(fid, []).append((path, [("format", "section", fid)]))
            continue
        bad = [(k, v, got(fid, d, k, v)) for k, v in want.items() if not close(v, got(fid, d, k, v))]
        if bad:
            fails.setdefault(fid, []).append((path, bad))
    for k in sorted(totals, key=str):
        n, f = totals[k], len(fails.get(k, []))
        print(f"{str(k):12} {n - f:4}/{n:<4} agree")
    print(f"oracle could not read {errors} files")
    for k, items in sorted(fails.items(), key=lambda x: str(x[0])):
        for path, bad in items[: int(os.environ.get("SHOW", "4"))]:
            print(f"  {path}")
            for key, v, g in bad[:4]:
                print(f"      {key}: oracle {json.dumps(v)[:200]} whiff {json.dumps(g)[:200]}")


if __name__ == "__main__":
    if sys.argv[1] == "expect":
        cmd_expect(sys.argv[2])
    else:
        cmd_check(sys.argv[2], sys.argv[3])
