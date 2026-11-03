"""Make whiff's 3D and CAD fixtures (run by scripts/fixtures/cad.sh in `whiff-cad`).

    python3 craft_cad.py OUT_DIR [STEP ...]

Everything describes a fictitious Saltmere Harbour: a navigation buoy, a
pier section, the lighthouse, a mooring bracket, the harbour office, the
buoy light's circuit board and a test chip. Each format is written by its
own tool where one exists (trimesh, assimp, Blender, usd-core, py-vox-io,
OpenVDB, c3d, PrusaSlicer, draco_encoder, cadquery / OpenCASCADE, ezdxf,
ifcopenshell, gerber-writer, kiutils, KLayout); IES, EULUMDAT, LDraw,
Excellon, OpenSCAD and CNC programs are written here from their
specifications.
"""

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


def run(*cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def out(fmt, name):
    d = os.path.join(OUT, fmt)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def want(step):
    return not STEPS or step in STEPS


def meshes():
    import numpy as np
    import trimesh

    buoy = trimesh.creation.cylinder(radius=0.6, height=1.4, sections=24)
    buoy.apply_translation([0, 0, 0.7])
    cone = trimesh.creation.cone(radius=0.4, height=0.8, sections=24)
    cone.apply_translation([0, 0, 1.4])
    buoy = trimesh.util.concatenate([buoy, cone])
    buoy.metadata["name"] = "Saltmere buoy"
    pier = trimesh.creation.box(extents=[12.0, 2.5, 0.6])
    pier.apply_translation([6.0, 0, 1.2])
    scene = trimesh.Scene({"buoy": buoy, "pier": pier})
    p = os.path.join(TMP, "buoy.obj")
    buoy.export(p)
    shutil.copy(p, out("obj", "buoy-trimesh.obj"))
    scene.export(out("obj", "harbour.obj"))
    for f in glob.glob(out("obj", "*.mtl")):
        shutil.move(f, out("mtl", os.path.basename(f)))
    buoy.export(out("stl", "buoy-binary.stl"))
    pier.export(out("stl", "pier-ascii.stl"), file_type="stl_ascii")
    buoy.export(out("ply", "buoy-binary.ply"))
    pier.export(out("ply", "pier-ascii.ply"), encoding="ascii")
    buoy.export(out("off", "buoy.off"))
    pier.export(out("off", "pier.off"))
    scene.export(out("3mf", "harbour.3mf"))
    buoy.export(out("3mf", "buoy.3mf"))
    scene.export(out("glb", "harbour.glb"))
    pier.export(out("glb", "pier.glb"))
    # glTF JSON with an embedded buffer (data URI).
    gltf = trimesh.exchange.gltf.export_gltf(scene, embed_buffers=True)
    open(out("gltf", "harbour.gltf"), "wb").write(gltf["model.gltf"])
    gltf2 = trimesh.exchange.gltf.export_gltf(trimesh.Scene({"pier": pier}), embed_buffers=True)
    open(out("gltf", "pier.gltf"), "wb").write(gltf2["model.gltf"])
    open(out("collada", "buoy-trimesh.dae"), "wb").write(trimesh.exchange.dae.export_collada(buoy))
    # assimp: COLLADA, 3DS, X3D, FBX binary and ASCII from the OBJ.
    src = out("obj", "harbour.obj")
    run("assimp", "export", src, out("collada", "harbour-assimp.dae"), "-fcollada")
    # assimp writes an MTL beside its OBJ.
    run("assimp", "export", src, os.path.join(TMP, "harbour-assimp.obj"), "-fobj")
    run("assimp", "export", p, os.path.join(TMP, "buoy-assimp.obj"), "-fobj")
    for f in glob.glob(os.path.join(TMP, "*.mtl")):
        shutil.copy(f, out("mtl", os.path.basename(f)))
    run("assimp", "export", src, out("3ds", "harbour.3ds"), "-f3ds")
    run("assimp", "export", p, out("3ds", "buoy.3ds"), "-f3ds")
    run("assimp", "export", src, out("x3d", "harbour.x3d"), "-fx3d")
    run("assimp", "export", p, out("x3d", "buoy.x3d"), "-fx3d")
    run("assimp", "export", src, out("fbx", "harbour-assimp.fbx"), "-ffbx")
    run("assimp", "export", p, out("fbx", "buoy-ascii.fbx"), "-ffbxa")
    # Draco: a mesh and a point cloud.
    run("draco_encoder", "-i", out("ply", "buoy-binary.ply"), "-o", out("draco", "buoy.drc"), "-cl", "7")
    run("draco_encoder", "-point_cloud", "-i", out("ply", "pier-ascii.ply"), "-o", out("draco", "pier-points.drc"))
    vrm(scene)


def vrm(scene):
    """VRM 1.0 and 0.x metadata on trimesh's glTF binary."""
    import pygltflib

    base = os.path.join(TMP, "avatar.glb")
    scene.export(base)
    for name, ext, used in (
        ("saltmere-keeper.vrm", {"VRMC_vrm": {"specVersion": "1.0", "meta": {
            "name": "Saltmere lighthouse keeper", "version": "1.0", "authors": ["Saltmere Harbour Office"],
            "copyrightInformation": "CC0 Saltmere Harbour", "licenseUrl": "https://vrm.dev/licenses/1.0/",
            "avatarPermission": "everyone", "commercialUsage": "personalNonProfit", "allowRedistribution": True}}}, ["VRMC_vrm"]),
        ("saltmere-keeper-0x.vrm", {"VRM": {"specVersion": "0.0", "meta": {
            "title": "Saltmere keeper (0.x)", "version": "0.9", "author": "Saltmere Harbour Office",
            "allowedUserName": "Everyone", "commercialUssageName": "Disallow", "licenseName": "CC0"}}}, ["VRM"]),
    ):
        g = pygltflib.GLTF2().load(base)
        g.extensions = ext
        g.extensionsUsed = used
        g.save_binary(out("vrm", name))


def blender():
    script = os.path.join(TMP, "blend.py")
    open(script, "w").write(f'''
import bpy, os
out = {OUT!r}
bpy.ops.wm.read_factory_settings(use_empty=True)
bpy.ops.mesh.primitive_cylinder_add(radius=0.6, depth=1.4, location=(0, 0, 0.7))
bpy.context.object.name = "Buoy"
mat = bpy.data.materials.new("BuoyRed")
bpy.context.object.data.materials.append(mat)
bpy.ops.mesh.primitive_cube_add(size=2.0, location=(6, 0, 1.2))
bpy.context.object.name = "Pier"
bpy.ops.object.camera_add(location=(10, -10, 6))
bpy.ops.object.light_add(type="SUN", location=(0, 0, 20))
bpy.context.scene.name = "Saltmere"
import shutil
# FBX first: once saved, Blender writes the .blend's path into the FBX.
os.makedirs(out + "/fbx", exist_ok=True)
bpy.ops.export_scene.fbx(filepath="/tmp/saltmere-blender.fbx")
shutil.copy("/tmp/saltmere-blender.fbx", out + "/fbx/saltmere-blender.fbx")
# Saved under /tmp: a .blend records the path it was saved to. Compressed:
# an uncompressed file (UI data included) is over the fixture limit.
os.makedirs(out + "/blend", exist_ok=True)
bpy.ops.wm.save_as_mainfile(filepath="/tmp/saltmere-pier.blend", compress=True)
bpy.data.objects.remove(bpy.data.objects["Pier"])
bpy.ops.wm.save_as_mainfile(filepath="/tmp/saltmere-buoy.blend", compress=True)
for n in ("saltmere-pier.blend", "saltmere-buoy.blend"):
    shutil.copy("/tmp/" + n, out + "/blend/" + n)
# An armature that waves, for BVH.
bpy.ops.object.armature_add(location=(0, 0, 0))
arm = bpy.context.object
bpy.ops.object.mode_set(mode="EDIT")
b = arm.data.edit_bones.new("Arm")
b.head = (0, 0, 1)
b.tail = (0, 0, 2)
b.parent = arm.data.edit_bones[0]
bpy.ops.object.mode_set(mode="POSE")
for f, angle in ((1, 0.0), (10, 0.6), (20, 0.0)):
    pb = arm.pose.bones["Arm"]
    pb.rotation_mode = "XYZ"
    pb.rotation_euler = (angle, 0, 0)
    pb.keyframe_insert("rotation_euler", frame=f)
bpy.ops.object.mode_set(mode="OBJECT")
bpy.context.scene.frame_start, bpy.context.scene.frame_end = 1, 20
os.makedirs(out + "/bvh", exist_ok=True)
for n, end in (("keeper-wave.bvh", 20), ("keeper-short.bvh", 5)):
    bpy.ops.export_anim.bvh(filepath="/tmp/" + n, frame_start=1, frame_end=end)
    shutil.copy("/tmp/" + n, out + "/bvh/" + n)
''')
    run("blender", "-b", "--factory-startup", "--python", script, stdout=subprocess.DEVNULL)
    for f in glob.glob(os.path.join(OUT, "blend", "*.blend1")):
        os.remove(f)


def usd():
    from pxr import Kind, Sdf, Usd, UsdGeom, UsdUtils

    def stage(path, name):
        s = Usd.Stage.CreateNew(path)
        UsdGeom.SetStageUpAxis(s, UsdGeom.Tokens.z)
        UsdGeom.SetStageMetersPerUnit(s, 1.0)
        root = UsdGeom.Xform.Define(s, "/Harbour")
        s.SetDefaultPrim(root.GetPrim())
        s.GetRootLayer().documentation = f"{name}, Saltmere Harbour"
        Usd.ModelAPI(root).SetKind(Kind.Tokens.assembly)
        UsdGeom.Cylinder.Define(s, "/Harbour/Buoy").CreateRadiusAttr(0.6)
        UsdGeom.Cube.Define(s, "/Harbour/Pier")
        m = UsdGeom.Mesh.Define(s, "/Harbour/Deck")
        m.CreatePointsAttr([(0, 0, 0), (12, 0, 0), (12, 2.5, 0), (0, 2.5, 0)])
        m.CreateFaceVertexCountsAttr([4])
        m.CreateFaceVertexIndicesAttr([0, 1, 2, 3])
        s.GetRootLayer().Save()

    stage(out("usda", "harbour.usda"), "Harbour scene")
    stage(out("usda", "buoy.usda"), "Buoy")
    stage(out("usdc", "harbour.usdc"), "Harbour scene (crate)")
    stage(out("usdc", "pier.usd"), "Pier (crate)")
    for name, src in (("harbour.usdz", out("usdc", "harbour.usdc")), ("buoy.usdz", out("usda", "buoy.usda"))):
        UsdUtils.CreateNewUsdzPackage(Sdf.AssetPath(src), out("usdz", name))


def voxels_and_volumes():
    import numpy as np
    from pyvox.models import Vox
    from pyvox.writer import VoxWriter

    v = np.zeros((8, 8, 12), dtype=np.uint8)
    v[2:6, 2:6, 0:8] = 1
    v[3:5, 3:5, 8:12] = 2
    VoxWriter(out("vox", "buoy.vox"), Vox.from_dense(v)).write()
    w = np.zeros((16, 4, 3), dtype=np.uint8)
    w[:, :, 0] = 3
    VoxWriter(out("vox", "pier.vox"), Vox.from_dense(w)).write()
    # OpenVDB: Debian's bindings live with the system Python.
    script = os.path.join(TMP, "vdb.py")
    open(script, "w").write(f'''
import pyopenvdb as vdb
for name, size in (("fog", 8), ("fog-small", 3)):
    g = vdb.FloatGrid()
    g.name = "density"
    acc = g.getAccessor()
    for i in range(size):
        for j in range(size):
            acc.setValueOn((i, j, 0), 0.5)
    t = vdb.Vec3SGrid()
    t.name = "velocity"
    vdb.write({OUT!r} + "/openvdb/harbour-" + name + ".vdb", grids=[g, t], metadata={{"creator": "Saltmere fog model", "frame": 1}})
''')
    os.makedirs(os.path.join(OUT, "openvdb"), exist_ok=True)
    run("/usr/bin/python3", script)


def capture():
    import c3d
    import numpy as np

    for name, frames, rate in (("keeper-walk.c3d", 60, 100.0), ("keeper-short.c3d", 10, 50.0)):
        w = c3d.Writer(point_rate=rate)
        w.set_point_labels(["HEAD", "LHAND", "RHAND", "LFOOT"])
        for i in range(frames):
            pts = np.zeros((4, 5), dtype=np.float32)
            pts[:, 0] = np.arange(4) * 100 + i
            pts[:, 2] = 1000
            w.add_frames([(pts, np.zeros((0, 0), dtype=np.float32))])
        with open(out("c3d", name), "wb") as f:
            w.write(f)


def photometry():
    # ANSI/IES LM-63-2002 and EULUMDAT, for the lighthouse lantern.
    for name, lumens, watts in (("lantern.ies", 12000, 150), ("pier-light.ies", 3200, 40)):
        angles_v = [0, 45, 90]
        angles_h = [0]
        cd = [900, 600, 100]
        open(out("ies", name), "w").write("\n".join([
            "IESNA:LM-63-2002",
            "[TEST] SALT-2025-001",
            "[TESTLAB] Saltmere Harbour bench",
            "[ISSUEDATE] 2025-09-01",
            "[MANUFAC] Saltmere Lantern Works",
            f"[LUMINAIRE] {name[:-4].replace('-', ' ').title()}",
            "[LAMP] LED module",
            "TILT=NONE",
            f"1 {lumens} 1.0 {len(angles_v)} {len(angles_h)} 1 2 0.30 0.30 0.40",
            f"1.0 1.0 {watts}",
            " ".join(map(str, angles_v)),
            " ".join(map(str, angles_h)),
            " ".join(map(str, cd)),
        ]) + "\n")
    for name, flux in (("lantern.ldt", 12000), ("pier-light.ldt", 3200)):
        lines = ["Saltmere Lantern Works", "1", "1", "1", "0", "3", "45", "SALT-2025-001", "Saltmere lantern" if "lantern" in name else "Pier light",
                 "SLW-01", name, "2025-09-01 / bench", "300", "300", "400", "300", "300", "0", "0", "0", "0", "100", "85", "1.0", "0", "1",
                 "1", "LED module", str(flux), "4000K", "80", "150" if "lantern" in name else "40"]
        lines += ["0"] * 10 + ["0", "45", "90", "900", "600", "100"]
        open(out("ldt", name), "w").write("\r\n".join(lines) + "\r\n")


def ldraw():
    parts = [("3001.dat", 4, (0, 0, 0)), ("3001.dat", 4, (40, 0, 0)), ("3062b.dat", 15, (20, -24, 0)), ("3062b.dat", 15, (20, -48, 0))]
    body = "\n".join(f"1 {c} {x} {y} {z} 1 0 0 0 1 0 0 0 1 {p}" for p, c, (x, y, z) in parts)
    open(out("ldraw", "lighthouse.ldr"), "w").write(f"0 Saltmere lighthouse\n0 Name: lighthouse.ldr\n0 Author: Saltmere Harbour Office\n0 !LICENSE Licensed under CC0\n{body}\n")
    open(out("ldraw", "harbour.mpd"), "w").write(
        f"0 FILE harbour.ldr\n0 Saltmere harbour\n0 Name: harbour.ldr\n0 Author: Saltmere Harbour Office\n1 16 0 0 0 1 0 0 0 1 0 0 0 1 lighthouse.ldr\n"
        f"0 NOFILE\n0 FILE lighthouse.ldr\n0 Saltmere lighthouse\n0 Name: lighthouse.ldr\n{body}\n0 NOFILE\n")


def gcode():
    # PrusaSlicer slices the buoy (two profiles).
    stl = os.path.join(TMP, "print-buoy.stl")
    import trimesh

    m = trimesh.creation.cylinder(radius=5, height=3, sections=24)
    m.apply_translation([0, 0, 1.5])
    m.export(stl)
    run("prusa-slicer", "--export-gcode", "--layer-height", "0.2", "--center", "100,100", "--output", out("gcode", "buoy-0.2mm.gcode"), stl,
        stdout=subprocess.DEVNULL)
    run("prusa-slicer", "--export-gcode", "--layer-height", "0.3", "--fill-density", "10%", "--center", "100,100",
        "--output", out("gcode", "buoy-draft.gcode"), stl, stdout=subprocess.DEVNULL)
    # CNC programs (RS-274NGC): a bracket's pocket and its drilling.
    open(out("cnc_gcode", "bracket-pocket.ngc"), "w").write(
        "%\nO1001 (SALTMERE MOORING BRACKET - POCKET)\n(T1 6MM END MILL)\nG21 G90 G17\nT1 M6\nS12000 M3\nG0 X0 Y0 Z5\n"
        "G1 Z-2 F300\nG1 X40 F800\nG1 Y20\nG1 X0\nG1 Y0\nG0 Z5\nM5\nM30\n%\n")
    open(out("cnc_gcode", "bracket-drill.tap"), "w").write(
        "%\nO1002 (SALTMERE MOORING BRACKET - DRILL)\nG20 G90\nT2 M6 (3/16 DRILL)\nS3000 M3\nG0 X0.5 Y0.5 Z0.2\nG81 Z-0.3 R0.1 F5\nX1.5\nX2.5\nG80\nM5\nM30\n%\n")


def cad():
    import cadquery as cq
    from OCP.IGESControl import IGESControl_Writer
    from OCP.Interface import Interface_Static

    bracket = cq.Workplane("XY").box(40, 20, 6).faces(">Z").workplane().pushPoints([(-12, 0), (12, 0)]).hole(5)
    post = cq.Workplane("XY").circle(15).extrude(120).faces(">Z").workplane().circle(12).extrude(20)
    cq.exporters.export(bracket, out("step", "mooring-bracket.step"))
    cq.exporters.export(post, out("step", "lighthouse-post.stp"), exportType="STEP")
    cq.exporters.export(bracket, out("amf", "mooring-bracket.amf"))
    cq.exporters.export(post, out("amf", "lighthouse-post.amf"))
    cq.exporters.export(bracket, out("vrml", "mooring-bracket.wrl"), exportType="VRML")
    cq.exporters.export(post, out("vrml", "lighthouse-post.wrl"), exportType="VRML")
    from OCP.IGESControl import IGESControl_Controller

    IGESControl_Controller.Init_s()
    for name, shape in (("mooring-bracket.igs", bracket), ("lighthouse-post.iges", post)):
        Interface_Static.SetCVal_s("write.iges.header.author", "Saltmere Harbour Office")
        Interface_Static.SetCVal_s("write.iges.header.company", "Saltmere Harbour")
        w = IGESControl_Writer("MM", 1)
        w.AddShape(shape.val().wrapped)
        w.ComputeModel()
        w.Write(out("iges", name))
    # DXF with ezdxf: R12 and R2018 (layers, blocks, text), binary R2000.
    import ezdxf

    for name, ver, binary in (("pier-plan-r12.dxf", "R12", False), ("pier-plan.dxf", "R2018", False), ("pier-plan-binary.dxf", "R2000", True), ("pier-plan-2018-binary.dxf", "R2018", True)):
        doc = ezdxf.new(ver, setup=True)
        doc.header["$INSUNITS"] = 6
        doc.layers.add("PIER", color=1)
        doc.layers.add("LABELS", color=3)
        blk = doc.blocks.new("BOLLARD")
        blk.add_circle((0, 0), 0.3)
        msp = doc.modelspace()
        msp.add_lwpolyline([(0, 0), (12, 0), (12, 2.5), (0, 2.5)], close=True, dxfattribs={"layer": "PIER"}) if ver != "R12" else \
            msp.add_polyline2d([(0, 0), (12, 0), (12, 2.5), (0, 2.5)], close=True, dxfattribs={"layer": "PIER"})
        for x in (1, 6, 11):
            msp.add_blockref("BOLLARD", (x, 1.25))
        msp.add_text("Saltmere pier", dxfattribs={"layer": "LABELS", "height": 0.4}).set_placement((0.5, 3))
        if ver != "R12":
            msp.add_mtext("Mooring bollards\\Pevery 5 m", dxfattribs={"layer": "LABELS"}).set_location((0.5, 4))
        doc.header["$TDCREATE"] = 2460919.75
        if binary:
            doc.saveas(out("dxf_binary", name), fmt="bin")
        else:
            doc.saveas(out("dxf", name))
    # IFC with ifcopenshell: IFC4 and IFC2X3, and an IFC-ZIP.
    import ifcopenshell
    import ifcopenshell.api

    for name, schema in (("harbour-office.ifc", "IFC4"), ("harbour-office-2x3.ifc", "IFC2X3")):
        f = ifcopenshell.api.run("project.create_file", version=schema)
        # IFC2X3 needs owner history: a fictitious office and this script.
        import ifcopenshell.api.owner.settings as owner

        person = f.create_entity("IfcPerson", FamilyName="Office", GivenName="Harbour")
        org = f.create_entity("IfcOrganization", Name="Saltmere Harbour")
        user = f.create_entity("IfcPersonAndOrganization", ThePerson=person, TheOrganization=org)
        app = f.create_entity("IfcApplication", ApplicationDeveloper=org, Version="1.0", ApplicationFullName="Saltmere fixtures", ApplicationIdentifier="saltmere")
        owner.get_user = lambda _f: user
        owner.get_application = lambda _f: app
        project = ifcopenshell.api.run("root.create_entity", f, ifc_class="IfcProject", name="Saltmere harbour office")
        ifcopenshell.api.run("unit.assign_unit", f)
        ctx = ifcopenshell.api.run("context.add_context", f, context_type="Model")
        site = ifcopenshell.api.run("root.create_entity", f, ifc_class="IfcSite", name="Saltmere quay")
        building = ifcopenshell.api.run("root.create_entity", f, ifc_class="IfcBuilding", name="Harbour office")
        storey = ifcopenshell.api.run("root.create_entity", f, ifc_class="IfcBuildingStorey", name="Ground floor")
        ifcopenshell.api.run("aggregate.assign_object", f, relating_object=project, products=[site])
        ifcopenshell.api.run("aggregate.assign_object", f, relating_object=site, products=[building])
        ifcopenshell.api.run("aggregate.assign_object", f, relating_object=building, products=[storey])
        wall = ifcopenshell.api.run("root.create_entity", f, ifc_class="IfcWall", name="Quay wall")
        ifcopenshell.api.run("spatial.assign_container", f, relating_structure=storey, products=[wall])
        f.write(out("ifc", name))
    for name in ("harbour-office.ifczip", "harbour-office-2x3.ifczip"):
        with zipfile.ZipFile(out("ifczip", name), "w", zipfile.ZIP_DEFLATED) as z:
            z.write(out("ifc", name.replace(".ifczip", ".ifc")), name.replace(".ifczip", ".ifc"))


def eda():
    # Gerber X2 with gerber-writer.
    from gerber_writer import Circle, DataLayer, Path, Rectangle

    for name, function in (("buoy-light-F_Cu.gbr", "Copper,L1,Top"), ("buoy-light-B_Cu.gbr", "Copper,L2,Bot")):
        layer = DataLayer(function, negative=False)
        pad = Circle(1.2, "ComponentPad")
        smd = Rectangle(1.0, 0.6, "SMDPad,CuDef")
        for x in (2, 6, 10):
            layer.add_pad(pad, (x, 3))
        layer.add_pad(smd, (14, 3))
        trace = Path()
        trace.moveto((2, 3))
        trace.lineto((10, 3))
        layer.add_trace_line((2, 3), (10, 3), 0.25, "Conductor")
        open(out("gerber", name), "w").write(layer.dumps_gerber())
    # Excellon drill files (IPC-NC-349 / KiCad style).
    open(out("excellon", "buoy-light-PTH.drl"), "w").write(
        "M48\n; DRILL file {Saltmere buoy light} date 2025-09-01\n; FORMAT={-:-/ absolute / metric / decimal}\nFMAT,2\nMETRIC\nT1C0.800\nT2C1.000\n%\nG90\nG05\n"
        "T1\nX2.0Y3.0\nX6.0Y3.0\nX10.0Y3.0\nT2\nX14.0Y8.0\nT0\nM30\n")
    open(out("excellon", "buoy-light-NPTH.drl"), "w").write("M48\nINCH,LZ\nT01C0.125\n%\nT01\nX005000Y005000\nX045000Y005000\nM30\n")
    # KiCad board and schematic with kiutils.
    from kiutils.board import Board
    from kiutils.items.common import Net, TitleBlock
    from kiutils.schematic import Schematic

    for name, title in (("buoy-light.kicad_pcb", "Saltmere buoy light"), ("buoy-charger.kicad_pcb", "Saltmere buoy charger")):
        b = Board.create_new()
        b.titleBlock = TitleBlock(title=title, date="2025-09-01", revision="1", company="Saltmere Harbour")
        b.nets = [Net(0, ""), Net(1, "GND"), Net(2, "+3V3"), Net(3, "LED")]
        b.to_file(out("kicad_pcb", name))
    for name, title in (("buoy-light.kicad_sch", "Saltmere buoy light"), ("buoy-charger.kicad_sch", "Saltmere buoy charger")):
        s = Schematic.create_new()
        s.titleBlock = TitleBlock(title=title, date="2025-09-01", revision="1", company="Saltmere Harbour")
        s.to_file(out("kicad_sch", name))
    # OpenSCAD sources.
    open(out("openscad", "buoy.scad"), "w").write("// Saltmere buoy\n// CC0, Saltmere Harbour Office\n$fn = 48;\nmodule buoy(r = 6) {\n  cylinder(h = 14, r = r);\n  translate([0, 0, 14]) cylinder(h = 8, r1 = r * 0.7, r2 = 0);\n}\nbuoy();\n")
    open(out("openscad", "bracket.scad"), "w").write("// Saltmere mooring bracket\nuse <bolts.scad>\nfunction hole_x(i) = -12 + 24 * i;\ndifference() {\n  cube([40, 20, 6], center = true);\n  for (i = [0, 1]) translate([hole_x(i), 0, 0]) cylinder(h = 10, r = 2.5, center = true);\n}\n")
    # GDSII and OASIS with KLayout.
    import klayout.db as kdb

    for name in ("saltmere-test-chip", "saltmere-ring"):
        ly = kdb.Layout()
        ly.dbu = 0.001
        top = ly.create_cell(name.upper().replace("-", "_"))
        pad = ly.create_cell("PAD")
        l1, l2 = ly.layer(1, 0), ly.layer(2, 0)
        pad.shapes(l1).insert(kdb.Box(0, 0, 80000, 80000))
        for i in range(4 if "chip" in name else 2):
            top.insert(kdb.CellInstArray(pad.cell_index(), kdb.Trans(kdb.Point(i * 120000, 0))))
        top.shapes(l2).insert(kdb.Path([kdb.Point(0, 100000), kdb.Point(400000, 100000)], 5000))
        top.shapes(l2).insert(kdb.Text("SALTMERE", kdb.Trans(kdb.Point(10000, 150000))))
        ly.write(out("gdsii", name + ".gds"))
        opt = kdb.SaveLayoutOptions()
        opt.format = "OASIS"
        opt.oasis_write_cblocks = "ring" not in name
        opt.oasis_strict_mode = True
        ly.write(out("oasis", name + ".oas"), opt)


if want("meshes"):
    meshes()
if want("blender"):
    blender()
if want("usd"):
    usd()
if want("voxels"):
    voxels_and_volumes()
if want("capture"):
    capture()
if want("photometry"):
    photometry()
if want("ldraw"):
    ldraw()
if want("gcode"):
    gcode()
if want("cad"):
    cad()
if want("eda"):
    eda()
shutil.rmtree(TMP, ignore_errors=True)
print("cad fixtures written to", OUT)
