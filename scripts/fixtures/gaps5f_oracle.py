#!/usr/bin/env python3
"""Oracle for the batch 5f fixtures (the last catalogue rows). Each
container contributes the checks its tools allow; `check` merges them.

    # libmagic, xdrlib, zipfile / json / plistlib and stdlib re-reads:
    podman run --rm -v "$PWD:/whiff" -w /whiff whiff-legacy \\
        python3 scripts/fixtures/gaps5f_oracle.py expect tests/fixtures > target/gaps5f-legacy.json
    # pandas (read_fwf):
    podman run --rm -v "$PWD:/whiff" -w /whiff whiff-science \\
        python3 scripts/fixtures/gaps5f_oracle.py expect tests/fixtures > target/gaps5f-science.json
    # olefile (Minitab compound files):
    podman run --rm -v "$PWD:/whiff" -w /whiff whiff-media \\
        python3 scripts/fixtures/gaps5f_oracle.py expect tests/fixtures > target/gaps5f-media.json
    python3 scripts/fixtures/gaps5f_oracle.py check target/gaps5f-*.json

Tools: pandas `read_fwf` (fixed-width columns as pandas infers them),
xdrlib (the XDR records and the RPC call, unpacked by their schema),
libmagic `file` (ETW, which names the log file), olefile (Minitab streams
and summary information), zipfile, json and plistlib (Fusion, GarageBand).
Pro Tools, ETW and GarageBand framing are also re-read here with the
standard library, following ptformat, Airbus CERT's etl-parser structures
and the chunk layout; ptformat's own expected outputs and etl-parser's and
JMPReader.jl's sample files were compared during development (see
docs/known-gaps.md). JMP facts come from JMPReader.jl's test suite.
"""

import importlib.util
import json
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from legacy_oracle import lookup  # noqa: E402

EXPECT = []


def want(fixture, path, value, tool):
    if value is not None:
        EXPECT.append({"file": str(fixture), "path": path, "value": value, "tool": tool})


def have(module):
    return importlib.util.find_spec(module) is not None


# ------------------------------------------------------------ pandas

def fixed_width(fx):
    import pandas as pd

    f = fx / "fixed_width/saltmere-tides.fwf"
    df = pd.read_fwf(f, colspecs="infer")
    want(f, "format.fixed_width.rows", len(df), "pandas")
    want(f, "format.fixed_width.columns", len(df.columns), "pandas")
    want(f, "format.fixed_width.column_profile.*.name", sorted(df.columns), "pandas")
    f = fx / "fixed_width/saltmere-moorings.prn"
    df = pd.read_fwf(f, colspecs="infer", header=None)
    want(f, "format.fixed_width.rows", len(df), "pandas")
    want(f, "format.fixed_width.columns", len(df.columns), "pandas")
    want(f, "format.fixed_width.column_profile.2.max", float(df[2].max()), "pandas")


# ------------------------------------------------------------ olefile

def minitab_ole(fx):
    import olefile

    for f, fmt in ((fx / "minitab_worksheet/saltmere-catches.mtw", "minitab_worksheet"),
                   (fx / "minitab_project/saltmere-survey.mpj", "minitab_project")):
        ole = olefile.OleFileIO(str(f))
        names = sorted(e[0].lstrip("\x05") for e in ole.listdir() if len(e) == 1)
        want(f, f"format.{fmt}.top_level_streams.*", names, "olefile")
        info = ole.openstream("WorksheetInfo" if ole.exists("WorksheetInfo") else "ProjectInfo").read(16)
        release = {bytes.fromhex("3B000000000000000100000001000000"): "14",
                   bytes.fromhex("5F000000000000000200000001000000"): "15+"}.get(info)
        want(f, f"format.{fmt}.release_range", release, "olefile + PRONOM fmt/1435-1438")
        meta = ole.get_metadata()
        if meta.title:
            want(f, "content.title", meta.title.decode(), "olefile")


# ------------------------------------------------------------ xdrlib and the standard library

def xdr(fx):
    import base64
    import xdrlib

    f = fx / "xdr/saltmere-gauge.xdr"
    raw = f.read_bytes()
    u = xdrlib.Unpacker(raw)
    strings = [u.unpack_string().decode()]
    for _ in range(u.unpack_uint()):
        u.unpack_uhyper()
        u.unpack_float()
    strings.append(u.unpack_string().decode())
    u.unpack_bool(), u.unpack_int(), u.unpack_double(), u.unpack_opaque()
    strings.append(u.unpack_string().decode())
    u.done()
    for name, data in (("saltmere-gauge.xdr", raw), ("saltmere-gauge-base64.xdr", None)):
        g = fx / "xdr" / name
        if data is None:
            data = base64.b64decode((fx / "xdr" / name).read_text())
            want(g, "format.xdr.encoding", "base64", "base64")
        want(g, "format.xdr.strings", strings, "xdrlib")
        want(g, "format.xdr.words", len(data) // 4, "xdrlib")
    f = fx / "xdr/saltmere-nfs-call.xdr"
    u = xdrlib.Unpacker(f.read_bytes())
    mark = u.unpack_uint()
    u.unpack_uint()  # xid
    kind, rpcvers, prog, vers, proc_ = (u.unpack_enum(), u.unpack_uint(), u.unpack_uint(), u.unpack_uint(), u.unpack_uint())
    assert mark & 0x80000000 and kind == 0 and rpcvers == 2
    want(f, "format.xdr.rpc.calls", 1, "xdrlib")
    want(f, "format.xdr.rpc.record_marking", True, "xdrlib")
    want(f, f"format.xdr.rpc.procedures.{'nfs' if prog == 100003 else prog} v{vers} procedure {proc_}", 1, "xdrlib")


def etw(fx):
    f = fx / "etw_trace/saltmere-tides.etl"
    desc = subprocess.run(["file", "-b", str(f)], capture_output=True, text=True).stdout
    want(f, "_libmagic", "Windows Event Trace Log" if "Windows Event Trace Log" in desc else f"MISSING ETL: {desc}", "file")
    want(f, "_libmagic", "saltmere-tides.etl" if "saltmere-tides.etl" in desc else f"MISSING name: {desc}", "file")
    # etl-parser's structures: WmiBufferHeader, SystemTraceHeader, EventTraceHeader, EventHeader.
    b = f.read_bytes()
    size = struct.unpack_from("<I", b, 0)[0]
    m = 0x48 + 0x20
    procs, buffers_written = struct.unpack_from("<I", b, m + 12)[0], struct.unpack_from("<I", b, m + 0x24)[0]
    names = b[m + 0x118:].split(b"\0\0\0")[0] + b"\0"
    session = names.decode("utf-16le").split("\0")[0]
    want(f, "format.etw_trace.processors", procs, "stdlib (etl-parser structures)")
    want(f, "format.etw_trace.buffers_written", buffers_written, "stdlib (etl-parser structures)")
    want(f, "format.etw_trace.session", session, "stdlib (etl-parser structures)")
    want(f, "format.etw_trace.buffers", len(b) // size, "stdlib (etl-parser structures)")
    providers = {}
    for at in range(0, len(b), size):
        saved = struct.unpack_from("<I", b, at + 4)[0]
        p = at + 0x48
        while p + 8 <= at + saved:
            kind = b[p + 2]
            n = struct.unpack_from("<H", b, p + 4 if kind in (1, 2, 3, 4, 0x10, 0x11) else p)[0]
            if kind in (0x12, 0x13):
                d1, d2, d3 = struct.unpack_from("<IHH", b, p + 0x18)
                g = f"{d1:08X}-{d2:04X}-{d3:04X}-{b[p + 0x20:p + 0x22].hex().upper()}-{b[p + 0x22:p + 0x28].hex().upper()}"
                providers[g] = providers.get(g, 0) + 1
            p += (n + 7) // 8 * 8
    want(f, "format.etw_trace.provider_count", len(providers), "stdlib (etl-parser structures)")
    for i, (g, n) in enumerate(sorted(providers.items(), key=lambda kv: (-kv[1], kv[0]))):
        want(f, f"format.etw_trace.providers.{i}.guid", g, "stdlib (etl-parser structures)")
        want(f, f"format.etw_trace.providers.{i}.events", n, "stdlib (etl-parser structures)")


def protools(fx):
    """ptformat's unxor and version detection, and the blocks it reads."""
    for f in sorted((fx / "protools_session").glob("*.pt?")):
        b = bytearray(f.read_bytes())
        kind, value = b[0x12], b[0x13]
        mul, neg = (53, False) if kind == 1 else (11, True)
        delta = next(i for i in range(256) if (i * mul) & 0xFF == value)
        delta = (-delta) & 0xFF if neg else delta
        key = [(i * delta) & 0xFF for i in range(256)]
        for i in range(0x14, len(b)):
            b[i] ^= key[i & 0xFF] if kind == 1 else key[(i >> 12) & 0xFF]
        e = ">" if b[0x11] else "<"
        content = struct.unpack_from(e + "H", b, 0x1F + 7)[0]
        if content == 0x2067:
            version = 2 + struct.unpack_from(e + "I", b, 0x1F + 7 + 20)[0]
        else:
            n = struct.unpack_from(e + "I", b, 0x1F + 7 + 3)[0]
            version = struct.unpack_from(e + "I", b, 0x1F + 7 + 3 + n + 8)[0]
        want(f, "format.protools_session.pro_tools_version", version, "stdlib (ptformat)")
        want(f, "format.protools_session.byte_order", "big" if e == ">" else "little", "stdlib (ptformat)")
        # The sample-rate block (content 0x1028): rate at content + 4.
        tag = b"Z" + struct.pack(e + "H", 1)
        at = 0x14
        while (at := b.find(tag, at)) >= 0:
            if struct.unpack_from(e + "H", b, at + 7)[0] == 0x1028:
                want(f, "format.protools_session.sample_rate", struct.unpack_from(e + "I", b, at + 11)[0], "stdlib (ptformat)")
                break
            at += 1


def garageband(fx):
    import plistlib

    f = fx / "garageband_project/ProjectData"
    b = f.read_bytes()
    want(f, "format.garageband_project.format_version", struct.unpack_from("<H", b, 4)[0], "stdlib")
    at, kinds = 0x1C, {}
    while at + 36 <= len(b):
        tag = b[at:at + 4][::-1].decode()
        kinds[tag] = kinds.get(tag, 0) + 1
        at += 36 + struct.unpack_from("<Q", b, at + 28)[0]
    want(f, "format.garageband_project.chunks_by_kind", kinds, "stdlib")
    f = fx / "bplist/saltmere-shanty-metadata.plist"
    p = plistlib.loads(f.read_bytes())
    want(f, "format.bplist.tempo_bpm", float(p["BeatsPerMinute"]), "plistlib")
    want(f, "format.bplist.key", f"{p['SongKey']} {p['SongGenderKey']}", "plistlib")
    want(f, "format.bplist.time_signature", f"{p['SongSignatureNumerator']}/{p['SongSignatureDenominator']}", "plistlib")
    want(f, "format.bplist.tracks", p["NumberOfTracks"], "plistlib")
    want(f, "format.bplist.sample_rate", p["SampleRate"], "plistlib")


def lp(b, at, utf16):
    n = struct.unpack_from("<I", b, at)[0]
    w = n * 2 if utf16 else n
    s = b[at + 4:at + 4 + w]
    return (s.decode("utf-16le") if utf16 else s.decode()), at + 4 + w


def fusion(fx):
    f = fx / "fusion_design/saltmere-bollard.f3d"
    z = zipfile.ZipFile(f)
    m = z.read("Manifest.dat")
    version, at = lp(m, 0, False)
    _, at = lp(m, at, False)
    doc_type, at = lp(m, at, True)
    name, at = lp(m, at, True)
    description, at = lp(m, at, True)
    want(f, "format.fusion_design.manifest_version", version, "zipfile (cadmpeg f3d notes)")
    want(f, "format.fusion_design.document_type", doc_type, "zipfile (cadmpeg f3d notes)")
    want(f, "format.fusion_design.display_name", name, "zipfile (cadmpeg f3d notes)")
    want(f, "format.fusion_design.description", description, "zipfile (cadmpeg f3d notes)")
    props = json.loads(z.read("Properties.dat")[4:])["docstruct"]
    want(f, "format.fusion_design.design_type", props["type"], "json")
    want(f, "format.fusion_design.entries", len(z.namelist()), "zipfile")
    breps = [n for n in z.namelist() if "Breps.BlobParts/" in n]
    want(f, "format.fusion_design.parts_by_role.brep_streams", len(breps), "zipfile")
    f = fx / "fusion_archive/saltmere-pontoon.f3z"
    z = zipfile.ZipFile(f)
    want(f, "format.fusion_archive.root", json.loads(z.read("Manifest.json"))["root"], "json")
    d = json.loads(z.read("DesignDescription.json"))["designDescription"]
    want(f, "format.fusion_archive.name", d["name"], "json")
    want(f, "format.fusion_archive.current_version", d["currentVersion"], "json")
    objs = [o["friendlyName"] for g in d["designGraphs"] for o in g["designObjects"]]
    want(f, "format.fusion_archive.design_objects.*.name", sorted(objs), "json")


def minitab_text(fx):
    f = fx / "minitab_worksheet/saltmere-landings-r11.mtw"
    want(f, "format.minitab_worksheet.signature", f.read_bytes().split(b"\r\n")[0].decode(), "stdlib (PRONOM fmt/1430)")
    f = fx / "minitab_portable/saltmere-catches.mtp"
    want(f, "format.minitab_portable.signature", f.read_text().splitlines()[0], "stdlib (PRONOM fmt/1431)")


def jmp(fx):
    """JMPReader.jl's test suite (test/runtests.jl) for example1.jmp."""
    f = fx / "jmp/example1.jmp"
    names = ["ints", "floats", "charconstwidth", "time", "date", "duration", "charconstwidth2", "charvariable16",
             "formula", "pressures", "char utf8", "charvariable8"]
    want(f, "format.jmp.rows", 4, "JMPReader.jl tests")
    want(f, "format.jmp.columns", len(names), "JMPReader.jl tests")
    want(f, "format.jmp.column_names", names, "JMPReader.jl tests")


def expect(root):
    fx = Path(root)
    if have("pandas"):
        fixed_width(fx)
    if have("olefile"):
        minitab_ole(fx)
    if have("xdrlib") and not have("pandas") and not have("olefile"):
        xdr(fx)
        etw(fx)
        protools(fx)
        garageband(fx)
        fusion(fx)
        minitab_text(fx)
        jmp(fx)
    print(json.dumps(EXPECT, indent=1))


def check(paths, whiff="target/debug/whiff"):
    exp = [e for p in paths for e in json.load(open(p))]
    cache, ok, bad, tools = {}, 0, 0, {}
    for e in exp:
        f = e["file"].replace("/whiff/", "")
        if f not in cache:
            line = subprocess.run([whiff, "--jsonl", f], capture_output=True, text=True, check=True).stdout.splitlines()[0]
            cache[f] = json.loads(line)
        if e["path"] == "_libmagic":
            got, good = e["value"], not e["value"].startswith("MISSING")
        else:
            got = lookup(cache[f], e["path"])
            good = got == e["value"]
        tools[e["tool"]] = tools.get(e["tool"], 0) + 1
        if good:
            ok += 1
        else:
            bad += 1
            print(f"DIFF {f} {e['path']}: whiff {got!r}, {e['tool']} {e['value']!r}")
    print(f"{ok}/{ok + bad} agree ({', '.join(f'{t} {n}' for t, n in sorted(tools.items()))})")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    if sys.argv[1] == "expect":
        expect(sys.argv[2])
    else:
        check(sys.argv[2:])
