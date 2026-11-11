#!/usr/bin/env python3
"""Stage 8 long tail, batch 5f: the last catalogue rows. Fixtures for the
fictitious Saltmere Harbour, CC0-1.0, written from each format's layout:
fixed-width tables, XDR (RFC 4506; Python's xdrlib) and an ONC RPC call
(RFC 5531), an ETW trace (TRACE_LOGFILE_HEADER / EVENT_HEADER as Microsoft
and Geoff Chappell document them), Minitab files (PRONOM's signatures),
Pro Tools sessions (ptformat's obfuscation and blocks), GarageBand project
data and its MetaData.plist, Fusion designs and archives (cadmpeg's f3d
format notes). Run in `whiff-legacy` (see gaps5f.sh).

    craft_gaps5f.py OUT_DIR
"""

import io
import json
import plistlib
import struct
import sys
import uuid
import xdrlib
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from office import VT_FILETIME, VT_LPSTR, cfb_bytes, filetime, property_set  # noqa: E402

OUT = Path(sys.argv[1])
DATE = (2025, 9, 1, 12, 0, 0)


def out(fmt, name, data):
    d = OUT / fmt
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data if isinstance(data, bytes) else data.encode())


def zip_bytes(entries, method=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name, DATE)
            info.compress_type = zipfile.ZIP_STORED if name.endswith((".dat", ".f3d")) else method
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
    return buf.getvalue()


# ------------------------------------------------------------ fixed-width

def fixed_width():
    rows = [
        ("station", "date", "high_water", "high_m", "low_water", "low_m"),
        ("Saltmere Quay", "2025-09-01", "06:12", "4.10", "12:31", "0.72"),
        ("Saltmere Quay", "2025-09-02", "06:58", "4.22", "13:15", "0.64"),
        ("Brackwell Point", "2025-09-01", "06:20", "3.95", "12:40", "0.81"),
        ("Brackwell Point", "2025-09-02", "07:05", "4.02", "13:22", "0.77"),
        ("Gull Rock", "2025-09-01", "06:05", "4.31", "12:24", "0.55"),
        ("Gull Rock", "2025-09-02", "06:51", "4.40", "13:09", "0.49"),
    ]
    widths = (17, 12, 12, 8, 11, 6)
    lines = []
    for r in rows:
        cells = [r[0].ljust(widths[0])] + [v.rjust(w) if i > 1 else v.ljust(w) for i, (v, w) in enumerate(zip(r[1:], widths[1:]), 1)]
        lines.append(" ".join(cells).rstrip())
    out("fixed_width", "saltmere-tides.fwf", "\n".join(lines) + "\n")
    # A Lotus-style print file: no header, numbers right-aligned.
    moorings = [("A01", "Kittiwake", 7.2, 1.1, 2019), ("A02", "Grey Seal", 9.8, 1.4, 2021),
                ("B01", "Lugworm", 6.1, 0.9, 2016), ("B02", "Sea Thrift", 11.3, 1.7, 2023),
                ("C01", "Bladderwrack", 8.4, 1.2, 2018)]
    prn = "".join(f"{m:<6}{n:<14}{l:>6.1f}{d:>6.1f}{y:>7}\r\n" for m, n, l, d, y in moorings)
    out("fixed_width", "saltmere-moorings.prn", prn)


# --------------------------------------------------------------------- XDR

def xdr():
    p = xdrlib.Packer()
    p.pack_string(b"Saltmere Quay tide gauge")
    p.pack_uint(3)  # readings
    for t, h in ((1756706400, 4.10), (1756729860, 0.72), (1756752720, 4.22)):
        p.pack_uhyper(t)
        p.pack_float(h)
    p.pack_string(b"metres above chart datum")
    p.pack_bool(True)
    p.pack_int(-12)
    p.pack_double(51.4729)
    p.pack_opaque(bytes(range(5)))
    p.pack_string(b"harbourmaster")
    gauge = p.get_buffer()
    out("xdr", "saltmere-gauge.xdr", gauge)
    # The same record as base64 text (as Stellar and other tools write XDR).
    import base64

    out("xdr", "saltmere-gauge-base64.xdr", base64.b64encode(gauge).decode() + "\n")
    # An ONC RPC call with record marking: NFS v3 GETATTR on a file handle.
    c = xdrlib.Packer()
    c.pack_uint(0x5A17)  # xid
    c.pack_enum(0)  # CALL
    c.pack_uint(2)  # RPC version
    c.pack_uint(100003)  # NFS
    c.pack_uint(3)
    c.pack_uint(1)  # GETATTR
    c.pack_enum(0)  # AUTH_NONE
    c.pack_opaque(b"")
    c.pack_enum(0)
    c.pack_opaque(b"")
    c.pack_opaque(bytes.fromhex("5a17000100000000000000000000002a"))
    msg = c.get_buffer()
    out("xdr", "saltmere-nfs-call.xdr", struct.pack(">I", 0x80000000 | len(msg)) + msg)


# --------------------------------------------------------------------- ETW

BUF = 0x1000
FT = lambda y, mo, d, h, mi, s: filetime(f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}Z")  # noqa: E731


def guid_le(s):
    return uuid.UUID(s).bytes_le


def wstr(s):
    return s.encode("utf-16le") + b"\0\0"


def buffer(records, kind, seq):
    body = b""
    for r in records:
        body += r + bytes(-len(r) % 8)
    saved = 0x48 + len(body)
    head = struct.pack("<IIIiQQQHHIIHH", BUF, saved, saved, 0, 0x1D0000 + seq, seq, (1 << 61) | 1, seq % 2, 1, 0, 0x48, 0, kind)
    head += bytes(0x48 - len(head))
    return (head + body).ljust(BUF, b"\0")


def logfile_header():
    tz = struct.pack("<i", 0) + "GMT Standard Time".encode("utf-16le").ljust(64, b"\0") + bytes(16) + struct.pack("<i", 0)
    tz += "GMT Daylight Time".encode("utf-16le").ljust(64, b"\0") + bytes(16) + struct.pack("<i", -60)
    tz = tz.ljust(0xB0, b"\0")
    h = struct.pack("<IBBBBII", BUF, 10, 0, 0, 0, 26100, 4)  # buffer size, version 10.0, build, processors
    h += struct.pack("<QIIII", FT(2025, 9, 1, 12, 30, 0), 156250, 64, 0x1, 3)  # end, timer, max MB, sequential, buffers
    h += struct.pack("<IIII", 1, 8, 0, 2400)  # start buffers, pointer size, events lost, CPU MHz
    h += struct.pack("<QQ", 0, 0)  # LoggerName / LogFileName (unused since 6.1)
    h += tz
    h += struct.pack("<QQQII", FT(2025, 9, 1, 6, 0, 0), 10_000_000, FT(2025, 9, 1, 12, 0, 0), 1, 0)
    assert len(h) == 0x118, hex(len(h))
    h += wstr("SaltmereTides") + wstr("C:\\Users\\harbourmaster\\Traces\\saltmere-tides.etl")
    # System trace header (64-bit): version 2, type 2, flags 0xC0; packet size, type 0, group 0.
    sys_head = struct.pack("<HBBHBBIIQII", 2, 2, 0xC0, 0x20 + len(h), 0, 0, 0x1F4, 0x4, 0x10000, 0, 0)
    return sys_head + h


TIDES = "6f3a2b1c-5d4e-4f60-8a71-b2c3d4e5f601"
KPROC = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"


def event(provider, eid, pid, payload, traits=None):
    ext = b""
    flags = 0
    if traits:
        flags |= 1
        data = struct.pack("<H", 2 + len(traits) + 1) + traits.encode() + b"\0"
        ext = struct.pack("<HHHH", 0, 0x000C, 0, len(data)) + data
        ext += bytes(-len(ext) % 8)
    size = 0x50 + len(ext) + len(payload)
    h = struct.pack("<HBBHHIIQ", size, 0x13, 0xC0, flags, 0, 0x2000 + pid, pid, 0x10000 + eid)
    h += guid_le(provider) + struct.pack("<HBBBBHQQ", eid, 0, 0x10, 4, 0, 0, 0, 0) + bytes(16)
    assert len(h) == 0x50
    return h + ext + payload


def system(group, kind, pid, payload):
    return struct.pack("<HBBHBBIIQII", 2, 2, 0xC0, 0x20 + len(payload), kind, group, 0x3000, pid, 0x20000, 0, 0) + payload


def perfinfo(group, kind, payload):
    return struct.pack("<HBBHBBQ", 2, 0x11, 0xC0, 0x10 + len(payload), kind, group, 0x30000) + payload


def etw():
    first = buffer([logfile_header()], 4, 1)
    events = [
        event(TIDES, 1, 4242, wstr("Saltmere Quay") + struct.pack("<f", 4.10), traits="Saltmere.Harbour.Tides"),
        event(TIDES, 2, 4242, wstr("Saltmere Quay") + struct.pack("<f", 0.72), traits="Saltmere.Harbour.Tides"),
        event(TIDES, 1, 4343, wstr("Gull Rock") + struct.pack("<f", 4.31), traits="Saltmere.Harbour.Tides"),
        event(KPROC, 1, 4, struct.pack("<II", 4242, 1) + wstr("tidegauge.exe")),
        event(KPROC, 2, 4, struct.pack("<II", 4242, 0)),
    ]
    second = buffer(events, 0, 2)
    kernel = [system(3, 1, 4242, struct.pack("<QI", 0xFFFF0000, 4242)), system(4, 64, 4242, bytes(16)), perfinfo(15, 46, bytes(8))]
    third = buffer(kernel, 0, 3)
    out("etw_trace", "saltmere-tides.etl", first + second + third)


# ----------------------------------------------------------------- Minitab

def minitab():
    summary = property_set([("F29F85E0-4FF9-1068-AB91-08002B27B3D9", [
        (2, VT_LPSTR, "Saltmere catches 2025"), (4, VT_LPSTR, "Saltmere Harbour"),
        (12, VT_FILETIME, filetime("2025-09-01T12:00:00Z")),
    ])])
    info15 = bytes.fromhex("5F000000000000000200000001000000") + bytes(48)
    out("minitab_worksheet", "saltmere-catches.mtw", cfb_bytes([
        ("WorksheetInfo", info15),
        ("Worksheet", bytes(96)),
        ("\x05SummaryInformation", summary),
    ]))
    info14 = bytes.fromhex("3B000000000000000100000001000000") + bytes(48)
    out("minitab_project", "saltmere-survey.mpj", cfb_bytes([
        ("ProjectInfo", info14),
        ("Worksheet1", bytes(64)),
        ("SessionWindow", bytes(32)),
    ]))
    legacy = b"WORKSHEET STORED BY MINITAB RELEASE 11\r\n".ljust(256, b"\0")
    out("minitab_worksheet", "saltmere-landings-r11.mtw", legacy)
    out("minitab_portable", "saltmere-catches.mtp",
        "Minitab Portable Worksheet\r\nSaltmere catches 2025 (header line only; data rows are not read)\r\n")


# ---------------------------------------------------------------- Pro Tools

def pt_block(content, body, children=b"", big=False):
    e = ">" if big else "<"
    inner = struct.pack(e + "H", content) + body + children
    return b"Z" + struct.pack(e + "HI", 1, len(inner)) + inner


def pt_string(s, big=False):
    raw = s.encode()
    return struct.pack((">" if big else "<") + "I", len(raw)) + raw


def protools(kind, value, big, version_block, name):
    e = ">" if big else "<"
    head = b"\x030010111100101011" + bytes([1 if big else 0, kind, value])
    head += bytes(0x1F - len(head))
    blocks = version_block
    blocks += pt_block(0x1028, struct.pack(e + "HI", 0, 48000), big=big)
    wavs = b"".join(pt_string(n, big) + t + bytes(5) for n, t in (
        ("Audio Files", b"\0\0\0\0"), ("harbour-bell.wav", b"EVAW"), ("gulls-dawn.wav", b"EVAW"), ("foghorn.aif", b"FFIA")))
    blocks += pt_block(0x1004, struct.pack(e + "HI", 0, 3), pt_block(0x103A, bytes(9) + wavs, big=big), big)
    tracks = b"".join(pt_block(0x1014, pt_string(n, big) + bytes(1) + struct.pack(e + "IH", 1, i), big=big)
                      for i, n in enumerate(("Harbour Bell", "Gulls", "Foghorn")))
    blocks += pt_block(0x1015, struct.pack(e + "HI", 0, 3), tracks, big)
    regions = b"".join(pt_block(0x2629, struct.pack(e + "H", 0) + bytes(7) + pt_string(n, big) + bytes(16), big=big)
                       for n in ("Harbour Bell-01", "Gulls-01", "Foghorn-01", "Foghorn-02"))
    blocks += pt_block(0x262A, struct.pack(e + "HI", 0, 4), regions, big)
    midi = b"".join(pt_block(0x251A, struct.pack(e + "H", 0) + pt_string(n, big) + bytes(18), big=big)
                    for n in ("Harbour Bell", "Gulls", "Foghorn", "Shanty Melody"))
    blocks += pt_block(0x2519, struct.pack(e + "HI", 0, 4), midi, big)
    blocks += pt_block(0x1018, struct.pack(e + "HI", 0, 1), pt_block(0x1017, bytes(2) + pt_string("Harbour Reverb", big), big=big), big)
    plain = head + blocks + bytes(32)
    # The XOR key: delta from the key byte (scheme 1: x*53, scheme 5: -(x*11)).
    mul, neg = (53, False) if kind == 1 else (11, True)
    delta = next(i for i in range(256) if (i * mul) & 0xFF == value)
    if neg:
        delta = (-delta) & 0xFF
    key = [(i * delta) & 0xFF for i in range(256)]
    data = bytearray(plain)
    for i in range(0x14, len(data)):
        data[i] ^= key[i & 0xFF] if kind == 1 else key[(i >> 12) & 0xFF]
    out("protools_session", name, bytes(data))


def protools_sessions():
    # Pro Tools 12: a version block (content 0x2067) at 0x1F, version - 2 at +20.
    v12 = pt_block(0x2067, bytes(18) + struct.pack("<I", 10) + bytes(8))
    protools(5, 0x37, False, v12, "saltmere-shanty.ptx")
    # Pro Tools 8, big-endian: product string, four bytes, version (content 0x0003).
    v8 = pt_block(0x0003, bytes(1) + pt_string("Pro Tools", True) + bytes(4) + struct.pack(">I", 8) + bytes(8), big=True)
    protools(1, 0x9F, True, v8, "saltmere-shanty-pt8.ptf")


# --------------------------------------------------------------- GarageBand

def garageband():
    def chunk(tag, data):
        return tag[::-1] + struct.pack("<HIIQIH", 1, 0x0E, 0x24, 0, 2, 1) + struct.pack("<Q", len(data)) + data

    data = b"\x23\x47\xc0\xab" + struct.pack("<HHIHHQ", 1761, 3, 4, 1, 8, 0x82462) + bytes(4)
    data += chunk(b"Song", b"Saltmere Shanty".ljust(64, b"\0"))
    for n in range(4):
        data += chunk(b"Trak", struct.pack("<I", n) + bytes(44))
    for n in range(4):
        data += chunk(b"MSeq", struct.pack("<I", n) + bytes(60))
        data += chunk(b"EvSq", struct.pack("<I", n) + bytes(28))
    for n in range(6):
        data += chunk(b"Envi", struct.pack("<I", n) + bytes(36))
        data += chunk(b"AuCU", struct.pack("<I", n) + bytes(40))
    data += chunk(b"Styl", bytes(32)) + chunk(b"TxSt", bytes(32))
    out("garageband_project", "ProjectData", data)
    meta = {
        "AudioFiles": ["Audio Files/Harbour Bell#01.aif"], "BeatsPerMinute": 96, "FrameRateIndex": 1,
        "ImpulsResponsesFiles": [], "isTimeCodeBased": False, "NumberOfTracks": 4, "PlaybackFiles": [],
        "SampleRate": 48000, "SamplerInstrumentsFiles": [], "SignatureKey": 2, "SongGenderKey": "minor",
        "SongKey": "D", "SongSignatureDenominator": 8, "SongSignatureNumerator": 6, "UltrabeatFiles": [],
        "UnusedAudioFiles": [], "Version": 3, "VideoFiles": [],
    }
    out("bplist", "saltmere-shanty-metadata.plist", plistlib.dumps(meta, fmt=plistlib.FMT_BINARY, sort_keys=True))


# ------------------------------------------------------------------ Fusion

def lp_ascii(s):
    return struct.pack("<I", len(s)) + s.encode()


def lp_utf16(s):
    return struct.pack("<I", len(s)) + s.encode("utf-16le")


DOC_ID = "5a17c0de-0001-4000-8000-000000000001"
ASSET_ID = "5a17c0de-0002-4000-8000-000000000002"


def f3d(name, description, refs=()):
    m = lp_ascii("3-2-0-0") + lp_ascii("FusionDocType") + lp_utf16(".f3d") + lp_utf16(name) + lp_utf16(description)
    m += lp_utf16(DOC_ID) + lp_utf16(ASSET_ID)
    m += struct.pack("<IIIII", 1234, 1, 2, 3, 1) + lp_ascii("Neutron3DAssetType") + struct.pack("<I", 1)
    m += lp_utf16(ASSET_ID) + struct.pack("<I", 1) + lp_utf16("FusionAssetName") + struct.pack("<I", 0)
    m += b"\x01" + lp_utf16("NA_OFFLINESAVE")
    asset = lp_utf16("FusionAssetName") + lp_utf16(ASSET_ID) + lp_utf16(DOC_ID) + lp_ascii("FusionAssetType")
    asset += struct.pack("<I", 20) + struct.pack("<I", 0) + lp_ascii("Neutron3DAssetType") + b"\0" + lp_ascii("")
    props = json.dumps({"docstruct": {"version": "1.0.0", "type": "part-design", "subtype": "part-standard", "attributes": {}}}).encode()
    redirections = {"name": "RedirectionsStream", "schema-version": 0, "designs": [
        {"file-version": 12, "targetFileName": f"{name}.f3d", "displayName": name}]
        + [{"file-version": 3, "targetFileName": f"{r}.f3d", "displayName": r} for r in refs], "references": {}}
    folder = "FusionAssetName[Active]"
    brep = b"ASM BinaryFile4" + struct.pack("<II", 22300, 3) + bytes(48)
    entries = [
        ("Manifest.dat", m),
        ("Properties.dat", struct.pack("<I", len(props)) + props),
        ("RedirectionsStream.dat", json.dumps(redirections).encode()),
        (f"{folder}/Manifest.dat", asset),
        (f"{folder}/Design1/BulkStream.dat", bytes(64)),
        (f"{folder}/Design1/MetaStream.dat", bytes(32)),
        (f"{folder}/Breps.BlobParts/BRep.BlobPart1.smbh", brep),
        (f"{folder}/Breps.BlobParts/BRep.BlobPart2.smb", brep),
        (f"{folder}/TSplines.BlobParts/Form1.tsm", bytes(24)),
        (f"{folder}/Previews/small.png", bytes(16)),
    ]
    return zip_bytes(entries)


def fusion():
    bollard = f3d("Saltmere bollard", "Cast-iron mooring bollard, quay type B")
    out("fusion_design", "saltmere-bollard.f3d", bollard)
    pontoon = f3d("Saltmere pontoon", "Floating pontoon with two bollards", refs=("Saltmere bollard",))
    graph = {"creationDate": "2025-09-01T12:00:00Z", "creatingService": "Fusion", "rootIds": [1],
             "designObjectRefs": [], "designObjects": [
                 {"id": 1, "version": 4, "relativePath": "Saltmere pontoon.f3d", "downloadAs": "Saltmere pontoon.f3d",
                  "friendlyName": "Saltmere pontoon", "contentType": "f3d"},
                 {"id": 2, "version": 12, "relativePath": "Saltmere bollard.f3d", "downloadAs": "Saltmere bollard.f3d",
                  "friendlyName": "Saltmere bollard", "contentType": "f3d"}]}
    description = {"name": "Autodesk Design Description", "version": "0.1", "designDescription": {
        "id": 1, "name": "Saltmere pontoon", "currentVersion": 4, "designGraphs": [graph]}}
    out("fusion_archive", "saltmere-pontoon.f3z", zip_bytes([
        ("Manifest.json", json.dumps({"root": "Saltmere pontoon.f3d"})),
        ("DesignDescription.json", json.dumps(description, indent=1)),
        ("Saltmere pontoon.f3d", pontoon),
        ("Saltmere bollard.f3d", bollard),
    ]))


fixed_width()
xdr()
etw()
minitab()
protools_sessions()
garageband()
fusion()
