#!/usr/bin/env python3
"""Stage 8 long tail, batch 5e part 4: package, bytecode, key, big-data and
wrapper fixtures for the fictitious Saltmere Harbour, CC0-1.0. Run in
`whiff-legacy` (see packages5e.sh). Everything is written from each
format's published layout (Hermes BytecodeFileFormat.h version 96, the
AVM2 overview, the OpenSmalltalk image header, draft-bottomley-tpm2-keys
and the TPM 2.0 structures, tpm2-tools context files, Hadoop's
SequenceFile and Hive's RCFile writers, Hudi's table config and commit
metadata, Unity's package layout); legacy_oracle.py reads them back with
tpm2-tools, OpenSSL, libmagic and Python's tarfile.

    craft_packages5e.py OUT_DIR
"""

import gzip
import hashlib
import io
import json
import struct
import sys
import tarfile
import zlib
from pathlib import Path

OUT = Path(sys.argv[1])
MTIME = 1756728000  # 2025-09-01T12:00:00Z


def out(fmt, name, data):
    d = OUT / fmt
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data if isinstance(data, bytes) else data.encode())


def pattern(n, seed):
    """Deterministic filler bytes (a 32-bit LCG)."""
    x, b = seed, bytearray()
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        b.append(x >> 24)
    return bytes(b)


def align4(b):
    return b + bytes(-len(b) % 4)


# ------------------------------------------------------------------ Hermes

def hermes():
    source = b"function tideHeight(h){return h*2}\nfunction bellRings(n){return n>3}\nprint(tideHeight(3), bellRings(4));\n"
    strings = [b"global", b"tideHeight", b"bellRings", b"print", b"Saltmere"]
    identifiers = 4
    storage = b"".join(strings)
    small, off = b"", 0
    for s in strings:
        small += struct.pack("<I", (off << 1) | (len(s) << 24))
        off += len(s)
    # Function bodies: tiny instruction streams (not decoded by whiff).
    bodies = [bytes([0x01, 0x00, 0x5c, 0x00]), bytes([0x2a, 0x00, 0x00, 0x5c, 0x00]), bytes([0x3b, 0x00, 0x5c, 0x00])]
    names = [0, 1, 2]
    params = [1, 2, 2]
    kinds = struct.pack("<II", (1 << 31) | identifiers, len(strings) - identifiers)  # identifier, then string runs
    hashes = b"".join(struct.pack("<I", zlib.crc32(s)) for s in strings[:identifiers])
    regexp_table = struct.pack("<II", 0, 8)
    regexp_storage = b"\x01\x00\x02tide"[:8].ljust(8, b"\0")
    nfun = len(bodies)
    head_len = 128
    sections = [
        b"",  # function headers, filled below
        align4(kinds),
        align4(hashes),
        align4(small),
        b"",  # overflow strings
        align4(storage),
        b"", b"", b"",  # array, object key, object value buffers
        b"", b"",  # bigint table and storage
        align4(regexp_table),
        align4(regexp_storage),
        b"", b"",  # CommonJS modules, function sources
    ]
    tables = 16 * nfun + sum(len(s) for s in sections)
    code_at = head_len + tables
    headers, code, at = b"", b"", code_at
    for body, name, p in zip(bodies, names, params):
        flags = 2 | 4  # prohibit none, strict mode
        headers += struct.pack("<IIII", at | (p << 25), len(body) | (name << 15), 0 | (4 << 25), 1 | (flags << 24))
        code += body
        at += len(body)
    sections[0] = headers
    body = b"".join(sections) + align4(code)
    debug_at = head_len + len(body)
    debug = struct.pack("<7I", 1, 8, 1, 0, 0, 0, 0) + b"tides.js"
    total = head_len + len(body) + len(debug) + 20
    header = struct.pack("<QI", 0x1F1903C103BC1FC6, 96) + hashlib.sha1(source).digest()
    header += struct.pack(
        "<19I", total, 0, nfun, 2, identifiers, len(strings), 0, len(storage), 0, 0, 1, 8, 0, 0, 0, 0, 0, 0, debug_at
    )
    header += bytes([0b101]) + bytes(19)
    assert len(header) == 128
    data = header + body + debug
    out("hermes_bytecode", "saltmere-tides.hbc", data + hashlib.sha1(data).digest())


# ---------------------------------------------------------------- Smalltalk

def smalltalk():
    heap = pattern(4096, 7)
    h = struct.pack("<II", 68021, 128) + struct.pack("<6Q", len(heap), 0x10000000, 0x10004A28, 0, (1024 << 16) | 768, 0)
    h += struct.pack("<IHHIHH", 0, 50, 0, 10 * 1024 * 1024, 0, 0) + struct.pack("<QQ", len(heap), 0)
    out("smalltalk_image", "saltmere-spur64.image", h.ljust(128, b"\0") + heap)
    heap = pattern(2048, 11)
    h = struct.pack(">II", 6505, 64) + struct.pack(">6I", len(heap), 0x0100_0000, 0x0100_0A28, 0, (800 << 16) | 600, 1)
    h += struct.pack(">IHHIHH", 0, 0, 0, 0, 0, 0) + struct.pack(">I", 0)
    out("smalltalk_image", "saltmere-classic.image", h.ljust(64, b"\0") + heap)
    log = (
        "'From Pharo12.0.0 of 1 May 2024 [Build information: Pharo-12.0.0+SNAPSHOT.build.1521] on 1 September 2025 at 12:00:00 pm'!\r"
        "!Object subclass: #Tide\r\tinstanceVariableNames: 'height'\r\tclassVariableNames: ''\r\tpackage: 'Saltmere-Harbour'!\r"
        "!Tide methodsFor: 'accessing' stamp: 'SH 9/1/2025 12:00'!\rheight\r\t^ height! !\r"
        "!Tide methodsFor: 'accessing' stamp: 'SH 9/1/2025 12:01'!\rheight: aNumber\r\theight := aNumber! !\r"
        "!Bell methodsFor: 'ringing' stamp: 'QM 9/1/2025 12:05'!\rring\r\t^ 'dong'! !\r"
        "\"----SNAPSHOT----(1 September 2025 12:10:00) saltmere.image priorSource: 812!\r"
        "\"----STARTUP---- (2 September 2025 08:00:00) as /harbour/saltmere.image!\r"
    )
    out("smalltalk_changes", "saltmere.changes", log)


# --------------------------------------------------------------------- ABC

def u30(n):
    b = bytearray()
    while True:
        x = n & 0x7F
        n >>= 7
        if n:
            b.append(x | 0x80)
        else:
            b.append(x)
            return bytes(b)


def abc_file():
    strings = ["", "saltmere.harbour", "Tide", "", "Object", "height", "Bell", "ring", "IRinger", "SWF", "width", "550"]
    S = {s: i for i, s in enumerate(strings) if i}
    S[""] = 3
    pool = u30(1) + u30(1) + u30(1)  # no ints, uints, doubles
    pool += u30(len(strings)) + b"".join(u30(len(s.encode())) + s.encode() for s in strings[1:])
    # Namespaces: 1 = package saltmere.harbour, 2 = the public package.
    pool += u30(3) + bytes([0x16]) + u30(S["saltmere.harbour"]) + bytes([0x16]) + u30(S[""])
    pool += u30(1)  # no namespace sets
    mn = [(1, "Tide"), (2, "Object"), (1, "Bell"), (2, "height"), (1, "IRinger"), (2, "ring")]
    pool += u30(len(mn) + 1) + b"".join(bytes([0x07]) + u30(ns) + u30(S[n]) for ns, n in mn)
    M = {n: i + 1 for i, (_, n) in enumerate(mn)}
    methods = 8
    out_ = struct.pack("<HH", 16, 46) + pool + u30(methods) + b"".join(u30(0) + u30(0) + u30(0) + b"\0" for _ in range(methods))
    out_ += u30(1) + u30(S["SWF"]) + u30(1) + u30(S["width"]) + u30(S["550"])
    # Classes: Tide (sealed; getter `height`, a slot with metadata), Bell
    # implements IRinger (method `ring`), IRinger (interface).
    def instance(name, sup, flags, interfaces, iinit, traits):
        return u30(M[name]) + u30(M[sup] if sup else 0) + bytes([flags]) + u30(len(interfaces)) + b"".join(u30(M[i]) for i in interfaces) + u30(iinit) + traits
    tide_traits = u30(2) + u30(M["height"]) + bytes([0x02]) + u30(0) + u30(2) + u30(M["Object"]) + bytes([0x40]) + u30(1) + u30(0) + u30(0) + u30(1) + u30(0)
    bell_traits = u30(1) + u30(M["ring"]) + bytes([0x01]) + u30(0) + u30(4)
    out_ += u30(3)
    out_ += instance("Tide", "Object", 0x01, [], 0, tide_traits)
    out_ += instance("Bell", "Object", 0x00, ["IRinger"], 3, bell_traits)
    out_ += instance("IRinger", None, 0x04, [], 5, u30(0))
    for cinit in (1, 6, 6):
        out_ += u30(cinit) + u30(0)
    script_traits = u30(3) + b"".join(u30(M[n]) + bytes([0x04]) + u30(i + 1) + u30(i) for i, n in enumerate(["Tide", "Bell", "IRinger"]))
    out_ += u30(1) + u30(7) + script_traits
    code = bytes([0xD0, 0x30, 0x47])
    bodies = [0, 1, 2, 3, 4, 7]
    out_ += u30(len(bodies)) + b"".join(u30(m) + u30(1) + u30(1) + u30(0) + u30(1) + u30(len(code)) + code + u30(0) + u30(0) for m in bodies)
    return out_


def abc():
    a = abc_file()
    out("flash_abc", "saltmere-harbour.abc", a)
    # A SWF 10 with FileAttributes (AS3) and the same ABC in a DoABC2 tag.
    def tag(code, body):
        if len(body) < 63:
            return struct.pack("<H", (code << 6) | len(body)) + body
        return struct.pack("<HI", (code << 6) | 0x3F, len(body)) + body
    def rect(xmax, ymax, nbits=15):
        bits = format(nbits, "05b") + "".join(format(v, f"0{nbits}b") for v in (0, xmax, 0, ymax))
        bits += "0" * (-len(bits) % 8)
        return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    rect = rect(550 * 20, 400 * 20)  # twips
    body = rect + struct.pack("<HH", 24 << 8, 1)
    body += tag(69, struct.pack("<I", 0x08)) + tag(82, struct.pack("<I", 1) + b"saltmere/harbour\0" + a) + tag(1, b"") + tag(0, b"")
    out("swf", "saltmere-abc.swf", b"FWS" + bytes([10]) + struct.pack("<I", 8 + len(body)) + body)


# --------------------------------------------------------------------- TPM

def der(tag, body):
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + body


def oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    b = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        b += bytes(reversed(enc))
    return der(0x06, b)


def tpm2b(b):
    return struct.pack(">H", len(b)) + b


def tpm_key(kind_oid, public, private, empty_auth, description=None):
    body = oid(kind_oid)
    if empty_auth:
        body += der(0xA0, der(0x01, b"\xff"))
    if description:
        body += der(0xA4, der(0x0C, description.encode()))
    body += der(0x02, b"\x40\x00\x00\x01") + der(0x04, tpm2b(public)) + der(0x04, tpm2b(private))
    return der(0x30, body)


def tpm():
    attrs = 0x2 | 0x10 | 0x20 | 0x40 | 0x400 | 0x20000 | 0x40000
    rsa = struct.pack(">HHI", 0x0001, 0x000B, attrs) + tpm2b(b"") + struct.pack(">HHHI", 0x0010, 0x0010, 2048, 0)
    rsa += tpm2b(bytes([0xC1]) + pattern(255, 3))
    key = tpm_key("2.23.133.10.1.3", rsa, pattern(222, 5), True)
    pem = "-----BEGIN TSS2 PRIVATE KEY-----\n"
    import base64
    b64 = base64.b64encode(key).decode()
    pem += "".join(b64[i:i + 64] + "\n" for i in range(0, len(b64), 64)) + "-----END TSS2 PRIVATE KEY-----\n"
    out("tpm2_key", "saltmere-signing.tss", pem)
    ecc_attrs = 0x2 | 0x10 | 0x20 | 0x40 | 0x40000
    ecc = struct.pack(">HHI", 0x0023, 0x000B, ecc_attrs) + tpm2b(b"") + struct.pack(">HHHHH", 0x0010, 0x0018, 0x000B, 0x0003, 0x0010)
    ecc += tpm2b(pattern(32, 9)) + tpm2b(pattern(32, 10))
    out("tpm2_key", "saltmere-ecc.der", tpm_key("2.23.133.10.1.3", ecc, pattern(126, 6), False, "Saltmere harbour signing key"))
    blob = pattern(64, 12)
    ctx = struct.pack(">III", 0xBADCC0DE, 1, 0x40000001) + struct.pack(">IQ", 0x80000000, 0x14) + tpm2b(blob)
    out("tpm2_context", "saltmere-primary.ctx", ctx)


# ------------------------------------------------------------------ Hadoop

def vlong(i):
    if -112 <= i <= 127:
        return struct.pack("b", i)
    ln = -112
    if i < 0:
        i, ln = ~i, -120
    t = i
    while t:
        t >>= 8
        ln -= 1
    b = struct.pack("b", ln)
    n = -(ln + 120) if ln < -120 else -(ln + 112)
    return b + bytes((i >> ((k - 1) * 8)) & 0xFF for k in range(n, 0, -1))


def text(s):
    s = s.encode()
    return vlong(len(s)) + s


SYNC = hashlib.md5(b"saltmere harbour sync").digest()
BERTHS = ["north-quay", "south-quay", "fish-dock", "ferry-slip", "lifeboat", "pilot-jetty"]


def seq_header(key, value, compressed, block, codec, meta):
    h = b"SEQ\x06" + text(key) + text(value) + bytes([compressed, block])
    if compressed:
        h += text(codec)
    h += struct.pack(">i", len(meta)) + b"".join(text(k) + text(v) for k, v in meta)
    return h + SYNC


def sequencefile():
    rows = [(BERTHS[i % 6] + f"-{i:02d}", 300 + 7 * i) for i in range(30)]
    data = seq_header("org.apache.hadoop.io.Text", "org.apache.hadoop.io.IntWritable", 0, 0, "", [("harbour", "saltmere")])
    for n, (k, v) in enumerate(rows):
        if n and n % 10 == 0:
            data += struct.pack(">i", -1) + SYNC
        kb, vb = text(k), struct.pack(">i", v)
        data += struct.pack(">ii", len(kb) + len(vb), len(kb)) + kb + vb
    out("sequencefile", "saltmere-berths.seq", data)
    codec = "org.apache.hadoop.io.compress.DefaultCodec"
    data = seq_header("org.apache.hadoop.io.Text", "org.apache.hadoop.io.IntWritable", 1, 1, codec, [])
    for block in (rows[:12], rows[12:]):
        keys = [text(k) for k, _ in block]
        vals = [struct.pack(">i", v) for _, v in block]
        def buf(b):
            z = zlib.compress(b, 9)
            return vlong(len(z)) + z
        data += struct.pack(">i", -1) + SYNC + vlong(len(block))
        data += buf(b"".join(vlong(len(k)) for k in keys)) + buf(b"".join(keys))
        data += buf(b"".join(vlong(len(v)) for v in vals)) + buf(b"".join(vals))
    out("sequencefile", "saltmere-berths-block.seq", data)


def rc_group(columns, compress):
    """One RCFile row group: key (rows, then per column its value length,
    uncompressed length and run-length row lengths) and the column values."""
    rows = len(columns[0])
    key, value = vlong(rows), b""
    for col in columns:
        cells = [c.encode() for c in col]
        raw = b"".join(cells)
        stored = zlib.compress(raw, 9) if compress else raw
        lengths = b"".join(vlong(len(c)) for c in cells)
        key += vlong(len(stored)) + vlong(len(raw)) + vlong(len(lengths)) + lengths
        value += stored
    stored_key = zlib.compress(key, 9) if compress else key
    return struct.pack(">iii", len(key) + len(value), len(key), len(stored_key)) + stored_key + value


def rcfile():
    meta = [("hive.io.rcfile.column.number", "3")]
    groups = [
        [BERTHS[:4], ["4.1", "3.8", "2.2", "5.0"], ["06:12", "06:14", "06:20", "06:31"]],
        [BERTHS[4:], ["1.9", "2.7"], ["07:02", "07:05"]],
    ]
    data = b"RCF\x01" + b"\0" + struct.pack(">i", len(meta)) + b"".join(text(k) + text(v) for k, v in meta) + SYNC
    data += rc_group(groups[0], False) + struct.pack(">i", -1) + SYNC + rc_group(groups[1], False)
    out("rcfile", "saltmere-readings.rc", data)
    data = seq_header(
        "org.apache.hadoop.hive.ql.io.RCFile$KeyBuffer", "org.apache.hadoop.hive.ql.io.RCFile$ValueBuffer", 1, 0,
        "org.apache.hadoop.io.compress.DefaultCodec", meta,
    )
    data += rc_group(groups[0], True) + struct.pack(">i", -1) + SYNC + rc_group(groups[1], True)
    out("rcfile", "saltmere-readings-seqform.rc", data)


# -------------------------------------------------------------------- Hudi

SCHEMA = {
    "type": "record", "name": "saltmere_tides_record", "namespace": "hoodie.saltmere_tides",
    "fields": [
        {"name": "reading_id", "type": "string"},
        {"name": "berth", "type": "string"},
        {"name": "height_m", "type": ["null", "double"], "default": None},
        {"name": "observed_at", "type": {"type": "long", "logicalType": "timestamp-micros"}},
    ],
}


def hudi():
    schema = json.dumps(SCHEMA, separators=(",", ":")).replace(":", "\\:").replace("=", "\\=")
    props = [
        "#Updated at 2025-09-01T12:00:00.000Z",
        "#Mon Sep 01 12:00:00 UTC 2025",
        "hoodie.table.name=saltmere_tides",
        "hoodie.database.name=harbour",
        "hoodie.table.type=MERGE_ON_READ",
        "hoodie.table.version=6",
        "hoodie.timeline.layout.version=1",
        "hoodie.table.base.file.format=PARQUET",
        "hoodie.table.recordkey.fields=reading_id",
        "hoodie.table.precombine.field=observed_at",
        "hoodie.table.partition.fields=berth",
        "hoodie.table.keygenerator.class=org.apache.hudi.keygen.SimpleKeyGenerator",
        "hoodie.table.metadata.partitions=files,column_stats",
        "hoodie.populate.meta.fields=true",
        "hoodie.datasource.write.hive_style_partitioning=true",
        "hoodie.archivelog.folder=archived",
        "hoodie.table.create.schema=" + schema,
        "hoodie.table.checksum=2735460341",
    ]
    out("hudi_table", "hoodie.properties", "\n".join(props) + "\n")
    def stat(berth, n, ins, upd, size):
        return {
            "fileId": f"{berth}-0001", "path": f"berth={berth}/{berth}-0001_0-12-34_20250901120000123.parquet",
            "prevCommit": "null", "numWrites": n, "numDeletes": 0, "numUpdateWrites": upd, "numInserts": ins,
            "totalWriteBytes": size, "totalWriteErrors": 0, "partitionPath": f"berth={berth}", "totalLogRecords": 0,
        }
    commit = {
        "partitionToWriteStats": {
            "berth=north-quay": [stat("north-quay", 120, 100, 20, 434512)],
            "berth=fish-dock": [stat("fish-dock", 48, 48, 0, 211040)],
        },
        "compacted": False,
        "extraMetadata": {"schema": json.dumps(SCHEMA)},
        "operationType": "UPSERT",
    }
    out("hudi_commit", "20250901120000123.deltacommit", json.dumps(commit, indent=2) + "\n")


# ------------------------------------------------------------------- Unity

def unity():
    assets = [
        ("3f2a9c4e5b6d7e8f90a1b2c3d4e5f601", "Assets/Saltmere", None),
        ("4a1b2c3d4e5f60718293a4b5c6d7e8f9", "Assets/Saltmere/Scripts/Tide.cs", b"public class Tide { public float Height; }\n"),
        ("5b2c3d4e5f60718293a4b5c6d7e8f90a", "Assets/Saltmere/Scripts/Bell.cs", b"public class Bell { public void Ring() {} }\n"),
        ("6c3d4e5f60718293a4b5c6d7e8f90a1b", "Assets/Saltmere/Materials/Harbour.mat", b"%YAML 1.1\n--- !u!21 &2100000\nMaterial:\n  m_Name: Harbour\n"),
        ("7d4e5f60718293a4b5c6d7e8f90a1b2c", "Assets/Saltmere/Scenes/Quay.unity", b"%YAML 1.1\n--- !u!29 &1\nOcclusionCullingSettings:\n  m_ObjectHideFlags: 0\n"),
    ]
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as t:
        def add(name, data=None):
            info = tarfile.TarInfo(name)
            info.mtime, info.uid, info.gid, info.uname, info.gname = MTIME, 0, 0, "", ""
            if data is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                t.addfile(info)
            else:
                info.size, info.mode = len(data), 0o644
                t.addfile(info, io.BytesIO(data))
        for guid, path, data in assets:
            add(guid)
            if data is not None:
                add(f"{guid}/asset", data)
            add(f"{guid}/asset.meta", f"fileFormatVersion: 2\nguid: {guid}\n".encode())
            add(f"{guid}/pathname", path.encode() + b"\n00")
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0, filename="") as g:
        g.write(raw.getvalue())
    out("unity_package", "saltmere-harbour.unitypackage", gz.getvalue())


# ---------------------------------------------------------------- Wrappers

def wrappers():
    # A download stopped part-way: the received bytes, then the space the
    # browser reserved for the rest.
    out("partial_download", "saltmere-chart.crdownload", pattern(12288, 21) + bytes(8192))
    # A backup copy of a binary ledger (fixed-size records).
    recs = b"".join(struct.pack("<I16sf", i, b.encode().ljust(16, b"\0"), 1.5 + i) for i, b in enumerate(BERTHS * 4))
    out("backup_copy", "saltmere-ledger.orig", b"\x7fLDG" + struct.pack("<I", len(BERTHS) * 4) + recs + bytes(4096))


# --------------------------------------------------------------------- OCI

def oci():
    out("json", "oci-index.json", json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 1013,
             "digest": "sha256:" + hashlib.sha256(b"amd64").hexdigest(),
             "platform": {"architecture": "amd64", "os": "linux"},
             "annotations": {"org.opencontainers.image.ref.name": "saltmere/tides:1.4"}},
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 1013,
             "digest": "sha256:" + hashlib.sha256(b"arm64").hexdigest(),
             "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"}},
        ],
        "annotations": {"org.opencontainers.image.created": "2025-09-01T12:00:00Z"},
    }, indent=2) + "\n")
    out("json", "oras-artifact.json", json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.saltmere.tide-table.v1",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "size": 2,
                   "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
        "layers": [
            {"mediaType": "text/csv", "size": 4210, "digest": "sha256:" + hashlib.sha256(b"tides").hexdigest(),
             "annotations": {"org.opencontainers.image.title": "tides-2025-09.csv"}},
            {"mediaType": "application/pdf", "size": 88120, "digest": "sha256:" + hashlib.sha256(b"chart").hexdigest(),
             "annotations": {"org.opencontainers.image.title": "harbour-chart.pdf"}},
        ],
        "subject": {"mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 1013,
                    "digest": "sha256:" + hashlib.sha256(b"amd64").hexdigest()},
        "annotations": {"org.opencontainers.image.created": "2025-09-01T12:00:00Z"},
    }, indent=2) + "\n")


for step in (hermes, smalltalk, abc, tpm, sequencefile, rcfile, hudi, unity, wrappers, oci):
    step()
