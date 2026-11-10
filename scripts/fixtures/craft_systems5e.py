#!/usr/bin/env python3
"""Stage 8 long tail, batch 5e part 3: database, log and cache fixtures for
the fictitious Saltmere Harbour, CC0-1.0. Run in `whiff-legacy` (see
systems5e.sh). Kafka batches come from kafka-python's record-batch builder
and the Anki collection from Python's sqlite3; the rest is written from
each format's published layout.

    craft_systems5e.py OUT_DIR
"""

import datetime
import gzip
import io
import json
import sqlite3
import struct
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

OUT = Path(sys.argv[1])
T0 = int(datetime.datetime(2025, 9, 1, 12, 0, tzinfo=datetime.timezone.utc).timestamp())


def out(fmt, name, data):
    d = OUT / fmt
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data if isinstance(data, bytes) else data.encode())


def realm():
    h = struct.pack("<QQ", 4096, 0) + b"T-DB" + bytes([23, 23, 0, 0])
    out("realm", "saltmere-tides.realm", h + bytes(4096 - len(h)))


def firebird():
    p = bytearray(8192)
    p[0] = 1
    struct.pack_into("<HH", p, 16, 8192, 0x8000 | 13)
    struct.pack_into("<I", p, 20, 0)
    struct.pack_into("<I", p, 36, 42)
    mjd = (datetime.date(2025, 9, 1) - datetime.date(1858, 11, 17)).days
    struct.pack_into("<iI", p, 44, mjd, 12 * 3600 * 10_000)
    struct.pack_into("<H", p, 64, 1)
    out("firebird", "saltmere-harbour.fdb", bytes(p))


def mtf_date(y, mo, d, h, mi, s):
    v = (y << 26) | (mo << 22) | (d << 17) | (h << 12) | (mi << 6) | s
    return v.to_bytes(5, "big")


def mtf_block(kind, body, strings):
    """A DBLK: the 52-byte common header, the body, then UTF-16 strings at
    the (size, offset) slots the body names with placeholders."""
    blob, addrs = b"", []
    # Each 5-byte placeholder becomes a 4-byte address.
    base = 52 + len(body) - len(strings)
    for s in strings:
        enc = s.encode("utf-16-le")
        addrs.append(struct.pack("<HH", len(enc), base + len(blob) if enc else 0))
        blob += enc
    body = body % tuple(addrs) if addrs else body
    head = kind + struct.pack("<IHBB", 0, 52 + len(body) + len(blob), 14, 0) + struct.pack("<QQ", 0, 0) + bytes(8) + struct.pack("<II", 0, 0)
    head += struct.pack("<HH", 0, 0) + bytes([2, 0]) + struct.pack("<H", 0)
    block = head + body + blob
    return block + bytes(-len(block) % 1024)


def mssql_backup():
    class Fmt(bytes):
        def __mod__(self, addrs):
            parts = self.split(b"\0ADDR")
            outb = parts[0]
            for a, p in zip(addrs, parts[1:]):
                outb += a + p
            return outb
    tape = Fmt(struct.pack("<IIHHHH", 1, 0, 1, 0, 0, 0) + b"\0ADDR" + b"\0ADDR" + b"\0ADDR" + b"\0ADDR"
               + struct.pack("<HH", 512, 0x1200) + mtf_date(2025, 9, 1, 12, 0, 0) + bytes([1]))
    sset = Fmt(struct.pack("<IHHHH", 0, 0, 0, 0x1200, 1) + b"\0ADDR" + b"\0ADDR" + b"\0ADDR" + b"\0ADDR" + struct.pack("<Q", 0)
               + mtf_date(2025, 9, 1, 12, 5, 0) + bytes([16, 0, 0, 0, 0]))
    data = (mtf_block(b"TAPE", tape, ["Saltmere nightly", "", "", "Microsoft SQL Server"])
            + mtf_block(b"SSET", sset, ["saltmere-harbour-Full Database Backup", "Nightly full backup", "", "SALTMERE\\harbourmaster"]))
    out("mssql_backup", "saltmere-harbour.bak", data)


def kafka():
    import time
    from kafka.record.default_records import DefaultRecordBatchBuilder
    # kafka-python's gzip header carries the current time: pin it.
    time.time = lambda: float(T0)
    events = [(b"berth-1", b'{"boat":"Grey Tern","event":"arrived"}'), (b"berth-2", b'{"boat":"Herring Gull","event":"departed"}'),
              (b"berth-1", b'{"boat":"Grey Tern","event":"departed"}')]
    # Gzip only pays (and kafka-python only compresses) on a larger batch.
    events += [(b"berth-3", b'{"boat":"Saltmere Ferry","event":"moored","note":"' + b"tide " * 40 + b'"}')] * 4
    segment = b""
    offset = 0
    for codec, chunk in ((0, events[:2]), (1, events[2:])):  # 2 plain records, then 5 gzipped
        b = DefaultRecordBatchBuilder(magic=2, compression_type=codec, is_transactional=0, producer_id=-1, producer_epoch=-1,
                                      base_sequence=-1, batch_size=1 << 20)
        for i, (k, v) in enumerate(chunk):
            b.append(i, timestamp=(T0 + offset + i) * 1000, key=k, value=v, headers=[])
        batch = bytearray(b.build())
        struct.pack_into(">q", batch, 0, offset)
        segment += bytes(batch)
        offset += len(chunk)
    out("kafka_log", "00000000000000000000.log", segment)
    out("kafka_index", "00000000000000000000.index", struct.pack(">II", 1, 70) + struct.pack(">II", 2, len(segment) // 2) + bytes(8 * 6))
    out("kafka_index", "00000000000000000000.timeindex", struct.pack(">qI", (T0 + 2) * 1000, 2) + bytes(12 * 4))


def uvar(n):
    out_ = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out_ += bytes([b | (0x80 if n else 0)])
        if not n:
            return out_


def tsdb():
    symbols = ["__name__", "harbour_boats_moored", "instance", "job", "quay", "east", "long_wall", "saltmere:9100", "harbour"]
    table = struct.pack(">I", len(symbols)) + b"".join(uvar(len(s)) + s.encode() for s in symbols)
    sym = struct.pack(">I", len(table)) + table + struct.pack(">I", zlib.crc32(table))
    body = b"\xba\xaa\xd7\x00\x02" + sym
    toc = struct.pack(">6Q", 5, len(body), 0, 0, 0, 0)
    out("prometheus_tsdb", "index", body + toc + struct.pack(">I", zlib.crc32(toc)))
    chunk = lambda data: uvar(len(data)) + b"\x01" + data + struct.pack(">I", zlib.crc32(b"\x01" + data))
    out("prometheus_tsdb", "000001", b"\x01\x30\xbc\x91\x01\0\0\0" + chunk(bytes(24)) + chunk(bytes(30)))
    meta = {"ulid": "01J6Z0000000000000SALTMERE", "minTime": T0 * 1000, "maxTime": (T0 + 7200) * 1000,
            "stats": {"numSamples": 1440, "numSeries": 2, "numChunks": 2},
            "compaction": {"level": 1, "sources": ["01J6Z0000000000000SALTMERE"]}, "version": 1}
    out("json", "tsdb-block-meta.json", json.dumps(meta, indent="\t") + "\n")


def anki():
    with tempfile.TemporaryDirectory() as d:
        db = sqlite3.connect(f"{d}/c.anki2")
        db.executescript("""
            CREATE TABLE col (id integer primary key, crt integer, mod integer, scm integer, ver integer, dty integer, usn integer, ls integer,
                              conf text, models text, decks text, dconf text, tags text);
            CREATE TABLE notes (id integer primary key, guid text, mid integer, mod integer, usn integer, tags text, flds text, sfld integer,
                                csum integer, flags integer, data text);
            CREATE TABLE cards (id integer primary key, nid integer, did integer, ord integer, mod integer, usn integer, type integer, queue integer,
                                due integer, ivl integer, factor integer, reps integer, lapses integer, left integer, odue integer, odid integer,
                                flags integer, data text);
            CREATE TABLE revlog (id integer primary key, cid integer, usn integer, ease integer, ivl integer, lastIvl integer, factor integer,
                                 time integer, type integer);
            CREATE TABLE graves (usn integer, oid integer, type integer);
        """)
        db.execute("INSERT INTO col VALUES (1, ?, ?, ?, 11, 0, 0, 0, '{}', '{}', '{\"1\": {\"name\": \"Saltmere knots\"}}', '{}', '{}')", (T0, T0 * 1000, T0 * 1000))
        for i, (front, back) in enumerate((("Bowline", "A fixed loop"), ("Clove hitch", "Two half hitches"), ("Cleat hitch", "Figure eight on a cleat"))):
            db.execute("INSERT INTO notes VALUES (?, ?, 1, ?, 0, '', ?, 0, 0, 0, '')", (i + 1, f"g{i}", T0, f"{front}\x1f{back}"))
            db.execute("INSERT INTO cards VALUES (?, ?, 1, 0, ?, 0, 0, 0, ?, 0, 2500, 0, 0, 0, 0, 0, 0, '')", (i + 1, i + 1, T0, i))
        db.execute("INSERT INTO revlog VALUES (1, 1, 0, 3, 1, 0, 2500, 6000, 0)")
        db.commit()
        db.close()
        coll = Path(f"{d}/c.anki2").read_bytes()
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as f:
        for name, data in (("collection.anki2", coll), ("media", json.dumps({"0": "bowline.png", "1": "bell.mp3"})), ("0", b"\x89PNG\r\n\x1a\n"), ("1", b"ID3")):
            f.writestr(zipfile.ZipInfo(name, (2025, 9, 1, 12, 0, 0)), data)
    out("anki", "saltmere-knots.apkg", z.getvalue())


def unified_log():
    def chunk(tag, sub, data):
        c = struct.pack("<IIQ", tag, sub, len(data)) + data
        return c + bytes(-len(c) % 8)
    def sub(tag, data):
        return struct.pack("<II", tag, len(data)) + data
    info = struct.pack("<II", 0, 0) + b"23G93".ljust(16, b"\0") + b"Mac14,2".ljust(32, b"\0")
    head = (struct.pack("<II", 125, 3) + struct.pack("<QQ", 0, T0) + struct.pack("<IiI", 0, 0, 0) + struct.pack("<I", 0)
            + sub(0x6100, struct.pack("<Q", 0)) + sub(0x6101, info) + sub(0x6102, bytes(range(16)) + struct.pack("<II", 77, 0))
            + sub(0x6103, b"/var/db/timezone/zoneinfo/Europe/London".ljust(48, b"\0")))
    data = chunk(0x1000, 0x11, head) + chunk(0x600B, 0x11, bytes(64)) + chunk(0x600D, 0, bytes(32)) + chunk(0x600D, 0, bytes(32))
    out("unified_log", "0000000000000001.tracev3", data)


def asl():
    hdr = b"ASL DB" + bytes(6) + struct.pack(">IQQIQ", 2, 0x80, T0, 0, 0)
    hdr += bytes(0x80 - len(hdr))
    recs, pos = [], 0x80
    for i, (level, dt) in enumerate(((5, 0), (3, 30), (6, 90))):
        recs.append((level, dt))
    blob = b""
    for i, (level, dt) in enumerate(recs):
        body_len = 96
        nxt = pos + body_len if i < len(recs) - 1 else 0
        rec = struct.pack(">HIQQQIHH", 0, body_len, nxt, i + 1, T0 + dt, 0, level, 0)  # 38 bytes
        rec += bytes(body_len - len(rec))
        blob += rec
        pos += len(rec)
    out("asl", "2025.09.01.G80.asl", hdr + blob)


def nfcapd():
    h = struct.pack("<HHIQBBHIQII", 0xA50C, 2, 0xF1070200, T0, 4, 0, 1, 0, 0, 5 * 1024 * 1024, 2)
    out("nfcapd", "nfcapd.202509011200", h + bytes(64))


def ipfix():
    template = struct.pack(">HH", 256, 3) + struct.pack(">HHHHHH", 8, 4, 12, 4, 2, 8)  # src, dst, packets
    tset = struct.pack(">HH", 2, 4 + len(template)) + template
    def data(rows):
        body = b"".join(struct.pack(">4s4sQ", bytes([10, 0, 0, a]), bytes([10, 0, 1, b]), n) for a, b, n in rows)
        return struct.pack(">HH", 256, 4 + len(body)) + body
    def msg(t, sets):
        return struct.pack(">HHIII", 10, 16 + len(sets), t, 1, 42) + sets
    out("ipfix", "saltmere-quay.ipfix", msg(T0, tset + data([(1, 2, 12)])) + msg(T0 + 60, data([(3, 4, 7), (1, 2, 5)])))


def firefox_cache():
    body = b"<!doctype html><title>Saltmere tides</title><p>High water 06:12</p>"
    key = b"a,:https://tides.saltmere.example/today?berth=4"
    elements = b"request-method\0GET\0response-head\0HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nServer: harbour\r\n\0"
    chunks = (len(body) + 262143) // 262144
    meta = struct.pack(">I", 0) + bytes(2 * chunks) + struct.pack(">8I", 3, 2, T0, T0 - 3600, 0, T0 + 86400, len(key), 0) + key + b"\0" + elements
    out("firefox_cache", "D8A4C90E2F7B1A3C5D6E7F8091A2B3C4D5E6F708", body + meta + struct.pack(">I", len(body)))


def chrome_cache():
    block = struct.pack("<IIhhiii", 0xC104CAC3, 0x20000, 1, 0, 256, 3, 2048) + bytes(8192 - 24)
    out("chrome_cache", "data_1", block)
    index = struct.pack("<IIiiiiiiii", 0xC103CAC3, 0x30000, 3, 12345, 1, 0, 0, 0x10000, 0, 0) + struct.pack("<Q", (T0 + 11644473600) * 1_000_000)
    out("chrome_cache", "index", index + bytes(256 - len(index)))
    key = b"1/0/_dk_https://saltmere.example https://saltmere.example https://tides.saltmere.example/chart.png"
    simple = struct.pack("<QIII", 0xFCFB6D1BA7725C30, 5, len(key), 0x1234ABCD) + key + b"\x89PNG\r\n\x1a\n" + bytes(16)
    out("chrome_cache", "4f1c2b3a5d6e7f80_0", simple)


for step in (realm, firebird, mssql_backup, kafka, tsdb, anki, unified_log, asl, nfcapd, ipfix, firefox_cache, chrome_cache):
    step()
