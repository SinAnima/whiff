#!/usr/bin/env python3
"""Write the batch 4 long-tail fixtures (older archivers, Mac and encoded
wrappers, Windows imaging, backups, executables, documents).

    craft_legacy.py <out> [STEP ...]

Runs in the `whiff-legacy` container (see legacy.sh). Each step writes
`<out>/<format id>/<file>`. Where a tool writes the format (arc, kgb, zpaq,
wimlib-imagex, …) the tool is used; the rest is built from the format's
specification and checked by legacy_oracle.py with an independent reader
(lsar, acefile, nomarch, …).

Names and texts are fictitious (Saltmere harbour). Times are fixed
(2025-09-01 12:00:00 UTC), so the output is the same on every run.
"""

import os
import re
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

OUT = Path(sys.argv[1])
WORK = OUT / "_work"
STAMP = "2025-09-01 12:00:00"
EPOCH = 1756728000  # STAMP as Unix seconds
DOS_DATE = ((2025 - 1980) << 9) | (9 << 5) | 1
DOS_TIME = 12 << 11

NOTES = (
    b"Saltmere harbour notes\r\n"
    b"High water 06:12, low water 12:31. The pilot launch leaves at dawn.\r\n"
    b"Ben Gull keeps the bell tower log; Ana Lighthouse keeps the charts.\r\n"
)
LOG = b"date,boat,berth\r\n2025-09-01,Harbour Bell,3\r\n2025-09-01,Grey Tern,5\r\n2025-09-02,Low Water,1\r\n"
CHART = b"Saltmere bay chart: soundings in fathoms, the long wall, the bell buoy.\r\n" * 6


def out(fmt: str, name: str, data: bytes) -> None:
    d = OUT / fmt
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data)


def run(*cmd: str, cwd: Path, faketime: bool = False) -> None:
    # NO_FAKE_STAT: libfaketime would also shift the files' own times.
    env = dict(os.environ, TZ="UTC", LC_ALL="C", NO_FAKE_STAT="1")
    if faketime:
        cmd = ("faketime", STAMP, *cmd)
    subprocess.run(cmd, cwd=cwd, env=env, check=True, stdout=subprocess.DEVNULL)


def payload(dos_names: bool = False) -> Path:
    """The harbour folder: two texts and a chart in a subfolder, fixed times."""
    p = WORK / ("HARBOUR" if dos_names else "harbour")
    shutil.rmtree(p, ignore_errors=True)
    (p / ("CHARTS" if dos_names else "charts")).mkdir(parents=True)
    files = {
        ("NOTES.TXT" if dos_names else "notes.txt"): NOTES,
        ("LOG.CSV" if dos_names else "log.csv"): LOG,
        (("CHARTS/BAY.TXT") if dos_names else "charts/bay.txt"): CHART,
    }
    for name, data in files.items():
        (p / name).write_bytes(data)
    for f in [p, *p.rglob("*")]:
        os.utime(f, (EPOCH, EPOCH))
    return p


def crc16_arc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


# --- older DOS archivers ------------------------------------------------------


def step_dos() -> None:
    p = payload(dos_names=True)
    # ARC 5.21: entries sorted by name; the chart compresses (crunched).
    run("arc", "a", str(WORK / "saltmere.arc"), "NOTES.TXT", "LOG.CSV", cwd=p)
    run("arc", "a", str(WORK / "saltmere.arc"), "CHARTS/BAY.TXT", cwd=p)
    out("arc", "saltmere-arc521.arc", arc_clean((WORK / "saltmere.arc").read_bytes()))
    # KGB Archiver 1.0b4 (PAQ6): a text header lists the files.
    run("kgb", "-3", str(WORK / "saltmere.kgb"), "NOTES.TXT", "LOG.CSV", cwd=p)
    out("kgb", "saltmere-kgb.kgb", (WORK / "saltmere.kgb").read_bytes())
    # zpaq 7.15, two transactions (the second adds the chart).
    (WORK / "saltmere.zpaq").unlink(missing_ok=True)
    run("zpaq", "a", str(WORK / "saltmere.zpaq"), "NOTES.TXT", "LOG.CSV", cwd=p, faketime=True)
    run("zpaq", "a", str(WORK / "saltmere.zpaq"), "CHARTS", cwd=p, faketime=True)
    out("zpaq", "saltmere-zpaq715.zpaq", (WORK / "saltmere.zpaq").read_bytes())
    out("zoo", "saltmere-crafted.zoo", zoo([("NOTES.TXT", "", NOTES), ("LOG.CSV", "", LOG), ("BAY.TXT", "CHARTS", CHART)]))
    out("ace", "saltmere-crafted.ace", ace([("NOTES.TXT", NOTES), ("LOG.CSV", LOG), ("CHARTS\\BAY.TXT", CHART)]))
    out("alz", "saltmere-crafted.alz", alz([("NOTES.TXT", NOTES, 0), ("LOG.CSV", LOG, 0), ("CHARTS\\BAY.TXT", CHART, 2)]))


def arc_clean(b: bytes) -> bytes:
    """ARC 5.21 leaves uninitialised memory after each 13-byte name's NUL:
    zero it (the output is otherwise unchanged)."""
    b = bytearray(b)
    at = 0
    while at + 2 <= len(b) and b[at] == 0x1A and b[at + 1] != 0:
        method = b[at + 1]
        name = b[at + 2 : at + 15]
        end = name.index(0) if 0 in name else 13
        b[at + 2 + end : at + 15] = bytes(13 - end)
        packed = struct.unpack_from("<L", b, at + 15)[0]
        at += (25 if method == 1 else 29) + packed
    return bytes(b)


def zoo(entries: list[tuple[str, str, bytes]]) -> bytes:
    """Zoo 2.10 archive, stored entries with long-name directory entries
    (`zoo.h`): a 42-byte archive header, then a chain of directory entries
    each followed by its data, ending with an empty entry."""
    tag = 0xFDC4A7DC
    text = b"ZOO 2.10 Archive.\x1a".ljust(20, b"\0")
    head = text + struct.pack("<LLlBBBLHB", tag, 42, -42, 2, 0, 1, 0, 0, 0)
    assert len(head) == 42
    body = bytearray(head)

    def direntry(name: str, folder: str, data: bytes, nxt: int, at: int) -> bytes:
        lname, ldir = name.encode(), folder.encode()
        var = bytes([len(lname), len(ldir)]) + lname + ldir + struct.pack("<H", 0) + b"\0\0\0" + struct.pack("<HH", 0, 0)
        short = name.encode()[:12].ljust(13, b"\0")
        fixed = struct.pack(
            "<LBBLLHHHLLBBBBLH13shBH",
            tag, 2, 0, nxt, at, DOS_DATE, DOS_TIME, crc16_arc(data), len(data), len(data),
            1, 0, 0, 0, 0, 0, short, len(var), 0x7F, 0,
        )
        entry = fixed + var
        crc = crc16_arc(entry)
        return entry[:54] + struct.pack("<H", crc) + entry[56:]

    for name, folder, data in entries:
        size = len(direntry(name, folder, data, 0, 0))
        start = len(body)
        nxt = start + size + len(data)
        body += direntry(name, folder, data, nxt, start + size) + data
    body += direntry("", "", b"", 0, 0)
    return bytes(body)


def alz(entries: list[tuple[str, bytes, int]]) -> bytes:
    """ALZip (`unalz`'s UnAlz.h): `ALZ\\x01`, then per entry `BLZ\\x01`, the
    name length, attributes, DOS time, a descriptor (0x40: 4-byte sizes),
    method (0 stored, 2 deflate), CRC-32, sizes, name and data; `CLZ`
    end records."""
    stamp = (DOS_DATE << 16) | DOS_TIME
    body = bytearray(b"ALZ\x01\x0a\x00\x00\x00")
    for name, data, method in entries:
        comp = data if method == 0 else zlib.compress(data, 9)[2:-4]
        n = name.encode()
        body += b"BLZ\x01" + struct.pack("<HBLBB", len(n), 0x20, stamp, 0x40, 0)
        body += struct.pack("<BBLLL", method, 0, zlib.crc32(data), len(comp), len(data)) + n + comp
    return bytes(body + b"CLZ\x01" + b"\0" * 12 + b"CLZ\x02")


def ace_crc32(data: bytes) -> int:
    return zlib.crc32(data) ^ 0xFFFFFFFF


def ace(entries: list[tuple[str, bytes]]) -> bytes:
    """ACE 2.0 archive (`acefile` / unace), stored entries, with the
    advertisement string unregistered copies carry."""

    def block(body: bytes) -> bytes:
        return struct.pack("<HH", ace_crc32(body) & 0xFFFF, len(body)) + body

    advert = b"*UNREGISTERED VERSION*"
    main = (
        struct.pack("<BH", 0, 0x0100 | 0x1000)
        + b"**ACE**"
        + struct.pack("<BBBBL", 20, 20, 2, 0, (DOS_DATE << 16) | DOS_TIME)
        + b"\0" * 8
        + bytes([len(advert)])
        + advert
    )
    out_ = bytearray(block(main))
    for name, data in entries:
        fname = name.encode()
        h = (
            struct.pack("<BHLL", 1, 0x0001, len(data), len(data))
            + struct.pack("<LLLBBHHH", (DOS_DATE << 16) | DOS_TIME, 0x20, ace_crc32(data), 0, 0, 0, 0, len(fname))
            + fname
        )
        out_ += block(h) + data
    return bytes(out_)


# --- Macintosh wrappers --------------------------------------------------------

MAC_EPOCH = 2082844800  # seconds from 1904 to 1970
MAC_STAMP = EPOCH + MAC_EPOCH


def crc16_xmodem(data: bytes, crc: int = 0) -> int:
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def resource_fork(resources: list[tuple[bytes, int, bytes]]) -> bytes:
    """A resource fork (Inside Macintosh: More Macintosh Toolbox 1-121):
    header, the resources' data, and a map with one type list entry per
    type and one reference per resource (no names)."""
    data = bytearray()
    offsets = []
    for _, _, body in resources:
        offsets.append(len(data))
        data += struct.pack(">L", len(body)) + body
    types: dict[bytes, list[int]] = {}
    for i, (kind, _, _) in enumerate(resources):
        types.setdefault(kind, []).append(i)
    type_list = bytearray(struct.pack(">H", len(types) - 1))
    refs = bytearray()
    ref_base = 2 + 8 * len(types)
    for kind, idx in types.items():
        type_list += kind + struct.pack(">HH", len(idx) - 1, ref_base + len(refs))
        for i in idx:
            refs += struct.pack(">hHL", resources[i][1], 0xFFFF, offsets[i] & 0xFFFFFF) + b"\0\0\0\0"
    map_ = bytearray(b"\0" * 16 + b"\0\0\0\0" + b"\0\0" + b"\0\0")
    map_ += struct.pack(">HH", 28, 28 + len(type_list) + len(refs))
    map_ += type_list + refs
    data_at = 256
    map_at = data_at + len(data)
    header = struct.pack(">LLLL", data_at, map_at, len(data), len(map_))
    map_[:16] = header
    return header + b"\0" * (256 - 16) + bytes(data) + bytes(map_)


RSRC = resource_fork([
    (b"STR ", 128, bytes([22]) + b"Saltmere harbour notes"),
    (b"vers", 1, b"\x01\x00\x80\x00\x00\x00\x031.0\x1aSaltmere Harbour 1.0 (CC0)"),
])


def macbinary(name: bytes, kind: bytes, creator: bytes, data: bytes, rsrc: bytes) -> bytes:
    """MacBinary II: a 128-byte header (CRC-16/XMODEM over its first 124
    bytes), then each fork padded to 128 bytes."""
    h = bytearray(128)
    h[1] = len(name)
    h[2 : 2 + len(name)] = name
    h[65:69], h[69:73] = kind, creator
    h[73] = 0x01  # Finder flags (high byte): on the desktop
    struct.pack_into(">LLLL", h, 83, len(data), len(rsrc), MAC_STAMP, MAC_STAMP)
    h[122], h[123] = 129, 129
    struct.pack_into(">H", h, 124, crc16_xmodem(bytes(h[:124])))

    def pad(b: bytes) -> bytes:
        return b + b"\0" * (-len(b) % 128)

    return bytes(h) + pad(data) + pad(rsrc)


def stuffit(entries: list) -> bytes:
    """Classic StuffIt 1.5 (`SIT!` … `rLau`, the count of top-level
    entries and the archive length): 112-byte entry headers with a
    CRC-16 (ARC) over their first 110 bytes, stored forks; folders are
    method 32 entries closed by a method 33 entry."""
    body = bytearray()
    count = 0

    def header(r_method, d_method, name, kind, creator, rlen, dlen, rcrc, dcrc):
        h = bytearray(112)
        h[0], h[1], h[2] = r_method, d_method, len(name)
        h[3 : 3 + len(name)] = name
        h[66:70], h[70:74] = kind, creator
        struct.pack_into(">HLLLLLLHH", h, 74, 0, MAC_STAMP, MAC_STAMP, rlen, dlen, rlen, dlen, rcrc, dcrc)
        struct.pack_into(">H", h, 110, crc16_arc(bytes(h[:110])))
        return bytes(h)

    for e in entries:
        if e[0] == "folder":
            body += header(32, 32, e[1], b"\0" * 4, b"\0" * 4, 0, 0, 0, 0)
            for name, kind, creator, data, rsrc in e[2]:
                body += header(0, 0, name, kind, creator, len(rsrc), len(data), crc16_arc(rsrc), crc16_arc(data)) + rsrc + data
            body += header(33, 33, e[1], b"\0" * 4, b"\0" * 4, 0, 0, 0, 0)
        else:
            name, kind, creator, data, rsrc = e
            body += header(0, 0, name, kind, creator, len(rsrc), len(data), crc16_arc(rsrc), crc16_arc(data)) + rsrc + data
        count += 1
    head = b"SIT!" + struct.pack(">HL", count, 22 + len(body)) + b"rLau" + bytes([2]) + b"\0" * 7
    return head + bytes(body)


def step_mac() -> None:
    mb = macbinary(b"Harbour Notes", b"TEXT", b"ttxt", NOTES.replace(b"\r\n", b"\r"), RSRC)
    out("macbinary", "harbour-notes-crafted.bin", mb)
    (WORK / "notes.bin").write_bytes(mb)
    # macutils `binhex` reads MacBinary and writes BinHex 4.0.
    hqx = subprocess.run(["binhex", str(WORK / "notes.bin")], check=True, capture_output=True).stdout
    out("binhex", "harbour-notes-macutils.hqx", hqx)
    # The same with the comment line BinHex 4.0 itself writes (macutils
    # writes its own).
    std = b"(This file must be converted with BinHex 4.0)" + hqx[hqx.index(b"\n"):]
    out("binhex", "harbour-notes-binhex40.hqx", std)
    out(
        "stuffit",
        "saltmere-crafted.sit",
        stuffit([
            (b"Harbour Notes", b"TEXT", b"ttxt", NOTES.replace(b"\r\n", b"\r"), RSRC),
            ("folder", b"Charts", [(b"Bay Chart", b"TEXT", b"ttxt", CHART.replace(b"\r\n", b"\r"), b"")]),
            (b"Berth Log", b"TEXT", b"XCEL", LOG.replace(b"\r\n", b"\r"), b""),
        ]),
    )


# --- encoded and shell-script wrappers -------------------------------------------


def yenc(name: str, data: bytes, line: int = 128) -> bytes:
    """yEnc 1.3, one part: each byte + 42, with NUL, LF, CR and `=`
    escaped (and a TAB, space or `.` that would start or end a line)."""
    out_ = bytearray(f"=ybegin line={line} size={len(data)} name={name}\r\n".encode())
    col = 0
    for b in data:
        c = (b + 42) & 0xFF
        if c in (0, 10, 13, 61) or (c in (9, 32) and col in (0, line - 1)) or (c == 46 and col == 0):
            out_ += bytes([61, (c + 64) & 0xFF])
            col += 2
        else:
            out_.append(c)
            col += 1
        if col >= line:
            out_ += b"\r\n"
            col = 0
    if col:
        out_ += b"\r\n"
    out_ += f"=yend size={len(data)} crc32={zlib.crc32(data):08x}\r\n".encode()
    return bytes(out_)


def step_encoded() -> None:
    p = payload()
    uue = subprocess.run(["uuencode", "notes.txt", "notes.txt"], cwd=p, check=True, capture_output=True).stdout
    out("uuencode", "harbour-notes-sharutils.uue", uue)
    gz = subprocess.run(["gzip", "-9nc", str(p / "log.csv")], check=True, capture_output=True).stdout
    (WORK / "log.csv.gz").write_bytes(gz)
    b64u = subprocess.run(["uuencode", "-m", "log.csv.gz", "log.csv.gz"], cwd=WORK, check=True, capture_output=True).stdout
    out("uuencode", "berth-log-base64-sharutils.uue", b64u)
    b64 = subprocess.run(["base64", str(p / "notes.txt")], check=True, capture_output=True).stdout
    out("base64", "harbour-notes-coreutils.b64", b64)
    out("yenc", "harbour-chart-crafted.yenc", yenc("bay.txt", CHART))
    # GNU sharutils; its header names the user, host and folder: replaced
    # with fictitious ones.
    shar = subprocess.run(
        ["faketime", STAMP, "shar", "notes.txt", "log.csv", "charts/bay.txt"],
        cwd=p, check=True, capture_output=True, env=dict(os.environ, TZ="UTC", NO_FAKE_STAT="1"),
    ).stdout
    shar = re.sub(rb"(# Made on [^\n]* by )<[^>]*>", rb"\1<harbour@saltmere.example>", shar)
    shar = re.sub(rb"# Source directory was '[^']*'", b"# Source directory was '/srv/harbour'", shar)
    out("shar", "saltmere-sharutils.shar", shar)
    # Plain (LF) text goes in as text, not uuencoded.
    lf = WORK / "lf"
    lf.mkdir(exist_ok=True)
    (lf / "tide-table.txt").write_bytes(b"Saltmere tides, September\nhigh 06:12  low 12:31\nhigh 18:40  low 00:55\n")
    os.utime(lf / "tide-table.txt", (EPOCH, EPOCH))
    shar = subprocess.run(
        ["faketime", STAMP, "shar", "tide-table.txt"],
        cwd=lf, check=True, capture_output=True, env=dict(os.environ, TZ="UTC", NO_FAKE_STAT="1"),
    ).stdout
    shar = re.sub(rb"(# Made on [^\n]* by )<[^>]*>", rb"\1<harbour@saltmere.example>", shar)
    shar = re.sub(rb"# Source directory was '[^']*'", b"# Source directory was '/srv/harbour'", shar)
    out("shar", "tide-table-sharutils.shar", shar)
    # Relative paths: the script records its build command.
    run(
        "makeself", "--nox11", "--tar-extra", "--owner=0 --group=0 --numeric-owner --mtime=@" + str(EPOCH),
        "harbour", "saltmere.run", "Saltmere harbour notes", "./notes.txt",
        cwd=WORK, faketime=True,
    )
    out("makeself", "saltmere-makeself250.run", (WORK / "saltmere.run").read_bytes())


# --- Windows imaging --------------------------------------------------------------


def step_wim() -> None:
    p = payload()
    wim, esd = WORK / "saltmere.wim", WORK / "saltmere.esd"
    for f in (wim, esd):
        f.unlink(missing_ok=True)
    run("wimlib-imagex", "capture", str(p), str(wim), "Saltmere", "Harbour notes and charts", "--compress=lzx", cwd=WORK, faketime=True)
    run("wimlib-imagex", "append", str(p / "charts"), str(wim), "Saltmere charts", cwd=WORK, faketime=True)
    # The properties a Windows image carries, with fictitious values.
    for prop in (
        "WINDOWS/ARCH=9",
        "WINDOWS/PRODUCTNAME=Saltmere Harbour Workstation",
        "WINDOWS/EDITIONID=Harbour",
        "WINDOWS/INSTALLATIONTYPE=Client",
        "WINDOWS/VERSION/MAJOR=10",
        "WINDOWS/VERSION/MINOR=0",
        "WINDOWS/VERSION/BUILD=26100",
        "WINDOWS/VERSION/SPBUILD=1",
        "WINDOWS/LANGUAGES/LANGUAGE=en-GB",
        "DISPLAYNAME=Saltmere Harbour Workstation",
        "FLAGS=Harbour",
    ):
        run("wimlib-imagex", "info", str(wim), "1", "--image-property", prop, cwd=WORK, faketime=True)
    out("wim", "saltmere-wimlib.wim", wim.read_bytes())
    run("wimlib-imagex", "export", str(wim), "all", str(esd), "--solid", cwd=WORK, faketime=True)
    out("wim", "saltmere-wimlib-solid.esd", esd.read_bytes())


# --- ZIP-based bundles -------------------------------------------------------------


def fixed_zip(path: Path, members: list[tuple[str, bytes]], prefix: bytes = b"") -> bytes:
    """A ZIP with fixed times (and an optional `#!` line ahead of it)."""
    import io
    import zipfile

    buf = io.BytesIO()
    buf.write(prefix)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            info = zipfile.ZipInfo(name, (2025, 9, 1, 12, 0, 0))
            info.external_attr = (0o40755 if name.endswith("/") else 0o100644) << 16
            info.compress_type = zipfile.ZIP_STORED if name.endswith("/") else zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    path.write_bytes(buf.getvalue())
    return buf.getvalue()


def step_bundles() -> None:
    import zipfile

    src = WORK / "app"
    shutil.rmtree(src, ignore_errors=True)
    (src / "harbour").mkdir(parents=True)
    (src / "harbour" / "__init__.py").write_bytes(b'"""Saltmere harbour bell."""\n\n\ndef main():\n    print("The harbour bell rings at high tide.")\n')
    (src / "__main__.py").write_bytes(b"from harbour import main\n\nmain()\n")
    for f in [src, *src.rglob("*")]:
        os.utime(f, (EPOCH, EPOCH))
    run("python3", "-m", "zipapp", str(src), "-p", "/usr/bin/env python3", "-o", str(WORK / "harbour.pyz"), cwd=WORK)
    out("zipapp", "harbour-bell-zipapp.pyz", (WORK / "harbour.pyz").read_bytes())
    # pex 2.107.1 (pip-installed in the container run); its `.bootstrap/`
    # (pex's own ~1 MB runtime) is left out to keep the file small: the
    # rest is the pex output unchanged.
    psrc = WORK / "pexsrc"
    shutil.rmtree(psrc, ignore_errors=True)
    shutil.copytree(src / "harbour", psrc / "harbour")
    run("pip", "install", "-q", "pex==2.107.1", cwd=WORK)
    run("pex", "-D", str(psrc), "-e", "harbour:main", "-o", str(WORK / "full.pex"), "--python-shebang=/usr/bin/env python3", cwd=WORK, faketime=True)
    full = (WORK / "full.pex").read_bytes()
    with zipfile.ZipFile(WORK / "full.pex") as z:
        keep = [(i.filename, z.read(i)) for i in z.infolist() if not i.filename.startswith(".bootstrap/")]
    out("pex", "harbour-bell-pex2107.pex", fixed_zip(WORK / "harbour.pex", keep, prefix=full[: full.index(b"\n") + 1]))
    # JDK 21 javac + jmod.
    mod = WORK / "mod"
    shutil.rmtree(mod, ignore_errors=True)
    (mod / "src" / "harbour").mkdir(parents=True)
    (mod / "src" / "module-info.java").write_text("module org.saltmere.harbour { exports harbour; }\n")
    (mod / "src" / "harbour" / "Bell.java").write_text(
        "package harbour;\n\n/** The Saltmere harbour bell. */\npublic class Bell {\n"
        "    public static void main(String[] args) { System.out.println(\"High tide.\"); }\n}\n"
    )
    run("javac", "--release", "21", "-d", str(mod / "classes"), str(mod / "src" / "module-info.java"), str(mod / "src" / "harbour" / "Bell.java"), cwd=mod)
    (WORK / "harbour.jmod").unlink(missing_ok=True)
    run("jmod", "create", "--class-path", str(mod / "classes"), "--module-version", "1.0", "--main-class", "harbour.Bell", "--date", "2025-09-01T12:00:00Z", str(WORK / "harbour.jmod"), cwd=mod)
    out("jmod", "org.saltmere.harbour-jdk21.jmod", (WORK / "harbour.jmod").read_bytes())
    # An expansion file: a ZIP with the obbtool footer (ObbFile.cpp):
    # version, package version, flags, salt, package name, size, signature.
    blob = fixed_zip(WORK / "obb.zip", [("charts/bay.txt", CHART), ("notes.txt", NOTES)])
    pkg = b"org.saltmere.harbour"
    footer = struct.pack("<LLL8sL", 1, 7, 0, b"\0" * 8, len(pkg)) + pkg
    out("obb", "main.7.org.saltmere.harbour.obb", blob + footer + struct.pack("<LL", len(footer), 0x01059983))
    # 7-Zip volumes of 1 KiB (stored, so the parts have a fixed size); the
    # second is the fixture (the first is a 7z file).
    import hashlib

    noise = b"".join(hashlib.sha256(f"saltmere {i}".encode()).digest() for i in range(80))
    (WORK / "sounding.bin").write_bytes(noise)
    os.utime(WORK / "sounding.bin", (EPOCH, EPOCH))
    run("7z", "a", "-mx0", "-v1k", "-mtc=off", "-mta=off", "saltmere.7z", "sounding.bin", cwd=WORK)
    out("split_volume", "saltmere.7z.002", (WORK / "saltmere.7z.002").read_bytes())


# --- backups -------------------------------------------------------------------------


def step_backups() -> None:
    import hashlib
    import io
    import tarfile

    # adb backup: a text header, then a zlib-compressed tar laid out as
    # `apps/<package>/<domain>/<file>`.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, data in (
            ("apps/org.saltmere.harbour/_manifest", b"1\norg.saltmere.harbour\n7\n34\n"),
            ("apps/org.saltmere.harbour/f/notes.txt", NOTES),
            ("apps/org.saltmere.harbour/sp/settings.xml", b"<?xml version='1.0' encoding='utf-8'?>\n<map><string name=\"berth\">3</string></map>\n"),
        ):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), EPOCH, 0o600
            t.addfile(info, io.BytesIO(data))
    out("android_backup", "harbour-app-adb5.ab", b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(buf.getvalue(), 9))
    # An encrypted one: the header's salts, IV and wrapped key are
    # deterministic stand-in bytes, the body likewise.
    fake = lambda label, n: hashlib.sha256(label.encode()).hexdigest().upper()[: 2 * n]
    header = (
        "ANDROID BACKUP\n5\n1\nAES-256\n"
        f"{fake('user salt', 32)}\n{fake('checksum salt', 32)}\n10000\n{fake('iv', 16)}\n{fake('master key', 32) * 3}\n"
    )
    body = b"".join(hashlib.sha256(f"body {i}".encode()).digest() for i in range(8))
    out("android_backup", "harbour-app-encrypted-adb5.ab", header.encode() + body)
    # dump 0.4b49, level 0, of an ext2 image (the container's host name is
    # set by legacy.sh).
    p = payload()
    img = WORK / "fs.img"
    img.unlink(missing_ok=True)
    env = dict(os.environ, E2FSPROGS_FAKE_TIME=str(EPOCH))
    subprocess.run(
        ["mke2fs", "-q", "-t", "ext2", "-L", "saltmere", "-U", "5a17e2e0-0000-4000-8000-000000000001",
         "-E", "root_owner=0:0", "-d", str(p), str(img), "256"],
        check=True, env=env,
    )
    run("dump", "-0", "-L", "harbour-weekly", "-f", str(WORK / "harbour.dump"), "fs.img", cwd=WORK, faketime=True)
    out("unix_dump", "harbour-weekly-level0.dump", (WORK / "harbour.dump").read_bytes())
    # borg 1.4 repository files (no encryption: nothing secret in config).
    repo = WORK / "borg"
    shutil.rmtree(repo, ignore_errors=True)
    subprocess.run(
        ["borg", "init", "--encryption=none", str(repo)],
        check=True, env=dict(os.environ, BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK="yes", BORG_BASE_DIR=str(WORK / "borgbase")),
        capture_output=True,
    )
    out("borg_repository", "config", (repo / "config").read_bytes())
    out("borg_repository", "README", (repo / "README").read_bytes())


# --- debug information ----------------------------------------------------------------

TIDE_C = b"""/* Saltmere harbour tide helper. */
int bell(int tide) { return tide * 2; }
int main(void) { return bell(3); }
"""


def step_debug() -> None:
    # Built in /src/harbour so only that (fictitious) path is recorded.
    src = Path("/src/harbour")
    src.mkdir(parents=True, exist_ok=True)
    (src / "tide.c").write_bytes(TIDE_C)
    (src / "berth.c").write_bytes(b"int berth(int n) { return n + 1; }\n")
    # clang-cl style objects and lld-link: a PDB next to tide.exe.
    for c in ("tide", "berth"):
        run("clang", "--target=x86_64-pc-windows-msvc", "-g", "-gcodeview", "-c", f"{c}.c", "-o", f"{c}.obj", cwd=src)
    run("lld-link", "/nodefaultlib", "/entry:main", "/subsystem:console", "/debug", "/pdb:tide.pdb",
        "/out:tide.exe", "tide.obj", "berth.obj", cwd=src)
    out("ms_pdb", "tide-lld19.pdb", (src / "tide.pdb").read_bytes())
    # GCC split DWARF (DWARF 5), and llvm-dwp's package of two units.
    for c in ("tide", "berth"):
        run("gcc", "-g", "-gsplit-dwarf", "-O1", "-c", f"{c}.c", "-o", f"{c}.o", cwd=src)
    out("split_dwarf", "tide-gcc14.dwo", (src / "tide.dwo").read_bytes())
    run("llvm-dwp", "tide.dwo", "berth.dwo", "-o", "harbour.dwp", cwd=src)
    out("split_dwarf", "harbour-llvm19.dwp", (src / "harbour.dwp").read_bytes())


# --- other executable images -----------------------------------------------------------

KERNEL_VERSION = (
    b"6.12.0-saltmere (harbour@saltmere.example) (gcc (Debian 14.2.0-19) 14.2.0, GNU ld 2.44) "
    b"#1 SMP PREEMPT_DYNAMIC Mon Sep  1 12:00:00 UTC 2025"
)

DTS = b"""/dts-v1/;

/ {
\tmodel = "Saltmere Harbour Bell Controller";
\tcompatible = "saltmere,bell-controller", "saltmere,harbour";
\t#address-cells = <1>;
\t#size-cells = <1>;

\tmemory@80000000 {
\t\tdevice_type = "memory";
\t\treg = <0x80000000 0x10000000>;
\t};

\tbell@10000000 {
\t\tcompatible = "saltmere,bell";
\t\treg = <0x10000000 0x1000>;
\t\tstatus = "okay";
\t};
};
"""

DTS_OVERLAY = b"""/dts-v1/;
/plugin/;

/ {
\tfragment@0 {
\t\ttarget-path = "/";
\t\t__overlay__ {
\t\t\tfoghorn {
\t\t\t\tcompatible = "saltmere,foghorn";
\t\t\t\tstatus = "okay";
\t\t\t};
\t\t};
\t};
};
"""


def step_exec() -> None:
    import gzip

    # x86 bzImage (Documentation/arch/x86/boot.rst): 4 setup sectors after
    # the boot sector, the version string inside them, then the
    # protected-mode part with a gzip payload.
    setup = bytearray(5 * 512)
    setup[0x1F1] = 4
    setup[0x1FE:0x200] = b"\x55\xaa"
    setup[0x202:0x206] = b"HdrS"
    struct.pack_into("<H", setup, 0x206, 0x020F)
    struct.pack_into("<H", setup, 0x20E, 0x380)
    setup[0x200 + 0x380 : 0x200 + 0x380 + len(KERNEL_VERSION)] = KERNEL_VERSION
    setup[0x211] = 0x01
    payload = gzip.compress(b"Saltmere harbour kernel payload placeholder.\n" * 20, mtime=0)
    struct.pack_into("<LL", setup, 0x248, 0x40, len(payload))
    out("linux_kernel", "vmlinuz-6.12.0-saltmere", bytes(setup) + bytes(0x40) + payload)
    # arm64 Image (Documentation/arch/arm64/booting.rst): an EFI stub
    # (`MZ`), size, flags (little-endian, 4K pages) and `ARM\x64`.
    head = bytearray(64)
    head[0:4] = b"MZ\x00\x91"
    struct.pack_into("<QQQ", head, 8, 0, 4096, 0b010)
    head[56:60] = b"ARM\x64"
    struct.pack_into("<L", head, 60, 64)
    out("linux_kernel", "Image-arm64-crafted", bytes(head) + bytes(4096 - 64))
    # Android: VDEX 027 (four sections; two DEX checksums), an ART image
    # header and an OAT header in an ELF file, from AOSP's headers.
    sections = [(0, 64, 8), (1, 72, 0), (2, 72, 16), (3, 88, 0)]
    vd = b"vdex027\0" + struct.pack("<L", len(sections)) + b"".join(struct.pack("<LLL", *x) for x in sections)
    vd = vd.ljust(64, b"\0") + struct.pack("<LL", 0x5A17E2E0, 0x0B311000) + bytes(16)
    out("android_vdex", "harbour-crafted.vdex", vd)
    out("android_art", "harbour-crafted.art", b"art\n106\0" + bytes(248))
    elf = bytearray(64)
    elf[0:4] = b"\x7fELF"
    elf[4], elf[5], elf[6] = 2, 1, 1
    struct.pack_into("<HHL", elf, 16, 3, 183, 1)
    store = b"compiler-filter\0speed-profile\0debuggable\0false\0"
    oat_header = b"oat\n239\0" + bytes(64) + struct.pack("<L", len(store)) + store
    out("android_oat", "harbour-crafted.odex", bytes(elf) + bytes(4096 - 64) + oat_header)
    # XCOFF: clang's AIX objects, 64 and 32 bit.
    src = Path("/src/harbour")
    src.mkdir(parents=True, exist_ok=True)
    (src / "tide.c").write_bytes(TIDE_C)
    run("clang", "--target=powerpc64-ibm-aix", "-c", "tide.c", "-o", "tide64.o", cwd=src)
    run("clang", "--target=powerpc-ibm-aix", "-c", "tide.c", "-o", "tide32.o", cwd=src)
    out("xcoff", "tide-clang19-64.o", (src / "tide64.o").read_bytes())
    out("xcoff", "tide-clang19-32.o", (src / "tide32.o").read_bytes())
    # Device trees: dtc 1.7.
    (WORK / "bell.dts").write_bytes(DTS)
    (WORK / "foghorn.dts").write_bytes(DTS_OVERLAY)
    run("dtc", "-I", "dts", "-O", "dtb", "-o", "bell.dtb", "bell.dts", cwd=WORK)
    run("dtc", "-@", "-I", "dts", "-O", "dtb", "-o", "foghorn.dtbo", "foghorn.dts", cwd=WORK)
    out("fdt", "saltmere-bell-dtc17.dtb", (WORK / "bell.dtb").read_bytes())
    out("fdt", "saltmere-foghorn-dtc17.dtbo", (WORK / "foghorn.dtbo").read_bytes())
    out("dts", "saltmere-bell.dts", DTS)
    # Xilinx .bit: the header fields, then the configuration data (dummy
    # words, the sync word, NOOPs).
    def field(key, text):
        v = text.encode() + b"\0"
        return key + struct.pack(">H", len(v)) + v

    data = b"\xff" * 32 + b"\x00\x00\x00\xbb\x11\x22\x00\x44" + b"\xff" * 8 + b"\xaa\x99\x55\x66" + b"\x20\x00\x00\x00" * 16
    bit = (
        b"\x00\x09\x0f\xf0\x0f\xf0\x0f\xf0\x0f\xf0\x00\x00\x01"
        + field(b"a", "harbour_bell;UserID=0XFFFFFFFF;Version=2024.2")
        + field(b"b", "7a35tcpg236")
        + field(b"c", "2025/09/01")
        + field(b"d", "12:00:00")
        + b"e" + struct.pack(">L", len(data)) + data
    )
    out("xilinx_bit", "harbour-bell-crafted.bit", bit)


# --- script hosts ----------------------------------------------------------------------
# Plain scripts that only show text: the risk signals (external scripts,
# shell objects) are tested in memory, never with fixtures.

HTA = b"""<html>
<head>
<title>Saltmere tide board</title>
<HTA:APPLICATION ID="tideBoard" APPLICATIONNAME="Saltmere Tide Board" VERSION="1.0"
  BORDER="thin" SINGLEINSTANCE="yes" WINDOWSTATE="normal" SHOWINTASKBAR="yes"/>
<script language="VBScript">
Sub Window_OnLoad
    document.getElementById("next").innerText = "High water 06:12"
End Sub
</script>
</head>
<body><h1>Saltmere harbour</h1><p id="next"></p></body>
</html>
"""

WSF = b"""<?xml version="1.0"?>
<package>
  <job id="tides">
    <script language="JScript">
      WScript.Echo("Saltmere: high water 06:12, low water 12:31.");
    </script>
  </job>
  <job id="bell">
    <script language="VBScript">
      WScript.Echo "The harbour bell rings at high tide."
    </script>
  </job>
</package>
"""

WSC = b"""<?xml version="1.0"?>
<component>
  <registration description="Saltmere tide table" progid="Saltmere.Tides" version="1.00"
    classid="{5A17E2E0-0000-4000-8000-000000000001}"/>
  <public>
    <property name="Harbour"/>
    <method name="NextHighWater"/>
  </public>
  <script language="JScript">
    var Harbour = "Saltmere";
    function NextHighWater() { return "06:12"; }
  </script>
</component>
"""


def step_scripts() -> None:
    out("hta", "saltmere-tide-board.hta", HTA)
    out("wsf", "saltmere-tides.wsf", WSF)
    out("scriptlet", "saltmere-tides.wsc", WSC)


# --- writing: citations, typesetting, notes, screenplays, office XML ---------------------

BIB = b"""@article{gull2025tides, author={Gull, Ben and Lighthouse, Ana}, title={Tide tables for Saltmere Harbour},
  journal={Journal of Small Harbours}, year={2025}, volume={7}, pages={1--12}, doi={10.5555/saltmere.2025.1}}
@book{tern2024wall, author={Tern, Grey}, title={The long wall: a history}, publisher={Saltmere Press}, year={2024}}
@inproceedings{bell2023buoy, author={Bell, Harbour and Gull, Ben}, title={Bell buoys in fog}, booktitle={Proceedings of the Harbour Lights Meeting}, year={2023}}
"""

NBIB = b"""PMID- 40000001
OWN - NLM
DP  - 2025 Sep
TI  - Tide tables for Saltmere Harbour: a small-harbour
      study.
LID - 10.5555/saltmere.2025.1 [doi]
FAU - Gull, Ben
AU  - Gull B
FAU - Lighthouse, Ana
AU  - Lighthouse A
LA  - eng
PT  - Journal Article
TA  - J Small Harb

PMID- 40000002
DP  - 2024
TI  - Bell buoys in fog.
FAU - Bell, Harbour
AU  - Bell H
PT  - Review
"""

CSL = b"""<?xml version="1.0" encoding="utf-8"?>
<style xmlns="http://purl.org/net/xbiblio/csl" class="in-text" version="1.0" default-locale="en-GB">
  <info>
    <title>Saltmere Harbour Notes</title>
    <id>http://www.zotero.org/styles/saltmere-harbour-notes</id>
    <link href="http://www.zotero.org/styles/harvard-cite-them-right" rel="independent-parent"/>
    <author><name>Ana Lighthouse</name></author>
    <category citation-format="author-date"/>
    <updated>2025-09-01T12:00:00+00:00</updated>
  </info>
</style>
"""

TYPST = b"""#set document(title: "Saltmere tide tables", author: ("Ana Lighthouse", "Ben Gull"))
#import "@preview/tablex:0.0.8": tablex
#set page(paper: "a5")

= Saltmere tide tables

High water at the long wall comes at 06:12; the pilot launch leaves at dawn.

== September

#tablex(columns: 2, [Day], [High water], [1], [06:12])

== The bell

The harbour bell rings at high tide.
"""

LYX = b"""#LyX 2.4 created this file. For more info see https://www.lyx.org/
\\lyxformat 620
\\begin_document
\\begin_header
\\save_transient_properties true
\\textclass article
\\language british
\\end_header

\\begin_body

\\begin_layout Title
Saltmere tides
\\end_layout

\\begin_layout Author
Ana Lighthouse
\\end_layout

\\begin_layout Section
High water
\\end_layout

\\begin_layout Standard
The harbour bell rings at high tide; the pilot launch leaves at dawn.
\\end_layout

\\begin_layout Section
The long wall
\\end_layout

\\begin_layout Standard
Grey Tern berths at the long wall.
\\end_layout

\\end_body
\\end_document
"""

SLA = b"""<?xml version="1.0" encoding="UTF-8"?>
<SCRIBUSUTF8NEW Version="1.6.3">
  <DOCUMENT ANZPAGES="2" PAGEWIDTH="420" PAGEHEIGHT="595" TITLE="Saltmere harbour leaflet" AUTHOR="Ben Gull" COMMENTS="Tide times for visitors" LANGUAGE="en_GB">
    <PAGE NUM="0" PAGEXPOS="100" PAGEYPOS="20" PAGEWIDTH="420" PAGEHEIGHT="595"/>
    <PAGE NUM="1" PAGEXPOS="100" PAGEYPOS="635" PAGEWIDTH="420" PAGEHEIGHT="595"/>
    <PAGEOBJECT PTYPE="4" XPOS="130" YPOS="60" WIDTH="360" HEIGHT="80" OwnPage="0">
      <StoryText>
        <ITEXT CH="Saltmere harbour"/>
        <para/>
        <ITEXT CH="High water 06:12, low water 12:31."/>
      </StoryText>
    </PAGEOBJECT>
    <PAGEOBJECT PTYPE="2" XPOS="130" YPOS="200" WIDTH="360" HEIGHT="240" OwnPage="0" PFILE="harbour.png"/>
    <PAGEOBJECT PTYPE="4" XPOS="130" YPOS="700" WIDTH="360" HEIGHT="80" OwnPage="1">
      <StoryText><ITEXT CH="The bell rings at high tide."/></StoryText>
    </PAGEOBJECT>
  </DOCUMENT>
</SCRIBUSUTF8NEW>
"""

ENEX = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE en-export SYSTEM "http://xml.evernote.com/pub/evernote-export4.dtd">
<en-export export-date="20250901T120000Z" application="Evernote" version="10.105.4">
  <note>
    <title>Harbour bell</title>
    <created>20250830T080000Z</created>
    <updated>20250901T110000Z</updated>
    <tag>harbour</tag>
    <tag>bell</tag>
    <content><![CDATA[<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE en-note SYSTEM "http://xml.evernote.com/pub/enml2.dtd"><en-note><div>The bell rings at high tide.</div></en-note>]]></content>
  </note>
  <note>
    <title>Berths</title>
    <created>20250901T090000Z</created>
    <updated>20250901T090000Z</updated>
    <tag>harbour</tag>
    <content><![CDATA[<en-note><div>Grey Tern at berth 5, Harbour Bell at berth 3.</div></en-note>]]></content>
  </note>
</en-export>
"""

CANVAS = b"""{
  "nodes": [
    {"id": "a1", "type": "text", "text": "Saltmere: the harbour bell rings at high tide.", "x": 0, "y": 0, "width": 300, "height": 120},
    {"id": "a2", "type": "file", "file": "Harbour/Tides.md", "x": 400, "y": 0, "width": 300, "height": 200},
    {"id": "a3", "type": "group", "label": "Berths", "x": -20, "y": 200, "width": 760, "height": 300},
    {"id": "a4", "type": "text", "text": "Grey Tern, berth 5", "x": 0, "y": 240, "width": 200, "height": 60}
  ],
  "edges": [
    {"id": "e1", "fromNode": "a1", "fromSide": "right", "toNode": "a2", "toSide": "left"}
  ]
}
"""

FOUNTAIN = b"""Title: The Saltmere Bell
Credit: Written by
Author: Ana Lighthouse
Draft date: 2025-09-01

INT. BELL TOWER - DAWN

The harbour bell hangs still. BEN GULL climbs the stairs.

BEN
It rings at high tide.

ANA (V.O.)
Then we have an hour.

EXT. LONG WALL - CONTINUOUS

The pilot launch leaves the harbour.

CUT TO:

.THE TIDE TABLE

Grey Tern rounds the buoy.
"""

FDX = b"""<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<FinalDraft DocumentType="Script" Template="No" Version="5">
  <Content>
    <Paragraph Type="Scene Heading"><Text>INT. BELL TOWER - DAWN</Text></Paragraph>
    <Paragraph Type="Action"><Text>The harbour bell hangs still.</Text></Paragraph>
    <Paragraph Type="Character"><Text>BEN</Text></Paragraph>
    <Paragraph Type="Dialogue"><Text>It rings at high tide.</Text></Paragraph>
    <Paragraph Type="Scene Heading"><Text>EXT. LONG WALL - CONTINUOUS</Text></Paragraph>
    <Paragraph Type="Character"><Text>ANA (V.O.)</Text></Paragraph>
    <Paragraph Type="Dialogue"><Text>Then we have an hour.</Text></Paragraph>
  </Content>
  <TitlePage>
    <Content>
      <Paragraph Type="Text"><Text>The Saltmere Bell</Text></Paragraph>
    </Content>
  </TitlePage>
</FinalDraft>
"""

SCRIVX = b"""<?xml version="1.0" encoding="UTF-8"?>
<ScrivenerProject Template="No" Version="2.0" Identifier="5A17E2E0-0000-4000-8000-000000000002" Creator="SCRMAC-3.4-17342">
  <Binder>
    <BinderItem UUID="1" Type="DraftFolder" Created="2025-09-01 12:00:00 +0000" Modified="2025-09-01 12:00:00 +0000">
      <Title>Manuscript</Title>
      <Children>
        <BinderItem UUID="2" Type="Text"><Title>The bell</Title></BinderItem>
        <BinderItem UUID="3" Type="Text"><Title>The long wall</Title></BinderItem>
      </Children>
    </BinderItem>
    <BinderItem UUID="4" Type="ResearchFolder"><Title>Research</Title></BinderItem>
    <BinderItem UUID="5" Type="TrashFolder"><Title>Trash</Title></BinderItem>
  </Binder>
</ScrivenerProject>
"""

MARP = b"""---
marp: true
theme: gaia
paginate: true
title: Saltmere harbour
---

# Saltmere harbour

A small harbour and a bell.

---

## Tides

- High water 06:12
- Low water 12:31

---

## Berths

Grey Tern at berth 5.
"""


def step_writing() -> None:
    (WORK / "h.bib").write_bytes(BIB)
    subprocess.run("bib2xml h.bib > h.xml", shell=True, cwd=WORK, check=True, stderr=subprocess.DEVNULL)
    for tool, fmt, name in (("xml2ris", "ris", "saltmere-bibutils.ris"), ("xml2end", "endnote", "saltmere-bibutils.enw")):
        data = subprocess.run([tool, "h.xml"], cwd=WORK, check=True, capture_output=True).stdout
        out(fmt, name, data)
    out("medline", "saltmere-crafted.nbib", NBIB)
    out("csl_style", "saltmere-harbour-notes.csl", CSL)
    out("typst", "saltmere-tides.typ", TYPST)
    out("lyx", "saltmere-tides.lyx", LYX)
    out("scribus", "saltmere-leaflet.sla", SLA)
    out("enex", "saltmere-notes.enex", ENEX)
    out("obsidian_canvas", "saltmere-board.canvas", CANVAS)
    out("fountain", "the-saltmere-bell.fountain", FOUNTAIN)
    out("final_draft", "the-saltmere-bell.fdx", FDX)
    out("scrivener", "saltmere.scrivx", SCRIVX)
    out("marp", "saltmere-slides.marp", MARP)
    # AbiWord 3.0 and Gnumeric 1.12 converters.
    (WORK / "harbour.txt").write_bytes(b"Saltmere harbour notes\n\nHigh water 06:12, low water 12:31.\n\nThe bell rings at high tide.\n")
    run("abiword", "--to=abw", "harbour.txt", cwd=WORK, faketime=True)
    out("abiword", "saltmere-notes-abiword3.abw", (WORK / "harbour.abw").read_bytes())
    (WORK / "berths.csv").write_bytes(b"boat,berth,arrived\nGrey Tern,5,2025-09-01\nHarbour Bell,3,2025-09-01\nLow Water,1,2025-09-02\n")
    run("ssconvert", "berths.csv", "berths.gnumeric", cwd=WORK, faketime=True)
    out("gnumeric", "saltmere-berths-gnumeric112.gnumeric", (WORK / "berths.gnumeric").read_bytes())


# --- ebooks and OpenOffice.org 1.x packages ---------------------------------------------

OOO = 'xmlns:office="http://openoffice.org/2000/office" xmlns:text="http://openoffice.org/2000/text" ' \
      'xmlns:table="http://openoffice.org/2000/table" xmlns:draw="http://openoffice.org/2000/drawing" ' \
      'xmlns:meta="http://openoffice.org/2000/meta" xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.0"'


def ooo_package(kind: str, body: str, stats: str) -> bytes:
    """An OpenOffice.org 1.x package (`application/vnd.sun.xml.<kind>`):
    mimetype first and stored, the manifest, meta.xml and content.xml."""
    import io
    import zipfile

    meta = (
        f'<?xml version="1.0" encoding="UTF-8"?><office:document-meta {OOO}><office:meta>'
        "<meta:generator>OpenOffice.org 1.1.5 (Linux)</meta:generator><dc:title>Saltmere harbour</dc:title>"
        "<meta:initial-creator>Ana Lighthouse</meta:initial-creator><dc:creator>Ben Gull</dc:creator>"
        "<meta:creation-date>2025-09-01T12:00:00</meta:creation-date><dc:date>2025-09-01T12:00:00</dc:date>"
        f"<dc:language>en-GB</dc:language><meta:document-statistic {stats}/></office:meta></office:document-meta>"
    )
    content = f'<?xml version="1.0" encoding="UTF-8"?><office:document-content {OOO}><office:body>{body}</office:body></office:document-content>'
    manifest = (
        '<?xml version="1.0" encoding="UTF-8"?><manifest:manifest xmlns:manifest="http://openoffice.org/2001/manifest">'
        f'<manifest:file-entry manifest:media-type="application/vnd.sun.xml.{kind}" manifest:full-path="/"/>'
        '<manifest:file-entry manifest:media-type="text/xml" manifest:full-path="content.xml"/>'
        '<manifest:file-entry manifest:media-type="text/xml" manifest:full-path="meta.xml"/></manifest:manifest>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data, method in (
            ("mimetype", f"application/vnd.sun.xml.{kind}", zipfile.ZIP_STORED),
            ("content.xml", content, zipfile.ZIP_DEFLATED),
            ("meta.xml", meta, zipfile.ZIP_DEFLATED),
            ("META-INF/manifest.xml", manifest, zipfile.ZIP_DEFLATED),
        ):
            info = zipfile.ZipInfo(name, (2025, 9, 1, 12, 0, 0))
            info.compress_type = method
            z.writestr(info, data)
    return buf.getvalue()


OPF_OEB = b"""<?xml version="1.0"?>
<!DOCTYPE package PUBLIC "+//ISBN 0-9673008-1-9//DTD OEB 1.2 Package//EN" "http://openebook.org/dtds/oeb-1.2/oebpkg12.dtd">
<package unique-identifier="bookid" xmlns="http://openebook.org/namespaces/oeb-package/1.0/">
  <metadata>
    <dc-metadata xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:oebpackage="http://openebook.org/namespaces/oeb-package/1.0/">
      <dc:Title>Tides of Saltmere</dc:Title>
      <dc:Creator role="aut">Ana Lighthouse</dc:Creator>
      <dc:Identifier id="bookid">urn:uuid:5a17e2e0-0000-4000-8000-000000000003</dc:Identifier>
      <dc:Language>en</dc:Language>
      <dc:Date>2025-09-01</dc:Date>
    </dc-metadata>
  </metadata>
  <manifest>
    <item id="ch1" href="ch1.html" media-type="text/x-oeb1-document"/>
    <item id="ch2" href="ch2.html" media-type="text/x-oeb1-document"/>
  </manifest>
  <spine><itemref idref="ch1"/><itemref idref="ch2"/></spine>
</package>
"""

NCX = b"""<?xml version="1.0" encoding="UTF-8"?>
<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">
  <head>
    <meta name="dtb:uid" content="urn:uuid:5a17e2e0-0000-4000-8000-000000000003"/>
    <meta name="dtb:depth" content="2"/>
    <meta name="dtb:totalPageCount" content="0"/>
  </head>
  <docTitle><text>Tides of Saltmere</text></docTitle>
  <docAuthor><text>Ana Lighthouse</text></docAuthor>
  <navMap>
    <navPoint id="n1" playOrder="1"><navLabel><text>High water</text></navLabel><content src="ch1.html"/>
      <navPoint id="n2" playOrder="2"><navLabel><text>The bell</text></navLabel><content src="ch1.html#bell"/></navPoint>
    </navPoint>
    <navPoint id="n3" playOrder="3"><navLabel><text>Low water</text></navLabel><content src="ch2.html"/></navPoint>
  </navMap>
</ncx>
"""


def step_books() -> None:
    import io
    import zipfile

    out("sxw", "saltmere-ooo11.sxw", ooo_package(
        "writer",
        "<text:h text:level=\"1\">Saltmere harbour</text:h><text:p>High water 06:12, low water 12:31.</text:p>"
        "<text:p>The bell rings at high tide.</text:p>",
        'meta:page-count="1" meta:paragraph-count="3" meta:word-count="15"',
    ))
    out("sxc", "saltmere-berths-ooo11.sxc", ooo_package(
        "calc",
        '<table:table table:name="Berths"><table:table-row><table:table-cell><text:p>Grey Tern</text:p></table:table-cell>'
        "<table:table-cell><text:p>5</text:p></table:table-cell></table:table-row></table:table>"
        '<table:table table:name="Tides"><table:table-row><table:table-cell><text:p>06:12</text:p></table:table-cell></table:table-row></table:table>',
        'meta:table-count="2" meta:cell-count="3"',
    ))
    out("sxi", "saltmere-talk-ooo11.sxi", ooo_package(
        "impress",
        '<draw:page draw:name="Saltmere"><draw:text-box><text:p>Saltmere harbour</text:p></draw:text-box></draw:page>'
        '<draw:page draw:name="Tides"><draw:text-box><text:p>High water 06:12</text:p></draw:text-box></draw:page>',
        'meta:object-count="2"',
    ))
    out("sxd", "saltmere-chart-ooo11.sxd", ooo_package(
        "draw",
        '<draw:page draw:name="Chart"><draw:rect draw:name="Long wall"/></draw:page>',
        'meta:object-count="1"',
    ))
    # iBooks Author: an EPUB 3 package under its own media type.
    opf3 = (
        '<?xml version="1.0"?><package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="id">'
        '<metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Saltmere Tide Book</dc:title>'
        '<dc:creator>Ben Gull</dc:creator><dc:identifier id="id">urn:uuid:5a17e2e0-0000-4000-8000-000000000004</dc:identifier>'
        "<dc:language>en</dc:language></metadata><manifest>"
        '<item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/>'
        '<item id="c1" href="ch1.xhtml" media-type="application/xhtml+xml"/></manifest><spine><itemref idref="c1"/></spine></package>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data, method in (
            ("mimetype", "application/x-ibooks+zip", zipfile.ZIP_STORED),
            ("META-INF/container.xml", '<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container" version="1.0"><rootfiles>'
             '<rootfile full-path="OPS/book.opf" media-type="application/oebps-package+xml"/></rootfiles></container>', zipfile.ZIP_DEFLATED),
            ("OPS/book.opf", opf3, zipfile.ZIP_DEFLATED),
            ("OPS/nav.xhtml", '<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops"><body>'
             '<nav epub:type="toc"><ol><li><a href="ch1.xhtml">High water</a></li></ol></nav></body></html>', zipfile.ZIP_DEFLATED),
            ("OPS/ch1.xhtml", '<html xmlns="http://www.w3.org/1999/xhtml"><body><h1>High water</h1>'
             "<p>The harbour bell rings at high tide.</p></body></html>", zipfile.ZIP_DEFLATED),
        ):
            info = zipfile.ZipInfo(name, (2025, 9, 1, 12, 0, 0))
            info.compress_type = method
            z.writestr(info, data)
    out("ibooks", "saltmere-tide-book.ibooks", buf.getvalue())
    out("opf", "tides-of-saltmere-oeb12.opf", OPF_OEB)
    out("ncx", "tides-of-saltmere.ncx", NCX)


# --- document packages ---------------------------------------------------------------------


def zip_of(members: list[tuple[str, bytes | str]], stored_first: bool = False) -> bytes:
    """A ZIP with fixed times; the first member stored when asked (a
    `mimetype` entry)."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i, (name, data) in enumerate(members):
            info = zipfile.ZipInfo(name, (2025, 9, 1, 12, 0, 0))
            info.compress_type = zipfile.ZIP_STORED if (stored_first and i == 0) or name.endswith("/") else zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buf.getvalue()


CORE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>Saltmere tide card</dc:title><dc:creator>Ana Lighthouse</dc:creator><dc:language>en-GB</dc:language>
<dcterms:created xsi:type="dcterms:W3CDTF">2025-09-01T12:00:00Z</dcterms:created></cp:coreProperties>"""

XPS_NS = "http://schemas.microsoft.com/xps/2005/06"


def fpage(lines: list[str]) -> str:
    glyphs = "".join(
        f'<Glyphs Fill="#ff000000" FontUri="/Resources/Fonts/Harbour.odttf" FontRenderingEmSize="14" OriginX="96" '
        f'OriginY="{120 + 24 * i}" UnicodeString="{t}"/>' for i, t in enumerate(lines)
    )
    return f'<FixedPage xmlns="{XPS_NS}" Width="816" Height="1056" xml:lang="en-GB">{glyphs}</FixedPage>'


WORDML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<?mso-application progid="Word.Document"?>
<w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml" xmlns:o="urn:schemas-microsoft-com:office:office" w:macrosPresent="no" w:embeddedObjPresent="no">
  <o:DocumentProperties>
    <o:Title>Saltmere harbour notes</o:Title>
    <o:Author>Ben Gull</o:Author>
    <o:LastAuthor>Ana Lighthouse</o:LastAuthor>
    <o:Revision>2</o:Revision>
    <o:Created>2025-09-01T12:00:00Z</o:Created>
    <o:Pages>1</o:Pages>
    <o:Words>18</o:Words>
    <o:Company>Saltmere Harbour</o:Company>
    <o:Version>11.5604</o:Version>
  </o:DocumentProperties>
  <w:body>
    <w:p><w:r><w:t>Saltmere harbour notes</w:t></w:r></w:p>
    <w:p><w:r><w:t>High water 06:12, low water 12:31. The bell rings at high tide.</w:t></w:r></w:p>
  </w:body>
</w:wordDocument>
"""

IDML_STORY = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<idPkg:Story xmlns:idPkg="http://ns.adobe.com/AdobeInDesign/idml/1.0/packaging" DOMVersion="20.0">
<Story Self="u1"><ParagraphStyleRange><CharacterStyleRange><Content>{}</Content></CharacterStyleRange></ParagraphStyleRange></Story>
</idPkg:Story>"""

XMP = """<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
<dc:title><rdf:Alt><rdf:li xml:lang="x-default">Saltmere harbour leaflet</rdf:li></rdf:Alt></dc:title>
<dc:creator><rdf:Seq><rdf:li>Ben Gull</rdf:li></rdf:Seq></dc:creator><xmp:CreatorTool>Adobe InDesign 20.0 (Macintosh)</xmp:CreatorTool>
<xmp:CreateDate>2025-09-01T12:00:00Z</xmp:CreateDate></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>"""

MIF = """<MIFFile 2015> # Generated by FrameMaker 2015.0.0
<Units Uin>
<Page
 <PageType BodyPage>
 <PageNum `1'>
> # end of Page
<Page
 <PageType BodyPage>
 <PageNum `2'>
> # end of Page
<TextFlow
 <Para
  <PgfTag `Heading1'>
  <ParaLine
   <String `Saltmere harbour'>
  > # end of ParaLine
 > # end of Para
 <Para
  <PgfTag `Body'>
  <ParaLine
   <String `The bell rings at high tide.'>
  > # end of ParaLine
 > # end of Para
> # end of TextFlow
# End of MIFFile
"""


def step_packages() -> None:
    import plistlib

    # XPS 1.0, two pages; the font is a placeholder (only listed).
    xps = zip_of([
        ("[Content_Types].xml", '<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
         '<Default Extension="fdseq" ContentType="application/vnd.ms-package.xps-fixeddocumentsequence+xml"/>'
         '<Default Extension="fdoc" ContentType="application/vnd.ms-package.xps-fixeddocument+xml"/>'
         '<Default Extension="fpage" ContentType="application/vnd.ms-package.xps-fixedpage+xml"/>'
         '<Default Extension="odttf" ContentType="application/vnd.ms-package.obfuscated-opentype"/>'
         '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
         '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>'),
        ("_rels/.rels", '<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
         '<Relationship Type="http://schemas.microsoft.com/xps/2005/06/fixedrepresentation" Target="/FixedDocumentSequence.fdseq" Id="R0"/>'
         '<Relationship Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="/docProps/core.xml" Id="R1"/></Relationships>'),
        ("FixedDocumentSequence.fdseq", f'<FixedDocumentSequence xmlns="{XPS_NS}"><DocumentReference Source="/Documents/1/FixedDocument.fdoc"/></FixedDocumentSequence>'),
        ("Documents/1/FixedDocument.fdoc", f'<FixedDocument xmlns="{XPS_NS}"><PageContent Source="Pages/1.fpage"/><PageContent Source="Pages/2.fpage"/></FixedDocument>'),
        ("Documents/1/Pages/1.fpage", fpage(["Saltmere tide card", "High water 06:12"])),
        ("Documents/1/Pages/2.fpage", fpage(["Low water 12:31", "The bell rings at high tide."])),
        ("Resources/Fonts/Harbour.odttf", b"\0" * 64),
        ("docProps/core.xml", CORE),
    ])
    out("xps", "saltmere-tide-card-crafted.xps", xps)
    out("wordml_2003", "saltmere-notes-word2003.xml", WORDML.encode())
    # Flat OPC from a real package: pandoc's .docx, folded into one XML file
    # the way Word saves "Word XML Document".
    (WORK / "notes.md").write_text("# Saltmere harbour notes\n\nHigh water 06:12, low water 12:31.\n\nThe bell rings at high tide.\n")
    run("pandoc", "notes.md", "-o", "notes.docx", "--metadata", "title=Saltmere harbour notes", "--metadata", "author=Ben Gull", cwd=WORK)
    import zipfile

    parts = []
    with zipfile.ZipFile(WORK / "notes.docx") as z:
        for info in z.infolist():
            # The theme lists CJK font names, which `wc` splits into words
            # differently: left out.
            if (info.filename.endswith(".xml") or info.filename.endswith(".rels")) and "theme/" not in info.filename:
                body = z.read(info).decode("utf-8")
                body = body.split("?>", 1)[1] if body.startswith("<?xml") else body
                ctype = "application/vnd.openxmlformats-package.relationships+xml" if info.filename.endswith(".rels") else "application/xml"
                parts.append(f'<pkg:part pkg:name="/{info.filename}" pkg:contentType="{ctype}"><pkg:xmlData>{body}</pkg:xmlData></pkg:part>')
    flat = ('<?xml version="1.0" standalone="yes"?><?mso-application progid="Word.Document"?>'
            '<pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage">' + "".join(parts) + "</pkg:package>")
    out("flat_opc", "saltmere-notes-pandoc-flatopc.xml", flat.encode())
    # iWork 2013+: Metadata property lists, an IWA stub (not read).
    def iwork(app: str, version: str, extra: list) -> bytes:
        props = plistlib.dumps({"documentUUID": "5A17E2E0-0000-4000-8000-000000000005", "fileFormatVersion": "14.0.1",
                                "isMultiPage": False, "revision": "0::5A17E2E0-0000-4000-8000-000000000006",
                                "versionUUID": "5A17E2E0-0000-4000-8000-000000000007"}, fmt=plistlib.FMT_BINARY)
        history = plistlib.dumps([f"{app} {version}"], fmt=plistlib.FMT_XML)
        return zip_of([("Index/Document.iwa", b"\0\x05\0\0\0\0\0\0\0"), *extra,
                       ("Metadata/Properties.plist", props), ("Metadata/BuildVersionHistory.plist", history),
                       ("Metadata/DocumentIdentifier", "5A17E2E0-0000-4000-8000-000000000005")])
    out("iwork_pages", "saltmere-notes-crafted.pages", iwork("Pages", "14.0 (7037.0.101)", [("Data/harbour-1.png", b"\x89PNG\r\n\x1a\n")]))
    out("iwork_numbers", "saltmere-berths-crafted.numbers", iwork("Numbers", "14.0 (7037.0.101)", [("Index/Tables/DataList.iwa", b"\0\x05\0\0\0\0\0\0\0")]))
    out("iwork_keynote", "saltmere-talk-crafted.key", iwork("Keynote", "14.0 (7037.0.101)", [("Index/Slide.iwa", b"\0\x05\0\0\0\0\0\0\0")]))
    # HWPX (KS X 6101).
    hwpx = zip_of([
        ("mimetype", "application/hwp+zip"),
        ("version.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><hv:HCFVersion xmlns:hv="http://www.hancom.co.kr/hwpml/2011/version" '
         'tagetApplication="WORDPROCESSOR" major="5" minor="1" micro="0" buildNumber="1" os="1" xmlVersion="1.4" application="Hancom Office Hangul" appVersion="12, 0, 0, 3650"/>'),
        ("Contents/content.hpf", '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><opf:package xmlns:opf="http://www.idpf.org/2007/opf/" version="" unique-identifier="" id="">'
         '<opf:metadata><opf:title>Saltmere harbour</opf:title><opf:language>ko</opf:language><opf:meta name="creator" content="text">Ana Lighthouse</opf:meta>'
         '<opf:meta name="CreatedDate" content="text">2025-09-01T12:00:00Z</opf:meta></opf:metadata></opf:package>'),
        ("Contents/section0.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><hs:sec xmlns:hs="http://www.hancom.co.kr/hwpml/2011/section" '
         'xmlns:hp="http://www.hancom.co.kr/hwpml/2011/paragraph"><hp:p><hp:run><hp:t>Saltmere harbour</hp:t></hp:run></hp:p>'
         '<hp:p><hp:run><hp:t>The bell rings at high tide.</hp:t></hp:run></hp:p></hs:sec>'),
    ], stored_first=True)
    out("hwpx", "saltmere-crafted.hwpx", hwpx)
    # IDML (Adobe's IDML specification).
    idml = zip_of([
        ("mimetype", "application/vnd.adobe.indesign-idml-package"),
        ("designmap.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><?aid style="50" type="document" readerVersion="6.0" featureSet="257" product="20.0(66)" ?>'
         '<Document xmlns:idPkg="http://ns.adobe.com/AdobeInDesign/idml/1.0/packaging" DOMVersion="20.0" Self="d">'
         '<idPkg:Spread src="Spreads/Spread_u2.xml"/><idPkg:Story src="Stories/Story_u1.xml"/><idPkg:Story src="Stories/Story_u3.xml"/></Document>'),
        ("MasterSpreads/MasterSpread_u4.xml", '<idPkg:MasterSpread xmlns:idPkg="http://ns.adobe.com/AdobeInDesign/idml/1.0/packaging" DOMVersion="20.0"/>'),
        ("Spreads/Spread_u2.xml", '<idPkg:Spread xmlns:idPkg="http://ns.adobe.com/AdobeInDesign/idml/1.0/packaging" DOMVersion="20.0"/>'),
        ("Stories/Story_u1.xml", IDML_STORY.format("Saltmere harbour")),
        ("Stories/Story_u3.xml", IDML_STORY.format("High water 06:12, low water 12:31.")),
        ("Resources/Fonts.xml", '<idPkg:Fonts xmlns:idPkg="http://ns.adobe.com/AdobeInDesign/idml/1.0/packaging" DOMVersion="20.0">'
         '<FontFamily Self="di1" Name="Harbour Serif"/><FontFamily Self="di2" Name="Tide Sans"/></idPkg:Fonts>'),
        ("META-INF/container.xml", '<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="designmap.xml" media-type="text/xml"/></rootfiles></container>'),
        ("META-INF/metadata.xml", XMP),
    ], stored_first=True)
    out("idml", "saltmere-leaflet-crafted.idml", idml)
    indd = bytearray(b"\x06\x06\xed\xf5\xd8\x1d\x46\xe5\xbd\x31\xef\xe7\xfe\x74\xb7\x1d" + b"DOCUMENT" + b"\x01" + bytes(4096 - 25))
    out("indesign", "saltmere-leaflet-crafted.indd", bytes(indd) + XMP.encode() + bytes(512))
    out("framemaker", "saltmere-manual-crafted.fm", b"<MakerFile 9.0>\n  Aa\x00\x00" + bytes(2048))
    # No `.mif` (MapInfo, feature `geo`): content decides.
    out("framemaker_mif", "saltmere-manual-fm2015-mif", MIF.encode())
    # Exports: Notion (pages named with their 32-hex id) and Confluence (a
    # space folder with index.html and styles/site.css).
    hexid = lambda n: f"{n:032x}"
    notion = zip_of([
        (f"Saltmere Harbour {hexid(0x5a17e2e0)}.md", "# Saltmere Harbour\n\nThe harbour handbook.\n"),
        (f"Saltmere Harbour/Tides {hexid(0x5a17e2e1)}.md", "# Tides\n\nHigh water 06:12.\n"),
        (f"Saltmere Harbour/Berths {hexid(0x5a17e2e2)}.md", "# Berths\n\nGrey Tern at berth 5.\n"),
        (f"Saltmere Harbour/Tides/chart.png", b"\x89PNG\r\n\x1a\n"),
    ])
    out("wiki_export", "saltmere-notion-export.zip", notion)
    confluence = zip_of([
        ("SALT/index.html", "<html><head><title>Saltmere Harbour</title></head><body><h1>Saltmere Harbour</h1></body></html>"),
        ("SALT/Tides_5767169.html", "<html><head><title>Tides</title></head><body><p>High water 06:12.</p></body></html>"),
        ("SALT/Berths_5767170.html", "<html><head><title>Berths</title></head><body><p>Grey Tern at berth 5.</p></body></html>"),
        ("SALT/styles/site.css", "body { font-family: serif; }"),
        ("SALT/attachments/5767169/5767171.png", b"\x89PNG\r\n\x1a\n"),
    ])
    out("wiki_export", "saltmere-confluence-export.zip", confluence)
    # KFX: the container header (Calibre's KFX notes) and a DRM-wrapped one.
    cont = b"CONT" + struct.pack("<HLLL", 2, 18, 18, 42) + bytes(42) + bytes(64)
    out("kfx", "saltmere-crafted.kfx", cont)
    out("kfx", "saltmere-drmion-crafted.kfx", b"\xeaDRMION\xee" + bytes(64))
    # Goes into the shared tests/fixtures/pdf/ (legacy.sh leaves its
    # SOURCE.md alone).
    out("pdf", "saltmere-chart-illustrator-crafted.ai", illustrator_pdf())


def illustrator_pdf() -> bytes:
    """A PDF laid out as Illustrator's "PDF compatible" files are: the page
    carries an `/Illustrator` piece whose private dictionary points to
    `/AIMetaData` and `/AIPrivateData1` streams; the XMP names the tool."""
    xmp = XMP.replace("Adobe InDesign 20.0 (Macintosh)", "Adobe Illustrator 29.0 (Macintosh)").encode()
    content = b"BT /F1 18 Tf 72 720 Td (Saltmere harbour chart) Tj ET"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 9 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /ArtBox [36 36 559 806] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> /PieceInfo << /Illustrator 6 0 R >> /LastModified (D:20250901120000Z) >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /LastModified (D:20250901120000Z) /Private 7 0 R >>",
        b"<< /AIMetaData 8 0 R /AIPrivateData1 10 0 R /ContainerVersion 12 /CreatorVersion 29 /NumBlock 1 /RoundtripVersion 29 >>",
        b"<< /Length 22 >>\nstream\n%!PS-Adobe-3.0 harbour\nendstream",
        b"<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n" % len(xmp) + xmp + b"\nendstream",
        b"<< /Length 24 >>\nstream\n%AI24_ZStandard_Data....\nendstream",
    ]
    out_ = bytearray(b"%PDF-1.6\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out_))
        out_ += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out_)
    out_ += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offsets:
        out_ += b"%010d 00000 n \n" % o
    out_ += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out_)


# --- older binary documents, help files, print jobs ---------------------------------------

HHP = """[OPTIONS]
Compatibility=1.1 or later
Compiled file=saltmere.chm
Default topic=index.html
Language=0x809 English (United Kingdom)
Title=Saltmere Harbour Help
Contents file=toc.hhc

[FILES]
index.html
tides.html
"""


def guid_le(text: str) -> bytes:
    import uuid

    return uuid.UUID(text).bytes_le


def step_legacy_docs() -> None:
    # WordPerfect 6+: the 16-byte prefix packet, then the document area.
    wp = b"\xffWPC" + struct.pack("<LBBBBHH", 0x200, 1, 0x0A, 2, 0, 0, 0)
    out("wordperfect", "saltmere-notes-crafted.wpd", wp.ljust(0x200, b"\0") + b"Saltmere harbour notes. The bell rings at high tide.\0")
    # Lotus 1-2-3 release 2 (WK1): BOF, RANGE, labels and numbers, EOF.
    def rec(op, body):
        return struct.pack("<HH", op, len(body)) + body
    def label(col, row, text):
        return rec(0x0F, struct.pack("<BHH", 0xFF, col, row) + b"'" + text.encode() + b"\0")
    def number(col, row, v):
        return rec(0x0E, struct.pack("<BHHd", 0xFF, col, row, v))
    wk1 = (rec(0x0000, struct.pack("<H", 0x0406)) + rec(0x0006, struct.pack("<HHHH", 0, 0, 1, 2))
           + label(0, 0, "Boat") + label(1, 0, "Berth") + label(0, 1, "Grey Tern") + number(1, 1, 5.0)
           + label(0, 2, "Harbour Bell") + number(1, 2, 3.0) + rec(0x0001, b""))
    out("lotus123", "saltmere-berths-crafted.wk1", wk1)
    # ClarisWorks / AppleWorks 6: the version byte and `BOBO`.
    out("clarisworks", "saltmere-notes-crafted.cwk", b"\x06\x07\xe1\x00BOBO" + bytes(504))
    # Microsoft Write 3: a 128-byte header, the text, and empty tables.
    text = b"Saltmere harbour notes\r\nHigh water 06:12, low water 12:31.\r\nThe bell rings at high tide.\r\n"
    fc_mac = 128 + len(text)
    pn = (fc_mac + 127) // 128
    head = bytearray(128)
    struct.pack_into("<HHHHHHH", head, 0, 0xBE31, 0, 0xAB00, 0, 0, 0, 0)
    struct.pack_into("<L", head, 14, fc_mac)
    struct.pack_into("<HHHHHH", head, 18, pn, pn + 1, pn + 1, pn + 1, pn + 1, pn + 1)
    struct.pack_into("<H", head, 96, pn + 1)
    body = bytes(head) + text
    out("ms_write", "saltmere-notes-crafted.wri", body.ljust(pn * 128, b"\0") + bytes(128))
    # Ami Pro 3 (text with [section] lines).
    sam = ("[ver]\n\t4\n[sty]\n\t\nBody Text\n[lay]\nStandard\n[edoc]\n"
           "<+!>Saltmere harbour notes\n\nHigh water 06:12, low water 12:31.\n\nThe bell rings at high tide.\n").encode("cp1252")
    # No `.sam` (SAM alignments, feature `science`): content decides.
    out("ami_pro", "saltmere-notes-crafted-amipro", sam)
    # CHM: chmcmd (Free Pascal) from two topics and a contents file.
    chm = WORK / "chm"
    chm.mkdir(exist_ok=True)
    (chm / "saltmere.hhp").write_text(HHP)
    (chm / "index.html").write_text("<html><head><title>Saltmere Harbour</title></head><body><h1>Saltmere</h1><p>The bell rings at high tide.</p></body></html>")
    (chm / "tides.html").write_text("<html><head><title>Tides</title></head><body><p>High water 06:12.</p></body></html>")
    (chm / "toc.hhc").write_text('<HTML><BODY><UL><LI><OBJECT type="text/sitemap"><param name="Name" value="Saltmere"><param name="Local" value="index.html"></OBJECT>'
                                 '<LI><OBJECT type="text/sitemap"><param name="Name" value="Tides"><param name="Local" value="tides.html"></OBJECT></UL></BODY></HTML>')
    run("chmcmd", "saltmere.hhp", cwd=chm, faketime=True)
    out("chm", "saltmere-chmcmd.chm", (chm / "saltmere.chm").read_bytes())
    # WinHelp 4: header, a one-leaf directory B+ tree (|SYSTEM, |TOPIC),
    # |SYSTEM with title and copyright records.
    page = 1024
    def filehdr(data):
        return struct.pack("<LLB", len(data), len(data), 0) + data
    sys_records = b"".join(struct.pack("<HH", t, len(v)) + v for t, v in ((1, b"Saltmere Harbour Help\0"), (2, b"CC0 Saltmere Harbour\0")))
    system = filehdr(struct.pack("<HHHLH", 0x036C, 33, 1, EPOCH, 0) + sys_records)
    topic = filehdr(b"\0" * 32)
    dir_at = 16
    dir_size = 9 + 38 + page
    sys_at = dir_at + dir_size
    topic_at = sys_at + len(system)
    leaf = struct.pack("<HHhh", 0, 2, -1, -1) + b"|SYSTEM\0" + struct.pack("<L", sys_at) + b"|TOPIC\0" + struct.pack("<L", topic_at)
    btree = struct.pack("<HHH16sHHHhHHL", 0x293B, 0x0402, page, b"z4", 0, 0, 0, -1, 1, 1, 2)
    directory = struct.pack("<LLB", dir_size - 9, dir_size - 9, 4) + btree + leaf.ljust(page, b"\0")
    total = topic_at + len(topic)
    hlp = struct.pack("<LLlL", 0x00035F3F, dir_at, -1, total) + directory + system + topic
    out("winhelp", "saltmere-crafted.hlp", hlp)
    # OneNote section header ([MS-ONESTORE] 2.3.1), the rest empty.
    one = bytearray(1024)
    one[0:16] = guid_le("7B5C52E4-D88C-4DA7-AEB1-5378D02996D3")
    one[16:32] = guid_le("5A17E2E0-0000-4000-8000-000000000008")
    one[48:64] = guid_le("109ADD3F-911B-49F5-A5D0-1791EDC8AED8")
    struct.pack_into("<LLLL", one, 64, 0x2A, 0x2A, 0x2A, 0x2A)
    struct.pack_into("<L", one, 96, 3)
    struct.pack_into("<Q", one, 228, 7)
    struct.pack_into("<L", one, 280, 0x0F0D)
    out("onenote", "saltmere-tides-crafted.one", bytes(one))
    # PCL 5 from Ghostscript (ljet4, two pages), in a PJL job.
    (WORK / "tides.ps").write_text("%!PS\n/Helvetica findfont 18 scalefont setfont\n72 720 moveto (Saltmere tides) show showpage\n"
                                    "72 720 moveto (High water 06:12) show showpage\n")
    run("gs", "-q", "-dNOPAUSE", "-dBATCH", "-sDEVICE=ljet4", "-r300", "-sOutputFile=tides.pcl", "tides.ps", cwd=WORK)
    pjl = (b"\x1b%-12345X@PJL JOB NAME=\"Saltmere tides\"\r\n@PJL SET USERNAME=\"harbour\"\r\n@PJL SET RESOLUTION=300\r\n"
           b"@PJL SET COPIES=1\r\n@PJL ENTER LANGUAGE=PCL\r\n")
    out("pcl", "saltmere-tides-gs-ljet4.pcl", pjl + (WORK / "tides.pcl").read_bytes() + b"\x1b%-12345X@PJL EOJ\r\n\x1b%-12345X")
    # Windows spool: SPL header (document, port) then an EMF header record;
    # SHD with the string offsets in the order the forensic notes give.
    def u16s(t):
        return t.encode("utf-16-le") + b"\0\0"
    doc_name, port = u16s("Saltmere tides"), u16s("NUL:")
    spl_head = struct.pack("<LLLL", 0x00010000, 16 + len(doc_name) + len(port), 16, 16 + len(doc_name)) + doc_name + port
    emf = struct.pack("<LL", 1, 108) + bytes(32) + b" EMF" + bytes(108 - 44)
    out("spool_spl", "00007-crafted.spl", spl_head + struct.pack("<LL", 0x0C, len(emf)) + emf)
    strings = ["harbour", "harbour", "Saltmere tides", "NUL:", "Saltmere Harbour Printer", "Generic / Text Only", None, "WinPrint", "NT EMF 1.008"]
    header = 0x58
    blob, offsets = bytearray(), []
    for t in strings:
        if t is None:
            offsets.append(0)
            continue
        offsets.append(header + len(blob))
        blob += u16s(t)
    shd = struct.pack("<LLHHL", 0x5123, header, 0, 0, 7) + struct.pack("<L", 1) + b"".join(struct.pack("<L", o) for o in offsets)
    out("spool_shd", "00007-crafted.shd", shd.ljust(header, b"\0") + bytes(blob))


# --- known JSON / YAML schemas (batch 5b) ----------------------------------------------
# Into the shared json/ and yaml/ folders (legacy.sh keeps their SOURCE.md).

CONFIGS_JSON = {
    "terraform.tfstate": {
        "version": 4, "terraform_version": "1.9.5", "serial": 12, "lineage": "5a17e2e0-0000-4000-8000-000000000009",
        "outputs": {"bucket": {"value": "saltmere-charts", "type": "string"}},
        "resources": [
            {"mode": "managed", "type": "aws_s3_bucket", "name": "charts", "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
             "instances": [{"schema_version": 0, "attributes": {"bucket": "saltmere-charts", "id": "saltmere-charts"}, "sensitive_attributes": []}]},
            {"mode": "managed", "type": "aws_iam_user", "name": "harbourmaster", "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
             "instances": [{"schema_version": 0, "attributes": {"name": "harbourmaster"}, "sensitive_attributes": [[{"type": "get_attr", "value": "password"}]]}]},
            {"mode": "data", "type": "aws_region", "name": "here", "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
             "instances": [{"attributes": {"name": "eu-west-2"}}]},
        ],
    },
    "datapackage.json": {
        "name": "saltmere-berths", "title": "Saltmere berth register", "profile": "tabular-data-package",
        "licenses": [{"name": "CC0-1.0"}],
        "resources": [{"name": "berths", "path": "berths.csv", "schema": {"fields": [{"name": "boat", "type": "string"}, {"name": "berth", "type": "integer"}]}}],
    },
    "berths.csv-metadata.json": {
        "@context": "http://www.w3.org/ns/csvw", "url": "berths.csv", "dc:title": "Saltmere berths",
        "tableSchema": {"columns": [{"name": "boat", "datatype": "string"}, {"name": "berth", "datatype": "integer"}]},
    },
    "dbt-manifest.json": {
        "metadata": {"dbt_schema_version": "https://schemas.getdbt.com/dbt/manifest/v12.json", "dbt_version": "1.8.7", "adapter_type": "duckdb"},
        "nodes": {"model.harbour.berths": {"resource_type": "model"}, "model.harbour.tides": {"resource_type": "model"},
                  "test.harbour.not_null_berths_boat": {"resource_type": "test"}, "seed.harbour.boats": {"resource_type": "seed"}},
        "sources": {"source.harbour.raw.landings": {}}, "exposures": {}, "metrics": {},
    },
    "harbour.eslintrc.json": {"root": True, "extends": ["eslint:recommended", "plugin:@typescript-eslint/recommended"],
                              "plugins": ["@typescript-eslint"], "env": {"browser": True, "es2022": True}, "rules": {"no-unused-vars": "warn", "eqeqeq": "error"}},
    "harbour.prettierrc.json": {"semi": False, "singleQuote": True, "tabWidth": 2, "printWidth": 100},
    "harbour.babelrc.json": {"presets": [["@babel/preset-env", {"targets": "defaults"}], "@babel/preset-typescript"], "plugins": ["@babel/plugin-transform-runtime"]},
    "Records.json": {"locations": [
        {"latitudeE7": 500012345, "longitudeE7": -51234567, "accuracy": 20, "timestamp": "2025-09-01T08:00:00Z"},
        {"latitudeE7": 500022345, "longitudeE7": -51244567, "accuracy": 15, "timestamp": "2025-09-01T12:00:00Z"},
        {"latitudeE7": 500032345, "longitudeE7": -51254567, "accuracy": 18, "timestampMs": "1756742400000"},
    ]},
    "tide-table.gsheet": {"url": "https://docs.google.com/spreadsheets/d/SALTMERE0000000000000000000000000000000000/edit",
                          "doc_id": "SALTMERE0000000000000000000000000000000000", "resource_id": "spreadsheet:SALTMERE0000000000000000000000000000000000",
                          "email": "harbour@saltmere.example"},
    "scratch-project.json": {"targets": [
        {"isStage": True, "name": "Stage", "blocks": {}, "costumes": [{"name": "backdrop1"}], "sounds": []},
        {"isStage": False, "name": "Bell", "blocks": {"a": {"opcode": "event_whenflagclicked"}, "b": {"opcode": "sound_play"}}, "costumes": [{"name": "bell"}], "sounds": [{"name": "ring"}]},
        {"isStage": False, "name": "Boat", "blocks": {"c": {"opcode": "motion_movesteps"}}, "costumes": [{"name": "boat"}], "sounds": []},
    ], "monitors": [], "extensions": ["pen"], "meta": {"semver": "3.0.0", "vm": "11.1.0", "agent": "Saltmere"}},
    "launch.json": {"version": "0.2.0", "configurations": [
        {"type": "node", "request": "launch", "name": "Tide server", "program": "${workspaceFolder}/server.js"},
        {"type": "python", "request": "launch", "name": "Bell script", "program": "${file}"}]},
    "tasks.json": {"version": "2.0.0", "tasks": [{"label": "build charts", "type": "shell", "command": "make charts"}]},
    "harbour.code-snippets": {"Tide row": {"prefix": "tide", "body": ["| ${1:06:12} | ${2:12:31} |"], "description": "A tide table row", "scope": "markdown"},
                              "Bell": {"prefix": "bell", "body": "The bell rings at high tide.", "scope": "markdown"}},
    "high-tide.jscalendar.json": {"@type": "Event", "uid": "5a17e2e0-0000-4000-8000-00000000000a", "title": "High tide at Saltmere",
                                  "start": "2025-09-01T06:12:00", "timeZone": "Europe/London", "duration": "PT1H",
                                  "recurrenceRules": [{"@type": "RecurrenceRule", "frequency": "daily"}]},
    "harbourmaster.jscontact.json": {"@type": "Card", "version": "1.0", "uid": "urn:uuid:5a17e2e0-0000-4000-8000-00000000000b", "kind": "individual",
                                     "name": {"full": "Ana Lighthouse"}, "emails": {"e1": {"address": "ana@saltmere.example"}}, "phones": {}},
    "tides.zpln": {"name": "Saltmere tides", "id": "2KZAA0000", "config": {"looknfeel": "default"}, "paragraphs": [
        {"text": "%md\n# Saltmere tides\nHigh water 06:12.", "config": {}},
        {"text": "%python\nprint('The bell rings at high tide.')", "config": {}},
        {"text": "%sql\nselect boat, berth from berths", "config": {}}]},
}

CONFIGS_YAML = {
    "kustomization.yaml": "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: harbour\nresources:\n  - deployment.yaml\n  - service.yaml\n"
                          "patches:\n  - path: replicas.yaml\nimages:\n  - name: saltmere/tides\n    newTag: \"1.4\"\n",
    "serverless.yml": "service: saltmere-tides\nprovider:\n  name: aws\n  runtime: python3.12\nfunctions:\n  highWater:\n    handler: tides.high\n  bell:\n    handler: tides.bell\nplugins:\n  - serverless-offline\n",
    "dependabot.yml": "version: 2\nupdates:\n  - package-ecosystem: cargo\n    directory: /\n    schedule:\n      interval: weekly\n"
                      "  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: monthly\n",
    "harbour.pre-commit-config.yaml": "repos:\n  - repo: https://github.com/pre-commit/pre-commit-hooks\n    rev: v5.0.0\n    hooks:\n      - id: trailing-whitespace\n      - id: end-of-file-fixer\n"
                                      "  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.6.9\n    hooks:\n      - id: ruff\n",
    "asyncapi.yaml": "asyncapi: 3.0.0\ninfo:\n  title: Saltmere harbour events\n  version: 1.0.0\n  description: Tide and bell events.\nservers:\n  harbour:\n    host: mqtt.saltmere.example\n    protocol: mqtt\n"
                     "channels:\n  tides:\n    address: harbour/tides\n  bell:\n    address: harbour/bell\noperations:\n  onTide:\n    action: receive\n    channel:\n      $ref: '#/channels/tides'\n"
                     "components:\n  messages:\n    tide:\n      payload:\n        type: object\n",
}


def step_configs() -> None:
    import json as _json

    for name, v in CONFIGS_JSON.items():
        out("json", name, (_json.dumps(v, indent=2) + "\n").encode())
    out("json", "renovate.json", b'{\n  "$schema": "https://docs.renovatebot.com/renovate-schema.json",\n  "extends": ["config:recommended"],\n  "packageRules": [{"matchPackagePatterns": ["*"], "groupName": "all"}]\n}\n')
    for name, text in CONFIGS_YAML.items():
        out("yaml", name, text.encode())


# --- more languages for code.source (batch 5b) ----------------------------------------------

LANGUAGES = {
    ("erb", "berths.html.erb"): """<%# Saltmere berth list %>
<h1><%= @harbour.name %></h1>
<%= render partial: "shared/tide_banner" %>
<% content_for :sidebar do %>
  <p>High water <%= @tide.high %></p>
<% end %>
<ul>
<% @boats.each do |boat| %>
  <li><%= link_to boat.name, boat_path(boat) %> at berth <%= boat.berth %></li>
<% end %>
</ul>
""",
    ("jsp", "tides.jsp"): """<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.saltmere.harbour.TideTable" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%-- Saltmere tide page --%>
<jsp:useBean id="tides" class="org.saltmere.harbour.TideTable" scope="request"/>
<html><body>
<h1>Saltmere tides</h1>
<c:forEach var="t" items="${tides.today}"><p>${t.kind} at ${t.time}</p></c:forEach>
</body></html>
""",
    ("asp", "Berths.cshtml"): """@using Saltmere.Harbour.Models
@model BerthListModel
@* Saltmere berth list *@
<h1>@Model.HarbourName</h1>
<ul>
@foreach (var boat in Model.Boats)
{
    <li>@boat.Name at berth @boat.Berth</li>
}
</ul>
@section Scripts {
    <script src="~/js/tides.js"></script>
}
""",
    ("ejs", "bell.ejs"): """<%# Saltmere bell page %>
<%- include('partials/header') %>
<h1><%= harbour %></h1>
<p>The bell rings at <%= highWater %>.</p>
<%- include('partials/footer') %>
""",
    ("prql", "berths.prql"): """# Boats per berth at Saltmere
let busy = func min -> (filter count > min)
from berths
join side:left boats (==boat_id)
group berth (aggregate {count = count this})
sort {-count}
take 10
""",
    ("cypher", "harbour.cypher"): """// Saltmere harbour graph
CREATE CONSTRAINT boat_name FOR (b:Boat) REQUIRE b.name IS UNIQUE;
LOAD CSV WITH HEADERS FROM 'file:///berths.csv' AS row
MERGE (b:Boat {name: row.boat})
MERGE (s:Berth {number: toInteger(row.berth)})
MERGE (b)-[:MOORED_AT]->(s);
/* boats that share a berth */
MATCH (a:Boat)-[:MOORED_AT]->(s:Berth)<-[:MOORED_AT]-(b:Boat) RETURN a.name, b.name, s.number;
""",
}


def step_languages() -> None:
    for (lang, name), text in LANGUAGES.items():
        out(lang, name, text.encode())


# --- record-based data (batch 5b) ---------------------------------------------------------
# Accounts, ids and people are fictitious (Saltmere): the masking is tested
# in memory, never with a realistic file.

LCOV = """TN:harbour
SF:/src/harbour/tides.c
FN:2,bell
FNDA:3,bell
FNF:1
FNH:1
DA:2,3
DA:3,3
DA:4,0
LF:3
LH:2
BRDA:3,0,0,2
BRDA:3,0,1,1
BRF:2
BRH:2
end_of_record
SF:/src/harbour/berth.c
FN:1,berth
FNDA:0,berth
FNF:1
FNH:0
DA:1,0
LF:1
LH:0
end_of_record
"""

TAP = """TAP version 13
1..5
ok 1 - high water is at 06:12
ok 2 - low water is at 12:31
not ok 3 - the bell rings twice
  ---
  message: rang once
  ...
ok 4 - fog horn # SKIP no fog today
not ok 5 - pilot launch # TODO not built yet
"""

PROM = """# HELP harbour_boats_moored Boats moored in the harbour.
# TYPE harbour_boats_moored gauge
harbour_boats_moored{quay="long_wall"} 12
harbour_boats_moored{quay="east"} 4
# HELP harbour_bell_rings_total Times the bell has rung.
# TYPE harbour_bell_rings_total counter
harbour_bell_rings_total 1432
# HELP harbour_tide_height_metres Tide height.
# TYPE harbour_tide_height_metres histogram
harbour_tide_height_metres_bucket{le="1"} 3
harbour_tide_height_metres_bucket{le="+Inf"} 9
harbour_tide_height_metres_sum 21.5
harbour_tide_height_metres_count 9
"""

OFX = """OFXHEADER:100
DATA:OFXSGML
VERSION:102
SECURITY:NONE
ENCODING:USASCII
CHARSET:1252
COMPRESSION:NONE
OLDFILEUID:NONE
NEWFILEUID:NONE

<OFX>
<SIGNONMSGSRSV1><SONRS><STATUS><CODE>0<SEVERITY>INFO</STATUS><DTSERVER>20250901120000<LANGUAGE>ENG<FI><ORG>Saltmere Harbour Bank<FID>9999</FI></SONRS></SIGNONMSGSRSV1>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1<STATUS><CODE>0<SEVERITY>INFO</STATUS>
<STMTRS><CURDEF>GBP
<BANKACCTFROM><BANKID>999999<ACCTID>00000000012345<ACCTTYPE>CHECKING</BANKACCTFROM>
<BANKTRANLIST><DTSTART>20250801<DTEND>20250901
<STMTTRN><TRNTYPE>DEBIT<DTPOSTED>20250805<TRNAMT>-12.50<FITID>1<NAME>Harbour chandlery</STMTTRN>
<STMTTRN><TRNTYPE>CREDIT<DTPOSTED>20250815<TRNAMT>200.00<FITID>2<NAME>Mooring refund</STMTTRN>
<STMTTRN><TRNTYPE>DEBIT<DTPOSTED>20250830<TRNAMT>-4.20<FITID>3<NAME>Bell tower cafe</STMTTRN>
</BANKTRANLIST>
<LEDGERBAL><BALAMT>1183.30<DTASOF>20250901</LEDGERBAL>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>
"""

QIF = """!Type:Bank
D08/05'25
T-12.50
PHarbour chandlery
^
D08/15'25
T200.00
PMooring refund
^
"""

MT940 = """:20:SALT2025090101
:25:GB00SALT00000000012345
:28C:00001/001
:60F:C250801GBP1000,00
:61:2508050805D12,50NTRFNONREF//1
:86:Harbour chandlery
:61:2508150815C200,00NTRFNONREF//2
:86:Mooring refund
:62F:C250901GBP1187,50
"""

CAMT = """<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08">
  <BkToCstmrStmt>
    <GrpHdr><MsgId>SALT-2025-09</MsgId><CreDtTm>2025-09-01T12:00:00</CreDtTm></GrpHdr>
    <Stmt>
      <Id>SALT-STMT-1</Id>
      <Acct><Id><IBAN>GB00SALT00000000012345</IBAN></Id><Ccy>GBP</Ccy></Acct>
      <Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy="GBP">1000.00</Amt><CdtDbtInd>CRDT</CdtDbtInd></Bal>
      <Ntry><Amt Ccy="GBP">12.50</Amt><CdtDbtInd>DBIT</CdtDbtInd><BookgDt><Dt>2025-08-05</Dt></BookgDt></Ntry>
      <Ntry><Amt Ccy="GBP">200.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><BookgDt><Dt>2025-08-15</Dt></BookgDt></Ntry>
    </Stmt>
  </BkToCstmrStmt>
</Document>
"""

BEANCOUNT = """option "title" "Saltmere harbour accounts"
option "operating_currency" "GBP"

2025-08-01 open Assets:Bank:Current GBP
2025-08-01 open Expenses:Chandlery GBP
2025-08-01 open Income:Moorings GBP
2025-08-01 open Equity:Opening GBP

2025-08-01 * "Opening balance"
  Assets:Bank:Current   1000.00 GBP
  Equity:Opening

2025-08-05 * "Harbour chandlery" "Rope"
  Expenses:Chandlery      12.50 GBP
  Assets:Bank:Current

2025-08-15 * "Mooring refund"
  Assets:Bank:Current    200.00 GBP
  Income:Moorings
"""

LEDGER = """; Saltmere harbour ledger
2025/08/05 Harbour chandlery
    Expenses:Chandlery          £12.50
    Assets:Bank:Current

2025/08/15 Mooring refund
    Assets:Bank:Current        £200.00
    Income:Moorings
"""

X12 = ("ISA*00*          *00*          *ZZ*SALTMEREHARBOR *ZZ*TIDECHANDLERY  *250901*1200*U*00401*000000001*0*T*:~"
       "GS*PO*SALTMERE*TIDECHANDLERY*20250901*1200*1*X*004010~"
       "ST*850*0001~BEG*00*SA*PO-2025-001**20250901~PO1*1*10*EA*4.50**VP*ROPE-20M~CTT*1~SE*5*0001~"
       "GE*1*1~IEA*1*000000001~\n")

EDIFACT = ("UNA:+.? '"
           "UNB+UNOC:3+SALTMEREHARBOUR:ZZ+TIDECHANDLERY:ZZ+250901:1200+1'"
           "UNH+1+ORDERS:D:96A:UN'BGM+220+PO-2025-001+9'DTM+137:20250901:102'LIN+1++ROPE-20M:SA'QTY+21:10'UNS+S'UNT+7+1'"
           "UNH+2+INVOIC:D:96A:UN'BGM+380+INV-2025-001+9'UNT+3+2'"
           "UNZ+2+1'\n")

GEDCOM = """0 HEAD
1 SOUR SALTMERE_TREE
2 VERS 1.0
2 NAME Saltmere Family Tree
1 GEDC
2 VERS 5.5.1
2 FORM LINEAGE-LINKED
1 CHAR UTF-8
1 LANG English
0 @I1@ INDI
1 NAME Ben /Gull/
1 BIRT
2 DATE 12 MAR 1890
2 PLAC Saltmere
1 DEAT
2 DATE 1961
0 @I2@ INDI
1 NAME Ana /Lighthouse/
1 BIRT
2 DATE ABT 1893
0 @I3@ INDI
1 NAME Grey /Gull/
1 BIRT
2 DATE 1 JUN 1920
0 @F1@ FAM
1 HUSB @I1@
1 WIFE @I2@
1 CHIL @I3@
1 MARR
2 DATE 1915
0 @S1@ SOUR
1 TITL Saltmere parish register
0 TRLR
"""

FORTUNE = """The harbour bell rings at high tide.
%
Fog on the long wall: listen for the horn.
%
A boat in the harbour is safe, but that is not
what boats are for.
%
Low water at 12:31; mind the bar.
%
"""

LDIF = """version: 1

dn: ou=harbour,dc=saltmere,dc=example
objectClass: top
objectClass: organizationalUnit
ou: harbour

dn: uid=ben,ou=harbour,dc=saltmere,dc=example
objectClass: top
objectClass: inetOrgPerson
uid: ben
cn: Ben Gull
sn: Gull
mail: ben@saltmere.example

dn: uid=ana,ou=harbour,dc=saltmere,dc=example
changetype: modify
replace: telephoneNumber
telephoneNumber: +44 0000 000000
"""

MATHEMATICA = """(* Content-type: application/vnd.wolfram.mathematica *)

(*** Wolfram Notebook File ***)
(* http://www.wolfram.com/nb *)

(* CreatedBy='Mathematica 14.1' *)
(* Created By: Wolfram Mathematica 14.1 *)

Notebook[{
Cell["Saltmere tides", "Title"],
Cell["High water", "Section"],
Cell["The bell rings at high tide.", "Text"],
Cell[BoxData[RowBox[{"tide", "[", "t_", "]", ":=", RowBox[{"2", " ", RowBox[{"Sin", "[", "t", "]"}]}]}]], "Input"],
Cell[BoxData["2"], "Output"]
}]
"""

LIVEBOOK = """# Saltmere tides

```elixir
Mix.install([{:kino, "~> 0.14"}, {:explode, "~> 0.1"}])
```

## High water

The bell rings at high tide.

```elixir
high_water = ~T[06:12:00]
```

## Berths

```elixir
Kino.DataTable.new([%{boat: "Grey Tern", berth: 5}])
```
"""


def step_records() -> None:
    import io
    import zipfile

    for fmt, name, text in (
        ("lcov", "harbour.lcov", LCOV), ("tap", "harbour-tests.tap.txt", TAP), ("prometheus", "harbour-metrics.prom", PROM),
        ("ofx", "saltmere-statement.ofx", OFX), ("qif", "saltmere-statement.qif", QIF), ("mt940", "saltmere-statement.sta", MT940),
        ("camt", "saltmere-statement.camt.xml", CAMT), ("ledger", "saltmere.beancount", BEANCOUNT), ("ledger", "saltmere.ledger", LEDGER),
        ("edi_x12", "purchase-order.x12", X12), ("edifact", "orders.edifact", EDIFACT), ("gedcom", "saltmere-tree.ged", GEDCOM),
        ("fortune", "harbour-sayings.fortune", FORTUNE), ("ldif", "saltmere-directory.ldif", LDIF),
        ("mathematica_nb", "saltmere-tides.nb", MATHEMATICA), ("livebook", "saltmere-tides.livemd", LIVEBOOK),
    ):
        out(fmt, name, text.encode())
    # The strfile index of the fortune file (strfile(1): version 2, counts,
    # flags, delimiter, then the offsets).
    quotes = [q for q in FORTUNE.split("%\n") if q.strip()]
    offsets, at = [], 0
    for q in FORTUNE.split("%\n")[:-1]:
        offsets.append(at)
        at += len(q.encode()) + 2
    lens = [len(q.encode()) for q in quotes]
    dat = struct.pack(">LLLLLc3x", 2, len(quotes), max(lens), min(lens), 0, b"%") + b"".join(struct.pack(">L", o) for o in offsets + [at])
    out("fortune", "harbour-sayings.dat", dat)
    # GTFS: a tiny feed for the Saltmere ferry.
    files = {
        "agency.txt": "agency_id,agency_name,agency_url,agency_timezone\nSF,Saltmere Ferry,https://ferry.saltmere.example,Europe/London\n",
        "stops.txt": "stop_id,stop_name,stop_lat,stop_lon\nLW,Long Wall,50.0001,-5.0001\nEQ,East Quay,50.0011,-5.0021\n",
        "routes.txt": "route_id,agency_id,route_short_name,route_long_name,route_type\nF1,SF,F1,Harbour crossing,4\n",
        "trips.txt": "route_id,service_id,trip_id\nF1,WK,F1-0700\nF1,WK,F1-0800\n",
        "stop_times.txt": "trip_id,arrival_time,departure_time,stop_id,stop_sequence\nF1-0700,07:00:00,07:00:00,LW,1\nF1-0700,07:10:00,07:10:00,EQ,2\n",
        "calendar.txt": "service_id,monday,tuesday,wednesday,thursday,friday,saturday,sunday,start_date,end_date\nWK,1,1,1,1,1,0,0,20250901,20251231\n",
    }
    out("gtfs", "saltmere-ferry-gtfs.zip", zip_of(list(files.items())))


STEPS = {"records": step_records, "languages": step_languages, "configs": step_configs, "legacy_docs": step_legacy_docs, "packages": step_packages, "books": step_books, "writing": step_writing, "scripts": step_scripts, "exec": step_exec, "debug": step_debug, "dos": step_dos, "mac": step_mac, "encoded": step_encoded, "wim": step_wim, "bundles": step_bundles, "backups": step_backups}

if __name__ == "__main__":
    WORK.mkdir(parents=True, exist_ok=True)
    for name in sys.argv[2:] or STEPS:
        STEPS[name]()
