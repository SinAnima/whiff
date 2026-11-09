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


STEPS = {"books": step_books, "writing": step_writing, "scripts": step_scripts, "exec": step_exec, "debug": step_debug, "dos": step_dos, "mac": step_mac, "encoded": step_encoded, "wim": step_wim, "bundles": step_bundles, "backups": step_backups}

if __name__ == "__main__":
    WORK.mkdir(parents=True, exist_ok=True)
    for name in sys.argv[2:] or STEPS:
        STEPS[name]()
