"""Make whiff's games fixtures (run by scripts/fixtures/games.sh in `whiff-games`).

    python3 craft_games.py OUT_DIR [STEP ...]

Everything belongs to a fictitious game, "Saltmere Tides", set in Saltmere
Harbour. Each format is written by its own tool where one exists: cc65
(the NES ROM and the NSF), Inform 6 (Z-code and Glulx), Tiled (TMJ and
TSJ from TMX and TSX), omgifol (Doom WADs), vgio (Quake PAK and WAD2), vpk
(Valve VPK), nbtlib (Minecraft NBT) and vdf (Steam KeyValues). The other
formats are written here from their specifications: ROM headers (with only
the first bytes of the boot logos), console packages, chiptunes, BSP,
Bethesda, RPG Maker, Ren'Py, Godot, Unreal and Unity containers, GameMaker
and Godot projects, Paradox descriptors, Aseprite sprites, interactive
fiction sources and Blorb, and emulator save states.
"""

import gzip
import hashlib
import json
import os
import pickle
import shutil
import struct
import subprocess
import sys
import zlib

# Set by main() (or by games_oracle.py, which reuses the builders).
OUT = TMP = None
STEPS = []
os.environ["SOURCE_DATE_EPOCH"] = "1762329600"  # 2025-11-05T08:00:00Z
EPOCH = 1762329600


def run(*cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def out(fmt, name):
    d = os.path.join(OUT, fmt)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def write(fmt, name, data):
    with open(out(fmt, name), "wb") as f:
        f.write(data)


def want(step):
    return not STEPS or step in STEPS


def pad(b, n, fill=b"\0"):
    return b[:n] + fill * (n - len(b[:n]))


# ---------------------------------------------------------------- ROMs

# Only the first bytes of each boot logo: enough for identification.
GB_LOGO = bytes.fromhex("ceed6666cc0d000b")
GBA_LOGO = bytes.fromhex("24ffae51699aa221")


def nes():
    src = os.path.join(TMP, "harbour.c")
    open(src, "w").write(
        '#include <conio.h>\nint main(void) {\n  clrscr();\n  cputs("SALTMERE TIDES");\n  for (;;) {}\n  return 0;\n}\n'
    )
    rom = os.path.join(TMP, "harbour.nes")
    run("cl65", "-t", "nes", "-O", "-o", rom, src)
    data = open(rom, "rb").read()
    shutil.copy(rom, out("nes_rom", "harbour-nrom.nes"))
    # The same PRG and CHR behind a NES 2.0 header: MMC1, battery, 8 KiB of
    # PRG-NVRAM, PAL.
    h = bytearray(data[:16])
    h[6] = (1 << 4) | 0x02 | 0x01
    h[7] = 0x08
    h[8] = 0x00
    h[9] = 0x00
    h[10] = 0x70
    h[11] = 0x00
    h[12] = 0x01
    h[13:16] = b"\0\0\0"
    write("nes_rom", "buoy-mmc1-nes2.nes", bytes(h) + data[16:])


def snes_sum(rom):
    base = 1 << (len(rom).bit_length() - 1)
    total = sum(rom[:base])
    rest = rom[base:]
    if rest:
        total += sum(rest) * (base // len(rest))
    return total & 0xFFFF


def snes(name, hirom, title, region, size_code, chipset, maker_ext=None, copier=False):
    size = 1024 << size_code
    rom = bytearray(b"\xff" * size)
    base = 0xFFC0 if hirom else 0x7FC0
    # Reset: sei; clc; xce; bra *.
    code_at = 0x8000 if hirom else 0x0000
    rom[code_at : code_at + 5] = bytes([0x78, 0x18, 0xFB, 0x80, 0xFE])
    h = bytearray(64)
    h[0:21] = pad(title.encode(), 21, b" ")
    h[0x15] = (0x31 if hirom else 0x30)
    h[0x16] = chipset
    h[0x17] = size_code
    h[0x18] = 3 if chipset in (0x02, 0x05) else 0
    h[0x19] = region
    if maker_ext:
        h[0x1A] = 0x33
        rom[base - 0x10 : base] = pad(maker_ext.encode(), 16)
    else:
        h[0x1A] = 0x01
    h[0x1B] = 1
    h[0x1C:0x20] = b"\xff\xff\x00\x00"
    h[0x3C:0x3E] = struct.pack("<H", 0x8000)
    rom[base : base + 64] = h
    chk = snes_sum(rom)
    rom[base + 0x1C : base + 0x20] = struct.pack("<HH", chk ^ 0xFFFF, chk)
    data = (b"\0" * 512 if copier else b"") + bytes(rom)
    write("snes_rom", name, data)


def gb_header(rom, title, cgb, maker, cart, rom_code, ram_code, region, licensee, version):
    rom[0x100:0x104] = bytes([0x00, 0xC3, 0x50, 0x01])
    rom[0x104:0x134] = pad(GB_LOGO, 48)
    rom[0x150:0x153] = bytes([0x18, 0xFE, 0x00])  # jr * (wait forever)
    t = title.encode()
    if cgb is None:
        rom[0x134:0x144] = pad(t, 16)
    elif maker:
        rom[0x134:0x13F] = pad(t, 11)
        rom[0x13F:0x143] = maker.encode()
        rom[0x143] = cgb
    else:
        rom[0x134:0x143] = pad(t, 15)
        rom[0x143] = cgb
    if isinstance(licensee, str):
        rom[0x144:0x146] = licensee.encode()
        rom[0x14B] = 0x33
    else:
        rom[0x14B] = licensee
    rom[0x146] = 0
    rom[0x147] = cart
    rom[0x148] = rom_code
    rom[0x149] = ram_code
    rom[0x14A] = region
    rom[0x14C] = version
    x = 0
    for b in rom[0x134:0x14D]:
        x = (x - b - 1) & 0xFF
    rom[0x14D] = x
    s = (sum(rom) - rom[0x14E] - rom[0x14F]) & 0xFFFF
    rom[0x14E:0x150] = struct.pack(">H", s)


def gameboy():
    rom = bytearray(32768)
    gb_header(rom, "SALTMERE", None, None, 0x00, 0, 0, 0, 0x01, 0)
    write("gameboy_rom", "saltmere-dmg.gb", bytes(rom))
    rom = bytearray(65536)
    gb_header(rom, "TIDES", 0x80, "STMR", 0x1B, 1, 2, 1, "ZZ", 2)
    write("gameboy_rom", "tides-color.gbc", bytes(rom))


def gba(name, title, code, maker, version):
    rom = bytearray(8192)
    rom[0:4] = struct.pack("<I", 0xEA00002E)  # b 0xC0
    rom[4:0xA0] = pad(GBA_LOGO, 156)
    rom[0xA0:0xAC] = pad(title.encode(), 12)
    rom[0xAC:0xB0] = code.encode()
    rom[0xB0:0xB2] = maker.encode()
    rom[0xB2] = 0x96
    rom[0xBC] = version
    chk = 0
    for b in rom[0xA0:0xBD]:
        chk = (chk - b) & 0xFF
    rom[0xBD] = (chk - 0x19) & 0xFF
    rom[0xC0:0xC4] = struct.pack("<I", 0xEAFFFFFE)  # b .
    write("gba_rom", name, bytes(rom))


def n64():
    rom = bytearray(8192)
    rom[0:4] = bytes([0x80, 0x37, 0x12, 0x40])
    struct.pack_into(">III", rom, 4, 0x0000000F, 0x80000400, 0x0000144B)
    struct.pack_into(">II", rom, 0x10, 0x5A1D2C3B, 0x0F1E2D3C)
    rom[0x20:0x34] = pad(b"SALTMERE TIDES", 20, b" ")
    rom[0x3B:0x3F] = b"NSTE"
    rom[0x3F] = 1
    z64 = bytes(rom)
    write("n64_rom", "tides.z64", z64)
    write("n64_rom", "tides-byteswapped.v64", bytes(b for i in range(0, len(z64), 2) for b in (z64[i + 1], z64[i])))
    write("n64_rom", "tides-wordswapped.n64", b"".join(z64[i : i + 4][::-1] for i in range(0, len(z64), 4)))


def megadrive(name, system, copyright_, domestic, overseas, serial, devices, region, size):
    rom = bytearray(size)
    struct.pack_into(">II", rom, 0, 0x00FFFE00, 0x00000200)
    rom[0x200:0x204] = bytes([0x60, 0xFE, 0x4E, 0x71])  # bra.s *; nop
    h = bytearray(256)
    h[0x00:0x10] = pad(system.encode(), 16, b" ")
    h[0x10:0x20] = pad(copyright_.encode(), 16, b" ")
    h[0x20:0x50] = pad(domestic.encode(), 48, b" ")
    h[0x50:0x80] = pad(overseas.encode(), 48, b" ")
    h[0x80:0x8E] = pad(serial.encode(), 14, b" ")
    h[0x90:0xA0] = pad(devices.encode(), 16, b" ")
    struct.pack_into(">IIII", h, 0xA0, 0, size - 1, 0xFF0000, 0xFFFFFF)
    h[0xB0:0xBC] = pad(b"", 12, b" ")
    h[0xC8:0xF0] = pad(b"", 40, b" ")
    h[0xF0:0x100] = pad(region.encode(), 16, b" ")
    rom[0x100:0x200] = h
    s = 0
    for i in range(0x200, size, 2):
        s = (s + (rom[i] << 8 | rom[i + 1])) & 0xFFFF
    struct.pack_into(">H", rom, 0x18E, s)
    write("megadrive_rom", name, bytes(rom))


def roms():
    nes()
    snes("tides-lorom.sfc", False, "SALTMERE TIDES", 1, 6, 0x02)
    snes("pier-hirom.smc", True, "PIER PATROL", 2, 6, 0x35, maker_ext="ZZSPRE", copier=True)
    gameboy()
    gba("tides.gba", "SALTMERE", "BSHE", "ZZ", 0)
    gba("tides-europe.gba", "SALTMERE EU", "BSHP", "ZZ", 1)
    n64()
    megadrive("tides.gen", "SEGA MEGA DRIVE", "(C)SALT 2025.NOV", "SALTMERE TIDES", "SALTMERE TIDES", "GM 00000001-00", "J6", "JUE", 16384)
    megadrive("lighthouse.md", "SEGA GENESIS", "(C)T-99 2025.SEP", "TOUDAI", "LIGHTHOUSE KEEPER", "GM T-99001 -01", "JM", "4", 8192)


# ------------------------------------------------------- console packages


def pfs0(files, magic=b"PFS0", entry=0x18):
    names = b"".join(n.encode() + b"\0" for n, _ in files)
    names = pad(names, (len(names) + 31) // 32 * 32)
    hdr = magic + struct.pack("<III", len(files), len(names), 0)
    table, body, off, noff = b"", b"", 0, 0
    for n, d in files:
        if entry == 0x18:
            table += struct.pack("<QQII", off, len(d), noff, 0)
        else:
            table += struct.pack("<QQIIQ", off, len(d), noff, min(len(d), 0x200), 0) + hashlib.sha256(d[:0x200]).digest()
        body += d
        off += len(d)
        noff += len(n) + 1
    return hdr + table + names + body


def consoles():
    title = "0100f00dc0ffe000"
    rights = title + "0000000000000001"
    cnmt = (
        '<?xml version="1.0" encoding="utf-8"?>\n<ContentMeta>\n  <Type>Application</Type>\n'
        f"  <Id>0x{title}</Id>\n  <Version>0</Version>\n</ContentMeta>\n"
    ).encode()
    files = [
        ("6f0c6a6f2d8b4c2e9f1a3b5c7d9e0f12.nca", b"\x5a" * 512),
        ("1a2b3c4d5e6f708192a3b4c5d6e7f809.cnmt.nca", b"\x3c" * 256),
        ("1a2b3c4d5e6f708192a3b4c5d6e7f809.cnmt.xml", cnmt),
        (rights + ".tik", b"\0" * 0x2C0),
        (rights + ".cert", b"\0" * 0x700),
    ]
    write("nsp", "saltmere-tides.nsp", pfs0(files))
    write("nsp", "tides-update.nsp", pfs0([("0123456789abcdef0123456789abcdef.nca", b"\x11" * 128)]))
    # XCI: the card header at 0x100 and the root HFS0 at 0x200.
    x = bytearray(0x200)
    x[0x100:0x104] = b"HEAD"
    struct.pack_into("<I", x, 0x104, 0)
    x[0x10D] = 0xFA
    struct.pack_into("<Q", x, 0x110, 0x0123456789ABCDEF)
    root = pfs0([("update", b""), ("normal", b""), ("secure", b"\0" * 64)], b"HFS0", 0x40)
    struct.pack_into("<QQ", x, 0x130, 0x200, len(root))
    data = bytes(x) + root
    struct.pack_into("<Q", x, 0x118, (len(data) + 511) // 512 - 1)
    write("xci", "saltmere-tides.xci", bytes(x) + root)
    # CIA: header, certificate chain, ticket, TMD, content and the meta
    # section with an SMDH icon.
    def a64(n):
        return (n + 63) // 64 * 64

    certs, ticket, content = b"\0" * 0x40, b"\0" * 0x40, b"\xa5" * 0x100
    tid = 0x0004000000F00D00
    th = bytearray(0xC4)
    th[0:0x40] = pad(b"Root-CA00000003-CP0000000b", 0x40)
    th[0x40] = 1
    struct.pack_into(">Q", th, 0x4C, tid)
    struct.pack_into("<I", th, 0x5A, 0x80000)
    struct.pack_into(">HHH", th, 0x9C, (1 << 10) | (2 << 4) | 0, 1, 0)
    tmd = struct.pack(">I", 0x00010004) + b"\0" * 0x100 + b"\0" * 0x3C + bytes(th) + b"\0" * 0x900 + b"\0" * 0x30
    smdh = bytearray(0x36C0)
    smdh[0:4] = b"SMDH"
    for lang in range(16):
        at = 8 + lang * 0x200
        smdh[at : at + 0x80] = pad("Saltmere Tides".encode("utf-16-le"), 0x80)
        smdh[at + 0x80 : at + 0x180] = pad("Saltmere Tides: Harbour Edition".encode("utf-16-le"), 0x100)
        smdh[at + 0x180 : at + 0x200] = pad("Saltmere Harbour Games".encode("utf-16-le"), 0x80)
    struct.pack_into("<I", smdh, 0x2018, 0x00000006)
    meta = b"\0" * 0x400 + bytes(smdh)
    head = struct.pack("<IHHIIIIQ", 0x2020, 0, 0, len(certs), len(ticket), len(tmd), len(meta), len(content))
    head = pad(head + b"\0" * 0x2000, 0x2020)
    cia = b""
    for part in (head, certs, ticket, tmd, content):
        cia += part + b"\0" * (a64(len(part)) - len(part))
    cia += meta
    write("cia", "saltmere-tides.cia", cia)


# -------------------------------------------------------------- chiptunes


def ca65_binary(name, asm, cfg):
    s, c, o = (os.path.join(TMP, name + e) for e in (".s", ".cfg", ".bin"))
    open(s, "w").write(asm)
    open(c, "w").write(cfg)
    run("cl65", "-t", "none", "-C", c, "-o", o, s)
    return open(o, "rb").read()


NSF_CFG = """MEMORY { HDR: start = $0, size = $80, file = %O; PRG: start = $8000, size = $1000, file = %O, fill = no; }
SEGMENTS { HEADER: load = HDR, type = ro; CODE: load = PRG, type = ro; }
"""

NSF_ASM = """.segment "HEADER"
.byte "NESM", $1a, 1, 3, 1
.word $8000, init, play
.byte "Harbour Bells"
.res 32 - 13
.byte "Saltmere Band"
.res 32 - 13
.byte "2025 Saltmere Harbour"
.res 32 - 21
.word 16639
.byte 0, 0, 0, 0, 0, 0, 0, 0
.word 19997
.byte {region}, {chips}, 0, 0, 0, 0
.segment "CODE"
init:
  lda #$0f
  sta $4015
  rts
play:
  lda #$bf
  sta $4000
  rts
"""


def tag(s, n):
    return pad(s.encode("latin-1"), n)


def chiptunes():
    write("nsf", "harbour-bells.nsf", ca65_binary("bells", NSF_ASM.format(region=0, chips=0), NSF_CFG))
    write("nsf", "foghorn-vrc6.nsf", ca65_binary("fog", NSF_ASM.format(region=2, chips=1), NSF_CFG).replace(b"Harbour Bells", b"Foghorn Waltz"))
    code = bytes([0xA9, 0x0F, 0x8D, 0x15, 0x40, 0x60, 0xA9, 0xBF, 0x8D, 0x00, 0x40, 0x60])

    def chunk(cid, d):
        return struct.pack("<I", len(d)) + cid + d

    info = struct.pack("<HHHBBBB", 0x8000, 0x8000, 0x8006, 0, 0, 2, 0)
    auth = b"\0".join(s.encode() for s in ("Saltmere Tides", "Saltmere Band", "2025 Saltmere Harbour", "craft_games")) + b"\0"
    tlbl = b"Low Tide\0High Tide\0"
    time = struct.pack("<ii", 95000, 120500)
    write("nsfe", "tides.nsfe", b"NSFE" + chunk(b"INFO", info) + chunk(b"DATA", code) + chunk(b"auth", auth)
          + chunk(b"tlbl", tlbl) + chunk(b"time", time) + chunk(b"NEND", b""))
    # SPC: ID666 text and binary forms, the 64 KiB RAM, DSP registers, xid6.
    for name, binary in (("low-tide.spc", False), ("gull-song.spc", True)):
        h = bytearray(0x100)
        h[0:33] = b"SNES-SPC700 Sound File Data v0.30"
        h[0x21:0x24] = bytes([26, 26, 26])
        h[0x24] = 30
        struct.pack_into("<H", h, 0x25, 0x0400)
        h[0x2E:0x4E] = tag("Gull Song" if binary else "Low Tide", 32)
        h[0x4E:0x6E] = tag("Saltmere Tides", 32)
        h[0x6E:0x7E] = tag("craft_games", 16)
        h[0x7E:0x9E] = tag("Harbour theme, first loop", 32)
        if binary:
            h[0x9E:0xA2] = bytes([5, 11]) + struct.pack("<H", 2025)
            h[0xA9:0xAC] = (90).to_bytes(3, "little")
            struct.pack_into("<I", h, 0xAC, 8000)
            h[0xB0:0xD0] = tag("Saltmere Band", 32)
        else:
            h[0x9E:0xA9] = b"11/05/2025\0"
            h[0xA9:0xAC] = b"120"
            h[0xAC:0xB1] = b"10000"
            h[0xB1:0xD1] = tag("Saltmere Band", 32)
        ram = bytearray(0x10000)
        ram[0x400:0x403] = bytes([0x2F, 0xFE, 0x00])  # bra *
        dsp = bytearray(128)
        extra = b""
        if not binary:
            def sub(i, t, d):
                if t == 0:
                    return struct.pack("<BBH", i, 0, d)
                return struct.pack("<BBH", i, t, len(d)) + d + b"\0" * ((4 - len(d) % 4) % 4)

            x = sub(0x10, 1, b"Saltmere Tides OST\0") + sub(0x13, 1, b"Saltmere Harbour Games\0") + sub(0x14, 0, 2025)
            extra = b"xid6" + struct.pack("<I", len(x)) + x
        write("spc", name, bytes(h) + bytes(ram) + bytes(dsp) + b"\0" * 64 + b"\0" * 64 + extra)
    # VGM 1.71 (SN76489 + YM2612) and a gzipped VGM 1.50 (YM2151).
    def gd3(*fields):
        body = b"".join(f.encode("utf-16-le") + b"\0\0" for f in fields)
        return b"Gd3 " + struct.pack("<II", 0x100, len(body)) + body

    def vgm(version, clocks, samples, loop, fields):
        h = bytearray(0x100 if version >= 0x151 else 0x40)
        h[0:4] = b"Vgm "
        struct.pack_into("<I", h, 8, version)
        for at, hz in clocks.items():
            struct.pack_into("<I", h, at, hz)
        struct.pack_into("<I", h, 0x18, samples)
        if version >= 0x150:
            struct.pack_into("<I", h, 0x34, len(h) - 0x34)
        data = bytes([0x50, 0x9F, 0x61, 0x44, 0xAC, 0x66])
        g = gd3(*fields)
        struct.pack_into("<I", h, 0x14, len(h) + len(data) - 0x14)
        if loop:
            struct.pack_into("<II", h, 0x1C, len(h) - 0x1C, samples // 2)
        whole = bytes(h) + data + g
        whole = whole[:4] + struct.pack("<I", len(whole) - 4) + whole[8:]
        return whole

    fields = ("Harbour March", "", "Saltmere Tides", "", "Sega Mega Drive", "", "Saltmere Band", "", "2025/11/05", "craft_games", "Two chips")
    write("vgm", "harbour-march.vgm", vgm(0x171, {0x0C: 3579545, 0x2C: 7670453}, 44100 * 30, True, fields))
    fields2 = ("Night Watch", "", "Saltmere Tides", "", "Arcade", "", "Saltmere Band", "", "2025", "craft_games", "")
    write("vgm", "night-watch.vgz", gzip.compress(vgm(0x150, {0x30: 3579545}, 44100 * 12, False, fields2), mtime=0))
    # PSID v2 and RSID v3 with a second SID.
    def sid(kind, version, name, author, released, flags, second=0):
        h = bytearray(0x7C)
        h[0:4] = kind
        struct.pack_into(">HHHHHHHI", h, 4, version, 0x7C, 0, 0x1000 if kind == b"PSID" else 0, 0x1003 if kind == b"PSID" else 0, 3, 1, 0)
        h[0x16:0x36] = tag(name, 32)
        h[0x36:0x56] = tag(author, 32)
        h[0x56:0x76] = tag(released, 32)
        struct.pack_into(">H", h, 0x76, flags)
        h[0x7A] = second
        code = struct.pack("<H", 0x1000) + bytes([0x4C, 0x00, 0x10, 0x60])
        return bytes(h) + code

    write("sid", "lighthouse.sid", sid(b"PSID", 2, "Lighthouse", "Saltmere Band", "2025 Saltmere Harbour", (1 << 2) | (1 << 4)))
    write("sid", "two-tides.sid", sid(b"RSID", 3, "Two Tides", "Saltmere Band", "2025 Saltmere Harbour", (2 << 2) | (2 << 4) | (2 << 6), 0x42))
    g = bytearray(0x70)
    g[0:4] = b"GBS\x01"
    g[4], g[5] = 4, 1
    struct.pack_into("<HHHH", g, 6, 0x0470, 0x0470, 0x0473, 0xFFFE)
    g[0x0E], g[0x0F] = 0, 0
    g[0x10:0x30] = tag("Saltmere Tides", 32)
    g[0x30:0x50] = tag("Saltmere Band", 32)
    g[0x50:0x70] = tag("2025 Saltmere Harbour", 32)
    write("gbs", "saltmere-tides.gbs", bytes(g) + bytes([0xC9, 0x00, 0x00, 0xC9]))


# --------------------------------------------------------------- archives

PIER_ENTITIES = """{
"classname" "worldspawn"
"message" "The Saltmere Pier"
"wad" "C:\\quake\\id1\\gfx\\base.wad;harbour.wad"
"sounds" "4"
"worldtype" "2"
"_generator" "craft_games"
}
{
"classname" "info_player_start"
"origin" "0 0 24"
"angle" "90"
}
{
"classname" "light"
"origin" "0 0 128"
"light" "300"
}
{
"classname" "light"
"origin" "256 0 128"
"light" "200"
}
"""


def wads():
    import omg

    def map_lumps(rooms):
        ed = omg.MapEditor()
        ed.draw_sector([(0, 0), (512, 0), (512, 512), (0, 512)], sector=omg.Sector(z_floor=0, z_ceil=128))
        for i in range(rooms):
            x = 512 + i * 256
            ed.draw_sector([(x, 0), (x + 256, 0), (x + 256, 256), (x, 256)], sector=omg.Sector(z_floor=8, z_ceil=96))
        ed.things.append(omg.Thing(x=64, y=64, angle=90, type=1, flags=7))
        ed.things.append(omg.Thing(x=128, y=64, angle=0, type=2001, flags=7))
        return ed.to_lumps()

    w = omg.WAD()
    w.maps["MAP01"] = map_lumps(1)
    w.maps["MAP02"] = map_lumps(2)
    w.data["DEHACKED"] = omg.Lump(b"Patch File for DeHackEd v3.0\n# Saltmere Tides\n")
    w.data["MAPINFO"] = omg.Lump(b'map MAP01 "The Pier"\nmap MAP02 "The Lighthouse"\n')
    w.sprites["GULLA0"] = omg.Lump(b"\0" * 64)
    w.sprites["GULLB0"] = omg.Lump(b"\0" * 64)
    w.flats["WATER1"] = omg.Lump(b"\x60" * 4096)
    p = os.path.join(TMP, "harbour.wad")
    w.to_file(p)
    shutil.copy(p, out("wad", "harbour-pwad.wad"))
    e = omg.WAD()
    e.maps["E1M1"] = map_lumps(0)
    e.data["PLAYPAL"] = omg.Lump(bytes(range(256)) * 3 * 14)
    e.data["ENDOOM"] = omg.Lump(b"\x20\x07" * 2000)
    q = os.path.join(TMP, "tides.wad")
    e.to_file(q)
    data = bytearray(open(q, "rb").read())
    data[0:4] = b"IWAD"
    write("wad", "tides-iwad.wad", bytes(data))
    # Quake WAD2 (vgio) and Half-Life WAD3 (the same layout, written here).
    from vgio.quake.wad import WadFile

    w2 = os.path.join(TMP, "gfx.wad")
    with WadFile(w2, "w") as wf:
        wf.writestr("conchars", b"\0" * 128 * 128)
        wf.writestr("palette", bytes(768))
        wf.writestr("water1", b"\0" * 64)
    shutil.copy(w2, out("wad", "gfx-wad2.wad"))
    lumps = [(b"WATER1", 0x43, b"\0" * 40 + b"\x10" * 256), (b"ROPE", 0x43, b"\0" * 40 + b"\x20" * 256), (b"FONT", 0x46, b"\0" * 64)]
    body, d = b"", b""
    for n, t, data in lumps:
        d += struct.pack("<iiibbh", 12 + len(body), len(data), len(data), t, 0, 0) + pad(n, 16)
        body += data
    write("wad", "harbour-wad3.wad", b"WAD3" + struct.pack("<ii", len(lumps), 12 + len(body)) + body + d)


def quake_paks():
    from vgio.quake.pak import PakFile

    p = os.path.join(TMP, "pak0.pak")
    with PakFile(p, "w") as pak:
        pak.writestr("maps/pier.bsp", b"\0" * 64)
        pak.writestr("maps/lighthouse.bsp", b"\0" * 64)
        pak.writestr("gfx/palette.lmp", bytes(768))
        pak.writestr("sound/harbour/bell.wav", b"RIFF" + b"\0" * 40)
        pak.writestr("progs/gull.mdl", b"IDPO" + b"\0" * 60)
        pak.writestr("default.cfg", b"bind w +forward\n")
    shutil.copy(p, out("quake_pak", "pak0.pak"))
    q = os.path.join(TMP, "pak1.pak")
    with PakFile(q, "w") as pak:
        pak.writestr("maps/tidepool.bsp", b"\0" * 32)
    shutil.copy(q, out("quake_pak", "pak1.pak"))


def bsps():
    from vgio.quake.bsp import bsp29 as q

    b = q.Bsp()
    b.entities = PIER_ENTITIES
    b.planes = [q.Plane(0, 0, 1, 0, 2), q.Plane(1, 0, 0, 0, 0)]
    m = q.Miptexture()
    m.name = "water1"
    m.width = m.height = 16
    m.offsets = [40, 40 + 256, 40 + 256 + 64, 40 + 256 + 64 + 16]
    m.pixels = bytes(256 + 64 + 16 + 4)
    b.miptextures = [m]
    b.vertexes = [q.Vertex(0, 0, 0), q.Vertex(256, 0, 0), q.Vertex(256, 256, 0), q.Vertex(0, 256, 0)]
    b.edges = [q.Edge(0, 0), q.Edge(0, 1), q.Edge(1, 2), q.Edge(2, 3), q.Edge(3, 0)]
    b.surf_edges = [1, 2, 3, 4]
    b.texture_infos = [q.TextureInfo(1, 0, 0, 0, 0, 1, 0, 0, 0, 0)]
    b.faces = [q.Face(0, 0, 0, 4, 0, 0, 255, 255, 255, -1)]
    b.mark_surfaces = struct.pack("<H", 0)  # vgio writes this lump as bytes
    b.visibilities = b"\xff" * 4
    b.lighting = bytes(range(64))
    b.leafs = [q.Leaf(-2, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), q.Leaf(-1, -1, 0, 0, 0, 256, 256, 64, 0, 1, 0, 0, 0, 0)]
    b.nodes = [q.Node(0, -2, -1, 0, 0, 0, 256, 256, 64, 0, 1)]
    b.clip_nodes = [q.ClipNode(0, -2, -1)]
    b.models = [q.Model(0, 0, 0, 256, 256, 64, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1)]
    p = os.path.join(TMP, "pier.bsp")
    open(p, "wb").close()  # vgio opens the target for update
    b.save(p)
    shutil.copy(p, out("bsp", "pier-quake.bsp"))
    # Half-Life: the same map as version 30.
    hl = bytearray(open(p, "rb").read())
    struct.pack_into("<i", hl, 0, 30)
    write("bsp", "pier-halflife.bsp", bytes(hl))

    def lumped(magic, version, nlumps, stride, lumps, tail=b""):
        head = len(magic) + 4 + nlumps * stride + len(tail)
        table, body = b"", b""
        for i in range(nlumps):
            d = lumps.get(i, b"")
            off = head + len(body) if d else 0
            if stride == 16:
                table += struct.pack("<iiii", off, len(d), 0, 0)
            else:
                table += struct.pack("<ii", off, len(d))
            body += d + b"\0" * ((4 - len(d) % 4) % 4)
        return magic + struct.pack("<i", version) + table + tail + body

    ents = "\n".join(l for l in PIER_ENTITIES.splitlines() if not l.startswith('"wad"')).encode() + b"\0"
    q2 = lumped(b"IBSP", 38, 19, 8, {0: ents, 2: b"\0" * 12 * 6, 5: b"\0" * 76 * 2, 6: b"\0" * 20 * 3, 13: b"\0" * 48})
    write("bsp", "pier-quake2.bsp", q2)
    q3ents = ents.replace(b'"worldtype" "2"', b'"music" "music/harbour.wav"')
    q3 = lumped(b"IBSP", 46, 17, 8, {0: q3ents, 1: b"\0" * 72 * 3, 7: b"\0" * 40, 10: b"\0" * 44 * 8, 13: b"\0" * 104 * 2})
    write("bsp", "pier-quake3.bsp", q3)
    src_ents = ents.replace(b'"message" "The Saltmere Pier"', b'"message" "Saltmere Pier (Source)"\n"skyname" "sky_day01_01"\n"mapversion" "12"')
    vb = lumped(b"VBSP", 20, 64, 16, {0: src_ents, 2: b"\0" * 32 * 2, 3: b"\0" * 12 * 8, 7: b"\0" * 56 * 4, 14: b"\0" * 48}, struct.pack("<i", 1207))
    write("bsp", "pier-source.bsp", vb)


def vpks():
    import vpk

    d = os.path.join(TMP, "vpkroot")
    for rel, data in (
        ("materials/harbour/water.vmt", b'"LightmappedGeneric"\n{\n}\n'),
        ("materials/harbour/rope.vtf", b"VTF\0" + b"\0" * 60),
        ("models/props_harbour/buoy.mdl", b"IDST" + b"\0" * 60),
        ("sound/harbour/gull.wav", b"RIFF" + b"\0" * 40),
        ("scripts/game_sounds_harbour.txt", b'"Harbour.Gull"\n{\n}\n'),
        ("readme.txt", b"Saltmere Tides content\n"),
    ):
        f = os.path.join(d, rel)
        os.makedirs(os.path.dirname(f), exist_ok=True)
        open(f, "wb").write(data)
    p = os.path.join(TMP, "harbour_dir.vpk")
    vpk.new(d).save(p)
    shutil.copy(p, out("vpk", "harbour_dir.vpk"))


def bethesda():
    files = {
        "meshes\\harbour": ["pier01.nif", "buoy01.nif"],
        "textures\\harbour": ["pier01.dds", "pier01_n.dds", "water.dds"],
        "sound\\fx\\harbour": ["gull01.wav"],
    }
    for name, version in (("SaltmereTides.bsa", 104), ("SaltmereTides - SE.bsa", 105)):
        flags = 0x1 | 0x2
        folders = list(files)
        count = sum(len(v) for v in files.values())
        fnames = b"".join(n.encode() + b"\0" for v in files.values() for n in v)
        dnames = sum(len(f) + 1 for f in folders)
        rec = 24 if version == 105 else 16
        head = b"BSA\0" + struct.pack("<IIIIIIIHH", version, 36, flags, len(folders), count, dnames, len(fnames), 0x1 | 0x2 | 0x8, 0)
        recs, blocks = b"", b""
        off = 36 + rec * len(folders) + dnames + len(folders)
        for f in folders:
            n = len(files[f])
            if version == 105:
                recs += struct.pack("<QIIQ", 0, n, 0, off + len(fnames))
            else:
                recs += struct.pack("<QII", 0, n, off + len(fnames))
            blocks += bytes([len(f) + 1]) + f.encode() + b"\0"
            for i in range(n):
                blocks += struct.pack("<QII", 0, 4, 0)
        write("bsa", name, head + recs + blocks + fnames + b"DATA" * count)
    names = ["Meshes/Harbour/Pier01.nif", "Meshes/Harbour/Buoy01.nif", "Sound/FX/Harbour/Gull01.xwm", "Interface/Harbour.swf"]
    body = b""
    records = b""
    head_len = 24
    for n in names:
        records += struct.pack("<I4sIIQIII", 0, b"nif\0", 0, 0, 0, 0, 4, 0xBAADF00D)
    data_at = head_len + len(records)
    for _ in names:
        body += b"DATA"
    table = b"".join(struct.pack("<H", len(n)) + n.encode() for n in names)
    write("ba2", "SaltmereTides - Main.ba2", b"BTDX" + struct.pack("<I4sIQ", 1, b"GNRL", len(names), data_at + len(body)) + records + body + table)


def rgss():
    names = ["Data\\Map001.rxdata", "Data\\System.rxdata", "Graphics\\Characters\\001-Sailor01.png", "Audio\\BGM\\Harbour.mid"]
    out_ = bytearray(b"RGSSAD\0\x01")
    key = 0xDEADCAFE

    def step(k):
        return (k * 7 + 3) & 0xFFFFFFFF

    for n in names:
        nb = n.encode()
        data = b"\x00" * 16
        out_ += struct.pack("<I", len(nb) ^ key)
        key = step(key)
        for c in nb:
            out_.append(c ^ (key & 0xFF))
            key = step(key)
        out_ += struct.pack("<I", len(data) ^ key)
        key = step(key)
        out_ += data
    write("rgssad", "Game.rgssad", bytes(out_))
    # RGSS3A: a key, then the index, then the data.
    seed = 0x1234ABCD
    k = (seed * 9 + 3) & 0xFFFFFFFF
    names3 = ["Data\\Map001.rvdata2", "Data\\Scripts.rvdata2", "Graphics\\Tilesets\\Harbour_A1.png"]
    index = b""
    data_at = 8 + 4 + sum(16 + len(n) for n in names3) + 16
    for i, n in enumerate(names3):
        nb = n.encode()
        index += struct.pack("<IIII", (data_at + i * 16) ^ k, 16 ^ k, 0x5555 ^ k, len(nb) ^ k)
        index += bytes(c ^ ((k >> (8 * (j % 4))) & 0xFF) for j, c in enumerate(nb))
    index += struct.pack("<IIII", 0 ^ k, 0, 0, 0)
    write("rgssad", "Game.rgss3a", b"RGSSAD\0\x03" + struct.pack("<I", seed) + index + b"\0" * 16 * len(names3))


def rpas():
    # As Ren'Py's archiver writes them: data, then a zlib-compressed pickle
    # of {name: [(offset ^ key, length ^ key, prefix)]}.
    for name, version, key in (("archive.rpa", "3.0", 0x42424242), ("images.rpa", "2.0", None)):
        files = {
            "script.rpyc": b"RENPY RPC2" + b"\0" * 22,
            "images/bg harbour.png": b"\x89PNG\r\n\x1a\n" + b"\0" * 24,
            "audio/gulls.ogg": b"OggS" + b"\0" * 28,
            "gui/textbox.png": b"\x89PNG\r\n\x1a\n" + b"\0" * 8,
        }
        if version == "2.0":
            files = {k: v for k, v in files.items() if k.startswith(("images", "gui"))}
        header_len = 34 if version == "3.0" else 25
        body, index = b"", {}
        for n, d in files.items():
            off = header_len + len(body)
            index[n] = [((off ^ key), (len(d) ^ key), b"") if key else (off, len(d))]
            body += d
        idx = zlib.compress(pickle.dumps(index, 2))
        at = header_len + len(body)
        head = f"RPA-3.0 {at:016x} {key:08x}\n" if key else f"RPA-2.0 {at:016x}\n"
        assert len(head) == header_len, (head, header_len)
        write("rpa", name, head.encode() + body + idx)


def godot_pcks():
    for name, fmt, ver in (("harbour-godot3.pck", 1, (3, 5, 3)), ("harbour-godot4.pck", 2, (4, 3, 0))):
        files = {
            "res://project.binary": b"ECFG" + b"\0" * 12,
            "res://scenes/pier.tscn": b'[gd_scene format=3]\n[node name="Pier" type="Node3D"]\n',
            "res://.godot/imported/water.png-1a2b.ctex": b"GST2" + b"\0" * 28,
            "res://icon.svg": b"<svg/>",
        }
        head = b"GDPC" + struct.pack("<IIII", fmt, *ver)
        if fmt >= 2:
            head += struct.pack("<IQ", 0, 0)
        head += b"\0" * 64
        entries = b""
        sizes = []
        for p in files:
            pb = p.encode()
            pl = (len(pb) + 3) // 4 * 4
            sizes.append(4 + pl + 8 + 8 + 16 + (4 if fmt >= 2 else 0))
        data_at = len(head) + 4 + sum(sizes)
        body = b""
        for p, d in files.items():
            pb = p.encode()
            pl = (len(pb) + 3) // 4 * 4
            entries += struct.pack("<I", pl) + pad(pb, pl) + struct.pack("<QQ", data_at + len(body), len(d)) + hashlib.md5(d).digest()
            if fmt >= 2:
                entries += struct.pack("<I", 0)
            body += d
        write("godot_pck", name, head + struct.pack("<I", len(files)) + entries + body)


def fstr(s):
    b = s.encode() + b"\0"
    return struct.pack("<i", len(b)) + b


def unreal_paks():
    # Version 3 (UE 4.0–4.15): entries inline in the index.
    files = {"SaltmereTides/Content/Maps/Pier.umap": b"\xc1\x83\x2a\x9e" + b"\0" * 60,
             "SaltmereTides/Content/Props/Buoy.uasset": b"\xc1\x83\x2a\x9e" + b"\0" * 28,
             "SaltmereTides/Config/DefaultGame.ini": b"[/Script/EngineSettings.GeneralProjectSettings]\nProjectName=Saltmere Tides\n"}
    body, index = b"", b""
    for n, d in files.items():
        rec = struct.pack("<QQQI", len(body), len(d), len(d), 0) + hashlib.sha1(d).digest() + struct.pack("<BI", 0, 0)
        body += rec + d
        index += fstr(n) + rec
    idx = fstr("../../../") + struct.pack("<i", len(files)) + index
    footer = struct.pack("<IiQQ", 0x5A6F12E1, 3, len(body), len(idx)) + hashlib.sha1(idx).digest()
    write("unreal_pak", "SaltmereTides-WindowsNoEditor.pak", body + idx + b"\0" + footer)
    # Version 11 (UE 4.26+ and 5): a path hash index and a full directory
    # index beside the primary index.
    body = b"\0" * 256
    dirs = {"/": ["SaltmereTides.uproject"], "SaltmereTides/Content/Maps/": ["Pier.umap", "Lighthouse.umap"], "SaltmereTides/Content/Props/": ["Buoy.uasset"]}
    fdi = struct.pack("<i", len(dirs))
    n = 0
    for d, fs in dirs.items():
        fdi += fstr(d) + struct.pack("<i", len(fs))
        for f in fs:
            fdi += fstr(f) + struct.pack("<i", n * 12)
            n += 1
    fdi_at = len(body)
    body += fdi
    primary = fstr("../../../") + struct.pack("<iQ", n, 0x5A17) + struct.pack("<I", 0)
    primary += struct.pack("<I", 1) + struct.pack("<QQ", fdi_at, len(fdi)) + hashlib.sha1(fdi).digest()
    primary += struct.pack("<i", 12 * n) + b"\0" * (12 * n) + struct.pack("<i", 0)
    idx_at = len(body)
    names = b"".join(pad(m, 32) for m in (b"Zlib", b"Oodle", b"", b"", b""))
    footer = b"\0" * 16 + b"\0" + struct.pack("<IiQQ", 0x5A6F12E1, 11, idx_at, len(primary)) + hashlib.sha1(primary).digest() + names
    write("unreal_pak", "SaltmereTides-Windows.pak", body + primary + footer)


def archives():
    wads()
    quake_paks()
    bsps()
    vpks()
    bethesda()
    rgss()
    rpas()
    godot_pcks()
    unreal_paks()


# ---------------------------------------------------------- engine files


def cstr(s):
    return s.encode() + b"\0"


def unity_serialized(version, unity, platform, objects, tree=False):
    """A SerializedFile with typed objects (class ID, path ID, data)."""
    classes = []
    for c, _, _ in objects:
        if c not in classes:
            classes.append(c)
    meta = cstr(unity) + struct.pack("<i", platform) + bytes([1 if tree else 0]) + struct.pack("<i", len(classes))
    for c in classes:
        meta += struct.pack("<iBh", c, 0, -1 if c != 114 else 0)
        if c == 114:
            meta += hashlib.md5(b"HarbourBell").digest()
        meta += hashlib.md5(str(c).encode()).digest()
        if tree:
            # One node: the class's root, named from the string buffer.
            strings = b"Base\0"
            node = struct.pack("<hBBiiiii", 1, 0, 0, 0, 0, -1, 0, 0x4000)
            if version >= 19:
                node += struct.pack("<Q", 0)
            meta += struct.pack("<ii", 1, len(strings)) + node + strings
            if version >= 21:
                meta += struct.pack("<i", 0)
    meta += struct.pack("<i", len(objects))
    header_len = 48 if version >= 22 else 20
    entries = b""
    data = b""
    at = header_len + len(meta)
    for c, path_id, payload in objects:
        pad_n = (-(at + len(entries))) % 4
        entries += b"\0" * pad_n
        if version >= 22:
            entries += struct.pack("<qqIi", path_id, len(data), len(payload), classes.index(c))
        else:
            entries += struct.pack("<qIIi", path_id, len(data), len(payload), classes.index(c))
        data += payload + b"\0" * ((-len(payload)) % 8)
    meta += entries + struct.pack("<i", 0) + struct.pack("<i", 0) + struct.pack("<i", 0) + cstr("")
    meta_size = len(meta)
    data_at = (header_len + meta_size + 15) // 16 * 16
    size = data_at + len(data)
    if version >= 22:
        head = struct.pack(">IIII", 0, 0, version, 0) + b"\0\0\0\0" + struct.pack(">IqqQ", meta_size, size, data_at, 0)
    else:
        head = struct.pack(">IIII", meta_size, size, version, data_at) + b"\0\0\0\0"
    blob = head + meta
    return blob + b"\0" * (data_at - len(blob)) + data


def unity_files():
    objs = [(1, 1, b"\0" * 32), (4, 2, b"\0" * 48), (4, 3, b"\0" * 48), (114, 4, b"\0" * 24), (1, 5, b"\0" * 32)]
    sf = unity_serialized(22, "2022.3.21f1", 19, objs)
    write("unity_assets", "level0", sf)
    sf17 = unity_serialized(17, "2018.4.36f1", 13, objs[:3], tree=True)
    write("unity_assets", "sharedassets0.assets", sf17)
    import lz4.block

    for name, version, revision in (("harbour.unity3d", 6, "2018.4.36f1"), ("harbour-2022.unity3d", 7, "2022.3.21f1")):
        member = sf if version == 7 else sf17
        res = b"\x10" * 512
        payload = member + res
        blocks = struct.pack(">IIH", len(payload), len(payload), 0x40)
        nodes = [(0, len(member), 4, "CAB-6f6c64e1a2b3c4d5e6f708192a3b4c5d"), (len(member), len(res), 0, "CAB-6f6c64e1a2b3c4d5e6f708192a3b4c5d.resS")]
        info = b"\0" * 16 + struct.pack(">i", 1) + blocks + struct.pack(">i", len(nodes))
        for off, n, f, p in nodes:
            info += struct.pack(">qqI", off, n, f) + cstr(p)
        comp = lz4.block.compress(info, store_size=False)
        head = cstr("UnityFS") + struct.pack(">I", version) + cstr("5.x.x") + cstr(revision)
        flags = 0x40 | 2
        rest_len = 8 + 4 + 4 + 4
        total = len(head) + rest_len
        if version >= 7:
            total = (total + 15) // 16 * 16
        size = total + len(comp) + len(payload)
        head += struct.pack(">qIII", size, len(comp), len(info), flags)
        head += b"\0" * (total - len(head))
        write("unity_bundle", name, head + comp + payload)


def uasset(ue5, umap):
    """A package summary (UE 4.27 or UE 5.1) with names, imports and exports."""
    names = ["/Script/Engine", "World" if umap else "StaticMesh", "Pier" if umap else "SM_Buoy", "None", "PersistentLevel"]
    legacy = -8 if ue5 else -7
    body = struct.pack("<Iii", 0x9E2A83C1, legacy, 864) + struct.pack("<i", 522)
    if ue5:
        body += struct.pack("<i", 1009)
    body += struct.pack("<i", 0)
    customs = [(hashlib.md5(b"FEditorObjectVersion").digest(), 40), (hashlib.md5(b"FReleaseObjectVersion").digest(), 30)]
    body += struct.pack("<i", len(customs)) + b"".join(g + struct.pack("<i", v) for g, v in customs)
    header_at = len(body)
    body += struct.pack("<i", 0)  # total header size, patched below
    body += fstr("None")
    flags = 0x00000000 | (0x00020000 if umap else 0)
    body += struct.pack("<I", flags)
    name_at_field = len(body)
    body += struct.pack("<ii", len(names), 0)
    if ue5:
        body += struct.pack("<ii", 0, 0)  # soft object paths
    body += fstr("8F3E2A1B4C5D6E7F8091A2B3C4D5E6F7")  # localization id
    body += struct.pack("<ii", 0, 0)  # gatherable text
    body += struct.pack("<iiii", 1, 0, 2, 0)  # exports, imports
    body += struct.pack("<i", 0)  # depends
    body += struct.pack("<ii", 0, 0)  # soft package references
    body += struct.pack("<i", 0)  # searchable names
    body += struct.pack("<i", 0)  # thumbnails
    body += hashlib.md5(b"Saltmere" + bytes([umap])).digest()  # guid
    body += hashlib.md5(b"persistent").digest()  # persistent guid
    body += struct.pack("<i", 1) + struct.pack("<ii", 1, len(names))  # generations
    if ue5:
        body += struct.pack("<HHHI", 5, 1, 1, 23901901) + fstr("++UE5+Release-5.1")
        body += struct.pack("<HHHI", 5, 1, 0, 0) + fstr("++UE5+Release-5.1")
    else:
        body += struct.pack("<HHHI", 4, 27, 2, 18319896) + fstr("++UE4+Release-4.27")
        body += struct.pack("<HHHI", 4, 27, 0, 0) + fstr("++UE4+Release-4.27")
    body += struct.pack("<I", 0) + struct.pack("<i", 0)  # compression flags, chunks
    body += struct.pack("<I", 0)  # package source
    name_at = len(body)
    for n in names:
        body += fstr(n) + struct.pack("<HH", 0, 0)
    b = bytearray(body)
    struct.pack_into("<i", b, header_at, len(b))
    struct.pack_into("<i", b, name_at_field + 4, name_at)
    return bytes(b)


def engines():
    unity_files()
    write("uasset", "SM_Buoy.uasset", uasset(False, False))
    write("uasset", "Pier.umap", uasset(True, True))
    yyp = """{
  "$GMProject":"",
  "%Name":"SaltmereTides",
  "AudioGroups":[
    {"$GMAudioGroup":"","%Name":"audiogroup_default","name":"audiogroup_default","resourceType":"GMAudioGroup","resourceVersion":"2.0","targets":-1,},
  ],
  "configs":{
    "children":[
      {"children":[],"name":"Release",},
      {"children":[],"name":"Steam",},
    ],
    "name":"Default",
  },
  "Folders":[
    {"$GMFolder":"","%Name":"Objects","folderPath":"folders/Objects.yy","name":"Objects","resourceType":"GMFolder","resourceVersion":"2.0",},
    {"$GMFolder":"","%Name":"Rooms","folderPath":"folders/Rooms.yy","name":"Rooms","resourceType":"GMFolder","resourceVersion":"2.0",},
    {"$GMFolder":"","%Name":"Sprites","folderPath":"folders/Sprites.yy","name":"Sprites","resourceType":"GMFolder","resourceVersion":"2.0",},
  ],
  "IncludedFiles":[],
  "isEcma":false,
  "LibraryEmitters":[],
  "MetaData":{
    "IDEVersion":"2024.8.1.218",
  },
  "name":"SaltmereTides",
  "resources":[
    {"id":{"name":"obj_sailor","path":"objects/obj_sailor/obj_sailor.yy",},},
    {"id":{"name":"obj_gull","path":"objects/obj_gull/obj_gull.yy",},},
    {"id":{"name":"rm_pier","path":"rooms/rm_pier/rm_pier.yy",},},
    {"id":{"name":"rm_lighthouse","path":"rooms/rm_lighthouse/rm_lighthouse.yy",},},
    {"id":{"name":"spr_sailor","path":"sprites/spr_sailor/spr_sailor.yy",},},
    {"id":{"name":"snd_bell","path":"sounds/snd_bell/snd_bell.yy",},},
    {"id":{"name":"scr_tides","path":"scripts/scr_tides/scr_tides.yy",},},
  ],
  "resourceType":"GMProject",
  "resourceVersion":"2.0",
  "RoomOrderNodes":[
    {"roomId":{"name":"rm_pier","path":"rooms/rm_pier/rm_pier.yy",},},
    {"roomId":{"name":"rm_lighthouse","path":"rooms/rm_lighthouse/rm_lighthouse.yy",},},
  ],
  "templateType":null,
  "TextureGroups":[],
}"""
    write("gamemaker_project", "SaltmereTides.yyp", yyp.encode())
    godot4 = """; Engine configuration file.
; It's best edited using the editor UI and not directly,
; since the parameters that go here are not all obvious.
;
; Format:
;   [section] ; section goes between []
;   param=value ; assign values to parameters

config_version=5

[application]

config/name="Saltmere Tides"
config/description="Keep the harbour lights burning."
config/version="0.4.1"
run/main_scene="res://scenes/pier.tscn"
config/features=PackedStringArray("4.3", "Forward Plus")
config/icon="res://icon.svg"

[autoload]

Tides="*res://autoload/tides.gd"
Weather="*res://autoload/weather.gd"

[editor_plugins]

enabled=PackedStringArray("res://addons/dialogue/plugin.cfg")

[rendering]

renderer/rendering_method="forward_plus"
"""
    write("godot_project", "project.godot", godot4.encode())
    godot3 = """; Engine configuration file.

config_version=4

[application]

config/name="Saltmere Tides (classic)"
run/main_scene="res://Pier.tscn"
config/icon="res://icon.png"

[rendering]

environment/default_environment="res://default_env.tres"
"""
    write("godot_project", "classic.godot", godot3.encode())
    write("paradox_mod", "descriptor.mod", b'version="1.2.0"\ntags={\n\t"Gameplay"\n\t"Economy"\n}\nname="Saltmere Harbour Trade"\nsupported_version="1.37.*"\nremote_file_id="3000000001"\n')
    write("paradox_mod", "saltmere_harbour.mod", b'name="Saltmere Harbour Trade"\npath="mod/saltmere_harbour"\ndependencies={\n\t"Better Ports"\n}\npicture="thumbnail.png"\nsupported_version="1.37.*"\n')


# ------------------------------------------------------------- Minecraft


def minecraft():
    import nbtlib
    from nbtlib import tag as t

    def gz(root, name=""):
        f = nbtlib.File(root, gzipped=True, root_name=name)
        p = os.path.join(TMP, "nbt.dat")
        f.save(p, gzipped=True)
        data = open(p, "rb").read()
        # Fixed gzip time for reproducible files.
        return data[:4] + b"\0\0\0\0" + data[8:]

    palette = t.Compound({"minecraft:air": t.Int(0), "minecraft:oak_planks": t.Int(1), "minecraft:lantern[hanging=true]": t.Int(2), "create:rope": t.Int(3)})
    v2 = t.Compound({
        "Version": t.Int(2), "DataVersion": t.Int(3700),
        "Width": t.Short(5), "Height": t.Short(3), "Length": t.Short(12),
        "Metadata": t.Compound({"Name": t.String("Saltmere Pier"), "Author": t.String("Harbour Builders"), "Date": t.Long(EPOCH * 1000),
                                "RequiredMods": t.List[t.String]([t.String("create")])}),
        "PaletteMax": t.Int(4), "Palette": palette,
        "BlockData": t.ByteArray([1] * 180),
        "BlockEntities": t.List[t.Compound]([t.Compound({"Id": t.String("minecraft:sign"), "Pos": t.IntArray([0, 1, 0])})]),
        "Entities": t.List[t.Compound]([]),
        "Offset": t.IntArray([0, 0, 0]),
    })
    write("minecraft_schematic", "pier-sponge2.schem", gz(v2, "Schematic"))
    v3 = t.Compound({"Schematic": t.Compound({
        "Version": t.Int(3), "DataVersion": t.Int(3953),
        "Width": t.Short(7), "Height": t.Short(16), "Length": t.Short(7),
        "Metadata": t.Compound({"Name": t.String("Saltmere Lighthouse"), "Author": t.String("Harbour Builders"), "Date": t.Long(EPOCH * 1000)}),
        "Blocks": t.Compound({"Palette": palette, "Data": t.ByteArray([2] * 784),
                              "BlockEntities": t.List[t.Compound]([t.Compound({"Id": t.String("minecraft:chest"), "Pos": t.IntArray([3, 0, 3])}),
                                                                   t.Compound({"Id": t.String("minecraft:sign"), "Pos": t.IntArray([3, 1, 3])})])}),
        "Entities": t.List[t.Compound]([t.Compound({"Id": t.String("minecraft:villager"), "Pos": t.List[t.Double]([3.5, 1.0, 3.5])})]),
    })})
    write("minecraft_schematic", "lighthouse-sponge3.schem", gz(v3))
    lite = t.Compound({
        "Version": t.Int(6), "MinecraftDataVersion": t.Int(3700), "SubVersion": t.Int(1),
        "Metadata": t.Compound({
            "Name": t.String("Harbour Office"), "Author": t.String("Harbour Builders"), "Description": t.String("Two floors and a clock tower"),
            "RegionCount": t.Int(2), "TotalBlocks": t.Int(1450), "TotalVolume": t.Int(2400),
            "EnclosingSize": t.Compound({"x": t.Int(12), "y": t.Int(20), "z": t.Int(10)}),
            "TimeCreated": t.Long(EPOCH * 1000 - 86_400_000), "TimeModified": t.Long(EPOCH * 1000),
        }),
        "Regions": t.Compound({
            "Office": t.Compound({"Size": t.Compound({"x": t.Int(12), "y": t.Int(10), "z": t.Int(10)})}),
            "Clock tower": t.Compound({"Size": t.Compound({"x": t.Int(4), "y": t.Int(10), "z": t.Int(4)})}),
        }),
    })
    write("minecraft_schematic", "harbour-office.litematic", gz(lite))
    mce = t.Compound({"Width": t.Short(3), "Height": t.Short(2), "Length": t.Short(4), "Materials": t.String("Alpha"),
                      "Blocks": t.ByteArray([5] * 24), "Data": t.ByteArray([0] * 24),
                      "Entities": t.List[t.Compound]([]), "TileEntities": t.List[t.Compound]([])})
    write("minecraft_schematic", "bollard.schematic", gz(mce, "Schematic"))
    # level.dat: Java (gzip, big-endian) and Bedrock (header + little-endian).
    level = t.Compound({"Data": t.Compound({
        "LevelName": t.String("Saltmere Harbour"), "DataVersion": t.Int(3953), "version": t.Int(19133),
        "Version": t.Compound({"Id": t.Int(3953), "Name": t.String("1.21"), "Series": t.String("main"), "Snapshot": t.Byte(0)}),
        "GameType": t.Int(1), "Difficulty": t.Byte(2), "hardcore": t.Byte(0), "allowCommands": t.Byte(1),
        "LastPlayed": t.Long(EPOCH * 1000), "SpawnX": t.Int(-120), "SpawnY": t.Int(64), "SpawnZ": t.Int(388),
        "ServerBrands": t.List[t.String]([t.String("vanilla"), t.String("fabric")]), "WasModded": t.Byte(1),
        "DataPacks": t.Compound({"Enabled": t.List[t.String]([t.String("vanilla"), t.String("file/harbour")]), "Disabled": t.List[t.String]([])}),
    })})
    write("minecraft_level", "level.dat", gz(level))
    be = nbtlib.File({"LevelName": t.String("Saltmere Bedrock"), "GameType": t.Int(0), "Difficulty": t.Int(1),
                      "LastPlayed": t.Long(EPOCH), "SpawnX": t.Int(0), "SpawnY": t.Int(70), "SpawnZ": t.Int(0),
                      "lastOpenedWithVersion": t.List[t.Int]([t.Int(1), t.Int(21), t.Int(40), t.Int(1), t.Int(0)]),
                      "commandsEnabled": t.Byte(0)}, byteorder="little")
    p = os.path.join(TMP, "be.dat")
    be.save(p, byteorder="little")
    raw = open(p, "rb").read()
    write("minecraft_level", "bedrock_level.dat", struct.pack("<ii", 10, len(raw)) + raw)
    # A region file: two chunks (zlib), their timestamps.
    def chunk(x, z, status):
        c = nbtlib.File({"DataVersion": t.Int(3953), "xPos": t.Int(x), "zPos": t.Int(z), "yPos": t.Int(-4),
                         "Status": t.String(status), "LastUpdate": t.Long(1200), "sections": t.List[t.Compound]([])})
        p = os.path.join(TMP, "c.nbt")
        c.save(p, gzipped=False)
        return zlib.compress(open(p, "rb").read())

    loc = bytearray(4096)
    ts = bytearray(4096)
    sectors = b""
    for i, (x, z, status, when) in enumerate(((0, -32, "minecraft:full", EPOCH - 3600), (1, -32, "minecraft:features", EPOCH))):
        d = chunk(x, z, status)
        blob = struct.pack(">IB", len(d) + 1, 2) + d
        blob += b"\0" * ((-len(blob)) % 4096)
        idx = (x & 31) + (z & 31) * 32
        struct.pack_into(">I", loc, idx * 4, ((2 + len(sectors) // 4096) << 8) | (len(blob) // 4096))
        struct.pack_into(">I", ts, idx * 4, when)
        sectors += blob
    write("mca", "r.0.-1.mca", bytes(loc) + bytes(ts) + sectors)


# ------------------------------------------------------------------ Tiled

TMX = """<?xml version="1.0" encoding="UTF-8"?>
<map version="1.10" tiledversion="1.11.0" orientation="orthogonal" renderorder="right-down" width="8" height="6" tilewidth="16" tileheight="16" infinite="0" nextlayerid="6" nextobjectid="4">
 <properties>
  <property name="music" value="harbour.ogg"/>
  <property name="tide" type="float" value="0.75"/>
 </properties>
 <tileset firstgid="1" source="harbour.tsx"/>
 <tileset firstgid="65" name="props" tilewidth="16" tileheight="16" tilecount="4" columns="2">
  <image source="props.png" width="32" height="32"/>
 </tileset>
 <layer id="1" name="Water" width="8" height="6">
  <data encoding="csv">
1,1,1,1,1,1,1,1,
1,1,1,1,1,1,1,1,
2,2,2,2,1,1,1,1,
3,3,3,2,1,1,1,1,
3,3,3,2,1,1,1,1,
3,3,3,2,2,2,2,2
</data>
 </layer>
 <group id="5" name="Pier">
  <layer id="2" name="Planks" width="8" height="6">
   <data encoding="csv">
0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,
0,0,0,0,9,9,9,9,
0,0,0,0,9,0,0,0,
0,0,0,0,9,0,0,0,
0,0,0,0,0,0,0,0
</data>
  </layer>
  <objectgroup id="3" name="Spawns">
   <object id="1" name="sailor" type="spawn" x="72" y="40"/>
   <object id="2" name="gull" type="spawn" x="100" y="20"/>
   <object id="3" name="bell" x="120" y="44" width="16" height="16"/>
  </objectgroup>
 </group>
 <imagelayer id="4" name="Sky">
  <image source="sky.png" width="128" height="96"/>
 </imagelayer>
</map>
"""

TSX = """<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.11.0" name="harbour" tilewidth="16" tileheight="16" tilecount="64" columns="8">
 <image source="harbour.png" width="128" height="128"/>
 <tile id="0" type="water">
  <properties>
   <property name="swimmable" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="200"/>
   <frame tileid="1" duration="200"/>
  </animation>
 </tile>
 <tile id="8" type="planks"/>
 <wangsets>
  <wangset name="Shore" type="corner" tile="-1">
   <wangcolor name="Sand" color="#ffd27f" tile="-1" probability="1"/>
  </wangset>
 </wangsets>
</tileset>
"""


def png(w, h, rgb):
    def ch(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))

    rows = b"".join(b"\0" + bytes(rgb) * w for _ in range(h))
    return b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + ch(b"IDAT", zlib.compress(rows)) + ch(b"IEND", b"")


def tiled():
    d = os.path.join(TMP, "tiled")
    os.makedirs(d, exist_ok=True)
    # Tiled counts tiles from the image, so the images exist.
    for name, w, h in (("harbour.png", 128, 128), ("props.png", 32, 32), ("sky.png", 128, 96)):
        open(os.path.join(d, name), "wb").write(png(w, h, (40, 90, 140)))
    tmx, tsx = os.path.join(d, "pier.tmx"), os.path.join(d, "harbour.tsx")
    open(tmx, "w").write(TMX)
    open(tsx, "w").write(TSX)
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    tmj, tsj = os.path.join(d, "pier.tmj"), os.path.join(d, "harbour.tsj")
    run("tiled", "--export-map", "json", tmx, tmj, env=env)
    run("tiled", "--export-tileset", "json", tsx, tsj, env=env)
    # A second map: isometric.
    iso = os.path.join(d, "lighthouse.tmx")
    open(iso, "w").write(TMX.replace('orientation="orthogonal"', 'orientation="isometric"').replace('tileheight="16" infinite', 'tileheight="8" infinite'))
    shutil.copy(tmx, out("tiled_map", "pier.tmx"))
    shutil.copy(tmj, out("tiled_map", "pier.tmj"))
    shutil.copy(iso, out("tiled_map", "lighthouse.tmx"))
    shutil.copy(tsx, out("tiled_tileset", "harbour.tsx"))
    shutil.copy(tsj, out("tiled_tileset", "harbour.tsj"))


# --------------------------------------------------------------- sprites


def ase_string(s):
    b = s.encode()
    return struct.pack("<H", len(b)) + b


def ase_chunk(t, data):
    return struct.pack("<IH", 6 + len(data), t) + data


def aseprite_file(w, h, depth, frames, palette_colors):
    body = b""
    for i, (duration, chunks) in enumerate(frames):
        data = b"".join(chunks)
        body += struct.pack("<IHHH2sI", 16 + len(data), 0xF1FA, min(len(chunks), 0xFFFF), duration, b"\0\0", len(chunks)) + data
    head = struct.pack("<IHHHHHIH", 128 + len(body), 0xA5E0, len(frames), w, h, depth, 1, 100)
    head += struct.pack("<II", 0, 0) + bytes([0, 0, 0, 0]) + struct.pack("<H", palette_colors)
    head += bytes([1, 1]) + struct.pack("<hhHH", 0, 0, 16, 16)
    head = pad(head, 128)
    return head + body


def sprites():
    def layer(name, kind=0, child=0, flags=3):
        return ase_chunk(0x2004, struct.pack("<HHHHHHB3s", flags, kind, child, 0, 0, 0, 255, b"\0\0\0") + ase_string(name))

    def cel(layer_i):
        return ase_chunk(0x2005, struct.pack("<HhhBHh5s", layer_i, 0, 0, 255, 0, 0, b"\0" * 5) + struct.pack("<HH", 1, 1) + b"\0\0\0\0")

    tags = ase_chunk(0x2018, struct.pack("<H8s", 2, b"\0" * 8)
                     + struct.pack("<HHBH6s3sB", 0, 1, 0, 0, b"\0" * 6, b"\0\0\0", 0) + ase_string("idle")
                     + struct.pack("<HHBH6s3sB", 2, 3, 2, 3, b"\0" * 6, b"\0\0\0", 0) + ase_string("wave"))
    palette = ase_chunk(0x2019, struct.pack("<III8s", 4, 0, 3, b"\0" * 8) + b"".join(struct.pack("<HBBBB", 0, *c) for c in ((0, 0, 0, 0), (32, 64, 128, 255), (240, 220, 160, 255), (255, 255, 255, 255))))
    profile = ase_chunk(0x2007, struct.pack("<HHI8s", 1, 0, 0, b"\0" * 8))
    user = ase_chunk(0x2020, struct.pack("<I", 1) + ase_string("Sailor, drawn for Saltmere Tides"))
    slice_ = ase_chunk(0x2022, struct.pack("<III", 1, 0, 0) + ase_string("hat") + struct.pack("<IiiII", 0, 4, 0, 8, 4))
    first = [profile, palette, layer("Body"), user, layer("Outfit", kind=1), layer("Hat", child=1), layer("Shadow", flags=2), tags, slice_, cel(0), cel(2)]
    frames = [(120, first), (120, [cel(0), cel(2)]), (200, [cel(0)]), (200, [cel(0)])]
    write("aseprite", "sailor.aseprite", aseprite_file(32, 32, 8, frames, 4))
    tileset = ase_chunk(0x2023, struct.pack("<IIIHHh14s", 0, 2, 4, 16, 16, 1, b"\0" * 14) + ase_string("harbour tiles") + struct.pack("<I", 0))
    tframes = [(100, [profile, layer("Ground", kind=2) + struct.pack("<I", 0), tileset, cel(0)])]
    write("aseprite", "pier-tiles.ase", aseprite_file(64, 48, 32, tframes, 0))


# ---------------------------------------------------------------- Steam


def steam():
    import vdf

    manifest = {"AppState": {
        "appid": "3999990", "Universe": "1", "LauncherPath": "", "name": "Saltmere Tides", "StateFlags": "4",
        "installdir": "Saltmere Tides", "LastUpdated": str(EPOCH), "LastPlayed": str(EPOCH), "SizeOnDisk": "734003200",
        "StagingSize": "0", "buildid": "16000001", "LastOwner": "76561190000000001", "BytesToDownload": "0",
        "BytesDownloaded": "0", "AutoUpdateBehavior": "0", "AllowOtherDownloadsWhileRunning": "0", "ScheduledAutoUpdate": "0",
        "InstalledDepots": {"3999991": {"manifest": "1234567890123456789", "size": "734003200"}},
        "UserConfig": {"language": "english"}, "MountedConfig": {"language": "english"},
    }}
    write("steam_vdf", "appmanifest_3999990.acf", vdf.dumps(manifest, pretty=True).encode())
    libs = {"libraryfolders": {
        "0": {"path": "/srv/steam", "label": "", "contentid": "1", "totalSize": "0",
              "apps": {"3999990": "734003200", "228980": "120000000"}},
        "1": {"path": "/mnt/games/SteamLibrary", "label": "Games", "contentid": "2", "totalSize": "500107862016",
              "apps": {"3999992": "52000000"}},
    }}
    write("steam_vdf", "libraryfolders.vdf", vdf.dumps(libs, pretty=True).encode())
    users = {"users": {"76561190000000001": {"AccountName": "harbourmaster", "PersonaName": "Harbour Master", "RememberPassword": "1",
                                              "MostRecent": "1", "Timestamp": str(EPOCH)}}}
    write("steam_vdf", "loginusers.vdf", vdf.dumps(users, pretty=True).encode())
    shortcuts = {"shortcuts": {
        "0": {"appid": -1234567, "AppName": "Saltmere Tides (itch.io)", "Exe": '"/opt/SaltmereTides/tides.x86_64"',
              "StartDir": '"/opt/SaltmereTides/"', "icon": "", "LaunchOptions": "", "IsHidden": 0,
              "AllowDesktopConfig": 1, "OpenVR": 0, "LastPlayTime": EPOCH, "tags": {"0": "Harbour", "1": "Indie"}},
        "1": {"appid": -7654321, "AppName": "Lighthouse Keeper", "Exe": '"C:\\Games\\Lighthouse\\keeper.exe"', "StartDir": '"C:\\Games\\Lighthouse\\"',
              "IsHidden": 0, "LastPlayTime": 0, "tags": {}},
    }}
    write("steam_binary_vdf", "shortcuts.vdf", vdf.binary_dumps(shortcuts))
    # appinfo.vdf (version 0x28): two apps, each with its binary KeyValues.
    def app(appid, name):
        kv = vdf.binary_dumps({"appinfo": {"appid": appid, "common": {"name": name, "type": "Game"}}})
        rest = struct.pack("<IIQ", 2, EPOCH, 0) + hashlib.sha1(kv).digest() + struct.pack("<I", 1) + hashlib.sha1(b"binary").digest() + kv
        return struct.pack("<II", appid, len(rest)) + rest

    write("steam_binary_vdf", "appinfo.vdf", bytes([0x28, 0x44, 0x56, 0x07]) + struct.pack("<I", 1) + app(3999990, "Saltmere Tides") + app(3999992, "Saltmere Tides Soundtrack") + struct.pack("<I", 0))


# ------------------------------------------------------ interactive fiction

INFORM = """Constant Story "SALTMERE TIDES";
Constant Headline "^A short harbour adventure^";
Release 3;
Serial "251105";
{uuid}
Include "parser";
Include "verblib";

Object Pier "Pier"
  with description "Gulls circle the end of the pier. The lighthouse is north.",
       n_to Lighthouse,
  has light;

Object Lighthouse "Lighthouse"
  with description "The lamp room smells of oil.",
       s_to Pier,
  has light;

Object -> lamp "brass lamp"
  with name 'brass' 'lamp',
       description "Polished, and cold.";

[ Initialise;
  location = Pier;
  "^The tide is coming in.^";
];

Include "grammar";
"""

IFID = "8A3F6C2E-5B1D-4E7A-9C0F-2D4B6E8A1C3E"

IFICTION = """<?xml version="1.0" encoding="UTF-8"?>
<ifindex version="1.0" xmlns="http://babel.ifarchive.org/protocol/iFiction/">
 <story>
  <identification>
   <ifid>{ifid}</ifid>
   <format>{fmt}</format>
  </identification>
  <bibliographic>
   <title>Saltmere Tides</title>
   <author>Harbour Writers</author>
   <language>en</language>
   <headline>A short harbour adventure</headline>
   <firstpublished>2025</firstpublished>
   <genre>Slice of life</genre>
   <description>Keep the lighthouse lamp burning<br/>until the fishing boats are home.</description>
  </bibliographic>
 </story>
</ifindex>
"""

TWEE3 = """:: StoryTitle
Saltmere Tides


:: StoryData
{
  "ifid": "D674C58C-DEFA-4F70-B7A2-27742230C0FC",
  "format": "Harlowe",
  "format-version": "3.3.9",
  "start": "Pier",
  "zoom": 1
}


:: Pier [start harbour] {"position":"100,100","size":"100,100"}
Gulls circle the end of the pier. The lighthouse stands to the north.

[[Climb the lighthouse->Lighthouse]]
[[Wait for the boats|Boats]]


:: Lighthouse [harbour] {"position":"250,100"}
The lamp room smells of oil. The brass lamp is cold.

[[Light the lamp->Ending]]
[[Go back down->Pier]]


:: Boats {"position":"100,250"}
The fishing boats are late tonight.

[[Pier]]


:: Ending [end] {"position":"400,100"}
The beam sweeps the water, and the boats turn for home.
"""

TWEE1 = """:: Start
You stand on the harbour wall. [[Walk to the pier|Pier]]

:: Pier
The pier creaks. [[Back|Start]]

:: StoryAuthor
Harbour Writers
"""

INK = """# title: Saltmere Tides
# author: Harbour Writers
INCLUDE characters.ink
VAR lamp_lit = false
CONST HIGH_TIDE = 6
LIST weather = calm, (windy), stormy

-> pier

=== pier ===
Gulls circle the end of the pier.
* [Climb the lighthouse] -> lighthouse
* [Wait for the boats]
    The boats are late tonight.
    -> pier
+ [Listen to the bell] The bell rings twice. -> pier

=== lighthouse ===
= stairs
The stairs wind up into the dark.
- The lamp room smells of oil.
* {not lamp_lit} [Light the lamp]
    ~ lamp_lit = true
    The beam sweeps the water.
    -> ending

=== ending ===
The boats turn for home.
-> END

=== function tide_height(hour) ===
~ return hour % HIGH_TIDE
"""

INK_JSON = {
    "inkVersion": 21,
    "root": [
        [{"->": "pier"}, ["done", {"#f": 5, "#n": "g-0"}], None],
        "done",
        {
            "pier": [["^Gulls circle the end of the pier.", "\n", "ev", "str", "^Climb the lighthouse", "/str", "/ev", {"*": "0.c-0", "flg": 20}, {"c-0": ["\n", {"->": "lighthouse"}, {"#f": 5}]}], None],
            "lighthouse": [["^The lamp room smells of oil.", "\n", {"->": "ending"}], None],
            "ending": ["^The boats turn for home.", "\n", "end", None],
            "global decl": ["ev", False, {"VAR=": "lamp_lit"}, "/ev", "end", None],
        },
    ],
    "listDefs": {"weather": {"calm": 1, "windy": 2, "stormy": 3}},
}


def blorb_file(story_id, story, png, ifmd):
    """FORM IFRS: RIdx, the story, a picture, the iFiction record, Fspc."""
    def ch(cid, d):
        return cid + struct.pack(">I", len(d)) + d + (b"\0" if len(d) % 2 else b"")

    ridx_len = 8 + 4 + 2 * 12
    start = 12 + ridx_len
    story_at = start
    pict_at = story_at + len(ch(story_id, story))
    ridx = struct.pack(">I", 2) + b"Exec" + struct.pack(">II", 0, story_at) + b"Pict" + struct.pack(">II", 1, pict_at)
    body = b"IFRS" + ch(b"RIdx", ridx) + ch(story_id, story) + ch(b"PNG ", png) + ch(b"IFmd", ifmd) + ch(b"Fspc", struct.pack(">I", 1))
    return b"FORM" + struct.pack(">I", len(body)) + body


def fiction():
    d = os.path.join(TMP, "inform")
    os.makedirs(d, exist_ok=True)
    lib = "+include_path=/usr/share/inform6/library"
    src = os.path.join(d, "tides.inf")
    open(src, "w").write(INFORM.format(uuid=f'Array UUID_ARRAY string "UUID://{IFID}//";'))
    run("inform", "-v5", "-q", lib, src, os.path.join(d, "tides.z5"), cwd=d)
    run("inform", "-v8", "-q", lib, src, os.path.join(d, "tides.z8"), cwd=d)
    plain = os.path.join(d, "plain.inf")
    open(plain, "w").write(INFORM.format(uuid=""))
    run("inform", "-v5", "-q", lib, plain, os.path.join(d, "harbour-plain.z5"), cwd=d)
    # Debian's library has no Glk header: the Glulx story is a bare program.
    glx = os.path.join(d, "tides-glulx.inf")
    open(glx, "w").write('Constant Story "SALTMERE TIDES";\nRelease 3;\nSerial "251105";\n[ Main;\n  @quit;\n];\n')
    run("inform", "-G", "-q", glx, os.path.join(d, "tides.ulx"), cwd=d)
    for f, fmt in (("tides.z5", "zcode"), ("tides.z8", "zcode"), ("harbour-plain.z5", "zcode"), ("tides.ulx", "glulx")):
        shutil.copy(os.path.join(d, f), out(fmt, f))
    png = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010806000000" "1f15c4890000000d4944415478da63f8ffff3f0005fe02fe0dd3b8f40000000049454e44ae426082")
    z5 = open(os.path.join(d, "tides.z5"), "rb").read()
    ulx = open(os.path.join(d, "tides.ulx"), "rb").read()
    write("blorb", "tides.zblorb", blorb_file(b"ZCOD", z5, png, IFICTION.format(ifid=IFID, fmt="zcode").encode()))
    write("blorb", "tides.gblorb", blorb_file(b"GLUL", ulx, png, IFICTION.format(ifid="GLULX-3-251105-00000000", fmt="glulx").encode()))
    write("twee", "saltmere-tides.twee", TWEE3.encode())
    write("twee", "harbour-wall.tw", TWEE1.encode())
    write("ink", "saltmere-tides.ink", INK.encode())
    write("ink", "characters.ink", b"=== keeper ===\nThe keeper nods.\n-> DONE\n")
    write("ink_json", "saltmere-tides.ink.json", json.dumps(INK_JSON).encode())


# ---------------------------------------------------------------- saves


def saves():
    def blk(tag_, d):
        return tag_ + struct.pack("<I", len(d)) + d + b"\0" * ((-len(d)) % 8)

    mem = bytes((i * 7) & 0xFF for i in range(4096))
    rastate = b"RASTATE\x01" + blk(b"MEM ", mem) + blk(b"ACHV", b"\x01\0\0\0" * 5) + blk(b"END ", b"")
    write("retroarch_state", "tides.state", rastate)
    # RZIP: 20-byte header, then 32-bit-sized zlib chunks.
    chunk_size = 2048
    rz = b"#RZIPv\x01#" + struct.pack("<IQ", chunk_size, len(rastate))
    for i in range(0, len(rastate), chunk_size):
        c = zlib.compress(rastate[i : i + chunk_size], 6)
        rz += struct.pack("<I", len(c)) + c
    write("retroarch_state", "tides.state1", rz)
    # Mednafen: header (magic, time, version, size, preview), sections.
    def section(name, d):
        return pad(name.encode(), 32) + struct.pack("<I", len(d)) + d

    secs = section("MAIN", b"\0" * 64) + section("CPU", b"\x12" * 32) + section("PPU", b"\x34" * 128) + section("APU", b"\x56" * 16)
    w, h = 4, 2
    preview = b"\x20\x40\x80" * (w * h)
    total = 32 + len(preview) + len(secs)
    head = b"MDFNSVST" + struct.pack("<QIIII", EPOCH, 0x00103201, total, w, h)
    st = head + preview + secs
    write("mednafen_state", "Saltmere Tides.mc1", st)
    write("mednafen_state", "Saltmere Tides.mc0", gzip.compress(st, mtime=0))
    sram = bytearray(8192)
    sram[0:16] = b"SALTMERE SAVE 01"
    sram[0x100:0x110] = bytes(range(16))
    write("battery_save", "Saltmere Tides.srm", bytes(sram))
    write("battery_save", "Lighthouse Keeper.srm", b"\xff" * 32768)


def main():
    global OUT, TMP, STEPS
    OUT = os.path.abspath(sys.argv[1])
    STEPS = sys.argv[2:]
    TMP = os.path.join(OUT, "_work")
    os.makedirs(TMP, exist_ok=True)
    if want("roms"):
        roms()
    if want("consoles"):
        consoles()
    if want("chiptunes"):
        chiptunes()
    if want("archives"):
        archives()
    if want("engines"):
        engines()
    if want("minecraft"):
        minecraft()
    if want("tiled"):
        tiled()
    if want("sprites"):
        sprites()
    if want("steam"):
        steam()
    if want("fiction"):
        fiction()
    if want("saves"):
        saves()
    shutil.rmtree(TMP, ignore_errors=True)
    print("games fixtures written to", OUT)


if __name__ == "__main__":
    main()
