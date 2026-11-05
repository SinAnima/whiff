"""Compare whiff's games reports with each format's own tools.

    # in `whiff-games`: build a corpus and the expected facts
    python3 games_oracle.py expect OUT_DIR
    # on the host
    python3 games_oracle.py check OUT_DIR WHIFF_BINARY

The corpus is generated with random titles, sizes and flags: cartridge ROMs
(through craft_games.py's builders), chiptunes, Inform 6 story files, Doom
WADs (omgifol), Quake PAKs and BSPs (vgio), Valve VPKs (vpk), Minecraft
schematics (nbtlib), Tiled maps (Tiled), Steam manifests (vdf), Unity
bundles and serialized files, and Ren'Py archives. Expected facts come
from libmagic (`file`), libgme (through ffprobe), omgifol, vgio, vpk,
nbtlib, pytmx, vdf, UnityPy and unrpa, never from the generator. Nothing
here ships with whiff.
"""

import gzip
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys

R = random.Random(8)
WORDS = ["Harbour", "Tide", "Gull", "Pier", "Lantern", "Buoy", "Anchor", "Mist", "Keeper", "Reef", "Bell", "Rope", "Shoal"]


def words(n, sep=" "):
    return sep.join(R.choice(WORDS) for _ in range(n))


def run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def file_b(p):
    return run("file", "-b", p).strip()


def gme(p):
    """libgme's tags and duration, through ffprobe."""
    out = run("ffprobe", "-v", "error", "-show_entries", "format_tags:format=duration", "-of", "json", p)
    f = json.loads(out).get("format", {})
    return f.get("tags", {}), f.get("duration")


def expect(out_dir):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import craft_games as cg

    corpus = os.path.join(out_dir, "corpus")
    cg.OUT = corpus
    cg.TMP = os.path.join(out_dir, "work")
    os.makedirs(cg.TMP, exist_ok=True)
    facts = []

    def add(fmt, name, checks):
        facts.append({"file": os.path.join(fmt, name), "format": fmt, "checks": checks})

    # Cartridge ROMs, checked against libmagic's console definitions.
    cg.nes()
    base = open(cg.out("nes_rom", "harbour-nrom.nes"), "rb").read()
    for i in range(12):
        h = bytearray(base[:16])
        mapper = R.choice([0, 1, 2, 3, 4, 7, 66])
        nes2 = i % 2 == 1
        h[6] = (mapper & 0x0F) << 4 | R.choice([0, 1]) | R.choice([0, 2])
        h[7] = (mapper & 0xF0) | (0x08 if nes2 else 0)
        h[12] = R.choice([0, 1]) if nes2 else 0
        h[8:12] = b"\0\0\0\0"
        name = f"rom{i}.nes"
        cg.write("nes_rom", name, bytes(h) + base[16:])
        f = file_b(cg.out("nes_rom", name))
        checks = {
            "prg_rom_bytes": int(re.search(r"(\d+)x16k PRG", f).group(1)) * 16384,
            "chr_rom_bytes": int(re.search(r"(\d+)x8k CHR", f).group(1)) * 8192,
            "mirroring": "vertical" if "[V-mirror]" in f else "horizontal",
            "battery": "[SRAM]" in f,
            "header": "NES 2.0" if "NES 2.0" in f else "iNES",
        }
        if nes2:
            checks["timing"] = "PAL" if "[PAL]" in f else "NTSC"
        add("nes_rom", name, checks)
    regions = {0: "Japan", 1: "USA", 2: "Europe"}
    for i in range(10):
        title = words(2).upper()[:21]
        hirom = i % 2 == 1
        name = f"snes{i}.sfc"
        cg.snes(name, hirom, title, R.choice(list(regions)), R.choice([5, 6, 7]), R.choice([0x00, 0x02]))
        f = file_b(cg.out("snes_rom", name))
        m = re.match(r'Super NES ROM image "(.*?)" \((\w+)\)', f)
        add("snes_rom", name, {"title": m.group(1).strip(), "layout": "HiROM" if "HiROM" in f else "LoROM",
                               "speed": "FastROM" if "FastROM" in f else "SlowROM", "checksum_valid": True})
    carts = {0x00: "ROM ONLY", 0x01: "MBC1", 0x03: "MBC1+RAM+BATT", 0x13: "MBC3+RAM+BATT", 0x19: "MBC5", 0x1B: "MBC5+RAM+BATT"}
    for i in range(10):
        cgb = R.choice([None, 0x80, 0xC0])
        title = words(1).upper()[: 11 if cgb else 16]
        rom = bytearray(32768 << (i % 2))
        cg.gb_header(rom, title, cgb, None, R.choice(list(carts)), i % 2, R.choice([0, 2, 3]), R.choice([0, 1]), 0x01, R.randint(0, 3))
        name = f"gb{i}.gb"
        cg.write("gameboy_rom", name, bytes(rom))
        f = file_b(cg.out("gameboy_rom", name))
        m = re.search(r'"(.*?)" \(Rev\.(\d+)\)', f)
        add("gameboy_rom", name, {"title": m.group(1).strip(), "version": int(m.group(2)),
                                  "declared_rom_bytes": int(re.search(r"ROM: (\d+)Kbit", f).group(1)) * 128,
                                  "header_checksum_valid": True, "global_checksum_valid": True})
    for i in range(8):
        title = words(1).upper()[:12]
        code = "B" + "".join(R.choice("ABCDEFGHJK") for _ in range(2)) + R.choice("EJP")
        name = f"gba{i}.gba"
        cg.gba(name, title, code, "ZZ", R.randint(0, 3))
        f = file_b(cg.out("gba_rom", name))
        m = re.search(r'"(.*?)" \((\w{4})(\w{2}), Rev\.(\d+)\)', f)
        add("gba_rom", name, {"title": m.group(1).strip(), "game_code": m.group(2), "maker_code": m.group(3),
                              "version": int(m.group(4)), "header_checksum_valid": True})
    for i in range(6):
        title = words(2).upper()
        name = f"md{i}.gen"
        cg.megadrive(name, "SEGA MEGA DRIVE", f"(C)SALT 202{i}.JAN", title, title, f"GM 0000000{i}-00", "J", "JUE", 8192)
        f = file_b(cg.out("megadrive_rom", name))
        m = re.search(r'"(.*?)" \((.*?), (\(C\).*?)\)', f)
        add("megadrive_rom", name, {"domestic_title": m.group(1).strip(), "serial": m.group(2).strip(),
                                    "copyright": m.group(3).strip(), "checksum_valid": True})

    # Chiptunes: libgme's tags.
    for i in range(10):
        title, author, copy = words(2), words(1) + " Band", f"20{R.randint(10, 25)} " + words(1)
        tracks = R.randint(1, 20)
        h = bytearray(0x80)
        h[0:5] = b"NESM\x1a"
        h[5], h[6], h[7] = 1, tracks, 1
        struct.pack_into("<HHH", h, 8, 0x8000, 0x8000, 0x8003)
        h[0x0E:0x2E] = cg.tag(title, 32)
        h[0x2E:0x4E] = cg.tag(author, 32)
        h[0x4E:0x6E] = cg.tag(copy, 32)
        struct.pack_into("<H", h, 0x6E, 16639)
        name = f"nsf{i}.nsf"
        cg.write("nsf", name, bytes(h) + bytes([0x60, 0, 0, 0x60]))
        t, _ = gme(cg.out("nsf", name))
        add("nsf", name, {"title": t["game"], "author": t["author"], "copyright": t["copyright"], "songs": int(t["tracks"])})
    for i in range(10):
        binary = i % 2 == 1
        song, game, artist = words(2), words(2), words(1) + " Band"
        secs = R.randint(30, 300)
        h = bytearray(0x100)
        h[0:33] = b"SNES-SPC700 Sound File Data v0.30"
        h[0x21:0x24] = bytes([26, 26, 26])
        h[0x24] = 30
        h[0x2E:0x4E] = cg.tag(song, 32)
        h[0x4E:0x6E] = cg.tag(game, 32)
        if binary:
            h[0xA9:0xAC] = secs.to_bytes(3, "little")
            struct.pack_into("<I", h, 0xAC, 5000)
            h[0xB0:0xD0] = cg.tag(artist, 32)
        else:
            h[0xA9:0xAC] = str(secs).encode()
            h[0xAC:0xB1] = b"5000\0"
            h[0xB1:0xD1] = cg.tag(artist, 32)
        name = f"spc{i}.spc"
        cg.write("spc", name, bytes(h) + bytes(0x10000) + bytes(256))
        t, d = gme(cg.out("spc", name))
        add("spc", name, {"title": t["song"], "game": t["game"], "author": t["author"], "play_seconds": round(float(d))})
    for i in range(10):
        song, game, author = words(2), words(2), words(1) + " Band"
        samples = 44100 * R.randint(5, 200)
        hdr = bytearray(0x40)
        hdr[0:4] = b"Vgm "
        struct.pack_into("<I", hdr, 8, 0x150)
        struct.pack_into("<I", hdr, 0x0C, 3579545)
        struct.pack_into("<I", hdr, 0x2C, R.choice([0, 7670453]))
        struct.pack_into("<I", hdr, 0x18, samples)
        struct.pack_into("<I", hdr, 0x34, 0x0C)
        data = bytes([0x50, 0x9F, 0x66])
        fields = (song, "", game, "", "Sega Master System", "", author, "", "2025", "oracle", "")
        body = b"".join(f.encode("utf-16-le") + b"\0\0" for f in fields)
        gd3 = b"Gd3 " + struct.pack("<II", 0x100, len(body)) + body
        struct.pack_into("<I", hdr, 0x14, 0x40 + len(data) - 0x14)
        whole = bytes(hdr) + data + gd3
        whole = whole[:4] + struct.pack("<I", len(whole) - 4) + whole[8:]
        name = f"vgm{i}." + ("vgz" if i % 3 == 0 else "vgm")
        cg.write("vgm", name, gzip.compress(whole, mtime=0) if name.endswith("vgz") else whole)
        t, _ = gme(cg.out("vgm", name))
        add("vgm", name, {"title": t["song"], "author": t["author"]})
    for i in range(8):
        h = bytearray(0x7C)
        h[0:4] = b"PSID"
        name_, author, rel = words(2), words(1) + " Band", f"20{R.randint(10, 25)} " + words(1)
        songs = R.randint(1, 30)
        struct.pack_into(">HHHHHHHI", h, 4, 2, 0x7C, 0, 0x1000, 0x1003, songs, 1, 0)
        h[0x16:0x36] = cg.tag(name_, 32)
        h[0x36:0x56] = cg.tag(author, 32)
        h[0x56:0x76] = cg.tag(rel, 32)
        name = f"sid{i}.sid"
        cg.write("sid", name, bytes(h) + struct.pack("<H", 0x1000) + b"\x60")
        f = file_b(cg.out("sid", name))
        m = re.search(r'(\d+) songs, default song: (\d+) name: "(.*?)" author: "(.*?)" copyright: "(.*?)"', f)
        add("sid", name, {"songs": int(m.group(1)), "start_song": int(m.group(2)), "title": m.group(3), "author": m.group(4), "copyright": m.group(5)})

    # Story files compiled by Inform 6.
    d = os.path.join(cg.TMP, "inform")
    os.makedirs(d, exist_ok=True)
    lib = "+include_path=/usr/share/inform6/library"
    for i, v in enumerate(("-v5", "-v8", "-v5", "-v8")):
        src = os.path.join(d, f"s{i}.inf")
        release = R.randint(1, 99)
        open(src, "w").write(cg.INFORM.format(uuid="").replace("Release 3;", f"Release {release};").replace('Serial "251105"', f'Serial "25{R.randint(10, 12)}{R.randint(10, 28)}"'))
        name = f"story{i}.z{v[-1]}"
        subprocess.run(["inform", v, "-q", lib, src, cg.out("zcode", name)], check=True, capture_output=True, cwd=d)
        f = file_b(cg.out("zcode", name))
        m = re.search(r"Z-machine (\d), Release (\d+), Serial (\d+)", f)
        add("zcode", name, {"version": int(m.group(1)), "release": int(m.group(2)), "serial": m.group(3), "checksum_valid": True})

    # Doom WADs: omgifol reads them back.
    import omg

    for i in range(6):
        w = omg.WAD()
        for m in range(R.randint(1, 4)):
            ed = omg.MapEditor()
            ed.draw_sector([(0, 0), (256, 0), (256, 256), (0, 256)])
            ed.things.append(omg.Thing(x=64, y=64, type=1))
            w.maps[f"MAP{m + 1:02d}"] = ed.to_lumps()
        for s in range(R.randint(0, 3)):
            w.sprites[f"GUL{s}A0"] = omg.Lump(b"\0" * 32)
        name = f"wad{i}.wad"
        w.to_file(cg.out("wad", name))
        back = omg.WAD(cg.out("wad", name))
        lumps = int(re.search(r"containing (\d+) lumps", file_b(cg.out("wad", name))).group(1))
        add("wad", name, {"maps": list(back.maps.keys()), "lump_count": lumps})

    # Quake PAKs and BSPs: vgio.
    from vgio.quake.pak import PakFile

    for i in range(6):
        name = f"pak{i}.pak"
        files = sorted({f"{R.choice(['maps', 'gfx', 'sound', 'progs'])}/{words(1).lower()}{n}.{R.choice(['bsp', 'lmp', 'wav', 'mdl'])}" for n in range(R.randint(1, 12))})
        with PakFile(cg.out("quake_pak", name), "w") as pak:
            for f in files:
                pak.writestr(f, b"\0" * R.randint(1, 64))
        with PakFile(cg.out("quake_pak", name)) as pak:
            names = pak.namelist()
        add("quake_pak", name, {"file_count": len(names), "files": names[:50]})

    # Valve VPKs: vpk.
    import vpk

    for i in range(4):
        root = os.path.join(cg.TMP, f"vpk{i}")
        for n in range(R.randint(1, 15)):
            p = os.path.join(root, R.choice(["materials", "models", "sound"]), words(1).lower(), f"f{n}.{R.choice(['vmt', 'vtf', 'mdl', 'wav'])}")
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(os.urandom(R.randint(1, 100)))
        name = f"v{i}_dir.vpk"
        vpk.new(root).save(cg.out("vpk", name))
        back = vpk.open(cg.out("vpk", name))
        add("vpk", name, {"file_count": len(list(back))})

    # Minecraft schematics: nbtlib.
    import nbtlib
    from nbtlib import tag as t

    for i in range(6):
        w_, h_, l_ = (R.randint(1, 60) for _ in range(3))
        root = t.Compound({"Version": t.Int(2), "DataVersion": t.Int(R.randint(2500, 4200)), "Width": t.Short(w_), "Height": t.Short(h_), "Length": t.Short(l_),
                           "Metadata": t.Compound({"Name": t.String(words(2)), "Author": t.String(words(1))}),
                           "Palette": t.Compound({f"minecraft:{words(1).lower()}{n}": t.Int(n) for n in range(R.randint(1, 9))}),
                           "BlockData": t.ByteArray([0] * (w_ * h_ * l_ % 1000))})
        name = f"s{i}.schem"
        nbtlib.File(root, root_name="Schematic").save(cg.out("minecraft_schematic", name), gzipped=True)
        back = nbtlib.load(cg.out("minecraft_schematic", name))
        add("minecraft_schematic", name, {"size": [int(back["Width"]), int(back["Height"]), int(back["Length"])], "data_version": int(back["DataVersion"]),
                                          "name": str(back["Metadata"]["Name"]), "author": str(back["Metadata"]["Author"]), "palette_size": len(back["Palette"])})

    # Tiled maps: written here, read back with pytmx.
    import pytmx

    for i in range(5):
        layers = [words(1) + str(n) for n in range(R.randint(1, 5))]
        objects = R.randint(0, 6)
        w_, h_ = R.randint(2, 30), R.randint(2, 30)
        body = "".join(f' <layer id="{n + 1}" name="{l}" width="{w_}" height="{h_}"><data encoding="csv">{",".join(["0"] * (w_ * h_))}</data></layer>\n' for n, l in enumerate(layers))
        objs = "".join(f'  <object id="{n + 1}" x="{n * 8}" y="0"/>\n' for n in range(objects))
        tmx = (f'<?xml version="1.0" encoding="UTF-8"?>\n<map version="1.10" tiledversion="1.11.0" orientation="orthogonal" renderorder="right-down" '
               f'width="{w_}" height="{h_}" tilewidth="16" tileheight="16" infinite="0">\n{body} <objectgroup id="99" name="Things">\n{objs} </objectgroup>\n</map>\n')
        name = f"m{i}.tmx"
        open(cg.out("tiled_map", name), "w").write(tmx)
        m = pytmx.TiledMap(cg.out("tiled_map", name))
        add("tiled_map", name, {"width": m.width, "height": m.height, "layers": [l.name for l in m.layers],
                                "object_count": sum(len(list(l)) for l in m.objectgroups)})

    # Steam manifests: vdf.
    import vdf

    for i in range(5):
        doc = {"AppState": {"appid": str(R.randint(10, 3999999)), "name": words(3), "installdir": words(2), "buildid": str(R.randint(1, 20000000)), "StateFlags": "4"}}
        name = f"appmanifest_{i}.acf"
        open(cg.out("steam_vdf", name), "w").write(vdf.dumps(doc, pretty=True))
        back = vdf.load(open(cg.out("steam_vdf", name)))["AppState"]
        add("steam_vdf", name, {"app_id": int(back["appid"]), "name": back["name"], "install_folder": back["installdir"], "build_id": int(back["buildid"])})

    # Unity bundles and serialized files: UnityPy reads them back.
    import UnityPy

    cg.unity_files()
    for fmt, name in (("unity_bundle", "harbour.unity3d"), ("unity_bundle", "harbour-2022.unity3d")):
        env = UnityPy.load(cg.out(fmt, name))
        f = list(env.files.values())[0]
        add(fmt, name, {"file_count": len(f.files), "unity_version": f.version_engine})
    for fmt, name in (("unity_assets", "level0"), ("unity_assets", "sharedassets0.assets")):
        env = UnityPy.load(cg.out(fmt, name))
        sf = list(env.files.values())[0]
        add(fmt, name, {"object_count": len(sf.objects), "unity_version": sf.unity_version})

    # Ren'Py archives: unrpa lists them.
    cg.rpas()
    for name in ("archive.rpa", "images.rpa"):
        names = [l for l in run("unrpa", "-l", cg.out("rpa", name)).splitlines() if l.strip()]
        add("rpa", name, {"file_count": len(names)})

    shutil.rmtree(cg.TMP, ignore_errors=True)
    json.dump(facts, open(os.path.join(out_dir, "expected.json"), "w"), indent=1)
    print(len(facts), "files,", sum(len(f["checks"]) for f in facts), "checks")


def check(out_dir, whiff):
    facts = json.load(open(os.path.join(out_dir, "expected.json")))
    corpus = os.path.join(out_dir, "corpus")
    bad = 0
    total = 0
    for f in facts:
        r = json.loads(subprocess.run([whiff, os.path.join(corpus, f["file"])], capture_output=True, text=True).stdout)
        got_fmt = r["identification"]["format"]
        total += 1
        if got_fmt != f["format"]:
            print(f"{f['file']}: detected as {got_fmt}")
            bad += 1
            continue
        fields = r.get("format", {}).get(f["format"], {})
        for k, want in f["checks"].items():
            total += 1
            got = fields.get(k)
            if k in ("files", "maps", "layers") and isinstance(got, list):
                ok = got[: len(want)] == want or sorted(got) == sorted(want)
            else:
                ok = got == want
            if not ok:
                bad += 1
                print(f"{f['file']}: {k}: whiff {got!r}, expected {want!r}")
    print(f"{total - bad} of {total} agree ({len(facts)} files)")
    return bad == 0


if __name__ == "__main__":
    if sys.argv[1] == "expect":
        expect(sys.argv[2])
    else:
        sys.exit(0 if check(sys.argv[2], sys.argv[3]) else 1)
