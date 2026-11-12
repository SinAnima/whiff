#!/usr/bin/env python3
"""Stage 8 long tail, batch 5d: audio and video fixtures for the fictitious
Saltmere Harbour, CC0-1.0. Run inside the `whiff-av` image (see av.sh).

Encoded with FFmpeg (AC-3, E-AC-3, DTS, TrueHD, MLP, GSM, DV, MXF, AMV),
SoX (Dialogic VOX), OpenTimelineIO (.otio) and pyaaf2 (.aaf); the other
files are written here from each format's published layout.

    craft_av.py OUT_DIR [STEP ...]   (raw instruments projects video edit)
"""

import gzip
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

OUT = Path(sys.argv[1])
FF = ["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-fflags", "+bitexact"]
SINE = ["-f", "lavfi", "-i", "sine=frequency=440:duration=1:sample_rate=48000"]


def path(fmt: str, name: str) -> Path:
    d = OUT / fmt
    d.mkdir(parents=True, exist_ok=True)
    return d / name


def out(fmt: str, name: str, data: bytes) -> None:
    path(fmt, name).write_bytes(data)


def ff(*args: str) -> None:
    subprocess.run([*FF, *args], check=True)


# --- raw audio ------------------------------------------------------------------------------


def step_raw() -> None:
    ff(*SINE, "-ac", "2", "-c:a", "ac3", "-b:a", "96k", "-flags", "+bitexact", str(path("ac3", "harbour-bell.ac3")))
    ff(*SINE, "-ac", "6", "-c:a", "eac3", "-b:a", "192k", "-flags", "+bitexact", str(path("eac3", "harbour-bell-5.1.eac3")))
    ff(*SINE, "-ac", "2", "-c:a", "dca", "-strict", "-2", "-flags", "+bitexact", str(path("dts_audio", "harbour-bell.dts")))
    ff(*SINE, "-ac", "2", "-c:a", "truehd", "-strict", "-2", "-flags", "+bitexact", str(path("truehd", "harbour-bell.thd")))
    ff(*SINE, "-ac", "2", "-c:a", "mlp", "-strict", "-2", "-flags", "+bitexact", str(path("truehd", "harbour-bell.mlp")))
    ff("-f", "lavfi", "-i", "sine=frequency=440:duration=1:sample_rate=8000", "-c:a", "libgsm", "-f", "gsm",
       str(path("gsm", "harbour-bell.gsm")))
    subprocess.run(["sox", "-n", "-r", "8000", "-c", "1", str(path("dialogic_vox", "harbour-bell.vox")), "synth", "1", "sine", "440"],
                   check=True)

    # Shorten 2: header in Rice-coded words, the WAV header kept verbatim, then FN_QUIT.
    bits: list[int] = []

    def uvar(v: int, n: int) -> None:
        bits.extend([0] * (v >> n) + [1])
        bits.extend((v >> i) & 1 for i in range(n - 1, -1, -1))

    def ulong(v: int) -> None:
        n = max(v.bit_length(), 0)
        uvar(n, 2)
        uvar(v, n)

    wav = b"RIFF" + struct.pack("<L", 36 + 16000) + b"WAVEfmt " + struct.pack("<LHHLLHH", 16, 1, 1, 8000, 16000, 2, 16) + b"data" + struct.pack("<L", 16000)
    for v in (5, 1, 256, 0, 4, 0):  # s16le, mono, block 256, no LPC, 4 means, no skip
        ulong(v)
    uvar(9, 2)  # FN_VERBATIM
    uvar(len(wav), 5)
    for b in wav:
        uvar(b, 8)
    uvar(4, 2)  # FN_QUIT
    bits.extend([0] * (-len(bits) % 8))
    body = bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))
    out("shorten", "harbour-bell.shn", b"ajkg\x02" + body)

    # QCP (RFC 3625): QCELP-13K, fixed rate, five 35-byte packets.
    guid = bytes.fromhex("416d7f5e15b1d011ba9100805fb4b97e")
    name = b"Qcelp 13K".ljust(80, b"\0")
    fmt = struct.pack("<BB", 1, 0) + guid + struct.pack("<H", 1) + name + struct.pack("<HHHHH", 14000, 35, 160, 8000, 16) + struct.pack("<L", 0) + bytes(16) + bytes(20)
    data = bytes([4] + [0] * 34) * 5
    riff = b"QLCM" + b"fmt " + struct.pack("<L", len(fmt)) + fmt + b"data" + struct.pack("<L", len(data)) + data
    out("qcp", "harbour-bell.qcp", b"RIFF" + struct.pack("<L", len(riff)) + riff)

    # OpenMG: an "ea3" ID3v2 tag with a title, then the 96-byte EA3 header (ATRAC3, 44.1 kHz, 132 kbps).
    title = b"\x03" + "Harbour bell".encode()
    frame = b"TIT2" + struct.pack(">L", len(title)) + b"\0\0" + title
    size = len(frame)
    syncsafe = bytes([(size >> 21) & 0x7f, (size >> 14) & 0x7f, (size >> 7) & 0x7f, size & 0x7f])
    tag = b"ea3\x03\x00\x00" + syncsafe + frame
    params = (1 << 13) | 0x030  # 44.1 kHz, 48 * 8 = 384-byte frames (132 kbps)
    ea3 = b"EA3\x01" + struct.pack(">HH", 96, 0xFFFF) + bytes(24) + bytes([0]) + params.to_bytes(3, "big") + bytes(96 - 36)
    out("atrac", "harbour-bell.oma", tag + ea3 + bytes(384 * 8))

    # TwinVQ: header chunks, then DATA.
    def chunk(i: bytes, b: bytes) -> bytes:
        return i + struct.pack(">L", len(b)) + b
    chunks = chunk(b"COMM", struct.pack(">LLL", 0, 20, 22) + bytes(4)) + chunk(b"NAME", b"Harbour bell") + chunk(b"AUTH", b"Saltmere Harbour") + chunk(b"(c) ", b"CC0-1.0")
    out("vqf", "harbour-bell.vqf", b"TWIN" + b"97012000" + struct.pack(">L", len(chunks)) + chunks + b"DATA" + bytes(2500))

    # RealAudio 1.0 (v3, 14.4) and 2.0 (v4, 28.8) standalone files.
    s8 = lambda s: bytes([len(s)]) + s
    meta = s8(b"Harbour bell") + s8(b"Saltmere Harbour") + s8(b"CC0-1.0") + s8(b"")
    v3_body = bytes(8) + struct.pack(">H", 60000) + bytes(4) + meta + b"\x00" + s8(b"lpcJ")
    out("realaudio", "harbour-bell-14_4.ra", b".ra\xfd" + struct.pack(">HH", 3, len(v3_body)) + v3_body + bytes(20 * 50))
    v4 = (struct.pack(">H", 4) + bytes(2) + b".ra4" + struct.pack(">L", 9000) + struct.pack(">H", 4) + struct.pack(">L", 78)
          + struct.pack(">H", 2) + struct.pack(">L", 228) + bytes(4) + struct.pack(">L", 120_000) + bytes(4)
          + struct.pack(">HHHH", 12, 456, 228, 0) + struct.pack(">H", 8000) + bytes(2) + struct.pack(">H", 16)
          + struct.pack(">H", 1) + s8(b"Int4") + s8(b"28_8") + b"\x01\x00\x00" + meta)
    out("realaudio", "harbour-bell-28_8.ra", b".ra\xfd" + v4 + bytes(9000))
    out("ram", "harbour-bell.ram", b"rtsp://media.saltmere.example/harbour-bell.ra\npnm://media.saltmere.example/harbour-bell.rm\n")


# --- instruments ---------------------------------------------------------------------------


def riff_chunk(i: bytes, b: bytes) -> bytes:
    return i + struct.pack("<L", len(b)) + b + (b"\0" if len(b) % 2 else b"")


def riff_list(kind: bytes, b: bytes) -> bytes:
    return riff_chunk(b"LIST", kind + b)


def zstr(s: str, n: int = 0) -> bytes:
    b = s.encode() + b"\0"
    return b + (b"\0" if len(b) % 2 else b"") if not n else b.ljust(n, b"\0")[:n]


def step_instruments() -> None:
    # SoundFont 2: one bell sample, one instrument, two presets.
    smpl = b"".join(struct.pack("<h", int(8000 * ((i % 40) - 20) / 20)) for i in range(4000)) + bytes(92)
    info = (riff_chunk(b"ifil", struct.pack("<HH", 2, 4)) + riff_chunk(b"isng", zstr("EMU8000")) + riff_chunk(b"INAM", zstr("Saltmere Harbour Bells"))
            + riff_chunk(b"IENG", zstr("Saltmere Harbour")) + riff_chunk(b"ICOP", zstr("CC0-1.0")) + riff_chunk(b"ISFT", zstr("craft_av.py")))
    phdr = (zstr("Harbour Bell", 20) + struct.pack("<HHHLLL", 0, 0, 0, 0, 0, 0) + zstr("Fog Horn", 20) + struct.pack("<HHHLLL", 1, 0, 1, 0, 0, 0)
            + zstr("EOP", 20) + struct.pack("<HHHLLL", 0, 0, 2, 0, 0, 0))
    pbag = struct.pack("<HH", 0, 0) * 2 + struct.pack("<HH", 0, 0)
    inst = zstr("Bell", 20) + struct.pack("<H", 0) + zstr("EOI", 20) + struct.pack("<H", 1)
    shdr = (zstr("bell-a4", 20) + struct.pack("<LLLLLBbHH", 0, 4000, 100, 3900, 22050, 69, 0, 0, 1)
            + zstr("EOS", 20) + struct.pack("<LLLLLBbHH", 0, 0, 0, 0, 0, 0, 0, 0, 0))
    pdta = (riff_chunk(b"phdr", phdr) + riff_chunk(b"pbag", pbag) + riff_chunk(b"pmod", bytes(10)) + riff_chunk(b"pgen", bytes(4))
            + riff_chunk(b"inst", inst) + riff_chunk(b"ibag", bytes(8)) + riff_chunk(b"imod", bytes(10)) + riff_chunk(b"igen", bytes(4))
            + riff_chunk(b"shdr", shdr))
    body = b"sfbk" + riff_list(b"INFO", info) + riff_list(b"sdta", riff_chunk(b"smpl", smpl)) + riff_list(b"pdta", pdta)
    out("soundfont", "saltmere-bells.sf2", b"RIFF" + struct.pack("<L", len(body)) + body)

    # DLS level 1: two instruments, one wave each.
    def ins(name: str, program: int) -> bytes:
        return riff_list(b"ins ", riff_chunk(b"insh", struct.pack("<LLL", 1, 0, program)) + riff_list(b"lrgn", riff_list(b"rgn ", riff_chunk(b"rgnh", struct.pack("<HHHHHH", 0, 127, 0, 127, 0, 0))))
                         + riff_list(b"INFO", riff_chunk(b"INAM", zstr(name))))
    wave = riff_list(b"wave", riff_chunk(b"fmt ", struct.pack("<HHLLHH", 1, 1, 22050, 44100, 2, 16)) + riff_chunk(b"data", smpl[:2000]))
    body = (b"DLS " + riff_chunk(b"colh", struct.pack("<L", 2)) + riff_chunk(b"vers", struct.pack("<HHHH", 0, 1, 0, 0))
            + riff_list(b"lins", ins("Harbour Bell", 0) + ins("Fog Horn", 1)) + riff_chunk(b"ptbl", struct.pack("<LL", 8, 2) + struct.pack("<LL", 0, 0))
            + riff_list(b"wvpl", wave + wave) + riff_list(b"INFO", riff_chunk(b"INAM", zstr("Saltmere Harbour Bells")) + riff_chunk(b"ICOP", zstr("CC0-1.0"))))
    out("dls", "saltmere-bells.dls", b"RIFF" + struct.pack("<L", len(body)) + body)

    out("sfz", "harbour-bells.sfz", b"""// Saltmere harbour bells
<control> default_path=samples/
<global> ampeg_release=0.8
<group> lovel=0 hivel=127
<region> sample=bell high.wav lokey=c5 hikey=b5 pitch_keycenter=c5
<region> sample=bell low.wav lokey=c3 hikey=b4 pitch_keycenter=a3
<group> trigger=release
<region> sample=fog horn.wav key=36
""")

    # EXS24: header, one zone, one group, two samples (little-endian, 84-byte chunk heads).
    def exs_chunk(kind: int, name: str, body: bytes) -> bytes:
        return struct.pack("<LLLL", 0x00000101 | (kind << 24), len(body), 0, 0) + b"TBOS" + zstr(name, 64) + body
    exs = (exs_chunk(0, "Saltmere Bells", bytes(32)) + exs_chunk(1, "Bell zone", bytes(104)) + exs_chunk(2, "Bells", bytes(80))
           + exs_chunk(3, "bell high.wav", bytes(336)) + exs_chunk(3, "bell low.wav", bytes(336)))
    out("exs", "Saltmere Bells.exs", exs)


# --- projects ------------------------------------------------------------------------------


def step_projects() -> None:
    out("audacity", "saltmere-tides.aup", b"""<?xml version="1.0" standalone="no" ?>
<!DOCTYPE project PUBLIC "-//audacityproject-1.3.0//DTD//EN" "http://audacity.sourceforge.net/xml/audacityproject-1.3.0.dtd" >
<project xmlns="http://audacity.sourceforge.net/xml/" projname="saltmere-tides_data" version="1.3.0" audacityversion="2.4.2" sel0="0.0" sel1="0.0" vpos="0" h="0.0" zoom="86.1328125" rate="44100.0" snapto="off" selectionformat="hh:mm:ss + milliseconds">
\t<tags>
\t\t<tag name="TITLE" value="Saltmere tides"/>
\t\t<tag name="ARTIST" value="Saltmere Harbour"/>
\t</tags>
\t<wavetrack name="Bell" channel="2" linked="0" mute="0" solo="0" height="150" minimized="0" isSelected="1" rate="44100" gain="1.0" pan="0.0">
\t\t<waveclip offset="0.00000000">
\t\t\t<sequence maxsamples="262144" sampleformat="262159" numsamples="441000"/>
\t\t</waveclip>
\t\t<waveclip offset="12.00000000">
\t\t\t<sequence maxsamples="262144" sampleformat="262159" numsamples="88200"/>
\t\t</waveclip>
\t</wavetrack>
\t<wavetrack name="Gulls" channel="2" linked="0" rate="44100">
\t\t<waveclip offset="0.00000000">
\t\t\t<sequence maxsamples="262144" sampleformat="262159" numsamples="220500"/>
\t\t</waveclip>
\t</wavetrack>
\t<labeltrack name="Label Track" numlabels="2" height="73" minimized="0" isSelected="1">
\t\t<label t="1.00000000" t1="1.00000000" title="High water"/>
\t\t<label t="6.50000000" t1="7.00000000" title="Bell"/>
\t</labeltrack>
</project>
""")
    als = """<?xml version="1.0" encoding="UTF-8"?>
<Ableton MajorVersion="5" MinorVersion="11.0_433" SchemaChangeCount="3" Creator="Ableton Live 11.3.4" Revision="0000000000000000000000000000000000000000">
\t<LiveSet>
\t\t<Tracks>
\t\t\t<AudioTrack Id="8">
\t\t\t\t<Name><EffectiveName Value="Harbour bell" /><UserName Value="Harbour bell" /></Name>
\t\t\t\t<DeviceChain><MainSequencer><ClipSlotList><ClipSlot><ClipSlot><Value><AudioClip Id="0" Time="0">
\t\t\t\t\t<SampleRef><FileRef><RelativePath Value="Samples/Imported/bell.wav" /><Path Value="/Users/harbourmaster/Music/Saltmere/Samples/Imported/bell.wav" /></FileRef></SampleRef>
\t\t\t\t</AudioClip></Value></ClipSlot></ClipSlot></ClipSlotList></MainSequencer>
\t\t\t\t<DeviceChain><Devices><Reverb Id="0" /><Eq8 Id="1" /><PluginDevice Id="2"><PluginDesc><Vst3PluginInfo Id="0"><Name Value="Harbour Delay" /></Vst3PluginInfo></PluginDesc></PluginDevice></Devices></DeviceChain>
\t\t\t\t</DeviceChain>
\t\t\t</AudioTrack>
\t\t\t<MidiTrack Id="9">
\t\t\t\t<Name><EffectiveName Value="Fog horn" /></Name>
\t\t\t\t<DeviceChain><MainSequencer><ClipSlotList><ClipSlot><ClipSlot><Value><MidiClip Id="0" Time="0" /></Value></ClipSlot></ClipSlot></ClipSlotList></MainSequencer>
\t\t\t\t<DeviceChain><Devices><OriginalSimpler Id="0" /></Devices></DeviceChain></DeviceChain>
\t\t\t</MidiTrack>
\t\t\t<ReturnTrack Id="2"><Name><EffectiveName Value="A-Reverb" /></Name></ReturnTrack>
\t\t</Tracks>
\t\t<MasterTrack>
\t\t\t<DeviceChain><Mixer><Tempo><LomId Value="0" /><Manual Value="96" /></Tempo>
\t\t\t<TimeSignature><TimeSignatures><RemoteableTimeSignature Id="0"><Numerator Value="6" /><Denominator Value="8" /><Time Value="0" /></RemoteableTimeSignature></TimeSignatures></TimeSignature>
\t\t\t</Mixer></DeviceChain>
\t\t</MasterTrack>
\t\t<Scenes><Scene Id="0" /><Scene Id="1" /></Scenes>
\t</LiveSet>
</Ableton>
"""
    out("ableton", "Saltmere Tides.als", gzip.compress(als.encode(), mtime=0))

    # FL Studio: FLhd (format, channels, PPQ), then FLdt events.
    def ev(i: int, v) -> bytes:
        if i < 64:
            return bytes([i, v])
        if i < 128:
            return bytes([i]) + struct.pack("<H", v)
        if i < 192:
            return bytes([i]) + struct.pack("<L", v)
        n, size = len(v), b""
        while True:
            b = n & 0x7f
            n >>= 7
            size += bytes([b | (0x80 if n else 0)])
            if not n:
                break
        return bytes([i]) + size + v
    u16 = lambda s: (s + "\0").encode("utf-16-le")
    events = (ev(199, b"20.8.4.2576\0") + ev(159, 2576) + ev(156, 96000) + ev(194, u16("Saltmere Tides")) + ev(207, u16("Saltmere Harbour"))
              + ev(206, u16("Ambient")) + ev(200, u16("Harbourmaster")) + ev(65, 1) + ev(65, 2) + ev(64, 0) + ev(201, u16("Sampler"))
              + ev(196, u16("C:\\Users\\Harbourmaster\\Documents\\Samples\\bell.wav")) + ev(64, 1) + ev(201, u16("FLEX")) + ev(203, u16("Fog horn")))
    flp = b"FLhd" + struct.pack("<LhHH", 6, 0, 2, 96) + b"FLdt" + struct.pack("<L", len(events)) + events
    # No extension: `.flp` is also a floppy image (forensics builds), which
    # would change the candidates between builds.
    out("fl_studio", "saltmere-tides-flp", flp)

    out("reaper", "Saltmere Tides.rpp", b"""<REAPER_PROJECT 0.1 "7.07/linux-x86_64" 1756728000
  RIPPLE 0
  TEMPO 96 6 8
  SAMPLERATE 48000 0 0
  MARKER 1 0 "High water" 0 0 1
  MARKER 2 12 "Low water" 0 0 1
  <TRACK {00000000-0000-0000-0000-000000000001}
    NAME "Harbour bell"
    <FXCHAIN
      <VST "VST3: ReaEQ (Cockos)" reaeq.vst3 0 "" 0<00000000> ""
      >
      <JS "utility/volume" ""
      >
    >
    <ITEM
      POSITION 0
      LENGTH 10
      NAME bell.wav
      <SOURCE WAVE
        FILE "/home/harbourmaster/Saltmere/bell.wav"
      >
    >
  >
  <TRACK {00000000-0000-0000-0000-000000000002}
    NAME Gulls
    <ITEM
      POSITION 4.5
      LENGTH 12
      <SOURCE WAVE
        FILE "gulls.wav"
      >
    >
  >
>
""")


# --- broadcast, game and camera video -------------------------------------------------------


def step_video() -> None:
    meta = ["-metadata", "creation_time=2025-09-01T12:00:00Z"]
    ff("-f", "lavfi", "-i", "testsrc=size=720x576:rate=25:duration=0.04", "-f", "lavfi", "-i", "sine=frequency=440:duration=0.04:sample_rate=48000",
       "-target", "pal-dv", *meta, str(path("dv", "harbour-pal.dv")))
    ff("-f", "lavfi", "-i", "testsrc=size=320x240:rate=25:duration=0.4", "-f", "lavfi", "-i", "sine=frequency=440:duration=0.4:sample_rate=48000",
       "-c:v", "mpeg2video", "-b:v", "500k", "-c:a", "pcm_s16le", "-timecode", "10:00:00:00", *meta, "-flags", "+bitexact",
       str(path("mxf", "harbour-op1a.mxf")))
    ff("-f", "lavfi", "-i", "testsrc=size=160x128:rate=15:duration=1", "-f", "lavfi", "-i", "sine=frequency=440:duration=1:sample_rate=22050",
       "-c:v", "amv", "-c:a", "adpcm_ima_amv", "-ac", "1", "-block_size", "1470", "-strict", "-1", "-pix_fmt", "yuvj420p",
       str(path("amv", "harbour-bell.amv")))

    # FLC: header, then two frames each holding one BLACK chunk.
    def flc_frame() -> bytes:
        black = struct.pack("<LH", 6, 13)
        return struct.pack("<LHH", 16 + len(black), 0xF1FA, 1) + bytes(8) + black
    frames = flc_frame() + flc_frame()
    dos = ((2025 - 1980) << 25) | (9 << 21) | (1 << 16) | (12 << 11)
    hdr = struct.pack("<LHHHHHHL", 128 + len(frames), 0xAF12, 2, 320, 200, 8, 3, 100) + struct.pack("<HLLLL", 0, dos, 0x45444153, dos, 0x45444153)
    hdr += struct.pack("<HH", 1, 1) + bytes(38) + struct.pack("<LL", 128, 128 + len(flc_frame())) + bytes(40)
    out("flic", "harbour-gulls.flc", hdr + frames)

    # Bink 1 (rev. i): header, one stereo DCT audio track, a frame index of two frames.
    bik = b"BIKi" + struct.pack("<LLLLLLLLLL", 0, 2, 64, 2, 320, 240, 25, 1, 0, 1) + struct.pack("<L", 4096) + struct.pack("<HH", 44100, 0x3000) + struct.pack("<L", 0)
    index_at = len(bik)
    bik += struct.pack("<LLL", index_at + 12 + 1, index_at + 12 + 33, index_at + 12 + 65) + bytes(64)
    bik = bik[:4] + struct.pack("<L", len(bik) - 8) + bik[8:]
    out("bink", "harbour-intro.bik", bik)

    # Smacker 4: 320x200, 10 frames at 15 fps (66.666 ms → -6667 in 1e-5 s), one 22 kHz mono 8-bit track.
    smk = b"SMK4" + struct.pack("<LLLlL", 320, 200, 10, -6667, 0) + struct.pack("<7L", 4096, 0, 0, 0, 0, 0, 0) + struct.pack("<L", 64) + struct.pack("<4L", 16, 16, 16, 16)
    smk += struct.pack("<L", 22050 | (0x40 << 24)) + bytes(24) + struct.pack("<L", 0)
    out("smacker", "harbour-intro.smk", smk + bytes(10 * 4) + bytes(10) + bytes(64))

    # NSV: file header with metadata, then one sync frame (VP62 video, MP3 audio, 25 fps).
    meta_s = b'Title="Saltmere harbour cam" URL="https://cam.saltmere.example/"\0'
    nsvf = b"NSVf" + struct.pack("<LLLLLL", 28 + len(meta_s), 0, 10_000, len(meta_s), 0, 0) + meta_s
    nsvs = b"NSVs" + b"VP62" + b"MP3 " + struct.pack("<HHBH", 320, 240, 25, 0) + bytes(5)
    out("nsv", "harbour-cam.nsv", nsvf + nsvs + bytes(64))

    out("r3d", "A001_C001_0901AB_001.R3D", struct.pack(">L", 512) + b"RED1" + bytes(504))
    ari = b"ARRI" + b"\x12\x34\x56\x78" + struct.pack("<LLLLL", 4096, 3, 0, 2880, 1620) + bytes(4096 - 28)
    out("arriraw", "A001C001_250901_R1AB.0000001.ari", ari)


# --- edit lists, timelines, casts -------------------------------------------------------------


def step_edit() -> None:
    out("edl", "saltmere-ferry.edl", b"""TITLE: SALTMERE FERRY
FCM: NON-DROP FRAME

001  A001C001 V     C        10:00:00:00 10:00:05:00 01:00:00:00 01:00:05:00
* FROM CLIP NAME: quay-wide.mov
002  A001C002 V     D    025 10:00:10:00 10:00:14:00 01:00:05:00 01:00:09:00
* FROM CLIP NAME: ferry-arrives.mov
003  AX       AA    C        00:00:00:00 00:00:09:00 01:00:00:00 01:00:09:00
* FROM CLIP NAME: harbour-bell.wav
""")
    import opentimelineio as otio
    tl = otio.schema.Timeline(name="Saltmere ferry")
    video, audio = otio.schema.Track(name="V1", kind=otio.schema.TrackKind.Video), otio.schema.Track(name="A1", kind=otio.schema.TrackKind.Audio)
    rng = lambda s, d: otio.opentime.TimeRange(otio.opentime.RationalTime(s, 25), otio.opentime.RationalTime(d, 25))
    for name, url, dur in (("quay-wide", "/media/saltmere/quay-wide.mov", 125), ("ferry-arrives", "/media/saltmere/ferry-arrives.mov", 100)):
        c = otio.schema.Clip(name=name, media_reference=otio.schema.ExternalReference(target_url=url), source_range=rng(0, dur))
        video.append(c)
    video[0].markers.append(otio.schema.Marker(name="Bell", marked_range=rng(25, 0)))
    video.append(otio.schema.Gap(source_range=rng(0, 25)))
    audio.append(otio.schema.Clip(name="harbour-bell", media_reference=otio.schema.ExternalReference(target_url="/media/saltmere/harbour-bell.wav"), source_range=rng(0, 225)))
    tl.tracks.append(video)
    tl.tracks.append(audio)
    otio.adapters.write_to_file(tl, str(path("otio", "saltmere-ferry.otio")))

    out("fcpxml", "saltmere-ferry.fcpxml", b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE fcpxml>
<fcpxml version="1.10">
    <resources>
        <format id="r1" name="FFVideoFormat1080p25" frameDuration="100/2500s" width="1920" height="1080" colorSpace="1-1-1 (Rec. 709)"/>
        <asset id="r2" name="quay-wide" start="0s" duration="10s" hasVideo="1" format="r1" hasAudio="1" audioSources="1" audioChannels="2" audioRate="48000">
            <media-rep kind="original-media" src="file:///Users/harbourmaster/Movies/Saltmere/quay-wide.mov"/>
        </asset>
        <asset id="r3" name="ferry-arrives" start="0s" duration="8s" hasVideo="1" format="r1">
            <media-rep kind="original-media" src="file:///Users/harbourmaster/Movies/Saltmere/ferry-arrives.mov"/>
        </asset>
    </resources>
    <library>
        <event name="Saltmere 2025-09-01">
            <project name="Saltmere ferry">
                <sequence format="r1" duration="225/25s" tcStart="0s" tcFormat="NDF" audioLayout="stereo" audioRate="48k">
                    <spine>
                        <asset-clip ref="r2" offset="0s" name="quay-wide" duration="5s" format="r1" tcFormat="NDF"/>
                        <gap name="Gap" offset="5s" duration="1s"/>
                        <asset-clip ref="r3" offset="6s" name="ferry-arrives" duration="3s" format="r1" tcFormat="NDF"/>
                    </spine>
                </sequence>
            </project>
        </event>
    </library>
</fcpxml>
""")
    out("mlt", "saltmere-ferry.kdenlive", b"""<?xml version='1.0' encoding='utf-8'?>
<mlt LC_NUMERIC="C" producer="main_bin" version="7.22.0" root="/home/harbourmaster/Videos/Saltmere">
 <profile frame_rate_num="25" sample_aspect_num="1" display_aspect_den="9" colorspace="709" progressive="1" description="HD 1080p 25 fps" display_aspect_num="16" frame_rate_den="1" width="1920" height="1080" sample_aspect_den="1"/>
 <producer id="producer0" in="00:00:00.000" out="00:00:09.960">
  <property name="resource">/home/harbourmaster/Videos/Saltmere/quay-wide.mov</property>
  <property name="mlt_service">avformat-novalidate</property>
  <property name="kdenlive:clipname">quay-wide</property>
 </producer>
 <producer id="producer1" in="00:00:00.000" out="00:00:07.960">
  <property name="resource">ferry-arrives.mov</property>
  <property name="mlt_service">avformat-novalidate</property>
 </producer>
 <playlist id="main_bin">
  <property name="kdenlive:docproperties.version">1.1</property>
  <property name="kdenlive:docproperties.kdenliveversion">24.08.1</property>
  <entry producer="producer0" in="00:00:00.000" out="00:00:09.960"/>
  <entry producer="producer1" in="00:00:00.000" out="00:00:07.960"/>
 </playlist>
 <playlist id="playlist0">
  <entry producer="producer0" in="00:00:00.000" out="00:00:04.960"/>
  <entry producer="producer1" in="00:00:00.000" out="00:00:02.960"/>
 </playlist>
 <tractor id="tractor0" in="00:00:00.000" out="00:00:07.960">
  <track producer="playlist0"/>
 </tractor>
</mlt>
""")
    prproj = """<?xml version="1.0" encoding="UTF-8" ?>
<PremiereData Version="3">
\t<Project ObjectRef="1"/>
\t<Project ObjectID="1" ClassID="62ad66dd-0dcd-42da-a660-6d8fbde94876" Version="42">
\t\t<Node Version="1"><Properties Version="1"><Name>Saltmere ferry</Name></Properties></Node>
\t</Project>
\t<BinProjectItem ObjectUID="00000000-0000-0000-0000-00000000b001" ClassID="dbf8ee65-0c0f-4d3c-9b6b-6b2b3e5a3c81" Version="3"><ProjectItem Version="1"><Name>Footage</Name></ProjectItem></BinProjectItem>
\t<ClipProjectItem ObjectUID="00000000-0000-0000-0000-00000000c001" ClassID="cb4e0ed7-aca1-4d9e-80b5-1d1a3f5c4a6d" Version="1"><ProjectItem Version="1"><Name>quay-wide.mov</Name></ProjectItem></ClipProjectItem>
\t<ClipProjectItem ObjectUID="00000000-0000-0000-0000-00000000c002" ClassID="cb4e0ed7-aca1-4d9e-80b5-1d1a3f5c4a6d" Version="1"><ProjectItem Version="1"><Name>ferry-arrives.mov</Name></ProjectItem></ClipProjectItem>
\t<Media ObjectUID="00000000-0000-0000-0000-00000000d001" ClassID="7a5c103e-f3ac-4391-b6b4-7cc3d2f9a7ff" Version="30"><FilePath>C:\\\\Users\\\\Harbourmaster\\\\Videos\\\\quay-wide.mov</FilePath></Media>
\t<Media ObjectUID="00000000-0000-0000-0000-00000000d002" ClassID="7a5c103e-f3ac-4391-b6b4-7cc3d2f9a7ff" Version="30"><FilePath>C:\\\\Users\\\\Harbourmaster\\\\Videos\\\\ferry-arrives.mov</FilePath></Media>
\t<Sequence ObjectUID="00000000-0000-0000-0000-00000000e001" ClassID="6a15d903-8739-11d5-af2d-9b7855ad8974" Version="11"><Name>Saltmere ferry</Name></Sequence>
\t<VideoTrack ObjectID="20" ClassID="f68dcd28-5d9c-4bd8-9e39-a1b9d36b4e3e" Version="3"/>
\t<AudioTrack ObjectID="21" ClassID="8f9a6b74-7b0b-4f5b-9c7a-0a8c4e8b5b2d" Version="3"/>
</PremiereData>
"""
    out("premiere", "Saltmere Ferry.prproj", gzip.compress(prproj.encode(), mtime=0))

    import aaf2
    with aaf2.open(str(path("aaf", "saltmere-ferry.aaf")), "w") as f:
        comp = f.create.CompositionMob()
        comp.name = "Saltmere ferry"
        f.content.mobs.append(comp)
        for name in ("quay-wide", "ferry-arrives"):
            master = f.create.MasterMob(name)
            f.content.mobs.append(master)

    head2 = {"version": 2, "width": 100, "height": 30, "timestamp": 1756728000, "title": "Saltmere tide table",
             "command": "tides --harbour saltmere", "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"}}
    ev2 = [[0.5, "o", "$ tides --harbour saltmere\r\n"], [1.2, "o", "High water 06:12\r\n"], [1.4, "o", "Low water 12:31\r\n"],
           [2.0, "m", "done"], [3.25, "o", "$ exit\r\n"]]
    out("asciicast", "saltmere-tides.cast", ("\n".join(json.dumps(x) for x in [head2, *ev2]) + "\n").encode())
    head3 = {"version": 3, "term": {"cols": 80, "rows": 24, "type": "xterm-256color"}, "timestamp": 1756728000, "title": "Saltmere bell"}
    ev3 = [[0.25, "o", "ring\r\n"], [1.0, "i", "q"], [0.5, "r", "100x30"], [0.75, "x", "0"]]
    out("asciicast", "saltmere-bell.v3.cast", ("\n".join(json.dumps(x) for x in [head3, *ev3]) + "\n").encode())


STEPS = {"raw": step_raw, "instruments": step_instruments, "projects": step_projects, "video": step_video, "edit": step_edit}

if __name__ == "__main__":
    for name in sys.argv[2:] or list(STEPS):
        STEPS[name]()
