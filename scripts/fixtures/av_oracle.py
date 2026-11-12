#!/usr/bin/env python3
"""Batch 5d oracle: what independent tools say about the audio / video
fixtures, checked against whiff's reports.

    podman run --rm -v "$PWD:/whiff" -w /whiff whiff-av python3 scripts/fixtures/av_oracle.py expect tests/fixtures > target/av-expect.json
    python3 scripts/fixtures/av_oracle.py check target/av-expect.json

Tools: ffprobe (streams), sf2utils (SoundFont),
OpenTimelineIO (.otio) and libmagic (`file`). The helpers and the check
come from legacy_oracle.py.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import legacy_oracle as lo  # noqa: E402

want, libmagic = lo.want, lo.libmagic

# Codec names whiff shares with ffprobe.
SAME = {"ac3", "eac3", "dts", "truehd", "mlp", "gsm", "shorten", "qcelp", "atrac3", "twinvq", "ra_144", "ra_288", "dvvideo",
        "pcm_s16le", "pcm_u8", "mpeg2video", "amv", "adpcm_ima_amv", "flic", "binkvideo", "binkaudio_dct", "smackvideo", "vp6"}


def probe(f):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_streams", "-show_format", "-of", "json", str(f)], capture_output=True, text=True)
    try:
        return json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return summary(f)


def summary(f):
    """Streams from ffprobe's text summary, for files whose codecs cannot
    be opened (the JSON writer stops there)."""
    import re
    text = subprocess.run(["ffprobe", "-hide_banner", str(f)], capture_output=True, text=True).stderr
    out = []
    for m in re.finditer(r"Stream #\d+:\d+.*?: (Video|Audio): (\w+)([^\n]*)", text):
        kind, codec, rest = m.group(1).lower(), m.group(2), m.group(3)
        s = {"codec_type": kind, "codec_name": codec}
        if kind == "video" and (size := re.search(r", (\d+)x(\d+)", rest)):
            s["width"], s["height"] = int(size.group(1)), int(size.group(2))
        if kind == "audio" and (hz := re.search(r"(\d+) Hz, (mono|stereo)", rest)):
            s["sample_rate"], s["channels"] = hz.group(1), 1 if hz.group(2) == "mono" else 2
        out.append(s)
    return {"streams": out}


def streams(fx, folder, pattern, *, video=True, audio=True):
    for f in sorted((fx / folder).glob(pattern)):
        p = probe(f)
        for i, s in enumerate(p.get("streams", [])):
            kind = s.get("codec_type")
            if (kind == "video" and not video) or (kind == "audio" and not audio):
                continue
            base = f"physical.media.streams.{i}"
            if s.get("codec_name") in SAME:
                want(f, f"{base}.codec", s["codec_name"], "ffprobe")
            if kind == "audio":
                want(f, f"{base}.sample_rate_hz", int(s["sample_rate"]) if s.get("sample_rate") else None, "ffprobe")
                want(f, f"{base}.channels", s.get("channels"), "ffprobe")
            if kind == "video":
                want(f, f"{base}.width", s.get("width"), "ffprobe")
                want(f, f"{base}.height", s.get("height"), "ffprobe")


def expect(root):
    fx = Path(root)
    for folder, pattern in (("ac3", "*.ac3"), ("eac3", "*.eac3"), ("dts_audio", "*.dts"), ("truehd", "*.thd"), ("truehd", "*.mlp"),
                            ("shorten", "*.shn"), ("qcp", "*.qcp"), ("atrac", "*.oma"), ("vqf", "*.vqf"), ("realaudio", "*.ra"),
                            ("dv", "*.dv"), ("mxf", "*.mxf"), ("amv", "*.amv"), ("flic", "*.flc"), ("bink", "*.bik"),
                            ("smacker", "*.smk"), ("nsv", "*.nsv")):
        streams(fx, folder, pattern)
    for f in sorted((fx / "gsm").glob("*.gsm")):
        p = probe(f)
        want(f, "physical.media.streams.0.codec", p["streams"][0]["codec_name"], "ffprobe")
    for f in sorted((fx / "mxf").glob("*.mxf")):
        tags = probe(f).get("format", {}).get("tags", {})
        want(f, "format.mxf.operational_pattern", "OP1a" if "OP1a" in tags.get("operational_pattern_ul", "OP1a") else None, "ffprobe")
        want(f, "format.mxf.identification.company", tags.get("company_name"), "ffprobe")
        want(f, "format.mxf.identification.product", tags.get("product_name"), "ffprobe")
        want(f, "format.mxf.start_timecode", tags.get("timecode"), "ffprobe")
    for f, needle in (("ac3/harbour-bell.ac3", "AC-3"), ("vqf/harbour-bell.vqf", "VQF"), ("realaudio/harbour-bell-14_4.ra", "RealAudio"),
                      ("soundfont/saltmere-bells.sf2", "SoundFont"), ("flic/harbour-gulls.flc", "FLC animation"),
                      ("bink/harbour-intro.bik", "Bink Video"), ("r3d/A001_C001_0901AB_001.R3D", "REDCode"),
                      ("arriraw/A001C001_250901_R1AB.0000001.ari", "ARRI ARI image data, little-endian, version 3, 2880x1620")):
        libmagic(fx, f, needle)

    from sf2utils.sf2parse import Sf2File
    for f in sorted((fx / "soundfont").glob("*.sf2")):
        with open(f, "rb") as h:
            sf = Sf2File(h)
            want(f, "format.soundfont.presets", len([p for p in sf.presets if p.name != "EOP"]), "sf2utils")
            want(f, "format.soundfont.samples", len([s for s in sf.samples if s.name != "EOS"]), "sf2utils")
            want(f, "format.soundfont.bank_name", sf.info.bank_name, "sf2utils")

    import opentimelineio as otio
    for f in sorted((fx / "otio").glob("*.otio")):
        tl = otio.adapters.read_from_file(str(f))
        want(f, "format.otio.name", tl.name, "opentimelineio")
        want(f, "physical.media.duration_s", round(tl.duration().to_seconds(), 6), "opentimelineio")
        want(f, "format.otio.markers", sum(len(c.markers) for c in tl.find_clips()), "opentimelineio")

    print(json.dumps(lo.EXPECT, indent=1))


if __name__ == "__main__":
    if sys.argv[1] == "expect":
        expect(sys.argv[2])
    else:
        lo.check(sys.argv[2], *sys.argv[3:])
