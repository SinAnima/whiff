//! Raw and lightly wrapped audio streams:
//!
//! * AC-3 and E-AC-3 (Dolby Digital / Plus) sync frames: sample rate,
//!   channel layout, LFE, bitrate, frames walked for the duration;
//! * DTS Coherent Acoustics core frames (big- or little-endian words);
//! * Dolby TrueHD and Meridian MLP access units with their major sync;
//! * GSM 06.10 full-rate frames, and headerless Dialogic / OKI ADPCM (`.vox`,
//!   assumed 8 kHz);
//! * Shorten (`ajkg`): version, channels, block size and the WAV header it
//!   keeps verbatim;
//! * QCP (Qualcomm PureVoice: QCELP, EVRC, SMV), Sony OpenMG ATRAC (`.oma`,
//!   `.aa3`) and TwinVQ (`.vqf`) headers, with their titles and authors.
//!
//! Specifications: ATSC A/52:2018 (AC-3 §5.4, E-AC-3 annex E); ETSI TS 102
//! 114 (DTS); the Dolby TrueHD / MLP major-sync layout (as FFmpeg reads
//! it); ETSI EN 300 961 (GSM 06.10); the Shorten 2/3 bitstream; RFC 3625
//! (QCP); the OMA EA3 header; the TwinVQ VQF header.

use super::{Stream, Tags};
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
};

/// Extractor for raw and lightly wrapped audio streams.
pub struct RawAudio;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec { id: $id, name: $name, family: "audio", mimes: &[$mime], extensions: &[$($ext),*], magic: &[$($magic),*], parent: None }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.raw",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("ac3", "AC-3 (Dolby Digital)", "audio/ac3", ["ac3", "a52"], [Magic::prefix(b"\x0b\x77")]),
        spec!("eac3", "E-AC-3 (Dolby Digital Plus)", "audio/eac3", ["ec3", "eac3"], []),
        spec!(
            "dts_audio",
            "DTS audio",
            "audio/vnd.dts",
            ["dtshd", "cpt"],
            [Magic::prefix(b"\x7f\xfe\x80\x01"), Magic::prefix(b"\xfe\x7f\x01\x80")]
        ),
        spec!("truehd", "Dolby TrueHD / MLP", "audio/vnd.dolby.mlp", ["thd", "mlp", "truehd"], []),
        spec!("gsm", "GSM 06.10 audio", "audio/x-gsm", ["gsm"], []),
        spec!("dialogic_vox", "Dialogic ADPCM (VOX)", "audio/x-vox", ["vox"], []),
        spec!("shorten", "Shorten", "audio/x-shorten", ["shn"], [Magic::prefix(b"ajkg")]),
        spec!(
            "qcp",
            "QCP (Qualcomm PureVoice)",
            "audio/qcelp",
            ["qcp"],
            [Magic::masked(0, b"RIFF\0\0\0\0QLCM", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff")]
        ),
        spec!("atrac", "Sony OpenMG ATRAC", "audio/x-oma", ["oma", "omg", "aa3"], []),
        spec!("vqf", "TwinVQ", "audio/x-twinvq", ["vqf", "vql"], [Magic::prefix(b"TWIN")]),
    ],
};

/// Frames walked at most.
const MAX_FRAMES: u64 = 2_000_000;

impl Extractor for RawAudio {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let pick = |format: &'static str, confidence: f64| Some(Sniff { format, confidence });
        let ext = probe.extension.unwrap_or("").to_ascii_lowercase();
        if h.starts_with(b"\x0b\x77") && h.len() > 6 {
            let bsid = h[5] >> 3;
            let next = ac3_frame(h).map(|f| f.bytes);
            // A second sync word where the first frame ends.
            let chained = next.is_some_and(|n| h.get(n..n + 2).is_none_or(|s| s == b"\x0b\x77"));
            if chained {
                return pick(if bsid > 10 { "eac3" } else { "ac3" }, 0.9);
            }
        }
        if (h.starts_with(b"\x7f\xfe\x80\x01") || h.starts_with(b"\xfe\x7f\x01\x80")) && dts_frame(h).is_some() {
            return pick("dts_audio", 0.9);
        }
        if h.len() >= 12 && (&h[4..8] == b"\xf8\x72\x6f\xba" || &h[4..8] == b"\xf8\x72\x6f\xbb") {
            return pick("truehd", 0.95);
        }
        if h.starts_with(b"ea3") || (h.starts_with(b"EA3") && h.get(4..6) == Some(&[0, 0x60])) {
            return pick("atrac", 0.9);
        }
        // GSM: 33-byte frames, each starting with the 0xD signature nibble.
        if ext == "gsm" && h.len() >= 66 && h.as_chunks::<33>().0.iter().take(8).all(|f| f[0] >> 4 == 0xd) {
            return pick("gsm", 0.85);
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        match cx.format_id() {
            "ac3" | "eac3" => {
                let (b, _) = cx.read_bytes(src)?;
                dolby(cx, &b, len);
            }
            "dts_audio" => {
                let (b, _) = cx.read_bytes(src)?;
                dts(cx, &b, len);
            }
            "truehd" => {
                let (b, _) = cx.read_bytes(src)?;
                truehd(cx, &b, len);
            }
            "gsm" => {
                let mut s = Stream::new("gsm");
                s.sample_rate_hz = Some(8000);
                s.channels = Some(1);
                s.bitrate_bps = Some(13_200);
                s.samples = Some(len / 33 * 160);
                cx.format_set("frames", len / 33);
                s.report(cx, None, len);
            }
            "dialogic_vox" => {
                // Headerless: 4-bit samples; 8 kHz is the common rate.
                let mut s = Stream::new("adpcm_ima_oki");
                s.sample_rate_hz = Some(8000);
                s.channels = Some(1);
                s.bits_per_sample = Some(4);
                s.bitrate_bps = Some(32_000);
                s.samples = Some(len * 2);
                cx.format_set("assumed_sample_rate", true);
                s.report(cx, None, len);
            }
            "shorten" => {
                let b = src.read_vec(0, usize::try_from(len.min(65_536)).unwrap_or(0))?;
                shorten(cx, &b, len);
            }
            "qcp" => {
                let b = src.read_vec(0, usize::try_from(len.min(65_536)).unwrap_or(0))?;
                qcp(cx, &b, len);
            }
            "atrac" => {
                let b = src.read_vec(0, usize::try_from(len.min(65_536)).unwrap_or(0))?;
                oma(cx, &b, len);
            }
            _ => {
                let b = src.read_vec(0, usize::try_from(len.min(65_536)).unwrap_or(0))?;
                vqf(cx, &b, len)?;
            }
        }
        Ok(())
    }
}

crate::register_extractor!(RawAudio);

/// An MSB-first bit reader.
struct Bits<'a> {
    b: &'a [u8],
    at: usize,
}

impl Bits<'_> {
    fn get(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = *self.b.get(self.at / 8)?;
            v = (v << 1) | u32::from((byte >> (7 - self.at % 8)) & 1);
            self.at += 1;
        }
        Some(v)
    }
}

// --- AC-3 / E-AC-3 -----------------------------------------------------------------------

struct DolbyFrame {
    eac3: bool,
    /// Independent frame of substream 0 (counts towards the duration).
    primary: bool,
    rate: u32,
    acmod: u32,
    lfe: bool,
    bytes: usize,
    samples: u32,
    bsmod: Option<u32>,
}

const AC3_KBPS: [u32; 19] = [32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640];
const ACMOD: [(&str, u16); 8] =
    [("1+1", 2), ("mono", 1), ("stereo", 2), ("3/0", 3), ("2/1", 3), ("3/1", 4), ("2/2", 4), ("3/2", 5)];

fn ac3_frame(h: &[u8]) -> Option<DolbyFrame> {
    if !h.starts_with(b"\x0b\x77") || h.len() < 8 {
        return None;
    }
    let bsid = h[5] >> 3;
    let mut r = Bits { b: h, at: 16 };
    if bsid <= 10 {
        r.get(16)?; // crc1
        let fscod = r.get(2)?;
        let frmsizecod = r.get(6)? as usize;
        r.get(5)?; // bsid
        let bsmod = r.get(3)?;
        let acmod = r.get(3)?;
        if acmod & 1 == 1 && acmod != 1 {
            r.get(2)?;
        }
        if acmod & 4 != 0 {
            r.get(2)?;
        }
        if acmod == 2 {
            r.get(2)?;
        }
        let lfe = r.get(1)? == 1;
        let kbps = *AC3_KBPS.get(frmsizecod >> 1)?;
        // 16-bit words per frame: 1536 samples at the frame's bitrate.
        let (rate, words) = match fscod {
            0 => (48_000, kbps * 2),
            1 => (44_100, kbps * 1000 * 1536 / 44_100 / 16 + u32::from(frmsizecod & 1 == 1)),
            2 => (32_000, kbps * 3),
            _ => return None,
        };
        return Some(DolbyFrame {
            eac3: false,
            primary: true,
            rate,
            acmod,
            lfe,
            bytes: words as usize * 2,
            samples: 1536,
            bsmod: Some(bsmod),
        });
    }
    if bsid > 16 {
        return None;
    }
    let strmtyp = r.get(2)?;
    let substream = r.get(3)?;
    let frmsiz = r.get(11)?;
    let fscod = r.get(2)?;
    let (rate, blocks) = if fscod == 3 {
        let fscod2 = r.get(2)?;
        ([24_000, 22_050, 16_000].get(fscod2 as usize).copied()?, 6)
    } else {
        ([48_000, 44_100, 32_000][fscod as usize], [1, 2, 3, 6][r.get(2)? as usize])
    };
    let acmod = r.get(3)?;
    let lfe = r.get(1)? == 1;
    Some(DolbyFrame {
        eac3: true,
        primary: strmtyp != 1 && substream == 0,
        rate,
        acmod,
        lfe,
        bytes: (frmsiz as usize + 1) * 2,
        samples: blocks * 256,
        bsmod: None,
    })
}

fn dolby(cx: &mut Context<'_>, b: &[u8], len: u64) {
    let (mut at, mut frames, mut samples, mut first, mut dependent) = (0usize, 0u64, 0u64, None::<DolbyFrame>, false);
    let mut bad = 0u64;
    while at + 8 <= b.len() && frames < MAX_FRAMES {
        let Some(f) = ac3_frame(&b[at..]) else {
            bad += 1;
            // Resynchronise on the next sync word.
            match b[at + 1..].windows(2).position(|w| w == b"\x0b\x77") {
                Some(p) => at += 1 + p,
                None => break,
            }
            continue;
        };
        if f.bytes == 0 {
            break;
        }
        if f.primary {
            frames += 1;
            samples += u64::from(f.samples);
        } else {
            dependent = true;
        }
        at += f.bytes;
        if first.is_none() {
            first = Some(f);
        }
    }
    let Some(f) = first else {
        cx.warn("no AC-3 sync frame found");
        return;
    };
    let mut s = Stream::new(if f.eac3 { "eac3" } else { "ac3" });
    s.sample_rate_hz = Some(f.rate);
    let (layout, ch) = ACMOD[f.acmod as usize];
    s.channels = Some(ch + u16::from(f.lfe));
    s.channel_layout = Some(if f.lfe { format!("{layout}+LFE") } else { layout.to_string() });
    s.samples = Some(samples);
    #[allow(clippy::cast_precision_loss)]
    let duration = (samples > 0).then(|| samples as f64 / f64::from(f.rate));
    if let Some(d) = duration.filter(|d| *d > 0.0) {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
        let bps = (len as f64 * 8.0 / d).round() as u64;
        s.bitrate_bps = Some(bps);
    }
    cx.format_set("frames", frames);
    if let Some(m) = f.bsmod {
        let service = [
            "main audio (complete)",
            "music and effects",
            "visually impaired",
            "hearing impaired",
            "dialogue",
            "commentary",
            "emergency",
            "voice over / karaoke",
        ];
        cx.format_set("service", service[m as usize]);
    }
    if dependent {
        cx.format_set("dependent_substreams", true);
    }
    if bad > 0 {
        cx.format_set("resyncs", bad);
    }
    s.report(cx, duration, len);
}

// --- DTS -----------------------------------------------------------------------------------

struct DtsFrame {
    bytes: usize,
    samples: u32,
    rate: u32,
    channels: u16,
    lfe: bool,
    kbps: Option<f64>,
}

/// Big-endian 16-bit words, whatever order the file uses.
fn dts_words(h: &[u8]) -> Vec<u8> {
    if h.starts_with(b"\xfe\x7f\x01\x80") {
        h.as_chunks::<2>().0.iter().flat_map(|w| [w[1], w[0]]).collect()
    } else {
        h.to_vec()
    }
}

const DTS_RATES: [u32; 16] =
    [0, 8000, 16_000, 32_000, 0, 0, 11_025, 22_050, 44_100, 0, 0, 12_000, 24_000, 48_000, 0, 0];
const DTS_CHANNELS: [u16; 16] = [1, 2, 2, 2, 2, 3, 3, 4, 4, 5, 6, 6, 6, 7, 8, 8];
const DTS_KBPS: [f64; 29] = [
    32.0, 56.0, 64.0, 96.0, 112.0, 128.0, 192.0, 224.0, 256.0, 320.0, 384.0, 448.0, 512.0, 576.0, 640.0, 768.0, 960.0,
    1024.0, 1152.0, 1280.0, 1344.0, 1408.0, 1411.2, 1472.0, 1536.0, 1920.0, 2048.0, 3072.0, 3840.0,
];

fn dts_frame(h: &[u8]) -> Option<DtsFrame> {
    let b = dts_words(&h[..h.len().min(16)]);
    if !b.starts_with(b"\x7f\xfe\x80\x01") || b.len() < 12 {
        return None;
    }
    let mut r = Bits { b: &b, at: 32 };
    r.get(1 + 5 + 1)?; // frame type, deficit samples, CRC present
    let nblks = r.get(7)?;
    let fsize = r.get(14)?;
    let amode = r.get(6)?;
    let sfreq = r.get(4)?;
    let rate_code = r.get(5)?;
    r.get(1 + 1 + 1 + 1 + 1 + 3 + 1 + 1)?;
    let lff = r.get(2)?;
    let rate = DTS_RATES[sfreq as usize];
    if rate == 0 || fsize < 95 || nblks < 5 {
        return None;
    }
    Some(DtsFrame {
        bytes: fsize as usize + 1,
        samples: (nblks + 1) * 32,
        rate,
        channels: *DTS_CHANNELS.get(amode as usize).unwrap_or(&0),
        lfe: lff == 1 || lff == 2,
        kbps: DTS_KBPS.get(rate_code as usize).copied(),
    })
}

fn dts(cx: &mut Context<'_>, b: &[u8], len: u64) {
    let (mut at, mut frames, mut samples, mut first) = (0usize, 0u64, 0u64, None::<DtsFrame>);
    while at + 16 <= b.len() && frames < MAX_FRAMES {
        let Some(f) = dts_frame(&b[at..]) else { break };
        frames += 1;
        samples += u64::from(f.samples);
        at += f.bytes;
        if first.is_none() {
            first = Some(f);
        }
    }
    let Some(f) = first else {
        cx.warn("no DTS core frame found");
        return;
    };
    let mut s = Stream::new("dts");
    s.sample_rate_hz = Some(f.rate);
    s.channels = Some(f.channels + u16::from(f.lfe)).filter(|c| *c > 0);
    s.samples = Some(samples);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let bps = f.kbps.map(|k| (k * 1000.0).round() as u64);
    s.bitrate_bps = bps;
    cx.format_set("frames", frames);
    cx.format_set("frame_bytes", f.bytes);
    if b.starts_with(b"\xfe\x7f\x01\x80") {
        cx.format_set("byte_order", "little-endian");
    }
    s.report(cx, None, len);
}

// --- TrueHD / MLP ------------------------------------------------------------------------------

fn mlp_rate(code: u32) -> Option<u32> {
    Some(match code {
        0 => 48_000,
        1 => 96_000,
        2 => 192_000,
        8 => 44_100,
        9 => 88_200,
        10 => 176_400,
        _ => return None,
    })
}

/// Channels in a `TrueHD` channel assignment (one bit per speaker or pair).
fn thd_channels(map: u32) -> u16 {
    const COUNT: [u16; 13] = [2, 1, 1, 2, 2, 2, 2, 1, 1, 2, 2, 1, 1];
    (0..13).filter(|i| map & (1 << i) != 0).map(|i| COUNT[i]).sum()
}

fn truehd(cx: &mut Context<'_>, b: &[u8], len: u64) {
    let (mut at, mut units, mut syncs) = (0usize, 0u64, 0u64);
    let mut header: Option<(bool, u32, u16)> = None;
    while at + 4 <= b.len() && units < MAX_FRAMES {
        let words = usize::from(u16::from_be_bytes([b[at], b[at + 1]]) & 0x0fff);
        if words < 2 {
            break;
        }
        if let Some(sync) = b.get(at + 4..at + 8)
            && (sync == b"\xf8\x72\x6f\xba" || sync == b"\xf8\x72\x6f\xbb")
        {
            syncs += 1;
            if header.is_none() {
                header = major_sync(&b[at + 4..]);
            }
        }
        units += 1;
        at += words * 2;
    }
    let Some((thd, rate, channels)) = header else {
        cx.warn("no major sync found");
        return;
    };
    let mut s = Stream::new(if thd { "truehd" } else { "mlp" });
    s.sample_rate_hz = Some(rate);
    s.channels = Some(channels).filter(|c| *c > 0);
    // An access unit is 1/1200 s at every rate.
    s.samples = Some(units * u64::from(rate) / 1200);
    cx.format_set("access_units", units);
    cx.format_set("major_syncs", syncs);
    s.report(cx, None, len);
}

/// MLP channel counts by channel assignment.
const MLP_CHANNELS: [u16; 21] = [1, 2, 3, 4, 3, 4, 5, 3, 4, 5, 4, 5, 6, 4, 5, 4, 5, 6, 5, 5, 6];

/// (`TrueHD`?, sample rate, channels) from a major sync.
fn major_sync(b: &[u8]) -> Option<(bool, u32, u16)> {
    let mut r = Bits { b, at: 24 };
    let kind = r.get(8)?;
    if kind == 0xba {
        let rate = mlp_rate(r.get(4)?)?;
        r.get(4 + 2 + 2)?;
        let six = r.get(5)?;
        r.get(2)?;
        let eight = r.get(13)?;
        let ch = if eight != 0 { thd_channels(eight) } else { thd_channels(six) };
        return Some((true, rate, ch));
    }
    if kind == 0xbb {
        r.get(4 + 4)?; // quantisation of groups 1 and 2
        let rate = mlp_rate(r.get(4)?)?;
        r.get(4 + 11)?;
        let ch = MLP_CHANNELS.get(r.get(5)? as usize).copied().unwrap_or(0);
        return Some((false, rate, ch));
    }
    None
}

// --- Shorten -----------------------------------------------------------------------------------

/// Shorten's variable-length integers: unary high part, then `n` low bits.
fn uvar(r: &mut Bits<'_>, n: u32) -> Option<u32> {
    let mut high = 0u32;
    while r.get(1)? == 0 {
        high += 1;
        if high > 1 << 20 {
            return None;
        }
    }
    let low = r.get(n)?;
    high.checked_shl(n)?.checked_add(low)
}

fn ulong(r: &mut Bits<'_>) -> Option<u32> {
    let n = uvar(r, 2)?;
    if n > 32 {
        return None;
    }
    uvar(r, n)
}

/// Shorten's internal sample types.
const SHORTEN_TYPES: [&str; 12] =
    ["u8", "s8", "u8", "s16be", "u16be", "s16le", "u16le", "s16 native", "u-law", "u-law", "a-law", "a-law"];

fn shorten(cx: &mut Context<'_>, b: &[u8], len: u64) {
    let Some(&version) = b.get(4) else { return };
    cx.format_set("shorten_version", version);
    let mut r = Bits { b: &b[5..], at: 0 };
    let mut read = || -> Option<(u32, u32, u32, Vec<u8>)> {
        let ftype = if version == 0 { uvar(&mut r, 4)? } else { ulong(&mut r)? };
        let channels = if version == 0 { uvar(&mut r, 0)? } else { ulong(&mut r)? };
        let block = if version == 0 { 256 } else { ulong(&mut r)? };
        if version > 0 {
            ulong(&mut r)?; // max LPC order
            ulong(&mut r)?; // means
            let skip = ulong(&mut r)?;
            for _ in 0..skip.min(1 << 16) {
                r.get(8)?;
            }
        }
        // The first command is usually FN_VERBATIM (9) with the WAV / AIFF header.
        let mut verbatim = Vec::new();
        if uvar(&mut r, 2)? == 9 {
            let n = uvar(&mut r, 5)?;
            for _ in 0..n.min(1 << 16) {
                verbatim.push(u8::try_from(uvar(&mut r, 8)?).ok()?);
            }
        }
        Some((ftype, channels, block, verbatim))
    };
    let Some((ftype, channels, block, verbatim)) = read() else {
        cx.warn("the Shorten header could not be read");
        return;
    };
    cx.format_set("sample_type", SHORTEN_TYPES.get(ftype as usize).copied().unwrap_or("unknown"));
    cx.format_set("block_size", block);
    let mut s = Stream::new("shorten");
    s.channels = u16::try_from(channels).ok().filter(|c| *c > 0);
    if verbatim.starts_with(b"RIFF") && verbatim.get(8..12) == Some(b"WAVE") {
        cx.format_set("wrapped_header", "WAV");
        if let Some(fmt) = verbatim.windows(4).position(|w| w == b"fmt ").and_then(|p| verbatim.get(p + 8..p + 24)) {
            let mut f = ByteReader::new(fmt);
            if let (Ok(_tag), Ok(ch), Ok(rate), Ok(_bps), Ok(_align), Ok(bits)) =
                (f.le_u16(), f.le_u16(), f.le_u32(), f.le_u32(), f.le_u16(), f.le_u16())
            {
                s.channels = Some(ch);
                s.sample_rate_hz = Some(rate);
                s.bits_per_sample = Some(bits);
                if let Some(p) = verbatim.windows(4).position(|w| w == b"data")
                    && let Some(d) = verbatim.get(p + 4..p + 8)
                    && ch > 0
                    && bits >= 8
                {
                    let data = u64::from(u32::from_le_bytes([d[0], d[1], d[2], d[3]]));
                    s.samples = Some(data / (u64::from(ch) * u64::from(bits / 8)));
                }
            }
        }
    } else if verbatim.starts_with(b"FORM") {
        cx.format_set("wrapped_header", "AIFF");
    }
    s.report(cx, None, len);
}

// --- QCP -----------------------------------------------------------------------------------------

fn qcp(cx: &mut Context<'_>, b: &[u8], len: u64) {
    let mut at = 12;
    let mut s = Stream::new("qcelp");
    let mut packet = 0u64;
    while at + 8 <= b.len() {
        let id = &b[at..at + 4];
        let size = u32::from_le_bytes([b[at + 4], b[at + 5], b[at + 6], b[at + 7]]) as usize;
        let body = &b[at + 8..b.len().min(at + 8 + size)];
        match id {
            b"fmt " if body.len() >= 2 + 16 + 2 + 80 + 10 => {
                let guid = &body[2..18];
                let codec = match (guid[0], guid[3]) {
                    (0x41 | 0x42, 0x5e) => "qcelp",
                    (0x8d, 0xe6) => "evrc",
                    (0x75, 0x8d) => "smv",
                    _ => "unknown",
                };
                s = Stream::new(codec);
                let name = crate::plugin::latin1_or_utf8(&body[20..100]).trim_matches('\0').trim().to_string();
                if !name.is_empty() {
                    cx.format_set("codec_name", name);
                }
                let mut r = ByteReader::new(&body[100..]);
                if let (Ok(bps), Ok(pkt), Ok(_block), Ok(rate), Ok(bits)) =
                    (r.le_u16(), r.le_u16(), r.le_u16(), r.le_u16(), r.le_u16())
                {
                    s.bitrate_bps = Some(u64::from(bps));
                    s.sample_rate_hz = Some(u32::from(rate));
                    s.bits_per_sample = Some(bits);
                    packet = u64::from(pkt);
                }
                s.channels = Some(1);
            }
            b"vrat" if body.len() >= 8 => {
                let packets = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
                cx.format_set("variable_rate", true);
                cx.format_set("packets", packets);
                s.samples = Some(u64::from(packets) * 160);
            }
            b"data" => {
                if s.samples.is_none() && packet > 0 {
                    s.samples = Some(u64::try_from(size).unwrap_or(0) / packet * 160);
                }
                break;
            }
            _ => {}
        }
        at += 8 + size + (size & 1);
    }
    s.report(cx, None, len);
}

// --- ATRAC (OpenMG) ---------------------------------------------------------------------------------

/// OpenMG sample rates by code.
const OMA_RATES: [u32; 5] = [32_000, 44_100, 48_000, 88_200, 96_000];

fn oma(cx: &mut Context<'_>, b: &[u8], len: u64) {
    let mut tags = Tags::default();
    // An ID3v2-like "ea3" tag (with ordinary ID3 frames), then the EA3 header.
    let mut at = 0usize;
    if b.starts_with(b"ea3") && b.len() > 10 {
        let size = b[6..10].iter().fold(0usize, |a, &x| (a << 7) | usize::from(x & 0x7f));
        // The tag is ID3v2 apart from its "ea3" marker.
        let mut tag = b[..(10 + size).min(b.len())].to_vec();
        tag[..3].copy_from_slice(b"ID3");
        super::id3::parse_bytes(&tag, cx, &mut tags);
        at = 10 + size;
    }
    let Some(h) = b.get(at..at + 96).filter(|h| h.starts_with(b"EA3")) else {
        cx.warn("no EA3 header");
        tags.report(cx);
        return;
    };
    let encrypted = !matches!(u16::from_be_bytes([h[6], h[7]]), 0xffff | 0xfffe);
    cx.format_set("encrypted", encrypted);
    let codec_id = h[32];
    let params = u32::from_be_bytes([0, h[33], h[34], h[35]]);
    let rate = OMA_RATES.get(((params >> 13) & 7) as usize).copied();
    let mut s = match codec_id {
        0 => {
            let mut s = Stream::new("atrac3");
            s.channels = Some(2);
            s.sample_rate_hz = rate;
            let frame = u64::from(params & 0x3ff) * 8;
            s.bitrate_bps = rate.map(|r| u64::from(r) * frame * 8 / 1024);
            s
        }
        1 => {
            let mut s = Stream::new("atrac3p");
            s.channels = [0u16, 1, 2, 3, 4, 6, 7, 8].get(((params >> 10) & 7) as usize).copied().filter(|c| *c > 0);
            s.sample_rate_hz = rate;
            let frame = u64::from(params & 0x3ff) * 8 + 8;
            s.bitrate_bps = rate.map(|r| u64::from(r) * frame * 8 / 2048);
            s
        }
        3 => Stream::new("mp3"),
        4 => {
            let mut s = Stream::new("pcm_s16be");
            s.channels = Some(2);
            s.sample_rate_hz = Some(44_100);
            s.bits_per_sample = Some(16);
            s
        }
        5 => Stream::new("wmav2"),
        _ => Stream::new("unknown"),
    };
    if let Some(bps) = s.bitrate_bps.filter(|b| *b > 0) {
        let data = len.saturating_sub((at + 96) as u64);
        s.samples = s.sample_rate_hz.map(|r| data * 8 * u64::from(r) / bps);
    }
    cx.format_set("codec_id", codec_id);
    tags.report(cx);
    s.report(cx, None, len);
}

// --- TwinVQ ---------------------------------------------------------------------------------------------

fn vqf(cx: &mut Context<'_>, b: &[u8], len: u64) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(b);
    r.advance(4)?;
    let version = String::from_utf8_lossy(r.bytes(8)?).to_string();
    cx.format_set("vqf_version", version);
    let header = r.be_u32()?;
    let mut s = Stream::new("twinvq");
    let mut tags = Tags::default();
    let mut kbps = 0u32;
    while r.remaining() >= 8 {
        let id: [u8; 4] = r.array()?;
        let n = r.be_u32()? as usize;
        if &id == b"DATA" {
            break;
        }
        let Ok(body) = r.bytes(n) else { break };
        match &id {
            b"COMM" if body.len() >= 12 => {
                let w = |i: usize| u32::from_be_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
                s.channels = u16::try_from(w(0) + 1).ok();
                kbps = w(4);
                s.sample_rate_hz = Some(match w(8) {
                    11 => 11_025,
                    22 => 22_050,
                    44 => 44_100,
                    other => other * 1000,
                });
                s.bitrate_bps = Some(u64::from(kbps) * 1000);
            }
            b"NAME" | b"AUTH" | b"(c) " | b"COMT" | b"FILE" | b"ALBM" => {
                let text = crate::plugin::latin1_or_utf8(body).trim_matches('\0').trim().to_string();
                if !text.is_empty() {
                    let key = match &id {
                        b"NAME" => "title",
                        b"AUTH" => "artist",
                        b"(c) " => "copyright",
                        b"COMT" => "comment",
                        b"ALBM" => "album",
                        _ => "original_filename",
                    };
                    if key == "original_filename" {
                        cx.format_set(key, text);
                    } else {
                        tags.set(key, &text, "vqf");
                    }
                }
            }
            _ => {}
        }
    }
    if kbps > 0 {
        let data = len.saturating_sub(u64::from(header) + 12);
        s.samples = s.sample_rate_hz.map(|r| data * 8 * u64::from(r) / (u64::from(kbps) * 1000));
    }
    tags.system("vqf");
    tags.report(cx);
    s.report(cx, None, len);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!(
        "ac3",
        "eac3",
        "dts_audio",
        "truehd",
        "gsm",
        "dialogic_vox",
        "shorten",
        "qcp",
        "atrac",
        "vqf"
    );

    #[test]
    fn helpers() {
        assert_eq!(thd_channels(0b1011), 2 + 1 + 2);
        assert_eq!(mlp_rate(8), Some(44_100));
        // uvar(2): "1" then two bits "10" → 2; "01" then "11" → (1 << 2) + 3 = 7.
        let mut r = Bits { b: &[0b1100_1110], at: 0 };
        assert_eq!(uvar(&mut r, 2), Some(2));
        assert_eq!(uvar(&mut r, 2), Some(7));
    }
}
