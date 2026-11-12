//! ISO base media files (MP4, M4A / M4B, MOV, 3GP): the brands, the movie
//! header, each track (handler, codec and its configuration, timescale,
//! duration, language, sample count and size), iTunes `ilst` metadata
//! (also keyed through QuickTime `keys`), QuickTime `©xyz`-style user data,
//! Nero (`chpl`) and QuickTime chapter-track chapters, the text of
//! subtitle tracks (3GPP timed text, QuickTime text, WebVTT in ISO BMFF),
//! XMP, the layout (fragmented, `moov` before `mdat`) and, for fragmented
//! files, the track durations from the movie fragments.
//!
//! Only the `moov` and `moof` boxes and chapter and subtitle text samples
//! are read; audio and video data never is.
//!
//! Specifications: ISO/IEC 14496-12 (ISO BMFF), 14496-14 (MP4), 14496-1
//! §7.2.6 (ES descriptors), 14496-3 §1.6.2 (AudioSpecificConfig); Apple
//! QuickTime File Format (metadata, `keys`, sample descriptions).

// Box parsers keep a reader `r`, box data `d`, version `v` and track `t`
// in scope: short names are clearer here.
#![allow(clippy::many_single_char_names, clippy::similar_names)]
use crate::io::{ByteReader, Source};
use crate::plugin::ExtractError;

/// Largest `moov` box read.
const MAX_MOOV: u64 = 64 << 20;
/// Top-level boxes listed (fragmented files have two per fragment).
const MAX_TOP: usize = 1 << 16;
/// Largest `moof` box read.
const MAX_MOOF: u64 = 1 << 20;
/// Largest top-level XMP `uuid` box read.
const MAX_XMP: u64 = 4 << 20;
/// Codec configuration boxes kept per sample entry, and their largest size.
const MAX_CONFIGS: usize = 16;
const MAX_CONFIG_BYTES: usize = 64 << 10;
/// The XMP `uuid` box type (Adobe XMP specification part 3).
const XMP_UUID: [u8; 16] =
    [0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac];
/// Tracks read.
const MAX_TRACKS: usize = 256;
/// Metadata items read.
const MAX_ITEMS: usize = 4096;
/// Chapter samples read from a chapter track.
const MAX_CHAPTER_SAMPLES: usize = 500;
/// Samples read from each subtitle track.
const MAX_TEXT_SAMPLES: usize = 20_000;
/// Largest subtitle sample read.
const MAX_TEXT_SAMPLE: u32 = 16 << 10;
/// Subtitle sample bytes read from one movie.
const MAX_TEXT_BYTES: u64 = 8 << 20;
/// QuickTime `wave` boxes followed inside one another.
const MAX_WAVE_DEPTH: usize = 4;

/// A box: type and body.
pub type BoxRef<'a> = ([u8; 4], &'a [u8]);

/// Boxes in `data` (`size`, `type`, body): 32- and 64-bit sizes, size 0 =
/// to the end. Stops at the first box that does not fit.
pub fn boxes(data: &[u8]) -> impl Iterator<Item = BoxRef<'_>> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let head = data.get(pos..pos + 8)?;
        let size32 = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        let kind = [head[4], head[5], head[6], head[7]];
        let (header, size) = match size32 {
            0 => (8, data.len() - pos),
            1 => {
                let ext = data.get(pos + 8..pos + 16)?;
                (16, usize::try_from(u64::from_be_bytes(ext.try_into().ok()?)).ok()?)
            }
            n => (8, n as usize),
        };
        if size < header {
            return None;
        }
        let body = data.get(pos + header..pos.checked_add(size)?)?;
        pos += size;
        Some((kind, body))
    })
}

/// The first child box of `kind`.
pub fn find(data: &[u8], kind: [u8; 4]) -> Option<&[u8]> {
    boxes(data).find(|(k, _)| *k == kind).map(|(_, b)| b)
}

/// The body of a nested box, following a path of types.
pub fn path<'a>(data: &'a [u8], kinds: &[&[u8; 4]]) -> Option<&'a [u8]> {
    kinds.iter().try_fold(data, |d, k| find(d, **k))
}

/// A top-level box: type, body offset and body length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopBox {
    /// Four-character type.
    pub kind: [u8; 4],
    /// Offset of the body.
    pub at: u64,
    /// Length of the body.
    pub len: u64,
}

/// The top-level boxes, reading headers only (at most `max`). Stops at the
/// first box that does not fit.
pub fn top_boxes(src: &mut dyn Source, max: usize) -> Result<Vec<TopBox>, ExtractError> {
    let mut out = Vec::new();
    let mut pos = 0u64;
    let len = src.len();
    while pos + 8 <= len && out.len() < max {
        let h = src.read_vec(pos, 8)?;
        let size32 = u64::from(u32::from_be_bytes([h[0], h[1], h[2], h[3]]));
        let kind = [h[4], h[5], h[6], h[7]];
        let (header, size) = match size32 {
            0 => (8, len - pos),
            1 => (16, u64::from_be_bytes(src.read_vec(pos + 8, 8)?.try_into().unwrap_or_default())),
            n => (8, n),
        };
        if size < header || pos.saturating_add(size) > len {
            break;
        }
        out.push(TopBox { kind, at: pos + header, len: size - header });
        pos += size;
    }
    Ok(out)
}

/// The value of an iTunes / QuickTime metadata item.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// UTF-8 / UTF-16 text.
    Text(String),
    /// A signed or unsigned big-endian integer.
    Int(i64),
    /// `trkn` / `disk`: number and total.
    Pair(u16, u16),
    /// Image data (`covr`): MIME type and bytes.
    Image(&'static str, Vec<u8>),
    /// Anything else: the well-known type and the bytes.
    Binary(u32, Vec<u8>),
}

/// One metadata item.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    /// The item key: an `ilst` type such as `©nam`, `----:mean:name` for
    /// free-form items, the QuickTime `keys` name (`com.apple.quicktime.make`),
    /// or `udta:©nam` for QuickTime user-data text.
    pub key: String,
    /// The value.
    pub value: Value,
}

/// A chapter.
#[derive(Debug, Clone, PartialEq)]
pub struct Chapter {
    /// Start in seconds.
    pub start_s: f64,
    /// Title.
    pub title: String,
}

/// A track (`trak`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Track {
    /// Track id.
    pub id: u32,
    /// Handler type: `soun`, `vide`, `text`, `sbtl`, `subt`, `tmcd`, `meta`…
    pub handler: String,
    /// Handler name.
    pub handler_name: String,
    /// Whether the track is enabled.
    pub enabled: bool,
    /// Media timescale (units per second).
    pub timescale: u32,
    /// Media duration in timescale units.
    pub duration: u64,
    /// ISO 639-2 language (`und` if unset).
    pub language: Option<String>,
    /// Sample-entry type: `mp4a`, `alac`, `Opus`, `fLaC`, `avc1`, `hvc1`, `tx3g`…
    pub codec: String,
    /// Codec detail: `aac_lc`, `he_aac`… for `mp4a`.
    pub profile: Option<String>,
    /// Audio: channels.
    pub channels: Option<u16>,
    /// Audio: sample rate.
    pub sample_rate: Option<u32>,
    /// Audio: bits per sample.
    pub bits: Option<u16>,
    /// Average bitrate (`esds`, `btrt`, ALAC config).
    pub avg_bitrate: Option<u32>,
    /// Maximum bitrate (`esds`, `btrt`).
    pub max_bitrate: Option<u32>,
    /// Video / visual: width and height of the sample entry.
    pub dimensions: Option<(u16, u16)>,
    /// Track header width and height (16.16 fixed, rounded).
    pub display: Option<(u32, u32)>,
    /// Rotation from the track matrix, in degrees (0, 90, 180, 270).
    pub rotation: Option<u16>,
    /// Number of samples.
    pub samples: u64,
    /// Total sample bytes.
    pub sample_bytes: u64,
    /// Track ids this track names as its chapter tracks (`tref/chap`).
    pub chapter_tracks: Vec<u32>,
    /// Creation time (seconds since 1904-01-01).
    pub created: Option<u64>,
    /// Media time skipped by the first edit (encoder delay), in movie units.
    pub edit_media_time: Option<i64>,
    /// Visual sample entries: the codec configuration and description
    /// boxes (`avcC`, `hvcC`, `av1C`, `vpcC`, `colr`, `pasp`, `mdcv`, `clli`,
    /// `dvcC`, `fiel`, `st3d`…), type and body.
    pub configs: Vec<([u8; 4], Vec<u8>)>,
    /// Visual sample entries: the compressor name.
    pub compressor: Option<String>,
    /// Visual sample entries: the pixel depth.
    pub depth: Option<u16>,
    /// The MPEG-4 decoder-specific info of an `esds` (a video object
    /// sequence header for `mp4v`).
    pub decoder_config: Option<Vec<u8>>,
    /// The sample duration, when every sample has the same one.
    pub sample_delta: Option<u32>,
    /// Whether sample durations differ (variable frame rate).
    pub variable_delta: bool,
    /// Track name (`udta/name`).
    pub name: Option<String>,
    /// Protected sample entries (`encv`, `enca`): the original format.
    pub original_format: Option<String>,
    /// Protected sample entries: the protection scheme (`cenc`, `cbcs`…).
    pub protection: Option<String>,
    /// Samples and duration from the movie fragments.
    pub fragment_samples: u64,
    /// Subtitle tracks (`tx3g`, `text`, `wvtt`): the samples that hold text,
    /// in order.
    pub text_samples: Vec<TextSample>,
    sample_table: Option<SampleTable>,
}

/// One text sample of a subtitle track.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TextSample {
    /// Start, seconds.
    pub start_s: f64,
    /// End, seconds.
    pub end_s: f64,
    /// The text as stored (styling is in separate boxes; WebVTT cue
    /// payloads keep their tags).
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct SampleTable {
    chunk_offsets: Vec<u64>,
    /// (first chunk, samples per chunk)
    to_chunk: Vec<(u32, u32)>,
    sizes: Vec<u32>,
    fixed_size: u32,
    /// (count, delta)
    times: Vec<(u32, u32)>,
}

/// A parsed movie.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Movie {
    /// Major brand.
    pub major_brand: String,
    /// Minor version.
    pub minor_version: u32,
    /// Compatible brands.
    pub compatible_brands: Vec<String>,
    /// Top-level box types, in order.
    pub top: Vec<String>,
    /// Movie timescale.
    pub timescale: u32,
    /// Movie duration in timescale units.
    pub duration: u64,
    /// Creation time (seconds since 1904-01-01; 0 when unset).
    pub created: u64,
    /// Modification time.
    pub modified: u64,
    /// Tracks.
    pub tracks: Vec<Track>,
    /// Metadata items, in file order.
    pub items: Vec<Item>,
    /// Chapters (Nero `chpl`, else the first chapter track).
    pub chapters: Vec<Chapter>,
    /// Fragmented (`mvex` / `moof`).
    pub fragmented: bool,
    /// `moov` before the first `mdat` (progressive download).
    pub faststart: Option<bool>,
    /// Bytes of media data (`mdat` bodies).
    pub mdat_bytes: u64,
    /// Movie fragments (`moof` boxes).
    pub fragments: u64,
    /// XMP packet (`moov/udta/XMP_` or a top-level XMP `uuid` box).
    pub xmp: Option<Vec<u8>>,
}

impl Movie {
    /// Duration in seconds (movie header, else the longest track, which
    /// for a fragmented file includes its fragments).
    pub fn duration_s(&self) -> Option<f64> {
        if self.timescale > 0 && self.duration > 0 && self.duration != u64::from(u32::MAX) {
            return Some(self.duration as f64 / f64::from(self.timescale));
        }
        self.tracks
            .iter()
            .filter(|t| t.timescale > 0)
            .map(|t| t.duration as f64 / f64::from(t.timescale))
            .reduce(f64::max)
    }
}

/// Read the movie: `ftyp`, `moov` (at most 64 MiB) and the chapter samples.
pub fn read(src: &mut dyn Source) -> Result<Movie, ExtractError> {
    let mut m = Movie::default();
    let top = top_boxes(src, MAX_TOP)?;
    let mut moov = None;
    let mut moofs = Vec::new();
    for b in &top {
        if m.top.len() < 64 {
            m.top.push(fourcc(&b.kind));
        }
        match &b.kind {
            b"ftyp" if b.len <= 4096 => {
                let f = src.read_vec(b.at, usize::try_from(b.len).unwrap_or(0))?;
                if f.len() >= 8 {
                    m.major_brand = fourcc(&f[..4]);
                    m.minor_version = u32::from_be_bytes([f[4], f[5], f[6], f[7]]);
                    m.compatible_brands = f[8..].as_chunks::<4>().0.iter().map(|c| fourcc(c)).take(64).collect();
                }
            }
            b"moov" if moov.is_none() => {
                if b.len > MAX_MOOV {
                    return Err(ExtractError::LimitExceeded("moov box larger than 64 MiB".into()));
                }
                moov = Some(src.read_vec(b.at, usize::try_from(b.len).unwrap_or(0))?);
                if m.faststart.is_none() {
                    m.faststart = Some(true);
                }
            }
            b"mdat" => {
                m.mdat_bytes += b.len;
                if moov.is_none() && m.faststart.is_none() {
                    m.faststart = Some(false);
                }
            }
            b"moof" => {
                m.fragmented = true;
                m.fragments += 1;
                if b.len <= MAX_MOOF {
                    moofs.push(*b);
                }
            }
            b"uuid" if m.xmp.is_none() && b.len > 16 && b.len <= MAX_XMP => {
                let d = src.read_vec(b.at, usize::try_from(b.len).unwrap_or(0))?;
                if d[..16] == XMP_UUID {
                    m.xmp = Some(d[16..].to_vec());
                }
            }
            _ => {}
        }
    }
    let moov = moov.ok_or_else(|| ExtractError::malformed("no moov box"))?;
    parse_moov(&moov, &mut m);
    if !moofs.is_empty() {
        fragments(src, &moofs, &moov, &mut m)?;
    }
    if m.chapters.is_empty() {
        chapter_track(src, &mut m);
    }
    text_tracks(src, &mut m);
    for t in &mut m.tracks {
        t.sample_table = None;
    }
    Ok(m)
}

fn parse_moov(moov: &[u8], m: &mut Movie) {
    for (kind, body) in boxes(moov) {
        match &kind {
            b"mvhd" => {
                let (v, _, d) = full(body);
                let mut r = ByteReader::new(d);
                let ok = if v == 1 {
                    (r.be_u64(), r.be_u64(), r.be_u32(), r.be_u64())
                } else {
                    (r.be_u32().map(u64::from), r.be_u32().map(u64::from), r.be_u32(), r.be_u32().map(u64::from))
                };
                if let (Ok(c), Ok(md), Ok(ts), Ok(dur)) = ok {
                    (m.created, m.modified, m.timescale, m.duration) = (c, md, ts, dur);
                }
            }
            b"trak" if m.tracks.len() < MAX_TRACKS => m.tracks.push(track(body)),
            b"mvex" => m.fragmented = true,
            b"udta" => udta(body, m),
            b"meta" => meta(body, m),
            _ => {}
        }
    }
}

/// Version, flags and body of a full box.
fn full(b: &[u8]) -> (u8, u32, &[u8]) {
    match b {
        [v, f0, f1, f2, rest @ ..] => (*v, u32::from_be_bytes([0, *f0, *f1, *f2]), rest),
        _ => (0, 0, &[]),
    }
}

fn track(trak: &[u8]) -> Track {
    let mut t = Track::default();
    if let Some(tkhd) = find(trak, *b"tkhd") {
        let (v, flags, d) = full(tkhd);
        t.enabled = flags & 1 != 0;
        let mut r = ByteReader::new(d);
        let created = if v == 1 { r.be_u64() } else { r.be_u32().map(u64::from) };
        let _ = if v == 1 { r.be_u64() } else { r.be_u32().map(u64::from) };
        t.created = created.ok().filter(|c| *c > 0);
        t.id = r.be_u32().unwrap_or(0);
        // reserved, duration, reserved(8), layer, group, volume, reserved
        let skip = 4 + if v == 1 { 8 } else { 4 } + 8 + 8;
        if r.advance(skip).is_ok()
            && let Ok(matrix) = r.bytes(36)
            && let (Ok(w), Ok(h)) = (r.be_u32(), r.be_u32())
        {
            if w > 0 && h > 0 {
                t.display = Some((w.div_ceil(65536), h.div_ceil(65536)));
            }
            let a = i32::from_be_bytes([matrix[0], matrix[1], matrix[2], matrix[3]]);
            let b = i32::from_be_bytes([matrix[4], matrix[5], matrix[6], matrix[7]]);
            t.rotation = Some(match (a.signum(), b.signum()) {
                (0, 1) => 90,
                (-1, 0) => 180,
                (0, -1) => 270,
                _ => 0,
            });
        }
    }
    if let Some(elst) = path(trak, &[b"edts", b"elst"]) {
        let (v, _, d) = full(elst);
        let mut r = ByteReader::new(d);
        if let Ok(n) = r.be_u32()
            && n > 0
        {
            let entry = if v == 1 {
                (r.be_u64(), r.be_u64().map(u64::cast_signed))
            } else {
                (r.be_u32().map(u64::from), r.be_i32().map(i64::from))
            };
            if let (Ok(_), Ok(media_time)) = entry {
                t.edit_media_time = Some(media_time);
            }
        }
    }
    if let Some(name) = path(trak, &[b"udta", b"name"]) {
        t.name = Some(mac_text(name)).filter(|n| !n.is_empty());
    }
    if let Some(chap) = path(trak, &[b"tref", b"chap"]) {
        t.chapter_tracks = chap.as_chunks::<4>().0.iter().map(|c| u32::from_be_bytes(*c)).take(16).collect();
    }
    let Some(mdia) = find(trak, *b"mdia") else { return t };
    if let Some(mdhd) = find(mdia, *b"mdhd") {
        let (v, _, d) = full(mdhd);
        let mut r = ByteReader::new(d);
        let skip = if v == 1 { 16 } else { 8 };
        if r.advance(skip).is_ok()
            && let Ok(ts) = r.be_u32()
        {
            t.timescale = ts;
            t.duration = if v == 1 { r.be_u64().unwrap_or(0) } else { r.be_u32().map_or(0, u64::from) };
            if let Ok(lang) = r.be_u16() {
                t.language = packed_language(lang);
            }
        }
    }
    if let Some(hdlr) = find(mdia, *b"hdlr") {
        let (_, _, d) = full(hdlr);
        if let Some(h) = d.get(4..8) {
            t.handler = fourcc(h);
        }
        if let Some(name) = d.get(20..) {
            // ISO: NUL-terminated; QuickTime: a Pascal string.
            let name = match name.first() {
                Some(&n) if usize::from(n) + 1 == name.len() && n > 0 => &name[1..],
                _ => name,
            };
            t.handler_name = String::from_utf8_lossy(name).trim_matches(char::from(0)).trim().to_string();
        }
    }
    if let Some(stbl) = path(mdia, &[b"minf", b"stbl"]) {
        sample_table(stbl, &mut t);
    }
    t
}

fn packed_language(v: u16) -> Option<String> {
    if v == 0 || v == 0x7fff || v < 0x400 {
        return None; // unset, or a Macintosh language code
    }
    let c = |s: u16| char::from(u8::try_from(((v >> s) & 0x1f) + 0x60).unwrap_or(b'?'));
    let lang: String = [c(10), c(5), c(0)].iter().collect();
    lang.chars().all(|ch| ch.is_ascii_lowercase()).then_some(lang)
}

#[allow(clippy::too_many_lines)] // one arm per sample-table box
fn sample_table(stbl: &[u8], t: &mut Track) {
    let mut st = SampleTable::default();
    for (kind, body) in boxes(stbl) {
        let (_, _, d) = full(body);
        let mut r = ByteReader::new(d);
        match &kind {
            b"stsd" => {
                if let Some(entry) = d.get(4..).and_then(|e| boxes(e).next()) {
                    sample_entry(entry, t);
                }
            }
            b"stsz" => {
                if let (Ok(size), Ok(n)) = (r.be_u32(), r.be_u32()) {
                    t.samples = u64::from(n);
                    st.fixed_size = size;
                    if size == 0 {
                        let list: Vec<u32> = r
                            .rest()
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .take(n as usize)
                            .map(|c| u32::from_be_bytes(*c))
                            .collect();
                        t.sample_bytes = list.iter().map(|&s| u64::from(s)).sum();
                        st.sizes = list;
                    } else {
                        t.sample_bytes = u64::from(size) * u64::from(n);
                    }
                }
            }
            b"stz2" => {
                if r.advance(3).is_ok()
                    && let (Ok(field), Ok(n)) = (r.u8(), r.be_u32())
                {
                    t.samples = u64::from(n);
                    let rest = r.rest();
                    let sizes: Vec<u32> = match field {
                        8 => rest.iter().take(n as usize).map(|&b| u32::from(b)).collect(),
                        16 => rest
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .take(n as usize)
                            .map(|c| u32::from(u16::from_be_bytes(*c)))
                            .collect(),
                        _ => {
                            rest.iter().flat_map(|&b| [u32::from(b >> 4), u32::from(b & 15)]).take(n as usize).collect()
                        }
                    };
                    t.sample_bytes = sizes.iter().map(|&s| u64::from(s)).sum();
                    st.sizes = sizes;
                }
            }
            b"stts" => {
                if let Ok(n) = r.be_u32() {
                    st.times = r
                        .rest()
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .take(n as usize)
                        .map(|c| {
                            (u32::from_be_bytes([c[0], c[1], c[2], c[3]]), u32::from_be_bytes([c[4], c[5], c[6], c[7]]))
                        })
                        .collect();
                    // A last single sample often has a remainder duration; ignore it.
                    let mut runs: Vec<u32> = st.times.iter().filter(|(c, _)| *c > 0).map(|&(_, d)| d).collect();
                    if runs.len() > 1 && st.times.last().is_some_and(|(c, _)| *c == 1) {
                        runs.pop();
                    }
                    t.variable_delta = runs.windows(2).any(|w| w[0] != w[1]);
                    t.sample_delta = runs.first().copied().filter(|_| !t.variable_delta);
                }
            }
            b"stsc" => {
                if let Ok(n) = r.be_u32() {
                    st.to_chunk = r
                        .rest()
                        .as_chunks::<12>()
                        .0
                        .iter()
                        .take(n as usize)
                        .map(|c| {
                            (u32::from_be_bytes([c[0], c[1], c[2], c[3]]), u32::from_be_bytes([c[4], c[5], c[6], c[7]]))
                        })
                        .collect();
                }
            }
            b"stco" => {
                if let Ok(n) = r.be_u32() {
                    st.chunk_offsets = r
                        .rest()
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .take(n as usize)
                        .map(|c| u64::from(u32::from_be_bytes(*c)))
                        .collect();
                }
            }
            b"co64" => {
                if let Ok(n) = r.be_u32() {
                    st.chunk_offsets =
                        r.rest().as_chunks::<8>().0.iter().take(n as usize).map(|c| u64::from_be_bytes(*c)).collect();
                }
            }
            _ => {}
        }
    }
    t.sample_table = Some(st);
}

fn sample_entry(entry: BoxRef<'_>, t: &mut Track) {
    let (kind, body) = entry;
    t.codec = fourcc(&kind);
    // 6 reserved bytes and the data reference index.
    let Some(d) = body.get(8..) else { return };
    let mut r = ByteReader::new(d);
    match t.handler.as_str() {
        "soun" => {
            let (Ok(version), Ok(_rev), Ok(_vendor), Ok(ch), Ok(bits), Ok(_cid), Ok(_ps), Ok(rate)) =
                (r.be_u16(), r.be_u16(), r.be_u32(), r.be_u16(), r.be_u16(), r.be_u16(), r.be_u16(), r.be_u32())
            else {
                return;
            };
            t.channels = Some(ch);
            t.bits = Some(bits).filter(|b| *b > 0);
            t.sample_rate = Some(rate >> 16).filter(|r| *r > 0);
            let children_at = match version {
                1 => 16 + 20,
                2 => {
                    // QuickTime v2: 64-bit float rate and 32-bit channel count.
                    if let (Ok(_size), Ok(rate), Ok(ch)) = (r.be_u32(), r.be_u64(), r.be_u32()) {
                        let rate = f64::from_bits(rate);
                        if rate.is_finite() && rate > 0.0 {
                            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, < u32::MAX
                            let r32 = rate.round().min(f64::from(u32::MAX)) as u32;
                            t.sample_rate = Some(r32);
                        }
                        t.channels = u16::try_from(ch).ok();
                    }
                    if let (Ok(_), Ok(bits)) = (r.be_u32(), r.be_u32()) {
                        t.bits = u16::try_from(bits).ok().filter(|b| *b > 0);
                    }
                    20 + 36
                }
                _ => 20,
            };
            let Some(children) = d.get(children_at..) else { return };
            audio_config(children, t, 0);
        }
        "vide" => {
            if r.advance(16).is_ok()
                && let (Ok(w), Ok(h)) = (r.be_u16(), r.be_u16())
            {
                t.dimensions = Some((w, h));
            }
            if let Some(name) = d.get(34..66) {
                let n = usize::from(name[0]).min(31);
                t.compressor = Some(mac_text(&name[1..=n])).filter(|c| !c.is_empty());
            }
            if let Some(depth) = d.get(66..68) {
                t.depth = Some(u16::from_be_bytes([depth[0], depth[1]]));
            }
            for (kind, body) in boxes(d.get(70..).unwrap_or_default()) {
                match &kind {
                    b"btrt" => bitrate_box(body, t),
                    b"esds" => esds(full(body).2, t),
                    b"sinf" => protection(body, t),
                    _ if t.configs.len() < MAX_CONFIGS && body.len() <= MAX_CONFIG_BYTES => {
                        t.configs.push((kind, body.to_vec()));
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// A protection scheme box (`sinf`): the original format (`frma`) and the
/// scheme type (`schm`).
fn protection(sinf: &[u8], t: &mut Track) {
    if let Some(f) = find(sinf, *b"frma") {
        t.original_format = Some(fourcc(f));
    }
    if let Some(s) = find(sinf, *b"schm")
        && let Some(kind) = full(s).2.get(..4)
    {
        t.protection = Some(fourcc(kind));
    }
}

fn audio_config(children: &[u8], t: &mut Track, depth: usize) {
    for (kind, body) in boxes(children) {
        match &kind {
            b"esds" => esds(full(body).2, t),
            // QuickTime wraps esds in a wave box.
            b"wave" if depth < MAX_WAVE_DEPTH => audio_config(body, t, depth + 1),
            b"alac" => {
                let (_, _, d) = full(body);
                if d.len() >= 24 {
                    t.bits = Some(u16::from(d[5]));
                    t.channels = Some(u16::from(d[9]));
                    t.avg_bitrate = Some(u32::from_be_bytes([d[16], d[17], d[18], d[19]])).filter(|b| *b > 0);
                    t.sample_rate = Some(u32::from_be_bytes([d[20], d[21], d[22], d[23]]));
                }
            }
            b"dOps" => {
                if body.len() >= 11 {
                    t.channels = Some(u16::from(body[1]));
                }
            }
            b"btrt" => bitrate_box(body, t),
            b"sinf" => protection(body, t),
            _ => {}
        }
    }
}

fn bitrate_box(b: &[u8], t: &mut Track) {
    if b.len() >= 12 {
        t.max_bitrate = Some(u32::from_be_bytes([b[4], b[5], b[6], b[7]])).filter(|v| *v > 0);
        t.avg_bitrate = t.avg_bitrate.or(Some(u32::from_be_bytes([b[8], b[9], b[10], b[11]])).filter(|v| *v > 0));
    }
}

/// An MPEG-4 descriptor: tag, body.
fn descriptor<'a>(r: &mut ByteReader<'a>) -> Option<(u8, &'a [u8])> {
    let tag = r.u8().ok()?;
    let mut len = 0usize;
    for _ in 0..4 {
        let b = r.u8().ok()?;
        len = (len << 7) | usize::from(b & 0x7f);
        if b & 0x80 == 0 {
            break;
        }
    }
    Some((tag, r.bytes(len).ok()?))
}

fn esds(d: &[u8], t: &mut Track) {
    let mut r = ByteReader::new(d);
    let Some((3, es)) = descriptor(&mut r) else { return };
    let mut r = ByteReader::new(es);
    let Ok(_id) = r.be_u16() else { return };
    let Ok(flags) = r.u8() else { return };
    if flags & 0x80 != 0 && r.advance(2).is_err() {
        return;
    }
    if flags & 0x40 != 0 {
        let Ok(n) = r.u8() else { return };
        if r.advance(usize::from(n)).is_err() {
            return;
        }
    }
    if flags & 0x20 != 0 && r.advance(2).is_err() {
        return;
    }
    let Some((4, dc)) = descriptor(&mut r) else { return };
    let mut r = ByteReader::new(dc);
    let (Ok(object), Ok(_stream), Ok(_buf), Ok(max), Ok(avg)) = (r.u8(), r.u8(), r.bytes(3), r.be_u32(), r.be_u32())
    else {
        return;
    };
    t.max_bitrate = Some(max).filter(|v| *v > 0);
    t.avg_bitrate = Some(avg).filter(|v| *v > 0);
    t.profile = Some(
        match object {
            0x40 | 0x66..=0x68 => "aac",
            0x69 | 0x6b => "mp3",
            0xa5 => "ac3",
            0xa6 => "eac3",
            0xa9 => "dts",
            0xad => "opus",
            0xdd => "vorbis",
            0x20 => "mpeg4",
            0x21 => "h264",
            0x23 => "hevc",
            0x60..=0x65 => "mpeg2video",
            0x6a => "mpeg1video",
            0x6c => "mjpeg",
            0x6e => "jpeg2000",
            _ => "other",
        }
        .to_string(),
    );
    let dsi = descriptor(&mut r).filter(|(tag, _)| *tag == 5).map(|(_, d)| d);
    if matches!(object, 0x20 | 0x60..=0x65 | 0x6a) {
        t.decoder_config = dsi.map(<[u8]>::to_vec);
    }
    if let Some(asc) = dsi
        && matches!(object, 0x40 | 0x66..=0x68)
        && let Some(c) = AudioConfig::parse(asc)
    {
        t.profile = Some(aac_profile(c.object).to_string());
        // The decoder's output rate and channels, which the sample entry
        // often gets wrong (HE-AAC's core rate, a hard-coded 2 channels).
        if let Some(rate) = c.rate {
            t.sample_rate = Some(rate);
        }
        if let Some(ch) = c.channels {
            t.channels = Some(ch);
        }
    }
}

/// The parts of an MPEG-4 AudioSpecificConfig that describe the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioConfig {
    /// Audio object type, with SBR / PS signalling resolved (5 = HE-AAC, 29 = HE-AAC v2).
    pub object: u8,
    /// Output sample rate (the SBR rate for HE-AAC).
    pub rate: Option<u32>,
    /// Channels from the channel configuration (`None` when given by a program config).
    pub channels: Option<u16>,
}

const AAC_RATES: [u32; 13] = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350];

impl AudioConfig {
    /// Parse an AudioSpecificConfig (ISO/IEC 14496-3 §1.6.2.1), including
    /// explicit hierarchical SBR / PS signalling and the backward-compatible
    /// `0x2b7` sync extension.
    pub fn parse(asc: &[u8]) -> Option<Self> {
        let mut b = Bits { data: asc, pos: 0 };
        let object_type = |b: &mut Bits<'_>| {
            let ot = b.take(5)?;
            let ot = if ot == 31 { 32 + b.take(6)? } else { ot };
            u8::try_from(ot).ok()
        };
        let rate = |b: &mut Bits<'_>| {
            let i = b.take(4)?;
            if i == 15 { b.take(24) } else { AAC_RATES.get(i as usize).copied() }
        };
        let mut object = object_type(&mut b)?;
        let mut out_rate = rate(&mut b);
        let config = b.take(4)?;
        let mut channels = match config {
            n @ 1..=6 => Some(u16::try_from(n).ok()?),
            11 => Some(7),
            7 | 12 | 14 => Some(8),
            13 => Some(24),
            _ => None, // 0: a program config element gives the layout
        };
        let core = object;
        if object == 5 || object == 29 {
            // Explicit hierarchical signalling: the extension rate, then the core type.
            out_rate = rate(&mut b);
            let _core = object_type(&mut b)?;
            if object == 29 && channels == Some(1) {
                channels = Some(2); // parametric stereo decodes mono to stereo
            }
            return Some(Self { object, rate: out_rate, channels });
        }
        // GASpecificConfig for the common object types, then a sync extension.
        if matches!(core, 1..=4 | 6 | 7 | 17 | 19..=23) {
            let _frame_length = b.take(1)?;
            if b.take(1)? == 1 {
                b.take(14)?; // core coder delay
            }
            let extension = b.take(1)?;
            if config == 0 || extension == 1 {
                return Some(Self { object, rate: out_rate, channels });
            }
            if b.remaining() >= 16 && b.take(11)? == 0x2b7 {
                let ext = object_type(&mut b)?;
                if ext == 5 && b.take(1)? == 1 {
                    object = 5;
                    out_rate = rate(&mut b).or(out_rate);
                    if b.remaining() >= 12 && b.take(11)? == 0x548 && b.take(1)? == 1 {
                        object = 29;
                        if channels == Some(1) {
                            channels = Some(2);
                        }
                    }
                }
            }
        }
        Some(Self { object, rate: out_rate, channels })
    }
}

/// A big-endian bit reader.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn remaining(&self) -> usize {
        (self.data.len() * 8).saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<u32> {
        if n > 32 || self.remaining() < n {
            return None;
        }
        let mut v = 0u32;
        for _ in 0..n {
            let bit = (self.data[self.pos / 8] >> (7 - self.pos % 8)) & 1;
            v = (v << 1) | u32::from(bit);
            self.pos += 1;
        }
        Some(v)
    }
}

/// An AAC audio object type.
pub fn aac_profile(ot: u8) -> &'static str {
    match ot {
        1 => "aac_main",
        2 => "aac_lc",
        3 => "aac_ssr",
        4 => "aac_ltp",
        5 => "he_aac",
        6 => "aac_scalable",
        17 => "er_aac_lc",
        23 => "aac_ld",
        29 => "he_aac_v2",
        39 => "aac_eld",
        42 => "xhe_aac",
        _ => "aac",
    }
}

fn udta(body: &[u8], m: &mut Movie) {
    for (kind, b) in boxes(body) {
        match &kind {
            b"meta" => meta(b, m),
            b"chpl" => nero_chapters(b, m),
            b"XMP_" if m.xmp.is_none() => m.xmp = Some(b.to_vec()),
            // QuickTime user data text: ©xyz atoms holding (length, language, text) entries.
            [0xa9, ..] if m.items.len() < MAX_ITEMS => {
                let mut r = ByteReader::new(b);
                if let (Ok(n), Ok(_lang)) = (r.be_u16(), r.be_u16())
                    && let Ok(text) = r.bytes(usize::from(n))
                    && n > 0
                {
                    m.items.push(Item { key: format!("udta:{}", fourcc(&kind)), value: Value::Text(mac_text(text)) });
                }
            }
            _ => {}
        }
    }
}

fn mac_text(b: &[u8]) -> String {
    crate::meta::latin1_or_utf8(b).trim_matches(char::from(0)).to_string()
}

fn meta(body: &[u8], m: &mut Movie) {
    // ISO `meta` is a full box; QuickTime's is not (its first child follows).
    let body = if body.get(4..8) == Some(b"hdlr") { body } else { full(body).2 };
    let mut keys = Vec::new();
    if let Some(k) = find(body, *b"keys") {
        let (_, _, d) = full(k);
        let mut r = ByteReader::new(d);
        if let Ok(n) = r.be_u32() {
            for _ in 0..n.min(4096) {
                let (Ok(size), Ok(_ns)) = (r.be_u32(), r.array::<4>()) else { break };
                let Ok(name) = r.bytes((size as usize).saturating_sub(8)) else { break };
                keys.push(String::from_utf8_lossy(name).into_owned());
            }
        }
    }
    let Some(ilst) = find(body, *b"ilst") else { return };
    for (kind, item) in boxes(ilst) {
        if m.items.len() >= MAX_ITEMS {
            break;
        }
        let key = if kind == *b"----" {
            let text = |k: &[u8; 4]| find(item, *k).map(|b| String::from_utf8_lossy(full(b).2).into_owned());
            format!("----:{}:{}", text(b"mean").unwrap_or_default(), text(b"name").unwrap_or_default())
        } else if !keys.is_empty() && kind[0] == 0 {
            let i = u32::from_be_bytes(kind) as usize;
            keys.get(i.wrapping_sub(1)).cloned().unwrap_or_else(|| format!("key:{i}"))
        } else {
            fourcc(&kind)
        };
        for (dk, data) in boxes(item) {
            if dk != *b"data" || data.len() < 8 {
                continue;
            }
            let kind_code = u32::from_be_bytes([0, data[1], data[2], data[3]]);
            let v = &data[8..];
            let value = item_value(&key, kind_code, v);
            m.items.push(Item { key: key.clone(), value });
        }
    }
}

fn item_value(key: &str, kind: u32, v: &[u8]) -> Value {
    match (key, kind) {
        ("trkn" | "disk", 0) if v.len() >= 6 => {
            Value::Pair(u16::from_be_bytes([v[2], v[3]]), u16::from_be_bytes([v[4], v[5]]))
        }
        (_, 1) => Value::Text(String::from_utf8_lossy(v).into_owned()),
        (_, 2) => {
            let units: Vec<u16> = v.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
            Value::Text(String::from_utf16_lossy(&units))
        }
        (_, 13) => Value::Image("image/jpeg", v.to_vec()),
        (_, 14) => Value::Image("image/png", v.to_vec()),
        (_, 27) => Value::Image("image/bmp", v.to_vec()),
        (_, 21 | 0) if (1..=8).contains(&v.len()) => {
            let mut n: i64 = if v[0] & 0x80 != 0 && kind == 21 { -1 } else { 0 };
            for &b in v {
                n = (n << 8) | i64::from(b);
            }
            Value::Int(n)
        }
        (_, 22) if (1..=8).contains(&v.len()) => Value::Int(v.iter().fold(0i64, |n, &b| (n << 8) | i64::from(b))),
        _ => Value::Binary(kind, v.to_vec()),
    }
}

fn nero_chapters(b: &[u8], m: &mut Movie) {
    let (v, _, d) = full(b);
    let mut r = ByteReader::new(d);
    if v == 1 && r.advance(4).is_err() {
        return;
    }
    let Ok(n) = r.u8() else { return };
    for _ in 0..n {
        let (Ok(start), Ok(len)) = (r.be_u64(), r.u8()) else { break };
        let Ok(title) = r.bytes(usize::from(len)) else { break };
        m.chapters.push(Chapter { start_s: start as f64 / 1e7, title: String::from_utf8_lossy(title).into_owned() });
    }
}

/// Chapters from the text track a `tref/chap` points to.
fn chapter_track(src: &mut dyn Source, m: &mut Movie) {
    let Some(id) = m.tracks.iter().flat_map(|t| t.chapter_tracks.iter()).next().copied() else { return };
    let Some(t) = m.tracks.iter().find(|t| t.id == id && t.timescale > 0) else { return };
    let Some(st) = &t.sample_table else { return };
    let timescale = f64::from(t.timescale);
    let offsets = sample_offsets(st, MAX_CHAPTER_SAMPLES);
    let mut time = 0u64;
    let mut times = st.times.iter().flat_map(|&(n, d)| std::iter::repeat_n(d, n as usize));
    let mut out = Vec::new();
    for (i, off) in offsets.into_iter().enumerate() {
        let size = if st.fixed_size > 0 { st.fixed_size } else { st.sizes.get(i).copied().unwrap_or(0) };
        let start = time;
        time += u64::from(times.next().unwrap_or(0));
        if !(2..=4096).contains(&size) {
            continue;
        }
        let Ok(d) = src.read_vec(off, size as usize) else { continue };
        let n = usize::from(u16::from_be_bytes([d[0], d[1]]));
        let text = d.get(2..2 + n).unwrap_or_default();
        let title = if text.starts_with(&[0xfe, 0xff]) {
            let units: Vec<u16> = text[2..].as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(text).into_owned()
        };
        out.push(Chapter { start_s: start as f64 / timescale, title });
    }
    m.chapters = out;
}

/// The text samples of subtitle tracks that are not chapter tracks.
fn text_tracks(src: &mut dyn Source, m: &mut Movie) {
    let chapters: Vec<u32> = m.tracks.iter().flat_map(|t| t.chapter_tracks.iter().copied()).collect();
    let mut budget = MAX_TEXT_BYTES;
    for t in &mut m.tracks {
        let subtitle = matches!(t.handler.as_str(), "text" | "sbtl" | "subt")
            && matches!(t.codec.as_str(), "tx3g" | "text" | "wvtt")
            && !chapters.contains(&t.id);
        let Some(st) = t.sample_table.as_ref().filter(|_| subtitle && t.timescale > 0) else { continue };
        let timescale = f64::from(t.timescale);
        let mut times = st.times.iter().flat_map(|&(n, d)| std::iter::repeat_n(d, n as usize));
        let mut time = 0u64;
        let mut out = Vec::new();
        for (i, off) in sample_offsets(st, MAX_TEXT_SAMPLES).into_iter().enumerate() {
            let size = if st.fixed_size > 0 { st.fixed_size } else { st.sizes.get(i).copied().unwrap_or(0) };
            let start = time;
            time += u64::from(times.next().unwrap_or(0));
            if !(2..=MAX_TEXT_SAMPLE).contains(&size) || u64::from(size) > budget {
                continue;
            }
            budget -= u64::from(size);
            let Ok(d) = src.read_vec(off, size as usize) else { continue };
            let text = if t.codec == "wvtt" { webvtt_sample(&d) } else { timed_text(&d) };
            if !text.trim().is_empty() {
                out.push(TextSample { start_s: start as f64 / timescale, end_s: time as f64 / timescale, text });
            }
        }
        t.text_samples = out;
    }
}

/// A 3GPP timed text / QuickTime text sample: a 16-bit length and the text
/// (UTF-8, or UTF-16 after a byte-order mark); style boxes follow.
fn timed_text(d: &[u8]) -> String {
    let n = usize::from(u16::from_be_bytes([d[0], d[1]]));
    // A length past the sample keeps what is there.
    let text = &d[2..(2 + n).min(d.len())];
    if text.starts_with(&[0xfe, 0xff]) {
        let units: Vec<u16> = text[2..].as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(text).into_owned()
    }
}

/// A WebVTT-in-ISO-BMFF sample: the `payl` text of each `vttc` cue box
/// (`vtte` boxes are empty cues).
fn webvtt_sample(d: &[u8]) -> String {
    let mut out = String::new();
    for (kind, body) in boxes(d) {
        if &kind != b"vttc" {
            continue;
        }
        if let Some(p) = find(body, *b"payl") {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&String::from_utf8_lossy(p));
        }
    }
    out
}

/// Track durations and sample counts from the movie fragments: the
/// fragment duration (`mvex/mehd`) when given, else each track fragment's
/// decode time (`tfdt`) plus its run durations (`trun`, defaulting through
/// `tfhd` and `trex`).
fn fragments(src: &mut dyn Source, moofs: &[TopBox], moov: &[u8], m: &mut Movie) -> Result<(), ExtractError> {
    let mut defaults = std::collections::HashMap::new();
    if let Some(mvex) = find(moov, *b"mvex") {
        for (kind, body) in boxes(mvex) {
            let (v, _, d) = full(body);
            let mut r = ByteReader::new(d);
            match &kind {
                b"mehd" => {
                    let dur = if v == 1 { r.be_u64() } else { r.be_u32().map(u64::from) };
                    if let Ok(dur) = dur
                        && m.duration == 0
                    {
                        m.duration = dur;
                    }
                }
                b"trex" => {
                    if let (Ok(id), Ok(_desc), Ok(duration)) = (r.be_u32(), r.be_u32(), r.be_u32()) {
                        defaults.insert(id, duration);
                    }
                }
                _ => {}
            }
        }
    }
    let mut ends: std::collections::HashMap<u32, (u64, u64)> = std::collections::HashMap::new();
    for b in moofs {
        let moof = src.read_vec(b.at, usize::try_from(b.len).unwrap_or(0))?;
        for (kind, traf) in boxes(&moof) {
            if kind != *b"traf" {
                continue;
            }
            let Some(tfhd) = find(traf, *b"tfhd") else { continue };
            let (_, flags, d) = full(tfhd);
            let mut r = ByteReader::new(d);
            let Ok(id) = r.be_u32() else { continue };
            if flags & 1 != 0 && r.advance(8).is_err() {
                continue;
            }
            if flags & 2 != 0 && r.advance(4).is_err() {
                continue;
            }
            let mut default = defaults.get(&id).copied().unwrap_or(0);
            if flags & 8 != 0 {
                default = r.be_u32().unwrap_or(default);
            }
            let entry = ends.entry(id).or_default();
            if let Some(tfdt) = find(traf, *b"tfdt") {
                let (v, _, d) = full(tfdt);
                let mut r = ByteReader::new(d);
                if let Ok(t) = if v == 1 { r.be_u64() } else { r.be_u32().map(u64::from) } {
                    entry.0 = t;
                }
            }
            for (k, trun) in boxes(traf) {
                if k != *b"trun" {
                    continue;
                }
                let (_, flags, d) = full(trun);
                let mut r = ByteReader::new(d);
                let Ok(n) = r.be_u32() else { continue };
                let skip = 4 * usize::from(flags & 1 != 0) + 4 * usize::from(flags & 4 != 0);
                if r.advance(skip).is_err() {
                    continue;
                }
                entry.1 += u64::from(n);
                if flags & 0x100 == 0 {
                    entry.0 += u64::from(n) * u64::from(default);
                    continue;
                }
                let per = 4 * (1 + [0x200, 0x400, 0x800].iter().filter(|f| flags & **f != 0).count());
                for chunk in r.rest().chunks_exact(per).take(n as usize) {
                    entry.0 += u64::from(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                }
            }
        }
    }
    for t in &mut m.tracks {
        if let Some(&(end, samples)) = ends.get(&t.id) {
            t.fragment_samples = samples;
            if t.duration == 0 {
                t.duration = end;
            }
        }
    }
    Ok(())
}

/// File offsets of the first `max` samples.
fn sample_offsets(st: &SampleTable, max: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let mut sample = 0usize;
    for (ci, &chunk_off) in st.chunk_offsets.iter().enumerate() {
        let chunk = u32::try_from(ci + 1).unwrap_or(u32::MAX);
        let per = st.to_chunk.iter().rev().find(|(first, _)| *first <= chunk).map_or(1, |(_, n)| *n);
        let mut off = chunk_off;
        for _ in 0..per {
            if out.len() >= max {
                return out;
            }
            out.push(off);
            let size = if st.fixed_size > 0 { st.fixed_size } else { st.sizes.get(sample).copied().unwrap_or(0) };
            off += u64::from(size);
            sample += 1;
        }
    }
    out
}

/// A four-character code as text.
pub fn fourcc(b: &[u8]) -> String {
    let s: String = b.iter().map(|&c| char::from(c)).collect();
    s.trim_end_matches(['\0', ' ']).to_string()
}

/// Seconds since 1904-01-01 as an RFC 3339 UTC timestamp (`None` for 0 or
/// out of range).
pub fn mac_time(secs: u64) -> Option<String> {
    const EPOCH_1904: i64 = -2_082_844_800;
    if secs == 0 {
        return None;
    }
    let unix = EPOCH_1904.checked_add(i64::try_from(secs).ok()?)?;
    let ts = jiff::Timestamp::from_second(unix).ok()?;
    Some(ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtitle_samples() {
        let bx = |kind: &[u8; 4], body: &[u8]| {
            let mut v = u32::try_from(body.len() + 8).unwrap().to_be_bytes().to_vec();
            v.extend_from_slice(kind);
            v.extend_from_slice(body);
            v
        };
        let mut cue = bx(b"iden", b"c1");
        cue.extend(bx(b"payl", b"<v Ana>Hello"));
        let mut sample = bx(b"vttc", &cue);
        sample.extend(bx(b"vtte", b""));
        sample.extend(bx(b"vttc", &bx(b"payl", b"again")));
        assert_eq!(webvtt_sample(&sample), "<v Ana>Hello\nagain");
        assert_eq!(timed_text(b"\x00\x05Hello\x00\x00\x00\x0cstyl"), "Hello");
        assert_eq!(timed_text(b"\x00\x06\xfe\xff\x00H\x00i"), "Hi");
        assert_eq!(timed_text(b"\x00\x09ab"), "ab");
    }

    #[test]
    fn languages_times_and_descriptors() {
        assert_eq!(packed_language(0x15c7).as_deref(), Some("eng"));
        assert_eq!(packed_language(0x55c4).as_deref(), Some("und"));
        assert_eq!(packed_language(0), None);
        assert_eq!(mac_time(3_786_912_000).as_deref(), Some("2024-01-01T00:00:00Z"));
        assert_eq!(mac_time(0), None);
        let mut r = ByteReader::new(&[5, 0x82, 0x01, 1, 2]);
        assert_eq!(descriptor(&mut r), None); // 257 bytes do not fit
        let mut r = ByteReader::new(&[5, 0x80, 0x02, 1, 2]);
        assert_eq!(descriptor(&mut r), Some((5, &[1u8, 2][..])));
        assert_eq!(fourcc(b"mp4a"), "mp4a");
        // AAC-LC 24 kHz stereo with a sync extension declaring SBR at 48 kHz (Apple HE-AAC).
        let he = AudioConfig::parse(&[0x13, 0x10, 0x56, 0xe5, 0x98]).unwrap();
        assert_eq!((he.object, he.rate, he.channels), (5, Some(48000), Some(2)));
        let lc = AudioConfig::parse(&[0x12, 0x10]).unwrap();
        assert_eq!((lc.object, lc.rate, lc.channels), (2, Some(44100), Some(2)));
        // Explicit HE-AAC v2: object 29, 24 kHz mono core, extension rate 48 kHz.
        let v2 = AudioConfig::parse(&[0xeb, 0x09, 0x88, 0x00]).unwrap();
        assert_eq!((v2.object, v2.rate, v2.channels), (29, Some(48000), Some(2)));
        assert_eq!(item_value("tmpo", 21, &[0, 96]), Value::Int(96));
        assert_eq!(item_value("trkn", 0, &[0, 0, 0, 3, 0, 9, 0, 0]), Value::Pair(3, 9));
    }
}
