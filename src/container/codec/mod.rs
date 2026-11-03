//! Decompression for every codec whiff reads: deflate, zlib and gzip
//! (`miniz_oxide`), bzip2, LZ4, Snappy and Unix `compress` (in-house), xz,
//! `.lzma`, lzip and raw LZMA / LZMA2 (`lzma-rust2`), Zstandard (`ruzstd`)
//! and Brotli (`brotli-decompressor`).
//!
//! [`decode`] turns compressed bytes into at most `max` bytes of output,
//! charged to the decompression budget (the zip-bomb guard). Reaching the
//! cap is not an error: the caller gets the prefix and [`End::Limit`], which
//! is what detection of the inner stream and listing a `.tar.gz` need.
//! Memory stays bounded by the output: LZMA dictionaries and Zstandard
//! windows are never larger than the output still allowed, since nothing
//! beyond it is ever referenced.

mod bzip2;
mod lz4;
mod lzw;
mod snappy;
mod xz;

use std::io::Read;

use crate::error::ExtractError;
use crate::io::Budget;

pub use xz::{XzIndex, filter_name as xz_filter_name, lzma2_dict_size, xz_first_filters, xz_index};

/// A compression codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// Raw deflate (RFC 1951): ZIP entries.
    Deflate,
    /// zlib (RFC 1950).
    Zlib,
    /// gzip (RFC 1952), every member.
    Gzip,
    /// bzip2, every stream.
    Bzip2,
    /// xz, every stream and block.
    Xz,
    /// The `.lzma` ("LZMA alone") format: a 13-byte header, then LZMA.
    LzmaAlone,
    /// Raw LZMA with its properties byte and dictionary size (7z, ZIP
    /// method 14), and the uncompressed size when known.
    Lzma {
        /// `lc` / `lp` / `pb` packed as `(pb * 5 + lp) * 9 + lc`.
        props: u8,
        /// Dictionary size.
        dict_size: u32,
        /// Uncompressed size (`None`: up to the end marker).
        size: Option<u64>,
    },
    /// Raw LZMA2 with its dictionary size (7z).
    Lzma2 {
        /// Dictionary size.
        dict_size: u32,
    },
    /// lzip, every member.
    Lzip,
    /// Zstandard, every frame (skippable frames skipped).
    Zstd,
    /// LZ4 frame format (and the legacy format), every frame.
    Lz4,
    /// Brotli.
    Brotli,
    /// Unix `compress` (`.Z`, LZW).
    Lzw,
    /// Snappy framing format.
    Snappy,
    /// One raw Snappy block (Parquet, ORC, Arrow pages).
    SnappyBlock,
    /// One raw LZ4 block of at most `max` bytes (ORC, Parquet `LZ4_RAW`).
    Lz4Block {
        /// The block's largest output.
        max: usize,
    },
}

/// How decoding ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// The stream ended normally.
    Complete,
    /// The output reached the cap; more would follow.
    Limit,
    /// The input ended before the stream did.
    Truncated,
    /// The data is malformed (or uses an unsupported feature) here.
    Error(String),
}

/// Decoder output.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// The decompressed bytes (all of them, or a prefix).
    pub data: Vec<u8>,
    /// How decoding ended.
    pub end: End,
    /// Input bytes the stream used, when it ended normally (what follows
    /// is trailing data).
    pub consumed: usize,
}

impl Decoded {
    /// Whether the whole stream was decoded.
    pub fn complete(&self) -> bool {
        self.end == End::Complete
    }
}

/// Why an in-house decoder stopped early.
#[derive(Debug)]
pub(crate) enum Stop {
    /// The output cap was reached.
    Full,
    /// The input ended.
    Truncated,
    /// Malformed data.
    Bad(String),
    /// The deadline passed.
    Timeout,
}

pub(crate) type Step<T> = Result<T, Stop>;

pub(crate) fn bad<T>(what: impl Into<String>) -> Step<T> {
    Err(Stop::Bad(what.into()))
}

/// Charge the budget every this many bytes, so the deadline is checked.
const CHARGE_EVERY: usize = 1 << 20;

/// Bounded output, charged to the budget as it grows.
pub(crate) struct Sink<'b> {
    pub out: Vec<u8>,
    max: usize,
    budget: &'b Budget,
    charged: usize,
}

impl<'b> Sink<'b> {
    fn new(max: usize, budget: &'b Budget) -> Self {
        let room = usize::try_from(budget.remaining_decompressed()).unwrap_or(usize::MAX);
        Self { out: Vec::new(), max: max.min(room), budget, charged: 0 }
    }

    /// Bytes that may still be written.
    pub fn room(&self) -> usize {
        self.max - self.out.len()
    }

    fn charge(&mut self) -> Step<()> {
        let n = self.out.len() - self.charged;
        self.charged = self.out.len();
        self.budget.charge_decompressed(n as u64).map_err(|e| match e {
            crate::io::SourceError::Timeout => Stop::Timeout,
            _ => Stop::Full,
        })
    }

    fn grown(&mut self) -> Step<()> {
        if self.out.len() - self.charged >= CHARGE_EVERY { self.charge() } else { Ok(()) }
    }

    /// Append `data`, as much as fits.
    pub fn extend(&mut self, data: &[u8]) -> Step<()> {
        let n = data.len().min(self.room());
        self.out.extend_from_slice(&data[..n]);
        self.grown()?;
        if n < data.len() { Err(Stop::Full) } else { Ok(()) }
    }

    /// Append one byte.
    pub fn push(&mut self, b: u8) -> Step<()> {
        if self.room() == 0 {
            return Err(Stop::Full);
        }
        self.out.push(b);
        self.grown()
    }

    /// Append `len` bytes copied from `dist` bytes back (LZ77), the copy
    /// overlapping itself when `dist < len`. `floor` is where the current
    /// window starts: references before it are malformed.
    pub fn copy_back(&mut self, floor: usize, dist: usize, len: usize) -> Step<()> {
        if dist == 0 || dist > self.out.len() - floor {
            return bad("match distance");
        }
        let n = len.min(self.room());
        let start = self.out.len() - dist;
        if dist >= n {
            self.out.extend_from_within(start..start + n);
        } else {
            for i in 0..n {
                let b = self.out[start + i];
                self.out.push(b);
            }
        }
        self.grown()?;
        if n < len { Err(Stop::Full) } else { Ok(()) }
    }
}

/// Decompress `input` with `codec` into at most `max` bytes (and no more
/// than the decompression budget has left). Only the deadline is an error;
/// malformed or truncated data gives what decoded before it.
pub fn decode(input: &[u8], codec: Codec, max: usize, budget: &Budget) -> Result<Decoded, ExtractError> {
    let mut sink = Sink::new(max, budget);
    let capped = sink.max < max;
    let result = match codec {
        Codec::Deflate => inflate(input, false, &mut sink),
        Codec::Zlib => inflate(input, true, &mut sink),
        Codec::Gzip => gzip(input, &mut sink),
        Codec::Bzip2 => bzip2::decode(input, &mut sink),
        Codec::Xz => xz::decode(input, &mut sink),
        Codec::LzmaAlone => lzma_alone(input, &mut sink),
        Codec::Lzma { props, dict_size, size } => {
            lzma_raw(input, props, dict_size, size.unwrap_or(u64::MAX), &mut sink)
        }
        Codec::Lzma2 { dict_size } => lzma2(input, dict_size, &mut sink),
        Codec::Lzip => lzip(input, &mut sink),
        Codec::Zstd => zstd(input, &mut sink),
        Codec::Lz4 => lz4::decode(input, &mut sink),
        Codec::Brotli => brotli(input, &mut sink),
        Codec::Lzw => lzw::decode(input, &mut sink),
        Codec::Snappy => snappy::decode(input, &mut sink),
        Codec::SnappyBlock => snappy::raw(input, &mut sink),
        Codec::Lz4Block { max } => lz4::block(input, 0, max, &mut sink).map(|()| input.len()),
    };
    let (end, consumed) = match result {
        Ok(consumed) => (End::Complete, consumed),
        Err(Stop::Full) => {
            if capped {
                budget.hit("decompressed_bytes");
            }
            (End::Limit, 0)
        }
        Err(Stop::Truncated) => (End::Truncated, 0),
        Err(Stop::Bad(e)) => (End::Error(e), 0),
        Err(Stop::Timeout) => return Err(ExtractError::Timeout),
    };
    sink.charge().map_err(|_| ExtractError::Timeout).or_else(|e| if end == End::Limit { Ok(()) } else { Err(e) })?;
    Ok(Decoded { data: sink.out, end, consumed })
}

/// One deflate (or zlib) stream; returns the input bytes it used.
fn inflate(input: &[u8], zlib: bool, sink: &mut Sink<'_>) -> Step<usize> {
    use miniz_oxide::inflate::TINFLStatus;
    use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
    const WINDOW: usize = 1 << 15;
    let mut state = Box::<DecompressorOxide>::default();
    let mut ring = vec![0u8; WINDOW];
    let mut flags = inflate_flags::TINFL_FLAG_HAS_MORE_INPUT;
    if zlib {
        flags |= inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER;
    }
    let (mut read, mut pos) = (0usize, 0usize);
    loop {
        if read == input.len() {
            flags &= !inflate_flags::TINFL_FLAG_HAS_MORE_INPUT;
        }
        let (status, r, w) = decompress(&mut state, &input[read..], &mut ring, pos, flags);
        read += r;
        sink.extend(&ring[pos..pos + w])?;
        pos = (pos + w) & (WINDOW - 1);
        match status {
            TINFLStatus::Done => return Ok(read),
            TINFLStatus::HasMoreOutput => {}
            TINFLStatus::NeedsMoreInput if read < input.len() || r > 0 || w > 0 => {}
            TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => return Err(Stop::Truncated),
            other => return bad(format!("deflate data ({other:?})")),
        }
    }
}

/// Largest output of one MSZIP block.
const MSZIP_BLOCK: usize = 32_768;

/// Decode Microsoft's MSZIP (cabinet files): blocks that each start with
/// `CK` and hold a deflate stream whose matches may reach back into the
/// output of the blocks before it. At most `max` bytes.
pub fn mszip<'a>(
    blocks: impl IntoIterator<Item = &'a [u8]>,
    max: usize,
    budget: &Budget,
) -> Result<Decoded, ExtractError> {
    use miniz_oxide::inflate::TINFLStatus;
    use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
    let mut sink = Sink::new(max, budget);
    let flags = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    let mut end = End::Complete;
    let mut state = Box::<DecompressorOxide>::default();
    for block in blocks {
        let Some(body) = block.strip_prefix(b"CK") else {
            end = End::Error("MSZIP block signature".into());
            break;
        };
        let start = sink.out.len();
        if sink.room() == 0 {
            end = End::Limit;
            break;
        }
        state.init();
        sink.out.resize(start + MSZIP_BLOCK, 0);
        let (status, _, written) = decompress(&mut state, body, &mut sink.out, start, flags);
        sink.out.truncate(start + written);
        if sink.out.len() > sink.max {
            sink.out.truncate(sink.max);
            end = End::Limit;
            break;
        }
        match status {
            TINFLStatus::Done => {}
            TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
                end = End::Truncated;
                break;
            }
            other => {
                end = End::Error(format!("MSZIP block ({other:?})"));
                break;
            }
        }
        if let Err(Stop::Timeout) = sink.grown() {
            return Err(ExtractError::Timeout);
        }
    }
    sink.charge().map_err(|_| ExtractError::Timeout).or_else(|e| if end == End::Limit { Ok(()) } else { Err(e) })?;
    Ok(Decoded { data: sink.out, end, consumed: 0 })
}

/// The length of a gzip member header at the start of `data`.
pub fn gzip_header_len(data: &[u8]) -> Option<usize> {
    if data.len() < 10 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return None;
    }
    let flags = data[3];
    let mut i = 10usize;
    if flags & 4 != 0 {
        let n = usize::from(u16::from_le_bytes([*data.get(i)?, *data.get(i + 1)?]));
        i += 2 + n;
    }
    for bit in [8u8, 16] {
        if flags & bit != 0 {
            i += data.get(i..)?.iter().position(|&b| b == 0)? + 1;
        }
    }
    if flags & 2 != 0 {
        i += 2;
    }
    (i <= data.len()).then_some(i)
}

fn gzip(input: &[u8], sink: &mut Sink<'_>) -> Step<usize> {
    let mut at = 0;
    loop {
        let Some(header) = gzip_header_len(&input[at..]) else {
            return if at > 0 {
                Ok(at)
            } else if input.len() < 10 || input.starts_with(&[0x1f, 0x8b, 8]) {
                Err(Stop::Truncated)
            } else {
                bad("gzip header")
            };
        };
        at += header;
        at += inflate(&input[at..], false, sink)?;
        if input.len() < at + 8 {
            return Err(Stop::Truncated);
        }
        at += 8;
        // Another member (`cat a.gz b.gz`, bgzip blocks) follows, or
        // trailing data (often zero padding).
        if !input[at..].starts_with(&[0x1f, 0x8b]) {
            return Ok(at);
        }
    }
}

/// A [`Read`] over a slice that remembers how much was read.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Read for Cursor<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Copy a decoder's output into the sink until it ends.
fn drain(mut reader: impl Read, sink: &mut Sink<'_>) -> Step<()> {
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let want = buf.len().min(sink.room().max(1));
        match reader.read(&mut buf[..want]) {
            Ok(0) => return Ok(()),
            Ok(n) => sink.extend(&buf[..n])?,
            Err(e) => return bad(e.to_string()),
        }
        if sink.room() == 0 {
            // Full, unless the stream also ends right here.
            return match reader.read(&mut buf[..1]) {
                Ok(0) => Ok(()),
                _ => Err(Stop::Full),
            };
        }
    }
}

/// A dictionary no larger than the output still allowed (nothing beyond
/// it is referenced), and at least 4 KiB.
fn capped_dict(dict_size: u32, sink: &Sink<'_>) -> u32 {
    let room = u32::try_from(sink.room()).unwrap_or(u32::MAX);
    dict_size.min(room.saturating_add(1 << 12)).max(1 << 12)
}

/// A decoder error once all input was read means the input was cut short.
fn truncated_if_exhausted(result: Step<()>, used: usize, input: &[u8]) -> Step<usize> {
    match result {
        Err(Stop::Bad(_)) if used >= input.len() => Err(Stop::Truncated),
        Err(e) => Err(e),
        Ok(()) => Ok(used),
    }
}

fn lzma_raw(input: &[u8], props: u8, dict_size: u32, size: u64, sink: &mut Sink<'_>) -> Step<usize> {
    let mut cursor = Cursor { data: input, pos: 0 };
    let dict = capped_dict(dict_size, sink);
    let reader = lzma_rust2::LzmaReader::new_with_props(&mut cursor, size, props, dict, None)
        .map_err(|e| Stop::Bad(format!("LZMA properties: {e}")))?;
    let result = drain(reader, sink);
    truncated_if_exhausted(result, cursor.pos, input)
}

fn lzma_alone(input: &[u8], sink: &mut Sink<'_>) -> Step<usize> {
    let Some(header) = input.get(..13) else { return Err(Stop::Truncated) };
    let dict = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
    let size = u64::from_le_bytes(header[5..13].try_into().unwrap_or_default());
    Ok(13 + lzma_raw(&input[13..], header[0], dict, size, sink)?)
}

fn lzma2(input: &[u8], dict_size: u32, sink: &mut Sink<'_>) -> Step<usize> {
    let mut cursor = Cursor { data: input, pos: 0 };
    let dict = capped_dict(dict_size, sink);
    let reader = lzma_rust2::Lzma2Reader::new(&mut cursor, dict, None);
    let result = drain(reader, sink);
    truncated_if_exhausted(result, cursor.pos, input)
}

/// lzip dictionary size from its coded byte.
pub fn lzip_dict_size(b: u8) -> u32 {
    let base = 1u32 << (b & 0x1f).clamp(12, 29);
    base - (base / 16) * u32::from(b >> 5)
}

/// lzip members found from the end of `input`, the way lzip does it: each
/// trailer ends with its member's size. `None` unless they cover all of it.
fn lzip_members(input: &[u8]) -> Option<Vec<(usize, usize)>> {
    let mut members = Vec::new();
    let mut end = input.len();
    while end > 0 {
        let size = u64::from_le_bytes(input.get(end.checked_sub(8)?..end)?.try_into().ok()?);
        let start = end.checked_sub(usize::try_from(size).ok()?)?;
        if size < 26 || !input[start..].starts_with(b"LZIP") {
            return None;
        }
        members.push((start, end));
        end = start;
    }
    members.reverse();
    Some(members)
}

fn lzip(input: &[u8], sink: &mut Sink<'_>) -> Step<usize> {
    if !input.starts_with(b"LZIP") {
        return if input.len() < 6 { Err(Stop::Truncated) } else { bad("lzip header") };
    }
    // The LZMA reader reads ahead, so members are bounded by their trailers;
    // a cut file has only its first member's start.
    let members = lzip_members(input);
    let whole = members.is_some();
    let members = members.unwrap_or_else(|| vec![(0, input.len() + 20)]);
    for (start, end) in members {
        let Some(&dict) = input.get(start + 5) else { return Err(Stop::Truncated) };
        let body = &input[start + 6..(end - 20).min(input.len())];
        let mut cursor = Cursor { data: body, pos: 0 };
        let size = capped_dict(lzip_dict_size(dict), sink);
        // lc 3, lp 0, pb 2, end marker.
        let reader = lzma_rust2::LzmaReader::new(&mut cursor, u64::MAX, 3, 0, 2, size, None)
            .map_err(|e| Stop::Bad(format!("lzip: {e}")))?;
        let result = drain(reader, sink);
        truncated_if_exhausted(result, cursor.pos, body).map_err(|e| match e {
            Stop::Truncated if whole => Stop::Bad("lzip member".into()),
            e => e,
        })?;
    }
    if whole { Ok(input.len()) } else { Err(Stop::Truncated) }
}

/// Largest Zstandard window accepted (the reference decoder's default limit).
const ZSTD_MAX_WINDOW: u64 = 1 << 27;

fn zstd(input: &[u8], sink: &mut Sink<'_>) -> Step<usize> {
    let mut at = 0;
    loop {
        let Some(magic) = input.get(at..at + 4) else { return if at == 0 { Err(Stop::Truncated) } else { Ok(at) } };
        let magic = u32::from_le_bytes([magic[0], magic[1], magic[2], magic[3]]);
        if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
            let Some(len) = input.get(at + 4..at + 8) else { return Err(Stop::Truncated) };
            at += 8 + u32::from_le_bytes([len[0], len[1], len[2], len[3]]) as usize;
            if at > input.len() {
                return Err(Stop::Truncated);
            }
            continue;
        }
        if magic != 0xFD2F_B528 {
            return if at == 0 { bad("zstd magic") } else { Ok(at) };
        }
        let mut cursor = Cursor { data: &input[at..], pos: 0 };
        // ruzstd refuses a larger window rather than decoding a prefix, so
        // the window is not capped by the output allowed.
        let reader = match ruzstd::decoding::StreamingDecoder::new_with_max_window_size(&mut cursor, ZSTD_MAX_WINDOW) {
            Ok(r) => r,
            Err(_) if input.len() - at < 18 => return Err(Stop::Truncated),
            Err(e) => return bad(format!("zstd frame header: {e}")),
        };
        let result = drain(reader, sink);
        at += truncated_if_exhausted(result, cursor.pos, &input[at..])?;
    }
}

fn brotli(input: &[u8], sink: &mut Sink<'_>) -> Step<usize> {
    let mut cursor = Cursor { data: input, pos: 0 };
    let reader = brotli_decompressor::Decompressor::new(&mut cursor, 1 << 16);
    let result = drain(reader, sink);
    truncated_if_exhausted(result, cursor.pos, input)
}

/// CRC-32 (IEEE 802.3, reflected), as ZIP, gzip and xz use it.
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0, data)
}

/// Continue a CRC-32 over more data.
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in (0u32..).zip(t.iter_mut()) {
            let mut c = i;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *slot = c;
        }
        t
    });
    let mut c = !crc;
    for &b in data {
        c = table[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8], codec: Codec, max: usize) -> Decoded {
        decode(input, codec, max, &Budget::unlimited()).unwrap()
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_update(crc32(b"1234"), b"56789"), 0xCBF4_3926);
    }

    #[test]
    fn deflate_zlib_gzip_and_limits() {
        let text = b"harbour bells ring out over the sea ".repeat(500);
        let raw = miniz_oxide::deflate::compress_to_vec(&text, 6);
        let d = run(&raw, Codec::Deflate, usize::MAX);
        assert_eq!((d.data.as_slice(), d.end.clone(), d.consumed), (text.as_slice(), End::Complete, raw.len()));
        let z = miniz_oxide::deflate::compress_to_vec_zlib(&text, 6);
        assert_eq!(run(&z, Codec::Zlib, usize::MAX).data, text);
        // Two gzip members and trailing zeros.
        let mut member = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 3];
        member.extend_from_slice(b"bells.txt\0");
        member.extend_from_slice(&raw);
        member.extend_from_slice(&crc32(&text).to_le_bytes());
        member.extend_from_slice(&u32::try_from(text.len()).unwrap().to_le_bytes());
        let mut gz = [member.clone(), member].concat();
        let members = gz.len();
        gz.extend_from_slice(&[0; 7]);
        let d = run(&gz, Codec::Gzip, usize::MAX);
        assert_eq!((d.data.len(), d.end.clone(), d.consumed), (text.len() * 2, End::Complete, members));
        let d = run(&gz, Codec::Gzip, 100);
        assert_eq!((d.data.as_slice(), d.end), (&text[..100], End::Limit));
        let d = run(&gz[..40], Codec::Gzip, usize::MAX);
        assert_eq!(d.end, End::Truncated);
        assert!(matches!(run(b"\x1f\x8b\x08\0\0\0\0\0\0\x03\xff\xff", Codec::Gzip, 99).end, End::Error(_)));
    }

    #[test]
    fn budget_caps_output() {
        let text = vec![b'a'; 100_000];
        let raw = miniz_oxide::deflate::compress_to_vec(&text, 6);
        let budget = Budget::new(u64::MAX, 1000, None);
        let d = decode(&raw, Codec::Deflate, usize::MAX, &budget).unwrap();
        assert_eq!((d.data.len(), d.end), (1000, End::Limit));
        assert!(budget.limits_hit().contains(&"decompressed_bytes"));
        assert_eq!(budget.remaining_decompressed(), 0);
    }

    #[test]
    fn copy_back_overlaps_and_checks_distance() {
        let budget = Budget::unlimited();
        let mut s = Sink::new(10, &budget);
        s.extend(b"ab").unwrap();
        s.copy_back(0, 2, 5).unwrap();
        assert_eq!(s.out, b"abababa");
        assert!(matches!(s.copy_back(0, 8, 1), Err(Stop::Bad(_))));
        assert!(matches!(s.copy_back(0, 1, 9), Err(Stop::Full)));
        assert_eq!(s.out.len(), 10);
    }

    #[test]
    fn lzip_dictionary_sizes() {
        assert_eq!(lzip_dict_size(0x0c), 4096);
        assert_eq!(lzip_dict_size(0x17), 8 << 20);
        assert_eq!(lzip_dict_size(0x1d), 1 << 29);
        assert_eq!(lzip_dict_size(0xd3), (1 << 19) - 6 * (1 << 15));
    }
}
