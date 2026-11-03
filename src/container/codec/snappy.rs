//! Snappy framing format (`.sz`): the stream identifier, compressed and
//! uncompressed chunks (checksums not verified), padding and skippable
//! chunks.
//!
//! Specification: Snappy `framing_format.txt` and `format_description.txt`.

use super::{Sink, Step, Stop, bad};

/// The stream identifier chunk.
pub const STREAM_ID: &[u8; 10] = b"\xff\x06\x00\x00sNaPpY";
const MAX_CHUNK: usize = 1 << 16;

/// One raw Snappy block of at most `max_len` bytes.
fn block(data: &[u8], max_len: usize, sink: &mut Sink<'_>) -> Step<()> {
    let start = sink.out.len();
    let mut i = 0;
    let mut expected = 0usize;
    for shift in (0..35).step_by(7) {
        let &b = data.get(i).ok_or_else(|| Stop::Bad("snappy length".into()))?;
        i += 1;
        expected |= usize::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
    }
    if expected > max_len {
        return bad("snappy chunk too large");
    }
    let take = |i: &mut usize, n: usize| -> Step<&[u8]> {
        let s = data.get(*i..*i + n).ok_or_else(|| Stop::Bad("snappy element".into()))?;
        *i += n;
        Ok(s)
    };
    let le = |b: &[u8]| b.iter().rev().fold(0usize, |acc, &x| (acc << 8) | usize::from(x));
    while i < data.len() {
        let tag = data[i];
        i += 1;
        let (len, dist) = match tag & 3 {
            0 => {
                let mut len = usize::from(tag >> 2);
                if len >= 60 {
                    len = le(take(&mut i, len - 59)?);
                }
                sink.extend(take(&mut i, len + 1)?)?;
                continue;
            }
            1 => (4 + usize::from((tag >> 2) & 7), (usize::from(tag >> 5) << 8) | le(take(&mut i, 1)?)),
            2 => (1 + usize::from(tag >> 2), le(take(&mut i, 2)?)),
            _ => (1 + usize::from(tag >> 2), le(take(&mut i, 4)?)),
        };
        if sink.out.len() - start + len > expected {
            return bad("snappy chunk overflow");
        }
        sink.copy_back(start, dist, len)?;
    }
    if sink.out.len() - start == expected { Ok(()) } else { bad("snappy chunk length") }
}

/// Decode a framed Snappy stream; returns the bytes used.
/// A raw Snappy block (no framing), as columnar formats store pages.
pub(super) fn raw(input: &[u8], sink: &mut Sink<'_>) -> Step<usize> {
    block(input, usize::MAX, sink)?;
    Ok(input.len())
}

pub(super) fn decode(input: &[u8], sink: &mut Sink<'_>) -> Step<usize> {
    if !input.starts_with(STREAM_ID) {
        return if input.len() < STREAM_ID.len() { Err(Stop::Truncated) } else { bad("snappy stream identifier") };
    }
    let mut at = 0;
    while at < input.len() {
        let header = input.get(at..at + 4).ok_or(Stop::Truncated)?;
        let len = usize::from(header[1]) | usize::from(header[2]) << 8 | usize::from(header[3]) << 16;
        let body = input.get(at + 4..at + 4 + len).ok_or(Stop::Truncated)?;
        match header[0] {
            0x00 => block(body.get(4..).ok_or_else(|| Stop::Bad("snappy chunk".into()))?, MAX_CHUNK, sink)?,
            0x01 => {
                let data = body.get(4..).ok_or_else(|| Stop::Bad("snappy chunk".into()))?;
                if data.len() > MAX_CHUNK {
                    return bad("snappy chunk too large");
                }
                sink.extend(data)?;
            }
            0xff => {
                if body != b"sNaPpY" {
                    return bad("snappy stream identifier");
                }
            }
            0x02..=0x7f => return bad("snappy reserved chunk"),
            _ => {} // padding and skippable chunks
        }
        at += 4 + len;
    }
    Ok(at)
}

#[cfg(test)]
mod tests {
    use super::super::{Codec, End, decode as run};
    use crate::io::Budget;

    #[test]
    fn chunks() {
        let mut s = super::STREAM_ID.to_vec();
        // Compressed: length 9, literal "abc", copy (1-byte offset) of 6 at distance 3.
        let block = [9, 0x08, b'a', b'b', b'c', 0x09, 3];
        s.extend_from_slice(&[0x00, u8::try_from(block.len() + 4).unwrap(), 0, 0, 0, 0, 0, 0]);
        s.extend_from_slice(&block);
        s.extend_from_slice(&[0xfe, 2, 0, 0, 0, 0]); // padding
        s.extend_from_slice(&[0x01, 6, 0, 0, 0, 0, 0, 0, b'o', b'k']);
        let budget = Budget::unlimited();
        let d = run(&s, Codec::Snappy, usize::MAX, &budget).unwrap();
        assert_eq!((d.data.as_slice(), d.end), (&b"abcabcabcok"[..], End::Complete));
        s.extend_from_slice(&[0x05, 0, 0, 0]);
        assert!(matches!(run(&s, Codec::Snappy, usize::MAX, &budget).unwrap().end, End::Error(_)));
    }
}
