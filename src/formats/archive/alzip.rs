//! ALZip archives (`.alz`, ESTsoft): an `ALZ\x01` header, then a local
//! header per entry (`BLZ\x01`: name, attributes, DOS time, a descriptor
//! whose high nibble gives the width of the size fields, method, CRC-32 and
//! sizes) followed by its data, and the `CLZ` end records. Stored and
//! deflated entries are handed on.
//!
//! Specification: the `unalz` sources (`UnAlz.h`); The Unarchiver's
//! `XADALZipParser`.

use super::{Entry, Inventory, Kind, child, dos_stamp, wanted};
use crate::plugin::{
    ByteReader, Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source,
    latin1_or_utf8,
};

/// Extractor for ALZip archives.
pub struct Alzip;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.alzip",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "alz",
        name: "ALZip archive",
        family: "archive",
        mimes: &["application/x-alz-compressed"],
        extensions: &["alz"],
        magic: &[Magic::prefix(b"ALZ\x01")],
        parent: None,
    }],
};

const MAX_ENTRIES: u64 = 1 << 20;

impl Extractor for Alzip {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let mut inv = Inventory::new();
        let mut pending: Vec<(String, u64, u64, u8, u64)> = Vec::new();
        let mut at = 8u64;
        for i in 0..MAX_ENTRIES {
            if i % 1024 == 1023 {
                cx.checkpoint()?;
            }
            if at + 4 > len {
                inv.truncated = true;
                break;
            }
            let h = src.read_vec(at, usize::try_from((len - at).min(13 + 6 + 16 + 1024)).unwrap_or(0))?;
            match &h[..4] {
                b"BLZ\x01" => {}
                // End of the local headers (comment and end records follow).
                b"CLZ\x01" | b"CLZ\x02" => break,
                _ => {
                    cx.warn(format!("no ALZip header at offset {at}"));
                    inv.truncated = true;
                    break;
                }
            }
            let mut r = ByteReader::new(&h).skip(4)?;
            let name_len = usize::from(r.le_u16()?);
            let attributes = r.u8()?;
            let stamp = r.le_u32()?;
            let descriptor = r.u8()?;
            r.u8()?;
            let width = usize::from(descriptor >> 4);
            let (mut method, mut packed, mut size) = (0u8, 0u64, 0u64);
            if width > 0 {
                if !matches!(width, 1 | 2 | 4 | 8) {
                    return Err(ExtractError::malformed("ALZip size width"));
                }
                method = r.u8()?;
                r.u8()?;
                r.le_u32()?;
                let mut sized = || -> Result<u64, ExtractError> {
                    let b = r.bytes(width)?;
                    Ok(b.iter().rev().fold(0u64, |a, &x| (a << 8) | u64::from(x)))
                };
                packed = sized()?;
                size = sized()?;
            }
            let name = latin1_or_utf8(r.bytes(name_len)?);
            let encrypted = descriptor & 0x01 != 0;
            // An encrypted entry carries a 12-byte check ahead of its data.
            let data_at = at + r.position() as u64 + if encrypted { 12 } else { 0 };
            let dir = attributes & 0x10 != 0;
            let e = Entry {
                path: name,
                kind: if dir { Kind::Dir } else { Kind::File },
                size: Some(if dir { 0 } else { size }),
                compressed: Some(packed),
                modified: dos_stamp(stamp),
                encrypted,
                method: (!dir).then(|| {
                    match method {
                        0 => "stored",
                        1 => "bzip2",
                        2 => "deflate",
                        _ => "other",
                    }
                    .to_string()
                }),
                ..Entry::default()
            };
            if matches!(method, 0 | 2) && wanted(&e) {
                pending.push((e.path.clone(), data_at, packed, method, size));
            }
            inv.push(e);
            at = data_at.saturating_add(packed);
        }
        inv.report(cx, len);
        let limit = cx.parse_limit() as u64;
        for (name, offset, packed, method, size) in pending {
            if cx.child_room() == 0 || offset >= len {
                break;
            }
            let n = packed.min(limit).min(len - offset);
            let raw = src.read_vec(offset, usize::try_from(n).unwrap_or(0))?;
            let (data, complete) = if method == 2 {
                let out = cx.inflate(&raw, Compression::Deflate, usize::try_from(size.min(limit)).unwrap_or(0))?;
                let complete = out.len() as u64 == size;
                (out, complete)
            } else {
                (raw, n == packed)
            };
            if !child(cx, &name, data, complete)? {
                break;
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Alzip);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("alz");
}
