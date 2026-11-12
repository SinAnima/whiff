//! `image` extractors (feature `common`): raster formats, camera raw,
//! layered documents, vector images and GPU textures.
//!
//! Extractors read headers and structure only (no pixel decoding) and hand
//! embedded EXIF / XMP / IPTC / ICC / Photoshop blocks to `whiff::meta`.

// Header parsers follow their specifications' field names (`w`, `h`, `x0`,
// `y1`) and keep a reader `r` and layout `l` in scope: short names are clearer here.
#![allow(clippy::many_single_char_names, clippy::similar_names)]

pub(crate) mod assets;
pub(crate) mod bmp;
pub(crate) mod codecs;
pub(crate) mod dds;
pub(crate) mod diagram;
pub(crate) mod emf;
pub(crate) mod exr;
pub(crate) mod film;
pub(crate) mod gif;
pub(crate) mod hdr;
pub(crate) mod heif;
pub(crate) mod ico;
pub(crate) mod jp2;
pub(crate) mod jpeg;
pub(crate) mod jxl;
pub(crate) mod ktx;
pub(crate) mod layered;
pub(crate) mod pcx;
pub(crate) mod png;
pub(crate) mod pnm;
pub(crate) mod psd;
pub(crate) mod qoi;
pub(crate) mod raw;
pub(crate) mod retro;
pub(crate) mod sidecar;
pub(crate) mod slide;
pub(crate) mod svg;
pub(crate) mod textures;
pub(crate) mod tga;
pub(crate) mod tiff;
pub(crate) mod webp;
pub(crate) mod xcf;

pub(crate) use crate::plugin::mp4::{TopBox, boxes, top_boxes};

/// The body of a top-level box, if it is at most `max` bytes.
pub(crate) fn read_box(src: &mut dyn crate::plugin::Source, b: &TopBox, max: u64) -> Option<Vec<u8>> {
    (b.len <= max).then(|| src.read_vec(b.at, usize::try_from(b.len).ok()?).ok()).flatten()
}

/// The first box of `kind` among `data`'s boxes.
pub(crate) fn find_box(data: &[u8], kind: [u8; 4]) -> Option<&[u8]> {
    boxes(data).find(|(k, _)| *k == kind).map(|(_, b)| b)
}

/// A computed size in pixels (from millimetres, inches, user units…):
/// rounded, with negative and non-finite values as 0.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // clamped to the u32 range first
pub(crate) fn px(v: f64) -> u32 {
    if v.is_finite() { v.round().clamp(0.0, f64::from(u32::MAX)) as u32 } else { 0 }
}

/// A four-character code as text.
pub(crate) fn fourcc(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim_end_matches(['\0', ' ']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterates_boxes() {
        let mut d = Vec::new();
        d.extend_from_slice(&12u32.to_be_bytes());
        d.extend_from_slice(b"ftypabcd");
        d.extend_from_slice(&9u32.to_be_bytes());
        d.extend_from_slice(b"free!");
        d.extend_from_slice(&100u32.to_be_bytes()); // does not fit
        d.extend_from_slice(b"mdat");
        let found: Vec<[u8; 4]> = boxes(&d).map(|(k, _)| k).collect();
        assert_eq!(found, [*b"ftyp", *b"free"]);
        assert_eq!(find_box(&d, *b"ftyp"), Some(&b"abcd"[..]));
        assert_eq!(boxes(&[0u8, 0, 0, 1]).count(), 0);
    }
}
