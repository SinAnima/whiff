//! LizardTech MrSID rasters: identified by their `msid` signature, with
//! the format version byte that follows (MrSID generation 2 / 3 / 4). The
//! image itself (size, bands, CRS) needs the vendor's decoder and is not
//! read.
//!
//! Specification: none published; the signature is the one GDAL's MrSID
//! driver checks.

use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for MrSID rasters.
pub struct MrSid;

static META: ExtractorMeta = ExtractorMeta {
    id: "geo.mrsid",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "mrsid",
        name: "MrSID raster",
        family: "geo",
        mimes: &["image/x-mrsid"],
        extensions: &["sid"],
        magic: &[Magic::prefix(b"msid")],
        parent: None,
    }],
};

impl Extractor for MrSid {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let h = src.read_vec(0, usize::try_from(src.len().min(8)).unwrap_or(0))?;
        if let Some(&v) = h.get(4) {
            cx.format_set("version_byte", v);
        }
        Ok(())
    }
}

crate::register_extractor!(MrSid);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("mrsid");
}
