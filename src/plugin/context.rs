use serde_json::Value;

use super::{BlockKind, TextRole, TextStore};
use crate::engine::Options;
use crate::error::ExtractError;
use crate::io::Budget;
use crate::report::{
    Content, ContentDate, DateField, Extent, Heading, ImagePhysical, Language, License, Location, Map, Physical,
    Report, Rights, Risk, Security, Temporal,
};

/// Compressed-data framing understood by [`Context::inflate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Compression {
    /// zlib (RFC 1950): PNG `zTXt` / `iCCP`, PDF `FlateDecode`.
    Zlib,
    /// Raw deflate (RFC 1951): ZIP entries.
    Deflate,
    /// gzip (RFC 1952): `.gz`, SVGZ.
    Gzip,
}

/// The deflate stream inside a gzip member (header skipped).
fn gzip_body(data: &[u8]) -> Result<&[u8], ExtractError> {
    let bad = || ExtractError::malformed("gzip header");
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return Err(bad());
    }
    let flags = data[3];
    let mut i = 10usize;
    if flags & 4 != 0 {
        let n = usize::from(u16::from_le_bytes([*data.get(i).ok_or_else(bad)?, *data.get(i + 1).ok_or_else(bad)?]));
        i += 2 + n;
    }
    for bit in [8u8, 16] {
        if flags & bit != 0 {
            i += data.get(i..).ok_or_else(bad)?.iter().position(|&b| b == 0).ok_or_else(bad)? + 1;
        }
    }
    if flags & 2 != 0 {
        i += 2;
    }
    data.get(i..).ok_or_else(bad)
}

/// Headings kept in `content.outline`.
pub const MAX_OUTLINE: usize = 500;

pub(crate) struct PendingBlock {
    pub kind: BlockKind,
    pub data: Vec<u8>,
}

pub(crate) struct PendingChild {
    pub name: String,
    pub data: Vec<u8>,
    /// The stream a compressed file holds: analysed without using up a
    /// recursion level.
    pub inner: bool,
    /// Only a prefix of the child (decompression stopped at a limit).
    pub truncated: bool,
}

/// The only way an extractor writes output.
///
/// Normalised sections are written through typed writers
/// ([`content`](Self::content), [`temporal`](Self::temporal),
/// [`rights`](Self::rights), [`security`](Self::security),
/// [`physical`](Self::physical)). Scalar fields are **first write wins**:
/// higher-priority sources run first, so later values never overwrite them.
/// Free-form data goes into [`metadata`](Self::metadata) (per standard) and
/// [`format`](Self::format) (this format only).
pub struct Context<'a> {
    pub(crate) report: &'a mut Report,
    pub(crate) text: &'a mut TextStore,
    pub(crate) blocks: &'a mut Vec<PendingBlock>,
    pub(crate) children: &'a mut Vec<PendingChild>,
    pub(crate) options: &'a Options,
    pub(crate) budget: &'a Budget,
    pub(crate) format_id: &'a str,
    pub(crate) emitter: &'static str,
    pub(crate) redirect: &'a mut Option<String>,
}

/// Records which source set which normalised field (`--provenance`).
struct Prov<'c> {
    map: Option<&'c mut Map>,
    source: String,
}

impl Prov<'_> {
    fn record(&mut self, field: &str) {
        if let Some(map) = self.map.as_deref_mut() {
            map.entry(field.to_string()).or_insert_with(|| Value::String(self.source.clone()));
        }
    }
}

fn set_once(slot: &mut Option<String>, value: impl Into<String>) -> bool {
    if slot.is_some() {
        return false;
    }
    let v: String = value.into();
    let v = v.trim();
    if v.is_empty() {
        return false;
    }
    *slot = Some(v.to_string());
    true
}

fn push_unique(list: &mut Vec<String>, value: impl Into<String>) -> bool {
    let v: String = value.into();
    let v = v.trim();
    if v.is_empty() || list.iter().any(|x| x == v) {
        return false;
    }
    list.push(v.to_string());
    true
}

impl Context<'_> {
    fn prov(&mut self) -> (&mut Report, String) {
        (self.report, self.emitter.to_string())
    }

    /// `content` section: title, description, authors, keywords, outline…
    pub fn content(&mut self) -> ContentWriter<'_> {
        let (r, source) = self.prov();
        let Report { content, diagnostics, .. } = r;
        ContentWriter { c: content, prov: Prov { map: diagnostics.provenance.as_mut(), source } }
    }

    /// `temporal` section: dates found in the content.
    pub fn temporal(&mut self) -> TemporalWriter<'_> {
        let (r, source) = self.prov();
        let Report { temporal, diagnostics, .. } = r;
        TemporalWriter { t: temporal, prov: Prov { map: diagnostics.provenance.as_mut(), source } }
    }

    /// `rights` section.
    pub fn rights(&mut self) -> RightsWriter<'_> {
        let (r, source) = self.prov();
        let Report { rights, diagnostics, .. } = r;
        RightsWriter { r: rights, prov: Prov { map: diagnostics.provenance.as_mut(), source } }
    }

    /// `security` section: encryption, signatures, active content, risks.
    pub fn security(&mut self) -> SecurityWriter<'_> {
        let (r, source) = self.prov();
        let Report { security, diagnostics, .. } = r;
        SecurityWriter { s: security, prov: Prov { map: diagnostics.provenance.as_mut(), source } }
    }

    /// `physical` section: dimensions, duration, pages, entries.
    pub fn physical(&mut self) -> PhysicalWriter<'_> {
        let (r, source) = self.prov();
        let Report { physical, diagnostics, .. } = r;
        PhysicalWriter { p: physical, prov: Prov { map: diagnostics.provenance.as_mut(), source } }
    }

    /// `metadata.<standard>`: raw fields of a metadata standard, with the
    /// standard's own field names (`exif`, `xmp`, `iptc`, `id3`, `docprops`, …).
    pub fn metadata(&mut self, standard: &str) -> &mut Map {
        object_entry(&mut self.report.metadata, standard)
    }

    /// `format.<format id>`: technical, format-specific details. Keys are
    /// `snake_case` with unit suffixes (`_bytes`, `_s`, `_px`, …).
    pub fn format(&mut self) -> &mut Map {
        let id = self.format_id.to_string();
        object_entry(&mut self.report.format, &id)
    }

    /// Set one `format.<id>.<key>` value.
    pub fn format_set(&mut self, key: &str, value: impl Into<Value>) {
        self.format().insert(key.to_string(), value.into());
    }

    /// Set one `metadata.<standard>.<key>` value.
    pub fn metadata_set(&mut self, standard: &str, key: &str, value: impl Into<Value>) {
        self.metadata(standard).insert(key.to_string(), value.into());
    }

    /// Hand an embedded metadata block to the matching [`BlockDecoder`](super::BlockDecoder).
    pub fn emit_block(&mut self, kind: BlockKind, data: impl Into<Vec<u8>>) {
        self.blocks.push(PendingBlock { kind, data: data.into() });
    }

    /// Hand text to the text analyzers (word counts, language, keywords, …).
    pub fn emit_text(&mut self, role: TextRole, text: &str) {
        self.text.push(role, text);
    }

    /// Add a heading to `content.outline` and hand its text to the analyzers.
    /// The outline keeps the first [`MAX_OUTLINE`] headings.
    pub fn emit_heading(&mut self, level: u8, text: &str) {
        let text = crate::text::squash_whitespace(text);
        if text.is_empty() {
            return;
        }
        self.text.push(TextRole::Heading(level), &text);
        if self.report.content.outline.len() < MAX_OUTLINE {
            self.content().heading(level, text);
        } else {
            self.report.diagnostics.truncated = true;
        }
    }

    /// Queue an embedded file for recursive extraction (bounded by depth and
    /// child limits). Fails with `LimitExceeded` once the child limit is reached,
    /// so extractors can stop listing early.
    pub fn emit_child(&mut self, name: &str, data: impl Into<Vec<u8>>) -> Result<(), ExtractError> {
        if self.children.len() >= self.options.limits.max_children as usize {
            self.budget.hit("max_children");
            return Err(ExtractError::LimitExceeded("max_children".into()));
        }
        self.children.push(PendingChild { name: name.to_string(), data: data.into(), inner: false, truncated: false });
        Ok(())
    }

    /// Like [`emit_child`](Self::emit_child), for a child of which `data`
    /// is only the start (an archive entry larger than the parse limit).
    pub fn emit_child_prefix(&mut self, name: &str, data: Vec<u8>) -> Result<(), ExtractError> {
        self.emit_child(name, data)?;
        if let Some(child) = self.children.last_mut() {
            child.truncated = true;
        }
        Ok(())
    }

    /// Queue the stream a compressed file holds (`x.tar` inside `x.tar.gz`)
    /// for extraction. Unlike [`emit_child`](Self::emit_child) it does not
    /// use up a recursion level (a few nested layers are allowed), so the
    /// entries of a compressed archive are analysed as those of a plain one.
    /// `truncated` says `data` is only a prefix of the stream. Counts
    /// towards the child limit.
    pub fn emit_inner(&mut self, name: &str, data: Vec<u8>, truncated: bool) -> Result<(), ExtractError> {
        self.emit_child(name, data)?;
        if let Some(child) = self.children.last_mut() {
            child.inner = true;
            child.truncated = truncated;
        }
        Ok(())
    }

    /// Children that may still be queued (`limits.max_children` minus those
    /// queued so far). Check it before decompressing something only to
    /// hand it on.
    pub fn child_room(&self) -> usize {
        (self.options.limits.max_children as usize).saturating_sub(self.children.len())
    }

    /// Decompress `data` with `codec` into at most `max` bytes (and no
    /// more than the decompression budget has left). Hitting the cap is not
    /// an error: the result says how decoding ended
    /// ([`End`](crate::container::codec::End)) and holds what came before.
    pub fn decompress(
        &mut self,
        data: &[u8],
        codec: crate::container::codec::Codec,
        max: usize,
    ) -> Result<crate::container::codec::Decoded, ExtractError> {
        self.checkpoint()?;
        crate::container::codec::decode(data, codec, max, self.budget)
    }

    /// Decompress the MSZIP blocks of a cabinet folder (each block a
    /// `CK`-prefixed deflate stream sharing the previous block's window) into
    /// at most `max` bytes.
    pub(crate) fn decompress_mszip(
        &mut self,
        blocks: &[&[u8]],
        max: usize,
    ) -> Result<crate::container::codec::Decoded, ExtractError> {
        self.checkpoint()?;
        crate::container::codec::mszip(blocks.iter().copied(), max, self.budget)
    }

    /// Read the input (up to `limits.max_parse_bytes`) and decode it as text.
    /// A longer input is cut, which is recorded in `diagnostics`.
    pub fn read_text(&mut self, src: &mut dyn crate::io::Source) -> Result<crate::text::Decoded, ExtractError> {
        let (bytes, _) = self.read_bytes(src)?;
        Ok(crate::text::decode(&bytes))
    }

    /// Read the input up to `limits.max_parse_bytes`; the flag says it was cut
    /// (also recorded in `diagnostics`).
    pub fn read_bytes(&mut self, src: &mut dyn crate::io::Source) -> Result<(Vec<u8>, bool), ExtractError> {
        let (bytes, cut) = src.read_prefix(self.parse_limit())?;
        if cut {
            self.budget.hit("max_parse_bytes");
            self.report.diagnostics.truncated = true;
        }
        Ok((bytes, cut))
    }

    /// Decompress `data` (zlib, raw deflate or gzip) into at most `max` bytes,
    /// charged to the decompression budget (the zip-bomb guard). Output
    /// beyond `max` or the remaining budget is an error, not a truncation.
    pub fn inflate(&mut self, data: &[u8], kind: Compression, max: usize) -> Result<Vec<u8>, ExtractError> {
        let room = usize::try_from(self.budget.remaining_decompressed()).unwrap_or(usize::MAX);
        let limit = max.min(room);
        let body = match kind {
            Compression::Gzip => gzip_body(data)?,
            _ => data,
        };
        let result = match kind {
            Compression::Zlib => miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(body, limit),
            Compression::Deflate | Compression::Gzip => miniz_oxide::inflate::decompress_to_vec_with_limit(body, limit),
        };
        match result {
            Ok(out) => {
                self.budget.charge_decompressed(out.len() as u64)?;
                Ok(out)
            }
            Err(e) if e.status == miniz_oxide::inflate::TINFLStatus::HasMoreOutput => {
                let what = if limit < max { "decompressed_bytes" } else { "inflate_limit" };
                self.budget.hit("decompressed_bytes");
                Err(ExtractError::LimitExceeded(what.into()))
            }
            Err(e) => Err(ExtractError::malformed(format!("{kind:?} data: {:?}", e.status))),
        }
    }

    /// Like [`inflate`](Self::inflate), but for damaged or truncated input:
    /// returns whatever decodes before the first error (at least one byte),
    /// charged to the same budget.
    pub fn inflate_prefix(&mut self, data: &[u8], kind: Compression, max: usize) -> Result<Vec<u8>, ExtractError> {
        use miniz_oxide::inflate::TINFLStatus;
        use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
        let room = usize::try_from(self.budget.remaining_decompressed()).unwrap_or(usize::MAX);
        let limit = max.min(room);
        let (body, mut flags) = match kind {
            Compression::Gzip => (gzip_body(data)?, 0),
            Compression::Zlib => (data, inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER),
            Compression::Deflate => (data, 0),
        };
        flags |= inflate_flags::TINFL_FLAG_HAS_MORE_INPUT | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        let mut state = Box::<DecompressorOxide>::default();
        let mut out = vec![0u8; limit.clamp(1, 1 << 16)];
        let (mut read, mut written) = (0usize, 0usize);
        loop {
            let (status, r, w) = decompress(&mut state, &body[read..], &mut out, written, flags);
            read += r;
            written += w;
            match status {
                TINFLStatus::HasMoreOutput if out.len() < limit => out.resize((out.len() * 2).min(limit), 0),
                TINFLStatus::HasMoreOutput => {
                    self.budget.hit("decompressed_bytes");
                    return Err(ExtractError::LimitExceeded("decompressed_bytes".into()));
                }
                TINFLStatus::NeedsMoreInput if r > 0 || w > 0 => {}
                _ => break,
            }
        }
        if written == 0 {
            return Err(ExtractError::malformed(format!("{kind:?} data")));
        }
        out.truncate(written);
        self.budget.charge_decompressed(written as u64)?;
        Ok(out)
    }

    /// An in-memory [`Source`](crate::io::Source) over `data` (a decompressed
    /// part, an embedded stream), charged to the same budget as the input.
    pub fn memory_source(&self, name: &str, data: Vec<u8>) -> crate::io::BytesSource {
        crate::io::BytesSource::new(Some(name.to_string()), data, self.budget.clone())
    }

    /// Bytes a structured parser may load (`limits.max_parse_bytes`).
    pub fn parse_limit(&self) -> usize {
        usize::try_from(self.options.limits.max_parse_bytes).unwrap_or(usize::MAX)
    }

    /// Record a non-fatal problem.
    pub fn warn(&mut self, message: impl Into<String>) {
        let m = format!("{}: {}", self.emitter, message.into());
        self.report.diagnostics.warnings.push(m);
    }

    /// Check the deadline; call this in loops that do not read from the source.
    pub fn checkpoint(&self) -> Result<(), ExtractError> {
        Ok(self.budget.check_deadline()?)
    }

    /// The options in effect.
    pub fn options(&self) -> &Options {
        self.options
    }

    /// Whether personal data must be counted rather than listed
    /// ([`Privacy::Strict`](crate::engine::Privacy::Strict), the default).
    pub fn privacy_strict(&self) -> bool {
        self.options.privacy == crate::engine::Privacy::Strict
    }

    /// A mailbox (display name and e-mail address) for the report:
    /// `{"name", "address"}`, or `{"name", "domain"}` under strict privacy.
    /// The name is kept either way; an address without a domain is dropped.
    pub fn mailbox(&self, name: Option<&str>, address: Option<&str>) -> Value {
        let mut m = Map::new();
        if let Some(n) = name.map(str::trim).filter(|n| !n.is_empty()) {
            // A display name that is itself an address is personal data too.
            let n = if self.privacy_strict() && n.contains('@') {
                crate::text::sensitive::redact(n, crate::text::sensitive::Category::Personal).into_owned()
            } else {
                n.to_string()
            };
            m.insert("name".into(), Value::String(n));
        }
        if let Some(a) = address.map(str::trim).filter(|a| !a.is_empty()) {
            if self.privacy_strict() {
                if let Some((_, domain)) = a.rsplit_once('@') {
                    m.insert("domain".into(), Value::String(domain.to_ascii_lowercase()));
                }
            } else {
                m.insert("address".into(), Value::String(a.to_string()));
            }
        }
        Value::Object(m)
    }

    /// Say that the input is really `format_id`, which this extractor found
    /// by looking inside a container (a compound file whose streams make it
    /// an Outlook message, a ZIP whose parts make it a Word document). The
    /// engine re-identifies the input and runs that format's extractors
    /// instead; return right after calling this. Honoured once per input,
    /// and only for a registered format.
    pub fn redirect(&mut self, format_id: &str) {
        *self.redirect = Some(format_id.to_string());
    }

    /// The format currently being extracted.
    pub fn format_id(&self) -> &str {
        self.format_id
    }
}

fn object_entry<'m>(map: &'m mut Map, key: &str) -> &'m mut Map {
    let v = map.entry(key.to_string()).or_insert_with(|| Value::Object(Map::new()));
    if !v.is_object() {
        *v = Value::Object(Map::new());
    }
    match v {
        Value::Object(m) => m,
        _ => unreachable!("just replaced with an object"),
    }
}

/// Writer for the `content` section.
pub struct ContentWriter<'c> {
    c: &'c mut Content,
    prov: Prov<'c>,
}

impl ContentWriter<'_> {
    /// Attribute the following writes to `source` (e.g. `xmp.dc:title`) instead of the extractor id.
    pub fn source(&mut self, source: impl Into<String>) -> &mut Self {
        self.prov.source = source.into();
        self
    }
    /// Title.
    pub fn title(&mut self, v: impl Into<String>) -> &mut Self {
        if set_once(&mut self.c.title, v) {
            self.prov.record("content.title");
        }
        self
    }
    /// Description / caption / abstract.
    pub fn description(&mut self, v: impl Into<String>) -> &mut Self {
        if set_once(&mut self.c.description, v) {
            self.prov.record("content.description");
        }
        self
    }
    /// Add an author.
    pub fn author(&mut self, v: impl Into<String>) -> &mut Self {
        if push_unique(&mut self.c.authors, v) {
            self.prov.record("content.authors");
        }
        self
    }
    /// Add a declared keyword.
    pub fn keyword(&mut self, v: impl Into<String>) -> &mut Self {
        if push_unique(&mut self.c.keywords, v) {
            self.prov.record("content.keywords");
        }
        self
    }
    /// Add a tag.
    pub fn tag(&mut self, v: impl Into<String>) -> &mut Self {
        if push_unique(&mut self.c.tags, v) {
            self.prov.record("content.tags");
        }
        self
    }
    /// Append a heading to the outline.
    pub fn heading(&mut self, level: u8, text: impl Into<String>) -> &mut Self {
        let text: String = text.into();
        let text = text.trim();
        if !text.is_empty() {
            self.c.outline.push(Heading { level: level.max(1), text: text.to_string() });
            self.prov.record("content.outline");
        }
        self
    }
    /// Natural language (ISO 639 code).
    pub fn language(&mut self, code: impl Into<String>, confidence: f64) -> &mut Self {
        if self.c.language.is_none() {
            self.c.language = Some(Language { code: code.into(), confidence: confidence.clamp(0.0, 1.0) });
            self.prov.record("content.language");
        }
        self
    }
    /// Location the content refers to.
    pub fn location(&mut self, lat: f64, lon: f64, alt_m: Option<f64>) -> &mut Self {
        if self.c.location.is_none() && lat.is_finite() && lon.is_finite() {
            self.c.location = Some(Location { lat, lon, alt_m, source: self.prov.source.clone() });
            self.prov.record("content.location");
        }
        self
    }
    /// Area covered, as a WGS84 box (west, south, east, north in degrees),
    /// rounded to 1e-7 degrees. Ignored unless the box is finite and within
    /// the globe.
    pub fn extent(&mut self, west: f64, south: f64, east: f64, north: f64) -> &mut Self {
        let lon = -180.0..=180.0;
        let lat = -90.0..=90.0;
        let valid = lon.contains(&west)
            && lon.contains(&east)
            && lat.contains(&south)
            && lat.contains(&north)
            && south <= north;
        if self.c.extent.is_none() && valid {
            // To 1e-7 degrees (about 1 cm): reprojected values differ in
            // their last bits between platforms' maths libraries.
            let r = |v: f64| (v * 1e7).round() / 1e7;
            let (west, south, east, north) = (r(west), r(south), r(east), r(north));
            self.c.extent = Some(Extent { west, south, east, north, source: self.prov.source.clone() });
            self.prov.record("content.extent");
        }
        self
    }
    /// Summary.
    pub fn summary(&mut self, v: impl Into<String>) -> &mut Self {
        if set_once(&mut self.c.summary, v) {
            self.prov.record("content.summary");
        }
        self
    }
}

/// Writer for the `temporal` section.
pub struct TemporalWriter<'c> {
    t: &'c mut Temporal,
    prov: Prov<'c>,
}

impl TemporalWriter<'_> {
    /// Attribute the following writes to `source` (e.g. `exif.DateTimeOriginal`).
    pub fn source(&mut self, source: impl Into<String>) -> &mut Self {
        self.prov.source = source.into();
        self
    }
    /// Add a content date. `value` is RFC 3339 when `tz_known`, otherwise a
    /// civil date-time such as `2026-09-14T17:03:22`. The same field and value
    /// from a second source is not repeated.
    pub fn content_date(&mut self, field: DateField, value: impl Into<String>, tz_known: bool) -> &mut Self {
        let value: String = value.into();
        let duplicate = self.t.content.iter().any(|d| d.field == field && d.value == value.trim());
        if !value.trim().is_empty() && !duplicate {
            self.t.content.push(ContentDate {
                field,
                value: value.trim().to_string(),
                source: self.prov.source.clone(),
                tz_known,
            });
            self.prov.record("temporal.content");
        }
        self
    }
}

/// Writer for the `rights` section.
pub struct RightsWriter<'c> {
    r: &'c mut Rights,
    prov: Prov<'c>,
}

impl RightsWriter<'_> {
    /// Attribute the following writes to `source`.
    pub fn source(&mut self, source: impl Into<String>) -> &mut Self {
        self.prov.source = source.into();
        self
    }
    /// Copyright notice.
    pub fn copyright(&mut self, v: impl Into<String>) -> &mut Self {
        if set_once(&mut self.r.copyright, v) {
            self.prov.record("rights.copyright");
        }
        self
    }
    /// Add a creator.
    pub fn creator(&mut self, v: impl Into<String>) -> &mut Self {
        if push_unique(&mut self.r.creators, v) {
            self.prov.record("rights.creators");
        }
        self
    }
    /// Credit line.
    pub fn credit(&mut self, v: impl Into<String>) -> &mut Self {
        if set_once(&mut self.r.credit, v) {
            self.prov.record("rights.credit");
        }
        self
    }
    /// Licence by name and/or URL.
    pub fn license(&mut self, name: Option<&str>, url: Option<&str>) -> &mut Self {
        if self.r.license.is_none() && (name.is_some() || url.is_some()) {
            self.r.license = Some(License { name: name.map(str::to_string), url: url.map(str::to_string) });
            self.prov.record("rights.license");
        }
        self
    }
    /// Usage terms.
    pub fn usage_terms(&mut self, v: impl Into<String>) -> &mut Self {
        if set_once(&mut self.r.usage_terms, v) {
            self.prov.record("rights.usage_terms");
        }
        self
    }
    /// Rights-managed flag.
    pub fn marked(&mut self, v: bool) -> &mut Self {
        if self.r.marked.is_none() {
            self.r.marked = Some(v);
            self.prov.record("rights.marked");
        }
        self
    }
    /// Embedding permission (fonts).
    pub fn embedding(&mut self, v: impl Into<String>) -> &mut Self {
        if set_once(&mut self.r.embedding, v) {
            self.prov.record("rights.embedding");
        }
        self
    }
}

/// Writer for the `security` section.
pub struct SecurityWriter<'c> {
    s: &'c mut Security,
    prov: Prov<'c>,
}

impl SecurityWriter<'_> {
    /// Encryption flag (`true` from any source wins).
    pub fn encrypted(&mut self, v: bool) -> &mut Self {
        self.s.encrypted = Some(self.s.encrypted.unwrap_or(false) || v);
        self.prov.record("security.encrypted");
        self
    }
    /// Signature flag (`true` from any source wins).
    pub fn signed(&mut self, v: bool) -> &mut Self {
        self.s.signed = Some(self.s.signed.unwrap_or(false) || v);
        self.prov.record("security.signed");
        self
    }
    /// Active content found (`macros`, `javascript`, `ole_objects`, …).
    pub fn active_content(&mut self, kind: impl Into<String>) -> &mut Self {
        if push_unique(&mut self.s.active_content, kind) {
            self.prov.record("security.active_content");
        }
        self
    }
    /// Add to the external reference count.
    pub fn external_references(&mut self, n: u64) -> &mut Self {
        self.s.external_references = Some(self.s.external_references.unwrap_or(0).saturating_add(n));
        self
    }
    /// Report a risk signal.
    pub fn risk(&mut self, kind: impl Into<String>, detail: Option<String>) -> &mut Self {
        let kind = kind.into();
        if !self.s.risks.iter().any(|r| r.kind == kind && r.detail == detail) {
            self.s.risks.push(Risk::new(kind, detail, self.prov.source.clone()));
            self.prov.record("security.risks");
        }
        self
    }
}

/// Writer for the `physical` section.
pub struct PhysicalWriter<'c> {
    p: &'c mut Physical,
    prov: Prov<'c>,
}

impl<'c> PhysicalWriter<'c> {
    /// Image dimensions; returns a writer for the remaining image properties.
    pub fn image(self, width: u32, height: u32) -> ImageWriter<'c> {
        let mut prov = self.prov;
        let img = self.p.image.get_or_insert_with(|| {
            prov.record("physical.image");
            ImagePhysical { width, height, ..ImagePhysical::default() }
        });
        ImageWriter { img }
    }
    /// The image properties written so far, to add to them (`None` before
    /// [`image`](Self::image) set the dimensions).
    pub fn existing_image(self) -> Option<ImageWriter<'c>> {
        self.p.image.as_mut().map(|img| ImageWriter { img })
    }

    /// Media duration in seconds.
    pub fn duration_s(&mut self, v: f64) -> &mut Self {
        let m = self.p.media.get_or_insert_with(Default::default);
        if m.duration_s.is_none() && v.is_finite() && v >= 0.0 {
            m.duration_s = Some(v);
            self.prov.record("physical.media.duration_s");
        }
        self
    }
    /// Overall bitrate.
    pub fn bitrate_bps(&mut self, v: u64) -> &mut Self {
        let m = self.p.media.get_or_insert_with(Default::default);
        m.bitrate_bps.get_or_insert(v);
        self
    }
    /// Add a media stream description.
    pub fn stream(&mut self, stream: Map) -> &mut Self {
        self.p.media.get_or_insert_with(Default::default).streams.push(stream);
        self
    }
    /// Page count.
    pub fn pages(&mut self, v: u64) -> &mut Self {
        self.p.document.get_or_insert_with(Default::default).pages.get_or_insert(v);
        self
    }
    /// Declared word count.
    pub fn words(&mut self, v: u64) -> &mut Self {
        self.p.document.get_or_insert_with(Default::default).words.get_or_insert(v);
        self
    }
    /// Slide count.
    pub fn slides(&mut self, v: u64) -> &mut Self {
        self.p.document.get_or_insert_with(Default::default).slides.get_or_insert(v);
        self
    }
    /// Sheet count.
    pub fn sheets(&mut self, v: u64) -> &mut Self {
        self.p.document.get_or_insert_with(Default::default).sheets.get_or_insert(v);
        self
    }
    /// Container entry count.
    pub fn entries(&mut self, v: u64) -> &mut Self {
        self.p.container.get_or_insert_with(Default::default).entries.get_or_insert(v);
        self
    }
    /// Total uncompressed size of a container; also sets the ratio when the size is known.
    pub fn uncompressed_bytes(&mut self, v: u64) -> &mut Self {
        let size = self.p.size_bytes;
        let c = self.p.container.get_or_insert_with(Default::default);
        c.uncompressed_bytes.get_or_insert(v);
        if let Some(s) = size.filter(|s| *s > 0) {
            c.ratio.get_or_insert(v as f64 / s as f64);
        }
        self
    }
    /// Encrypted entries in a container.
    pub fn encrypted_entries(&mut self, v: u64) -> &mut Self {
        self.p.container.get_or_insert_with(Default::default).encrypted_entries.get_or_insert(v);
        self
    }
}

/// Writer for `physical.image`.
pub struct ImageWriter<'c> {
    img: &'c mut ImagePhysical,
}

impl ImageWriter<'_> {
    /// Channel count.
    pub fn channels(&mut self, v: u8) -> &mut Self {
        self.img.channels.get_or_insert(v);
        self
    }
    /// Bits per channel.
    pub fn bit_depth(&mut self, v: u8) -> &mut Self {
        self.img.bit_depth.get_or_insert(v);
        self
    }
    /// Colour space.
    pub fn color_space(&mut self, v: impl Into<String>) -> &mut Self {
        set_once(&mut self.img.color_space, v);
        self
    }
    /// EXIF orientation (1–8).
    pub fn orientation(&mut self, v: u8) -> &mut Self {
        if (1..=8).contains(&v) {
            self.img.orientation.get_or_insert(v);
        }
        self
    }
    /// Resolution in dots per inch.
    pub fn dpi(&mut self, x: f64, y: f64) -> &mut Self {
        if x.is_finite() && y.is_finite() {
            self.img.dpi.get_or_insert([x, y]);
        }
        self
    }
    /// Frame / page count.
    pub fn frames(&mut self, v: u32) -> &mut Self {
        self.img.frames.get_or_insert(v);
        self
    }
}
