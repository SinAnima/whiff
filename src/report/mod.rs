//! The report: whiff's JSON contract (`whiff/1`).
//!
//! Every report has the same fixed top-level sections. Optional fields that
//! have no value are omitted from the JSON; sections are always present.
//! Free-form data is only allowed in [`Report::metadata`] (per standard, e.g.
//! `exif`, `xmp`) and [`Report::format`] (per format id).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A JSON object with insertion-ordered keys.
pub type Map = serde_json::Map<String, serde_json::Value>;

/// Everything whiff found out about one file (or one embedded child).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Report {
    /// Producer and schema information.
    pub whiff: WhiffInfo,
    /// How the input was named.
    pub source: SourceInfo,
    /// What the file is.
    pub identification: Identification,
    /// Filesystem identity.
    pub system: System,
    /// Filesystem times and dates found in the content.
    pub temporal: Temporal,
    /// Permissions, ownership and risk signals.
    pub security: Security,
    /// Copyright, creators and licence.
    pub rights: Rights,
    /// Size, entropy and dimensions.
    pub physical: Physical,
    /// Hashes.
    pub integrity: Integrity,
    /// The LLM-facing view: title, language, keywords, outline, summary.
    pub content: Content,
    /// Raw metadata, one object per standard (`exif`, `xmp`, `iptc`, `id3`, …).
    pub metadata: Map,
    /// Technical, format-specific details, keyed by format id.
    pub format: Map,
    /// Reports for embedded children (archive entries, attachments, …).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub embedded: Vec<Report>,
    /// What ran, what failed, which limits were hit.
    pub diagnostics: Diagnostics,
}

impl Report {
    /// An empty report stamped with this whiff version and the given profile.
    pub fn new(profile: Profile) -> Self {
        Self {
            whiff: WhiffInfo {
                version: env!("CARGO_PKG_VERSION").to_string(),
                schema: crate::SCHEMA.to_string(),
                profile,
            },
            ..Self::default()
        }
    }
}

pub use crate::engine::Profile;

mod llm;
mod risk;

pub use risk::{RISK_KINDS, RiskCategory, RiskKind, Severity, classify as classify_risk};

/// `whiff` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct WhiffInfo {
    /// whiff version that produced the report.
    pub version: String,
    /// Schema identifier, e.g. `whiff/1`.
    pub schema: String,
    /// Profile used.
    pub profile: Profile,
}

/// `source` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SourceInfo {
    /// Path as given by the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// File name (or entry name for embedded children).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// File name without the final extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stem: Option<String>,
    /// Final extension, without the dot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
}

impl SourceInfo {
    /// Fill name/stem/extension from a file name or path string.
    pub fn from_name(path: Option<String>, name: &str) -> Self {
        let p = std::path::Path::new(name);
        let file = p.file_name().map_or_else(|| name.to_string(), |f| f.to_string_lossy().into_owned());
        let fp = std::path::Path::new(&file);
        Self {
            path,
            stem: fp.file_stem().map(|s| s.to_string_lossy().into_owned()),
            extension: fp.extension().map(|s| s.to_string_lossy().into_owned()),
            name: Some(file),
        }
    }
}

/// How the format was determined.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DetectedBy {
    /// A magic signature matched.
    Magic,
    /// An extractor's content sniffer recognised it.
    Sniff,
    /// Only the file extension matched.
    Extension,
    /// Built-in text/binary heuristics.
    Heuristic,
    /// The caller forced the format.
    Forced,
    /// A container's extractor looked inside (a compound file's streams, a
    /// ZIP's parts) and named the real format.
    Content,
    /// Not applicable (directories, special files).
    #[default]
    None,
}

/// One detection candidate.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Candidate {
    /// Format id.
    pub format: String,
    /// Confidence in `0.0..=1.0`.
    pub confidence: f64,
}

/// `identification` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Identification {
    /// Stable whiff format id (`jpeg`, `docx`, …; built-ins: `empty`, `text`, `binary`, `directory`, …).
    pub format: String,
    /// Human-readable format name.
    pub name: String,
    /// MIME type.
    pub mime: String,
    /// Parser family (see docs/metadata-extracted.md).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Confidence in `0.0..=1.0`.
    pub confidence: f64,
    /// Which detector decided.
    pub detected_by: DetectedBy,
    /// `false` when the extension contradicts the detected format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_matches: Option<bool>,
    /// Ranked alternatives (best first).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<Candidate>,
    /// Text encoding, when the content is text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// Extractor that handled the file, or `null` when none is compiled in.
    pub extractor: Option<String>,
    /// Cargo feature that would add an extractor for this format, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_with_feature: Option<String>,
}

/// Kind of filesystem object.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A named pipe.
    Fifo,
    /// A Unix socket.
    Socket,
    /// A block device.
    BlockDevice,
    /// A character device.
    CharDevice,
    /// In-memory input (bytes, stdin, embedded child).
    #[default]
    Memory,
    /// Unknown.
    Other,
}

/// `system` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct System {
    /// Kind of object.
    pub kind: FileKind,
    /// Logical size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Bytes actually allocated on disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocated_bytes: Option<u64>,
    /// Device id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<u64>,
    /// Inode number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
    /// Hard-link count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<u64>,
    /// Hidden (dot-file on Unix, hidden attribute on Windows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    /// Read-only flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
    /// Target of a symbolic link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
}

/// Which date a content timestamp describes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DateField {
    /// Creation of the content.
    #[default]
    Created,
    /// Last modification.
    Modified,
    /// Capture (photo/video).
    Captured,
    /// Digitisation (scan).
    Digitized,
    /// Publication.
    Published,
    /// Expiry (certificates, licences).
    Expires,
    /// Last printed (office documents).
    Printed,
    /// Sent (e-mail `Date`, Outlook submit time).
    Sent,
    /// Received (e-mail delivery, `Received` hops).
    Received,
    /// Anything else (see `source`).
    Other,
}

/// A date found inside the content.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ContentDate {
    /// What the date means.
    pub field: DateField,
    /// RFC 3339 timestamp (or civil date-time when `tz_known` is false).
    pub value: String,
    /// Where it came from, e.g. `exif.DateTimeOriginal`.
    pub source: String,
    /// Whether the source carried a time-zone offset.
    pub tz_known: bool,
}

/// Filesystem timestamps (RFC 3339, UTC).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FsTimes {
    /// Last modification (mtime).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    /// Last access (atime).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed: Option<String>,
    /// Last status change (ctime, Unix only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<String>,
    /// Creation (birth time, where the platform provides it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
}

/// `temporal` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Temporal {
    /// Filesystem times.
    pub filesystem: FsTimes,
    /// Dates found in the content.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<ContentDate>,
    /// Earliest zone-aware content date (UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub earliest: Option<String>,
    /// Latest zone-aware content date (UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
}

/// File owner.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Owner {
    /// Numeric user id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// User name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Numeric group id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// Group name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// A risk signal (macro present, script in SVG, extension mismatch, …).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Risk {
    /// Stable `snake_case` kind, e.g. `macros`, `javascript`, `link_text_mismatch`;
    /// the vocabulary is listed in `docs/risks.md`.
    pub kind: String,
    /// What kind of threat it points to (decided by the kind).
    pub category: RiskCategory,
    /// How much it should worry the reader (decided by the kind).
    pub severity: Severity,
    /// Human-readable detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Who reported it.
    pub source: String,
}

/// `security` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Security {
    /// Octal permission bits, e.g. `0644`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// `ls`-style permission string, e.g. `rw-r--r--`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
    /// Owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,
    /// Set-user-id bit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setuid: Option<bool>,
    /// Set-group-id bit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setgid: Option<bool>,
    /// Sticky bit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sticky: Option<bool>,
    /// Access-control list present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acl: Option<bool>,
    /// Extended attributes of interest.
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub xattrs: Map,
    /// Content is encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    /// Content carries a signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    /// Kinds of active content found (`macros`, `javascript`, …).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub active_content: Vec<String>,
    /// Number of external references (links, remote resources).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_references: Option<u64>,
    /// Risk signals.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub risks: Vec<Risk>,
    /// The highest severity among `risks` and every embedded file's risks;
    /// absent when there are none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<Severity>,
    /// Risks of embedded files (attachments, archive entries, embedded
    /// objects, at any depth), counted by kind.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub embedded_risks: BTreeMap<String, u64>,
    /// Secrets found in the content, by kind (`aws_access_key_id`, `private_key`, …).
    /// Only counts: values are redacted from the report.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, u64>,
    /// Personal data found in the content, by kind (`email`, `phone`, `iban`, …). Only counts.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub personal_data: BTreeMap<String, u64>,
}

/// A licence.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct License {
    /// Name, e.g. `CC BY 4.0` or an SPDX id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Licence URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// `rights` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Rights {
    /// Copyright notice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copyright: Option<String>,
    /// Creators / authors / artists.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub creators: Vec<String>,
    /// Credit line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit: Option<String>,
    /// Licence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<License>,
    /// Usage terms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_terms: Option<String>,
    /// Marked as rights-managed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marked: Option<bool>,
    /// Embedding permission (fonts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding: Option<String>,
}

/// Which bytes an entropy value was computed over.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntropyScope {
    /// The whole file.
    #[default]
    File,
    /// Only the first bytes (minimal profile, or file too large to hash).
    Head,
}

/// Text physical properties (`wc` parity).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TextPhysical {
    /// Bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Unicode scalar values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chars: Option<u64>,
    /// Words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub words: Option<u64>,
    /// Newline count (`wc -l`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<u64>,
    /// Longest line (`wc -L`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_line_length: Option<u64>,
    /// `lf`, `crlf`, `cr` or `mixed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_endings: Option<String>,
    /// Byte-order mark present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bom: Option<bool>,
    /// Lines containing only whitespace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blank_lines: Option<u64>,
}

/// Image physical properties.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ImagePhysical {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bits per channel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_depth: Option<u8>,
    /// Channel count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channels: Option<u8>,
    /// Colour space, e.g. `sRGB`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color_space: Option<String>,
    /// EXIF orientation (1–8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orientation: Option<u8>,
    /// Horizontal and vertical resolution in dots per inch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpi: Option<[f64; 2]>,
    /// Frame count (animations, multi-page).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frames: Option<u32>,
}

/// Audio/video physical properties.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct MediaPhysical {
    /// Duration in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_s: Option<f64>,
    /// Overall bitrate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitrate_bps: Option<u64>,
    /// Streams (codec, type, …), one object each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub streams: Vec<Map>,
}

/// Document physical properties.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct DocumentPhysical {
    /// Pages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pages: Option<u64>,
    /// Words (as declared by the document).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub words: Option<u64>,
    /// Slides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slides: Option<u64>,
    /// Sheets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sheets: Option<u64>,
}

/// Container (archive) physical properties.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ContainerPhysical {
    /// Entry count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<u64>,
    /// Total uncompressed size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncompressed_bytes: Option<u64>,
    /// Uncompressed / compressed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratio: Option<f64>,
    /// Encrypted entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_entries: Option<u64>,
}

/// `physical` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Physical {
    /// Size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Shannon entropy in bits per byte (0–8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    /// Bytes the entropy covers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_scope: Option<EntropyScope>,
    /// Text properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<TextPhysical>,
    /// Image properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<ImagePhysical>,
    /// Audio/video properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media: Option<MediaPhysical>,
    /// Document properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<DocumentPhysical>,
    /// Container properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerPhysical>,
}

/// `integrity` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Integrity {
    /// SHA-256, lowercase hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// BLAKE3, lowercase hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
    /// Perceptual hash (images, `full` profile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phash: Option<String>,
    /// Why hashing was skipped, if it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

/// Detected natural language.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Language {
    /// ISO 639 code.
    pub code: String,
    /// Confidence in `0.0..=1.0`.
    pub confidence: f64,
}

/// One heading of the document outline.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Heading {
    /// Level, 1 = top.
    pub level: u8,
    /// Heading text.
    pub text: String,
}

/// A geographic location.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Location {
    /// Latitude, decimal degrees.
    pub lat: f64,
    /// Longitude, decimal degrees.
    pub lon: f64,
    /// Altitude in metres.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_m: Option<f64>,
    /// Where it came from.
    pub source: String,
}

/// A geographic extent: a WGS84 bounding box.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Extent {
    /// Western longitude, decimal degrees.
    pub west: f64,
    /// Southern latitude, decimal degrees.
    pub south: f64,
    /// Eastern longitude, decimal degrees.
    pub east: f64,
    /// Northern latitude, decimal degrees.
    pub north: f64,
    /// Where it came from.
    pub source: String,
}

/// `content` section: the LLM-facing view.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Content {
    /// Title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Description / caption / abstract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Authors.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,
    /// Natural language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    /// Keywords (declared or extracted).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
    /// Top terms with counts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub keyword_frequency: Vec<(String, u64)>,
    /// Heading outline in document order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub outline: Vec<Heading>,
    /// Extractive summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Text excerpt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    /// Merged tags.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Location the content refers to (e.g. photo GPS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// Area the content covers (e.g. a map's bounding box), in WGS84.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extent: Option<Extent>,
}

/// Outcome of one extractor, decoder or analyzer run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Finished normally.
    #[default]
    Ok,
    /// Returned an [`ExtractError`](crate::ExtractError) other than `internal`.
    Error,
    /// Panicked or broke an invariant (a bug).
    Internal,
}

/// One entry of `diagnostics.extractors`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ExtractorRun {
    /// Extractor / decoder / analyzer id.
    pub id: String,
    /// Its output version.
    pub version: u32,
    /// Wall time in milliseconds.
    pub ms: f64,
    /// Outcome.
    pub status: RunStatus,
    /// Error kind (`malformed`, `timeout`, …) when not `ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// Error message when not `ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `diagnostics` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Diagnostics {
    /// Everything that ran, in order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extractors: Vec<ExtractorRun>,
    /// Non-fatal problems.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Limits that stopped work early (`read_bytes`, `timeout`, `max_depth`, …).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limits_hit: Vec<String>,
    /// Some output was cut short.
    pub truncated: bool,
    /// Metadata blocks emitted that no decoder handled.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub undecoded_blocks: Vec<String>,
    /// Field path → source, when requested with `--provenance`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Map>,
    /// Total wall time in milliseconds.
    pub elapsed_ms: f64,
}
