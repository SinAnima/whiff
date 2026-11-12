/// A byte signature at a fixed offset, optionally masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Magic {
    /// Offset from the start of the file.
    pub offset: usize,
    /// Expected bytes.
    pub bytes: &'static [u8],
    /// Optional mask, same length as `bytes`; compared as `(data & mask) == (bytes & mask)`.
    pub mask: Option<&'static [u8]>,
}

impl Magic {
    /// `bytes` at offset 0.
    pub const fn prefix(bytes: &'static [u8]) -> Self {
        Self { offset: 0, bytes, mask: None }
    }

    /// `bytes` at `offset`.
    pub const fn at(offset: usize, bytes: &'static [u8]) -> Self {
        Self { offset, bytes, mask: None }
    }

    /// `bytes` at `offset`, compared through `mask`.
    pub const fn masked(offset: usize, bytes: &'static [u8], mask: &'static [u8]) -> Self {
        Self { offset, bytes, mask: Some(mask) }
    }

    /// Whether `head` (the file's first bytes) matches.
    pub fn matches(&self, head: &[u8]) -> bool {
        let Some(window) = head.get(self.offset..self.offset + self.bytes.len()) else {
            return false;
        };
        match self.mask {
            None => window == self.bytes,
            Some(mask) => window.iter().zip(self.bytes).zip(mask).all(|((d, b), m)| d & m == b & m),
        }
    }
}

/// How a format is recognised. Declared by the extractor that handles it.
#[derive(Debug, Clone, Copy)]
pub struct FormatSpec {
    /// Stable whiff id: `jpeg`, `docx`, `sqlite`.
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Parser family, e.g. `image.raster` (see docs/metadata-extracted.md).
    pub family: &'static str,
    /// MIME types, preferred first.
    pub mimes: &'static [&'static str],
    /// Extensions without the dot, lowercase.
    pub extensions: &'static [&'static str],
    /// Signatures; any one matching counts.
    pub magic: &'static [Magic],
    /// Container format refined by `sniff`, e.g. `zip` for `docx`.
    pub parent: Option<&'static str>,
}

/// How expensive an extractor is; profiles filter on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Cost {
    /// Reads headers / small structures only (all profiles).
    Header,
    /// Scans a bounded part of the content (`standard` and `full`).
    Scan,
    /// Decodes payloads: pixels, audio, full text (`full` only).
    Decode,
}

/// Static description of an extractor.
#[derive(Debug, Clone, Copy)]
pub struct ExtractorMeta {
    /// Extractor id, `<group>.<format>`, e.g. `image.jpeg`.
    pub id: &'static str,
    /// Output version; bump when the output changes.
    pub version: u32,
    /// Formats handled.
    pub formats: &'static [FormatSpec],
    /// Cost class.
    pub cost: Cost,
    /// Tie-break when several extractors claim one format (higher runs first).
    pub priority: i16,
}

/// What a sniffer sees.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Probe<'a> {
    /// First bytes (up to 64 KiB).
    pub head: &'a [u8],
    /// Last bytes (up to 64 KiB).
    pub tail: &'a [u8],
    /// Total length.
    pub len: u64,
    /// File or entry name.
    pub name: Option<&'a str>,
    /// Lowercase extension.
    pub extension: Option<&'a str>,
}

impl<'a> Probe<'a> {
    /// A probe over `head` and `tail` of a `len`-byte input named `name`
    /// (the extension is taken from the name, lowercased by the caller).
    pub const fn new(
        head: &'a [u8],
        tail: &'a [u8],
        len: u64,
        name: Option<&'a str>,
        extension: Option<&'a str>,
    ) -> Self {
        Self { head, tail, len, name, extension }
    }
}

/// A sniffer's verdict.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sniff {
    /// Format id (one of the extractor's formats).
    pub format: &'static str,
    /// Confidence in `0.0..=1.0`.
    pub confidence: f64,
}

/// Kind of an embedded metadata block. An open set: any `&'static str` works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockKind(pub &'static str);

impl BlockKind {
    /// EXIF (TIFF-structured).
    pub const EXIF: Self = Self("exif");
    /// XMP packet (RDF/XML).
    pub const XMP: Self = Self("xmp");
    /// IPTC IIM datasets.
    pub const IPTC_IIM: Self = Self("iptc");
    /// ICC colour profile.
    pub const ICC: Self = Self("icc");
    /// Photoshop image resource blocks (8BIM).
    pub const PHOTOSHOP_IRB: Self = Self("photoshop_irb");
}

impl std::fmt::Display for BlockKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
