//! The contributor API. Format modules import only `whiff::plugin::*`
//! (inside the crate: `crate::plugin::*`).
//!
//! An extractor is a unit struct implementing [`Extractor`] plus one
//! `crate::register_extractor!(Name);` line in its module under `src/formats/`.
//! `build.rs` turns those lines into the built-in registry. Shared decoders
//! for embedded metadata blocks implement [`BlockDecoder`]; whole-report
//! post-processing implements [`Analyzer`].
//!
//! Extractors defined in *other* crates are added explicitly:
//! `Engine::builder().registry(Registry::builtin().with(MyExtractor))`.

pub mod conformance;
pub(crate) mod context;
mod registry;
mod spec;
#[doc(hidden)]
pub mod testing;
mod text;
mod values;

pub use context::{
    Compression, ContentWriter, Context, ImageWriter, MAX_OUTLINE, PhysicalWriter, RightsWriter, SecurityWriter,
    TemporalWriter,
};
pub use registry::Registry;
pub use spec::{BlockKind, Cost, ExtractorMeta, FormatSpec, Magic, Probe, Sniff};
pub use text::{TextChunk, TextRole, TextStore};
pub use values::{AnyValue, MAX_NESTING, dotted_key_depth, nesting_depth};

pub use crate::container::cfb::{Cfb, CfbEntry, CfbKind, filetime, guid};
pub use crate::container::codec::{Codec, End};
pub use crate::container::zip::{
    Zip, ZipEntry, first_stored as zip_first_stored, method_name as zip_method_name, names as zip_names,
};
pub use crate::container::{asf, codec, der, flatbuf, mp4, oleps, proplist, protowire, volume, xmlwalk};
pub use crate::engine::{Options, Privacy, Profile};
pub use crate::meta::latin1_or_utf8;
pub use crate::text::decode::decode as decode_text;
pub use crate::text::latex::{latex_argument, latex_option, latex_text};
pub use crate::text::license::{find_copyright, identify_license, spdx_identifier};
pub use crate::text::markup::{decode_entities, html_text, risky_file_name};
pub use crate::text::sensitive::is_secret_key;
pub use crate::text::{Decoded, parse_date, squash_whitespace, truncate_chars};

/// Replace secrets (keys, tokens, credentials in URLs) in `text` with
/// `[redacted:<kind>]`. Use it for values written to `format` or `metadata`
/// that may hold credentials; the privacy analyzer also runs over the report.
pub fn redact_secrets(text: &str) -> std::borrow::Cow<'_, str> {
    crate::text::sensitive::redact(text, crate::text::sensitive::Category::Secret)
}

/// Replace secrets **and** personal data (e-mail addresses, phone numbers,
/// card numbers, IBANs) in `text`. Use it for sample values (CSV rows, schema
/// examples) that would otherwise list personal data.
pub fn redact_sensitive(text: &str) -> std::borrow::Cow<'_, str> {
    use crate::text::sensitive::{Category, redact};
    match redact(text, Category::Secret) {
        std::borrow::Cow::Borrowed(t) => redact(t, Category::Personal),
        std::borrow::Cow::Owned(t) => std::borrow::Cow::Owned(redact(&t, Category::Personal).into_owned()),
    }
}

/// A path with the user name of a profile folder (`C:\Users\name\…`,
/// `/Users/name/…`, `/home/name/…`) hidden when privacy is strict.
pub fn user_path(cx: &Context<'_>, path: &str) -> String {
    let path = truncate_chars(path, 1000);
    if !cx.privacy_strict() {
        return path;
    }
    let mut out = String::with_capacity(path.len());
    let mut rest = path.as_str();
    for marker in ["\\Users\\", "/Users/", "/home/", "\\Documents and Settings\\"] {
        if let Some(i) = rest.to_ascii_lowercase().find(&marker.to_ascii_lowercase()) {
            let end = i + marker.len();
            out.push_str(&rest[..end]);
            let tail = &rest[end..];
            let user_end = tail.find(['\\', '/']).unwrap_or(tail.len());
            let user = &tail[..user_end];
            if ["public", "default", "all users", "shared"].contains(&user.to_ascii_lowercase().as_str()) {
                out.push_str(user);
            } else if !user.is_empty() {
                out.push_str("[user]");
            }
            rest = &tail[user_end..];
            break;
        }
    }
    out.push_str(rest);
    out
}

pub use crate::error::ExtractError;
pub use crate::io::{BoundedReader, Budget, ByteReader, BytesSource, Source, SourceError};
pub use crate::report::{DateField, Map, Report};

/// Extracts information from one or more formats.
///
/// Implementations must never panic on bad input (the engine contains panics,
/// but reports them as bugs), never print, and write output only through the
/// [`Context`].
pub trait Extractor: Send + Sync + 'static {
    /// Static description: id, version, formats, cost.
    fn meta(&self) -> &'static ExtractorMeta;

    /// Optional content check beyond magic, e.g. ZIP→DOCX by
    /// `[Content_Types].xml`, XML→SVG by root element, text→Python by shebang.
    /// Gets the head/tail windows only, so it must be cheap.
    fn sniff(&self, _probe: &Probe<'_>) -> Option<Sniff> {
        None
    }

    /// Do the work.
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError>;
}

/// Decodes one kind of embedded metadata block (EXIF, XMP, IPTC, ICC, …),
/// wherever a container extractor found it.
pub trait BlockDecoder: Send + Sync + 'static {
    /// Block kind handled.
    fn kind(&self) -> BlockKind;
    /// Decoder id, e.g. `meta.exif`.
    fn id(&self) -> &'static str;
    /// Output version (bump when output changes).
    fn version(&self) -> u32 {
        1
    }
    /// Decode `data` into the report.
    fn decode(&self, data: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError>;
}

/// When an analyzer runs relative to the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnalyzerStage {
    /// Normalising embedded metadata (EXIF / IPTC / XMP by MWG rules) into
    /// title, creators, rights and dates, before the text analyzers read them.
    Metadata,
    /// Language identification (the text analyzers depend on it).
    Language,
    /// Keywords, keyword frequency, summary, excerpt.
    Text,
    /// Merging values from different sources into the normalised sections.
    Reconcile,
    /// Redaction of secrets and personal data.
    Privacy,
    /// Final shaping (LLM view).
    Output,
}

/// Post-processes the whole report after all extractors and decoders ran.
pub trait Analyzer: Send + Sync + 'static {
    /// Analyzer id, e.g. `text.stats`.
    fn id(&self) -> &'static str;
    /// Output version.
    fn version(&self) -> u32 {
        1
    }
    /// Stage; analyzers run in stage order, then by id.
    fn stage(&self) -> AnalyzerStage;
    /// Run over the report and the text collected from extractors.
    fn run(&self, report: &mut Report, text: &TextStore, options: &Options) -> Result<(), ExtractError>;
}

/// Mark a unit struct as a built-in [`Extractor`]. `build.rs` collects these
/// lines (one per line, `crate::register_extractor!(Name);`) into
/// [`Registry::builtin`]; the macro itself only checks the trait is implemented.
#[doc(hidden)]
#[macro_export]
macro_rules! register_extractor {
    ($t:ident) => {
        const _: () = {
            const fn registered<T: $crate::plugin::Extractor>() {}
            registered::<$t>();
        };
    };
}

/// Mark a unit struct as a built-in [`BlockDecoder`] (see [`register_extractor!`]).
#[doc(hidden)]
#[macro_export]
macro_rules! register_block_decoder {
    ($t:ident) => {
        const _: () = {
            const fn registered<T: $crate::plugin::BlockDecoder>() {}
            registered::<$t>();
        };
    };
}

/// Mark a unit struct as a built-in [`Analyzer`] (see [`register_extractor!`]).
#[doc(hidden)]
#[macro_export]
macro_rules! register_analyzer {
    ($t:ident) => {
        const _: () = {
            const fn registered<T: $crate::plugin::Analyzer>() {}
            registered::<$t>();
        };
    };
}

pub use crate::{fixture_tests, register_analyzer, register_block_decoder, register_extractor};
