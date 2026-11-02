//! Format extractors, one directory per family group and one file per format.
//!
//! Groups are gated by cargo features, matching the "Feature" column of
//! `docs/metadata-extracted.md`:
//!
//! | Feature | Groups |
//! |---|---|
//! | `common` (default) | text, data, code, doc, email, image, audio, video, subtitle, playlist, score, compress, archive, package, exec, bytecode, crypto, db, font, web, apple, binary |
//! | `geo` | geo |
//! | `science` | science |
//! | `data` | columnar |
//! | `cad` | cad |
//! | `forensics` | forensics |
//! | `games` | games |
//!
//! Format modules import only `crate::plugin::*`. Add a format with
//! `cargo run --features dev --bin whiff-dev -- new-extractor …`, which also
//! adds the `mod` line here.

// whiff-dev: group modules below this line
#[cfg(feature = "common")]
pub(crate) mod apple;
#[cfg(feature = "common")]
pub(crate) mod archive;
#[cfg(feature = "common")]
pub(crate) mod audio;
#[cfg(feature = "common")]
pub(crate) mod binary;
#[cfg(feature = "common")]
pub(crate) mod bytecode;
#[cfg(feature = "common")]
pub(crate) mod code;
#[cfg(feature = "data")]
pub(crate) mod columnar;
#[cfg(feature = "common")]
pub(crate) mod compress;
#[cfg(feature = "common")]
pub(crate) mod crypto;
#[cfg(feature = "common")]
pub(crate) mod data;
#[cfg(feature = "common")]
pub(crate) mod db;
#[cfg(feature = "forensics")]
pub(crate) mod disk;
#[cfg(feature = "common")]
pub(crate) mod doc;
#[cfg(feature = "common")]
pub(crate) mod email;
#[cfg(feature = "common")]
pub(crate) mod exec;
#[cfg(feature = "common")]
pub(crate) mod font;
#[cfg(feature = "forensics")]
pub(crate) mod forensic;
#[cfg(feature = "common")]
pub(crate) mod image;
#[cfg(feature = "science")]
pub(crate) mod medical;
#[cfg(feature = "common")]
pub(crate) mod package;
#[cfg(feature = "common")]
pub(crate) mod playlist;
#[cfg(feature = "science")]
pub(crate) mod science;
#[cfg(feature = "common")]
pub(crate) mod score;
#[cfg(feature = "common")]
pub(crate) mod subtitle;
#[cfg(feature = "common")]
pub(crate) mod text;
#[cfg(feature = "common")]
pub(crate) mod video;
