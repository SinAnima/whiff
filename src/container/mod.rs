//! Readers for the container formats documents and media are built on: ZIP
//! (OOXML, OpenDocument, EPUB, CBZ), the OLE2 compound file (legacy Office,
//! Outlook `.msg`, MSI) with the property sets (`\x05SummaryInformation`)
//! stored inside it, ISO base media files (MP4, M4A, MOV, HEIF), ASF
//! (WMA, WMV), disk partition tables and file-system superblocks, and the
//! DER encoding of certificates and CMS signatures.
//!
//! They read through a [`Source`](crate::io::Source), so every read is charged
//! to the budget, and decompress through
//! [`Context::inflate`](crate::plugin::Context::inflate), so ZIP entries count
//! against the decompression budget. Extractors reach them through
//! [`crate::plugin`].

pub mod asf;
pub mod cfb;
pub mod codec;
pub mod der;
pub mod flatbuf;
pub mod mp4;
pub mod oleps;
pub mod proplist;
pub mod protowire;
pub mod volume;
pub mod xmlwalk;
pub mod zip;
