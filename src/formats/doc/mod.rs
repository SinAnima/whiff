//! `doc` extractors (feature `common`): PDF, Office Open XML, OpenDocument,
//! legacy Office (OLE2 compound files), RTF, ebooks, PostScript and BibTeX.
//!
//! Document extractors fill the authoring metadata (title, authors, dates,
//! counts), the heading outline and the body text, and flag active content:
//! macros, scripts, embedded objects, external templates and links. Embedded
//! files become children.

pub(crate) mod djvu;
pub(crate) mod ebook;
pub(crate) mod field;
pub(crate) mod legacy;
pub(crate) mod odf;
pub(crate) mod ole;
pub(crate) mod ooxml;
pub(crate) mod other;
pub(crate) mod packages;
pub(crate) mod pdf;
pub(crate) mod rtf;
pub(crate) mod vba;
pub(crate) mod writing;
pub(crate) mod xml;
