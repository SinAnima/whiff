//! `db` extractors (feature `common`): database files, read without a
//! database engine. SQLite is read in-house down to its b-trees (header,
//! schema, columns, row counts, the application that made it); DBF and
//! Access files give their tables and fields; other engines give what
//! their headers hold (format version, page size, entry counts, the
//! database name). Nothing is executed and no row data is reported beyond
//! the few application summaries.

#![allow(clippy::many_single_char_names)] // bytes `b`, cursor `c`, page `p`, as in the specifications

pub(crate) mod access;
pub(crate) mod apps;
pub(crate) mod dbf;
pub(crate) mod engines;
pub(crate) mod schema;
pub(crate) mod sqlite;
pub(crate) mod stores;

// Helpers shared with the archive extractors.
pub(crate) use super::archive::unix_time;
