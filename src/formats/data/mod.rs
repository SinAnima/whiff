//! `data` extractors (feature `common`): JSON, YAML, TOML, INI, CSV and SQL,
//! with schema inference and known-schema detection shared between them.

pub(crate) mod binser;
pub(crate) mod csv;
pub(crate) mod ini;
pub(crate) mod json;
pub(crate) mod known;
pub(crate) mod records;
pub(crate) mod schema;
pub(crate) mod sql;
pub(crate) mod toml;
pub(crate) mod yaml;
