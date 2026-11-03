//! FlatBuffers binary schemas (`.bfbs`, written by `flatc --schema -b`):
//! the schema's file identifier and extension, root table, tables and
//! structs, enums and unions, services and the `.fbs` files it came from.
//! (Other FlatBuffers binaries cannot be read without their schema.)
//!
//! Specification: FlatBuffers "Internals" (tables, vtables, offsets) and
//! `reflection/reflection.fbs`.

use serde_json::Value;

use crate::plugin::flatbuf::FlatBuf;
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, truncate_chars};

/// Extractor for binary FlatBuffers schemas.
pub struct FlatBuffers;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.flatbuffers",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "bfbs",
        name: "FlatBuffers schema / binary",
        family: "data.binser",
        mimes: &[],
        extensions: &["bfbs"],
        magic: &[Magic::at(4, b"BFBS")],
        parent: None,
    }],
};

/// Names listed per kind.
const MAX_NAMES: usize = 200;

fn names(fb: &FlatBuf<'_>, tables: &[usize]) -> Vec<String> {
    tables.iter().take(MAX_NAMES).filter_map(|&t| fb.string(t, 0)).map(|s| truncate_chars(&s, 200)).collect()
}

impl Extractor for FlatBuffers {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, _) = cx.read_bytes(src)?;
        let fb = FlatBuf(&data);
        let root = fb.root().ok_or_else(|| ExtractError::malformed("root offset"))?;
        let objects = fb.tables(root, 0);
        let enums = fb.tables(root, 1);
        if let Some(i) = fb.string(root, 2).filter(|s| !s.is_empty()) {
            cx.format_set("file_identifier", truncate_chars(&i, 8));
        }
        if let Some(e) = fb.string(root, 3).filter(|s| !s.is_empty()) {
            cx.format_set("file_extension", truncate_chars(&e, 20));
        }
        if let Some(r) = fb.table(root, 4).and_then(|t| fb.string(t, 0)) {
            cx.format_set("root_table", truncate_chars(&r, 200));
        }
        let structs = objects.iter().filter(|&&o| fb.bool(o, 2)).count();
        cx.format_set("tables", objects.len() - structs);
        cx.format_set("structs", structs);
        let fields: usize = objects.iter().map(|&o| fb.tables(o, 1).len()).sum();
        cx.format_set("fields", fields);
        if !objects.is_empty() {
            cx.format_set("objects", names(&fb, &objects));
        }
        let unions = enums.iter().filter(|&&e| fb.bool(e, 2)).count();
        cx.format_set("enums", enums.len() - unions);
        cx.format_set("unions", unions);
        if !enums.is_empty() {
            cx.format_set("enum_names", names(&fb, &enums));
        }
        let services = fb.tables(root, 5);
        if !services.is_empty() {
            cx.format_set("services", names(&fb, &services));
        }
        let files = fb.tables(root, 7);
        if !files.is_empty() {
            cx.format_set("schema_files", Value::from(names(&fb, &files)));
        }
        Ok(())
    }
}

crate::register_extractor!(FlatBuffers);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("bfbs");
}
