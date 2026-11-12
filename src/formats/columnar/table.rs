//! Table-format metadata:
//! * Delta Lake commits (`_delta_log/*.json`): the operation, engine,
//!   commit time, protocol versions and features, table name, id and
//!   description, schema, partition columns, files and rows added and
//!   removed (from the per-file statistics);
//! * Apache Iceberg table metadata (`*.metadata.json`): format version,
//!   table UUID, location, the current schema, partition spec and sort
//!   order, properties, snapshots (count, time range, the current one's
//!   summary) and the last update;
//! * Apache Hudi tables: `.hoodie/hoodie.properties` (table name and type,
//!   table and timeline versions, base file format, record key, precombine
//!   and partition fields, key generator, metadata-table partitions, the
//!   schema the table was created with) and timeline commits (`.commit`,
//!   `.deltacommit`, `.replacecommit`: the instant, operation, partitions
//!   and files written, records inserted, updated and deleted, bytes and
//!   errors, the writer schema).
//!
//! Specifications: Delta Lake transaction protocol (`PROTOCOL.md`);
//! Apache Iceberg table specification v2 / v3 ("Table Metadata"); Apache
//! Hudi `HoodieTableConfig` and `HoodieCommitMetadata` (Hudi 0.x / 1.x).

use serde_json::{Map, Value};

use super::epoch_text;
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source,
    redact_sensitive, truncate_chars, user_path,
};

/// Extractor for Delta Lake, Iceberg and Hudi metadata.
pub struct TableMeta;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.table",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "delta_log",
            name: "Delta Lake transaction log",
            family: "columnar",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("ndjson"),
        },
        FormatSpec {
            id: "iceberg_metadata",
            name: "Iceberg table metadata",
            family: "columnar",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("json"),
        },
        FormatSpec {
            id: "hudi_table",
            name: "Apache Hudi table properties",
            family: "columnar",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("properties"),
        },
        FormatSpec {
            id: "hudi_commit",
            name: "Apache Hudi timeline commit",
            family: "columnar",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: Some("json"),
        },
    ],
};

/// Fields listed from a schema.
const MAX_FIELDS: usize = 500;

/// A Delta / Iceberg type as text (nested types abbreviated).
fn type_text(t: &Value, depth: usize) -> String {
    if depth > 16 {
        return "…".into();
    }
    match t {
        Value::String(s) => s.clone(),
        Value::Object(o) => match o.get("type").and_then(Value::as_str) {
            Some("struct") => {
                let fields = o.get("fields").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
                let body: Vec<String> = fields
                    .iter()
                    .take(50)
                    .map(|f| {
                        format!(
                            "{}: {}",
                            f.get("name").and_then(Value::as_str).unwrap_or(""),
                            type_text(f.get("type").unwrap_or(&Value::Null), depth + 1)
                        )
                    })
                    .collect();
                format!("struct<{}>", body.join(", "))
            }
            Some("array") => {
                let e = o.get("elementType").or_else(|| o.get("element")).unwrap_or(&Value::Null);
                format!("array<{}>", type_text(e, depth + 1))
            }
            Some("list") => format!("list<{}>", type_text(o.get("element").unwrap_or(&Value::Null), depth + 1)),
            Some("map") => {
                let k = o.get("keyType").or_else(|| o.get("key")).unwrap_or(&Value::Null);
                let v = o.get("valueType").or_else(|| o.get("value")).unwrap_or(&Value::Null);
                format!("map<{}, {}>", type_text(k, depth + 1), type_text(v, depth + 1))
            }
            Some(other) => other.to_string(),
            None => "?".into(),
        },
        _ => "?".into(),
    }
}

/// `name → type` for the fields of a struct schema.
fn fields(schema: &Value) -> Map<String, Value> {
    let list = schema.get("fields").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    list.iter()
        .take(MAX_FIELDS)
        .filter_map(|f| {
            let name = f.get("name")?.as_str()?;
            Some((truncate_chars(name, 200), Value::String(truncate_chars(&type_text(f.get("type")?, 0), 300))))
        })
        .collect()
}

fn ms_date(cx: &mut Context<'_>, key: &str, field: DateField, v: Option<&Value>) {
    if let Some(t) = v.and_then(Value::as_i64).and_then(|ms| epoch_text(ms, "ms")) {
        cx.format_set(key, t.clone());
        cx.temporal().source(key.to_string()).content_date(field, t, true);
    }
}

#[allow(clippy::too_many_lines)] // one pass over the actions
fn delta(cx: &mut Context<'_>, text: &str) {
    let (mut adds, mut removes, mut rows, mut bytes) = (0u64, 0u64, 0u64, 0u64);
    let mut actions: Map<String, Value> = Map::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()).take(1_000_000) {
        let Ok(Value::Object(o)) = serde_json::from_str::<Value>(line) else { continue };
        for (kind, a) in &o {
            let n = actions.entry(kind.clone()).or_insert(Value::from(0));
            *n = Value::from(n.as_u64().unwrap_or(0) + 1);
            match kind.as_str() {
                "commitInfo" => {
                    for (k, out) in
                        [("operation", "operation"), ("engineInfo", "engine"), ("clientVersion", "client_version")]
                    {
                        if let Some(v) = a.get(k).and_then(Value::as_str) {
                            cx.format_set(out, truncate_chars(v, 200));
                        }
                    }
                    ms_date(cx, "commit_time", DateField::Modified, a.get("timestamp"));
                    if let Some(p) = a.get("operationParameters").and_then(Value::as_object) {
                        let small: Map<String, Value> = p
                            .iter()
                            .take(20)
                            .map(|(k, v)| {
                                (
                                    k.clone(),
                                    Value::String(truncate_chars(
                                        &v.as_str().map_or_else(|| v.to_string(), str::to_string),
                                        200,
                                    )),
                                )
                            })
                            .collect();
                        cx.format_set("operation_parameters", Value::Object(small));
                    }
                }
                "protocol" => {
                    for (k, out) in
                        [("minReaderVersion", "min_reader_version"), ("minWriterVersion", "min_writer_version")]
                    {
                        if let Some(v) = a.get(k).and_then(Value::as_u64) {
                            cx.format_set(out, v);
                        }
                    }
                    for k in ["readerFeatures", "writerFeatures"] {
                        if let Some(f) = a.get(k).and_then(Value::as_array) {
                            let out = if k == "readerFeatures" { "reader_features" } else { "writer_features" };
                            cx.format_set(out, Value::Array(f.iter().take(50).cloned().collect()));
                        }
                    }
                }
                "metaData" => {
                    for (k, out) in [("id", "table_id"), ("name", "table_name"), ("description", "description")] {
                        if let Some(v) = a.get(k).and_then(Value::as_str) {
                            cx.format_set(out, truncate_chars(v, 500));
                        }
                    }
                    if let Some(n) = a.get("name").and_then(Value::as_str) {
                        cx.content().source("delta.metaData.name").title(truncate_chars(n, 200));
                    }
                    if let Some(f) = a.pointer("/format/provider").and_then(Value::as_str) {
                        cx.format_set("data_format", f);
                    }
                    if let Some(s) = a
                        .get("schemaString")
                        .and_then(Value::as_str)
                        .and_then(|s| serde_json::from_str::<Value>(s).ok())
                    {
                        let f = fields(&s);
                        cx.format_set("column_count", f.len());
                        cx.format_set("columns", Value::Object(f));
                    }
                    if let Some(p) = a.get("partitionColumns").and_then(Value::as_array).filter(|p| !p.is_empty()) {
                        cx.format_set("partition_columns", Value::Array(p.iter().take(50).cloned().collect()));
                    }
                    ms_date(cx, "table_created", DateField::Created, a.get("createdTime"));
                    if let Some(c) = a.get("configuration").and_then(Value::as_object).filter(|c| !c.is_empty()) {
                        let m: Map<String, Value> = c
                            .iter()
                            .take(50)
                            .map(|(k, v)| {
                                (
                                    k.clone(),
                                    Value::String(truncate_chars(
                                        &redact_sensitive(v.as_str().unwrap_or_default()),
                                        200,
                                    )),
                                )
                            })
                            .collect();
                        cx.format_set("configuration", Value::Object(m));
                    }
                }
                "add" => {
                    adds += 1;
                    bytes = bytes.saturating_add(a.get("size").and_then(Value::as_u64).unwrap_or(0));
                    let stats =
                        a.get("stats").and_then(Value::as_str).and_then(|s| serde_json::from_str::<Value>(s).ok());
                    rows = rows
                        .saturating_add(stats.and_then(|s| s.get("numRecords").and_then(Value::as_u64)).unwrap_or(0));
                }
                "remove" => removes += 1,
                _ => {}
            }
        }
    }
    cx.format_set("actions", Value::Object(actions));
    cx.format_set("files_added", adds);
    cx.format_set("files_removed", removes);
    if adds > 0 {
        cx.format_set("rows_added", rows);
        cx.format_set("bytes_added", bytes);
    }
}

fn iceberg(cx: &mut Context<'_>, v: &Value) {
    if let Some(f) = v.get("format-version").and_then(Value::as_u64) {
        cx.format_set("format_version", f);
    }
    if let Some(u) = v.get("table-uuid").and_then(Value::as_str) {
        cx.format_set("table_uuid", truncate_chars(u, 64));
    }
    if let Some(l) = v.get("location").and_then(Value::as_str) {
        cx.format_set("location", user_path(cx, l));
    }
    ms_date(cx, "last_updated", DateField::Modified, v.get("last-updated-ms"));
    // The current schema (format v2: `schemas` + `current-schema-id`; v1: `schema`).
    let current = v.get("current-schema-id").and_then(Value::as_i64);
    let schema = v
        .get("schemas")
        .and_then(Value::as_array)
        .and_then(|s| s.iter().find(|x| x.get("schema-id").and_then(Value::as_i64) == current).or_else(|| s.last()))
        .or_else(|| v.get("schema"));
    if let Some(s) = schema {
        let f = fields(s);
        cx.format_set("column_count", f.len());
        cx.format_set("columns", Value::Object(f));
    }
    if let Some(n) = v.get("schemas").and_then(Value::as_array) {
        cx.format_set("schema_versions", n.len());
    }
    let spec_id = v.get("default-spec-id").and_then(Value::as_i64);
    let spec = v
        .get("partition-specs")
        .and_then(Value::as_array)
        .and_then(|s| s.iter().find(|x| x.get("spec-id").and_then(Value::as_i64) == spec_id))
        .and_then(|s| s.get("fields"))
        .and_then(Value::as_array);
    if let Some(p) = spec.filter(|p| !p.is_empty()) {
        let parts: Vec<String> = p
            .iter()
            .take(50)
            .map(|f| {
                format!(
                    "{} ({})",
                    f.get("name").and_then(Value::as_str).unwrap_or(""),
                    f.get("transform").and_then(Value::as_str).unwrap_or("")
                )
            })
            .collect();
        cx.format_set("partitioning", parts);
    }
    if let Some(p) = v.get("properties").and_then(Value::as_object).filter(|p| !p.is_empty()) {
        let m: Map<String, Value> = p
            .iter()
            .take(50)
            .map(|(k, v)| {
                (k.clone(), Value::String(truncate_chars(&redact_sensitive(v.as_str().unwrap_or_default()), 200)))
            })
            .collect();
        cx.format_set("properties", Value::Object(m));
    }
    let snaps = v.get("snapshots").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    cx.format_set("snapshots", snaps.len());
    let times: Vec<i64> = snaps.iter().filter_map(|s| s.get("timestamp-ms").and_then(Value::as_i64)).collect();
    if let (Some(a), Some(b)) = (times.iter().min(), times.iter().max()) {
        if let Some(t) = epoch_text(*a, "ms") {
            cx.format_set("first_snapshot", t);
        }
        if let Some(t) = epoch_text(*b, "ms") {
            cx.format_set("last_snapshot", t);
        }
    }
    let cur = v.get("current-snapshot-id").and_then(Value::as_i64);
    if let Some(s) = snaps.iter().find(|s| s.get("snapshot-id").and_then(Value::as_i64) == cur)
        && let Some(sum) = s.get("summary").and_then(Value::as_object)
    {
        for (k, out) in [
            ("operation", "operation"),
            ("total-records", "rows"),
            ("total-data-files", "data_files"),
            ("total-delete-files", "delete_files"),
            ("total-files-size", "bytes"),
        ] {
            if let Some(x) = sum.get(k).and_then(Value::as_str) {
                match x.parse::<u64>() {
                    Ok(n) => cx.format_set(out, n),
                    Err(_) => cx.format_set(out, truncate_chars(x, 100)),
                }
            }
        }
    }
}

impl Extractor for TableMeta {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let name = probe.name.unwrap_or_default().replace('\\', "/");
        let starts = |k: &[u8]| h.trim_ascii_start().starts_with(k);
        let delta_action =
            [&b"{\"commitInfo\""[..], b"{\"protocol\"", b"{\"metaData\"", b"{\"add\"", b"{\"remove\"", b"{\"txn\""];
        if delta_action.iter().any(|k| starts(k)) {
            return Some(Sniff { format: "delta_log", confidence: 0.98 });
        }
        // The catalogue names a commit by its folder alone.
        if name.contains("_delta_log/") && name.to_ascii_lowercase().ends_with(".json") {
            return Some(Sniff { format: "delta_log", confidence: 0.6 });
        }
        let has = |k: &[u8]| h.windows(k.len()).any(|w| w == k);
        if has(b"hoodie.table.name=") || name.ends_with("hoodie.properties") && has(b"hoodie.") {
            return Some(Sniff { format: "hudi_table", confidence: 0.95 });
        }
        if starts(b"{") && has(b"\"partitionToWriteStats\"") {
            return Some(Sniff { format: "hudi_commit", confidence: 0.95 });
        }
        let iceberg = starts(b"{") && has(b"\"format-version\"") && has(b"\"table-uuid\"");
        iceberg.then_some(Sniff { format: "iceberg_metadata", confidence: 0.98 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        if cx.format_id() == "delta_log" {
            delta(cx, &text);
        } else if cx.format_id() == "hudi_table" {
            hudi_properties(cx, &text);
        } else if cx.format_id() == "hudi_commit" {
            let v: Value = serde_json::from_str(&text).map_err(|_| ExtractError::malformed("commit JSON"))?;
            hudi_commit(cx, &v, src.name_hint());
        } else {
            let v: Value = serde_json::from_str(&text).map_err(|_| ExtractError::malformed("metadata JSON"))?;
            iceberg(cx, &v);
        }
        Ok(())
    }
}

crate::register_extractor!(TableMeta);

/// A Java properties value with its `\:`, `\=` and `\\` escapes undone.
fn unescape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(match n {
                    't' => '\t',
                    'n' => '\n',
                    other => other,
                });
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `name → type` of an Avro record schema (Hudi keeps Avro schemas as JSON text).
fn avro_fields(schema: &str) -> Option<Map<String, Value>> {
    let v: Value = serde_json::from_str(schema).ok()?;
    let fields = v.get("fields")?.as_array()?;
    let ty = |t: &Value| -> String {
        let one = |t: &Value| match t {
            Value::String(s) => s.clone(),
            Value::Object(o) => match (o.get("logicalType"), o.get("type")) {
                (Some(Value::String(l)), _) => l.clone(),
                (_, Some(Value::String(s))) => s.clone(),
                _ => "?".into(),
            },
            _ => "?".into(),
        };
        match t {
            Value::Array(u) => {
                let rest: Vec<String> = u.iter().filter(|x| x.as_str() != Some("null")).map(one).collect();
                let opt = if rest.len() < u.len() { "?" } else { "" };
                format!("{}{opt}", rest.join(" | "))
            }
            other => one(other),
        }
    };
    Some(
        fields
            .iter()
            .take(MAX_FIELDS)
            .filter_map(|f| {
                let name = f.get("name")?.as_str()?;
                Some((truncate_chars(name, 200), Value::String(truncate_chars(&ty(f.get("type")?), 200))))
            })
            .collect(),
    )
}

fn hudi_properties(cx: &mut Context<'_>, text: &str) {
    let mut props: Vec<(String, String)> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with(['#', '!'])) {
        let Some(i) = line.find(['=', ':']).filter(|&i| i == 0 || !line[..i].ends_with('\\')) else { continue };
        props.push((unescape(line[..i].trim()), unescape(line[i + 1..].trim())));
        if props.len() >= 10_000 {
            break;
        }
    }
    let get = |k: &str| props.iter().find(|(p, _)| p == k).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty());
    for (key, out) in [
        ("hoodie.table.name", "table_name"),
        ("hoodie.database.name", "database"),
        ("hoodie.table.type", "table_type"),
        ("hoodie.table.version", "table_version"),
        ("hoodie.timeline.layout.version", "timeline_layout_version"),
        ("hoodie.table.base.file.format", "base_file_format"),
        ("hoodie.table.log.file.format", "log_file_format"),
        ("hoodie.table.precombine.field", "precombine_field"),
        ("hoodie.table.ordering.fields", "ordering_fields"),
        ("hoodie.table.keygenerator.class", "key_generator"),
        ("hoodie.table.keygenerator.type", "key_generator_type"),
        ("hoodie.table.payload.class", "payload_class"),
        ("hoodie.table.recordkey.fields", "record_key_fields"),
        ("hoodie.table.partition.fields", "partition_fields"),
        ("hoodie.table.metadata.partitions", "metadata_partitions"),
    ] {
        if let Some(v) = get(key) {
            let v = truncate_chars(v, 300);
            if out.ends_with("_fields") || out == "metadata_partitions" {
                let list: Vec<&str> = v.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
                cx.format_set(out, serde_json::json!(list));
            } else {
                cx.format_set(out, v);
            }
        }
    }
    for (key, out) in [
        ("hoodie.populate.meta.fields", "populate_meta_fields"),
        ("hoodie.datasource.write.hive_style_partitioning", "hive_style_partitioning"),
        ("hoodie.partition.metafile.use.base.format", "partition_metafile_base_format"),
    ] {
        if let Some(v) = get(key) {
            cx.format_set(out, v == "true");
        }
    }
    if let Some(f) = get("hoodie.table.create.schema").and_then(avro_fields) {
        cx.format_set("schema", Value::Object(f));
    }
    cx.format_set("properties", props.len());
}

fn hudi_commit(cx: &mut Context<'_>, v: &Value, name: Option<&str>) {
    // `<instant>.<action>[.inflight|.requested]`, the instant `yyyyMMddHHmmss[SSS]`.
    if let Some(file) = name.map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n)) {
        let mut parts = file.split('.');
        let instant = parts.next().unwrap_or("");
        if let Some(action) = parts.next() {
            cx.format_set("action", truncate_chars(action, 40));
        }
        if (instant.len() == 14 || instant.len() == 17) && instant.bytes().all(|b| b.is_ascii_digit()) {
            let t = &instant[..14];
            let when = format!("{}-{}-{}T{}:{}:{}Z", &t[..4], &t[4..6], &t[6..8], &t[8..10], &t[10..12], &t[12..14]);
            if when.parse::<jiff::Timestamp>().is_ok() {
                cx.format_set("instant", when.clone());
                cx.temporal().source("instant".to_string()).content_date(DateField::Modified, when, false);
            }
        }
    }
    if let Some(op) = v.get("operationType").and_then(Value::as_str) {
        cx.format_set("operation", truncate_chars(op, 40));
    }
    if let Some(c) = v.get("compacted").and_then(Value::as_bool) {
        cx.format_set("compacted", c);
    }
    let parts = v.get("partitionToWriteStats").and_then(Value::as_object);
    let mut totals: [(&str, &str, u64); 6] = [
        ("numWrites", "records_written", 0),
        ("numInserts", "inserts", 0),
        ("numUpdateWrites", "updates", 0),
        ("numDeletes", "deletes", 0),
        ("totalWriteBytes", "bytes_written", 0),
        ("totalWriteErrors", "write_errors", 0),
    ];
    let mut files = 0u64;
    for stats in parts.into_iter().flat_map(|p| p.values()).filter_map(Value::as_array).flatten() {
        files += 1;
        for (key, _, n) in &mut totals {
            *n += stats.get(*key).and_then(Value::as_u64).unwrap_or(0);
        }
    }
    cx.format_set("partitions", parts.map_or(0, Map::len));
    cx.format_set("files_written", files);
    for (_, out, n) in totals {
        cx.format_set(out, n);
    }
    if let Some(r) = v.get("partitionToReplaceFileIds").and_then(Value::as_object) {
        cx.format_set("files_replaced", r.values().filter_map(Value::as_array).map(Vec::len).sum::<usize>());
    }
    if let Some(f) = v.pointer("/extraMetadata/schema").and_then(Value::as_str).and_then(avro_fields) {
        cx.format_set("schema", Value::Object(f));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn properties_escapes() {
        assert_eq!(unescape(r"hdfs\://tides/a\=b"), "hdfs://tides/a=b");
        let f = avro_fields(r#"{"type":"record","fields":[{"name":"h","type":["null","double"]},{"name":"t","type":{"type":"long","logicalType":"timestamp-micros"}}]}"#).unwrap();
        assert_eq!(f["h"], "double?");
        assert_eq!(f["t"], "timestamp-micros");
    }

    #[test]
    fn nested_types() {
        let t: Value = serde_json::from_str(
            r#"{"type":"map","keyType":"string","valueType":{"type":"array","elementType":"long"}}"#,
        )
        .unwrap();
        assert_eq!(type_text(&t, 0), "map<string, array<long>>");
    }

    crate::fixture_tests!("delta_log", "iceberg_metadata", "hudi_table", "hudi_commit");
}
