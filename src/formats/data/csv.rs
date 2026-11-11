//! CSV, TSV and other delimiter-separated tables, and fixed-width text
//! tables: dialect (delimiter, quote, header; column spans for fixed-width
//! tables), columns with inferred types, null ratio, distinct counts,
//! numeric and date ranges, and a few sample rows with personal data
//! redacted.
//!
//! Fixed-width columns are found the way pandas' `read_fwf` infers them:
//! the runs of character positions that hold a non-blank character in any
//! of the first 100 lines.
//!
//! Specification: <https://www.rfc-editor.org/rfc/rfc4180>

use std::collections::HashSet;

use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, parse_date,
    redact_sensitive, truncate_chars,
};

/// Extractor for delimiter-separated tables.
pub struct Csv;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.csv",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "csv",
            name: "CSV table",
            family: "data.csv",
            mimes: &["text/csv"],
            extensions: &["csv", "psv"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "tsv",
            name: "TSV table",
            family: "data.csv",
            mimes: &["text/tab-separated-values"],
            extensions: &["tsv", "tab"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "fixed_width",
            name: "Fixed-width text table",
            family: "data.csv",
            mimes: &["text/x-fixed-width"],
            extensions: &["fwf"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

const MAX_COLUMNS: usize = 200;
const MAX_DISTINCT: usize = 1000;
const SAMPLE_ROWS: usize = 5;
/// Rows whose values are profiled; later rows are only counted.
const PROFILE_ROWS: u64 = 100_000;
/// Lines whose blank positions decide fixed-width columns (as pandas).
const INFER_LINES: usize = 100;

impl Extractor for Csv {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Only by name: aligned text is common and rarely a table. `.prn`
        // is also a print file, which carries no such layout.
        let ext = probe.extension?.to_ascii_lowercase();
        let confidence = match ext.as_str() {
            "fwf" => 0.9,
            "prn" => 0.6,
            _ => return None,
        };
        let head = &probe.head[..probe.head.len().min(16_384)];
        let text = std::str::from_utf8(head).ok().or_else(|| {
            let e = std::str::from_utf8(head).err()?;
            (e.error_len().is_none()).then(|| std::str::from_utf8(&head[..e.valid_up_to()]).ok()).flatten()
        })?;
        let lines = table_lines(text);
        tabular(&lines).then_some(Sniff { format: "fixed_width", confidence })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, cut) = cx.read_bytes(src)?;
        let text = crate::plugin::decode_text(&bytes).text;
        cx.emit_text(TextRole::Data, &text);
        if cx.format_id() == "fixed_width" {
            return fixed_width(&text, cut, cx);
        }
        let delimiter = if cx.format_id() == "tsv" { b'\t' } else { sniff_delimiter(&text) };
        let mut reader = csv::ReaderBuilder::new()
            .delimiter(delimiter)
            .has_headers(false)
            .flexible(true)
            .comment(None)
            .from_reader(text.as_bytes());

        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut table = Table::default();
        let mut errors = 0u64;
        for (n, record) in reader.records().enumerate() {
            if n % 8192 == 0 {
                cx.checkpoint()?;
            }
            match record {
                Ok(r) => {
                    let row: Vec<String> = r.iter().map(str::to_string).collect();
                    table.row(&row);
                    if rows.len() < 50 {
                        rows.push(row);
                    }
                }
                Err(_) => errors += 1,
            }
        }
        if cut && table.rows > 0 {
            // The last row of a cut input is incomplete.
            table.rows -= 1;
            cx.format_set("rows_counted_until_cut", true);
        }
        table.finish(&rows, Dialect::Delimited(delimiter), errors, cx);
        Ok(())
    }
}

crate::register_extractor!(Csv);

/// The non-blank lines of a fixed-width table (form feeds and trailing
/// carriage returns dropped).
fn table_lines(text: &str) -> Vec<&str> {
    text.lines().map(|l| l.trim_end_matches(['\r', '\x0c'])).filter(|l| !l.trim().is_empty()).collect()
}

/// Column spans `(start, end)` in characters, `end` open for a last column
/// that reaches the end of its longest line: the runs of positions that
/// hold a non-blank character in any of the first lines.
fn infer_spans(lines: &[&str]) -> Vec<(usize, Option<usize>)> {
    let mut mask: Vec<bool> = Vec::new();
    for line in lines.iter().take(INFER_LINES) {
        for (i, c) in line.chars().enumerate() {
            if i >= mask.len() {
                mask.resize(i + 1, false);
            }
            if !matches!(c, ' ' | '\t') {
                mask[i] = true;
            }
        }
    }
    let mut spans = Vec::new();
    let mut start = None;
    for (i, &on) in mask.iter().enumerate() {
        match (on, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                spans.push((s, Some(i)));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        spans.push((s, None));
    }
    spans
}

/// Whether `lines` read as a fixed-width table: several lines, no tabs, and
/// at least two columns that most lines fill (prose fills nearly every
/// position and gives one column).
fn tabular(lines: &[&str]) -> bool {
    if lines.len() < 3 || lines.iter().take(INFER_LINES).any(|l| l.contains('\t')) {
        return false;
    }
    let spans = infer_spans(lines);
    if !(2..=MAX_COLUMNS).contains(&spans.len()) {
        return false;
    }
    let sample: Vec<Vec<String>> = lines.iter().take(INFER_LINES).map(|l| split_fixed(l, &spans)).collect();
    // Most lines fill most columns.
    let filled = sample.iter().filter(|r| r.iter().filter(|v| !v.is_empty()).count() * 2 > spans.len()).count();
    filled * 10 >= sample.len() * 8
}

/// The fields of `line` cut at `spans`, trimmed.
fn split_fixed(line: &str, spans: &[(usize, Option<usize>)]) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    spans
        .iter()
        .map(|&(s, e)| {
            let e = e.unwrap_or(chars.len()).min(chars.len());
            chars.get(s..e.max(s)).map_or_else(String::new, |f| f.iter().collect::<String>().trim().to_string())
        })
        .collect()
}

fn fixed_width(text: &str, cut: bool, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let lines = table_lines(text);
    let spans = infer_spans(&lines);
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut table = Table::default();
    for (n, line) in lines.iter().enumerate() {
        if n % 8192 == 0 {
            cx.checkpoint()?;
        }
        let row = split_fixed(line, &spans);
        table.row(&row);
        if rows.len() < 50 {
            rows.push(row);
        }
    }
    if cut && table.rows > 0 {
        table.rows -= 1;
        cx.format_set("rows_counted_until_cut", true);
    }
    let spans_json: Vec<Value> = spans.iter().map(|&(s, e)| json!([s, e])).collect();
    table.finish(&rows, Dialect::Fixed(spans_json), 0, cx);
    Ok(())
}

/// How fields are separated.
enum Dialect {
    Delimited(u8),
    /// Column spans `[start, end]` in characters (`end` null: to the line end).
    Fixed(Vec<Value>),
}

/// The delimiter giving the most consistent field count over the first lines.
fn sniff_delimiter(text: &str) -> u8 {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).take(50).collect();
    let mut best = (b',', 0.0f64);
    for d in *b",\t;|" {
        let counts: Vec<usize> = lines.iter().map(|l| count_outside_quotes(l, d)).collect();
        let Some(&first) = counts.first() else { continue };
        if first == 0 {
            continue;
        }
        let consistent = counts.iter().filter(|&&c| c == first).count() as f64 / counts.len() as f64;
        let score = consistent * (first as f64).min(10.0);
        if score > best.1 {
            best = (d, score);
        }
    }
    best.0
}

fn count_outside_quotes(line: &str, d: u8) -> usize {
    let mut quoted = false;
    line.bytes()
        .filter(|&b| {
            if b == b'"' {
                quoted = !quoted;
            }
            b == d && !quoted
        })
        .count()
}

#[derive(Default, Clone)]
struct Column {
    integer: u64,
    float: u64,
    boolean: u64,
    date: u64,
    string: u64,
    nulls: u64,
    distinct: HashSet<String>,
    distinct_overflow: bool,
    min: Option<f64>,
    max: Option<f64>,
    sum: f64,
    numbers: u64,
    date_min: Option<String>,
    date_max: Option<String>,
    max_len: usize,
}

#[derive(Default)]
struct Table {
    rows: u64,
    width: usize,
    ragged: u64,
    columns: Vec<Column>,
}

fn is_null(v: &str) -> bool {
    matches!(v.trim(), "" | "NA" | "N/A" | "n/a" | "null" | "NULL" | "None" | "NaN" | "nan" | "-" | "\\N")
}

impl Table {
    fn row(&mut self, row: &[String]) {
        self.rows += 1;
        if self.width == 0 {
            self.width = row.len();
        } else if row.len() != self.width {
            self.ragged += 1;
        }
        if self.rows > PROFILE_ROWS {
            return;
        }
        if self.columns.len() < row.len().min(MAX_COLUMNS) {
            self.columns.resize(row.len().min(MAX_COLUMNS), Column::default());
        }
        for (c, v) in self.columns.iter_mut().zip(row.iter()) {
            c.add(v);
        }
    }

    fn finish(&self, rows: &[Vec<String>], dialect: Dialect, errors: u64, cx: &mut Context<'_>) {
        let header = has_header(rows);
        let names: Vec<String> = match (header, rows.first()) {
            (true, Some(h)) => h.iter().map(|s| s.trim().to_string()).collect(),
            _ => (1..=self.width).map(|i| format!("column_{i}")).collect(),
        };
        // Column statistics were collected over every row; take the header out.
        let header_row = rows.first().filter(|_| header);
        let data_rows = self.rows - u64::from(header);
        let mut columns = Vec::new();
        for (i, c) in self.columns.iter().enumerate() {
            let mut c = c.clone();
            if let Some(h) = header_row.and_then(|h| h.get(i)) {
                c.remove_header(h);
            }
            columns.push(c.to_json(names.get(i).map_or("", String::as_str), data_rows));
        }
        let samples: Vec<Value> = rows
            .iter()
            .skip(usize::from(header))
            .take(SAMPLE_ROWS)
            .map(|r| {
                json!(r.iter().take(MAX_COLUMNS).map(|v| truncate_chars(&redact_sensitive(v), 80)).collect::<Vec<_>>())
            })
            .collect();
        let dialect = match dialect {
            Dialect::Delimited(d) => {
                let name = match d {
                    b'\t' => "tab",
                    b';' => "semicolon",
                    b'|' => "pipe",
                    _ => "comma",
                };
                json!({ "delimiter": name, "quote": "\"", "header": header })
            }
            Dialect::Fixed(spans) => json!({ "layout": "fixed_width", "column_spans": spans, "header": header }),
        };
        cx.format_set("dialect", dialect);
        cx.format_set("rows", data_rows);
        cx.format_set("columns", self.width);
        if self.ragged > 0 {
            cx.format_set("ragged_rows", self.ragged);
        }
        if errors > 0 {
            cx.format_set("parse_errors", errors);
        }
        if self.rows > PROFILE_ROWS {
            cx.format_set("rows_profiled", PROFILE_ROWS);
        }
        cx.format_set("column_profile", Value::Array(columns));
        cx.format_set("sample_rows", Value::Array(samples));
    }
}

impl Column {
    fn add(&mut self, v: &str) {
        let t = v.trim();
        self.max_len = self.max_len.max(t.chars().count());
        if is_null(t) {
            self.nulls += 1;
            return;
        }
        if self.distinct.len() < MAX_DISTINCT {
            self.distinct.insert(t.to_string());
        } else if !self.distinct.contains(t) {
            self.distinct_overflow = true;
        }
        let numeric = t.replace(['_', ','], "");
        if let Ok(i) = numeric.parse::<i64>() {
            self.integer += 1;
            self.number(i as f64);
        } else if let Some(f) = numeric.parse::<f64>().ok().filter(|f| f.is_finite()) {
            self.float += 1;
            self.number(f);
        } else if matches!(t.to_ascii_lowercase().as_str(), "true" | "false" | "yes" | "no") {
            self.boolean += 1;
        } else if t.len() >= 8
            && t.chars().next().is_some_and(|c| c.is_ascii_digit())
            && let Some((d, _)) = parse_date(t)
        {
            self.date += 1;
            if self.date_min.as_ref().is_none_or(|m| d < *m) {
                self.date_min = Some(d.clone());
            }
            if self.date_max.as_ref().is_none_or(|m| d > *m) {
                self.date_max = Some(d);
            }
        } else {
            self.string += 1;
        }
    }

    fn number(&mut self, x: f64) {
        self.numbers += 1;
        self.sum += x;
        self.min = Some(self.min.map_or(x, |m| m.min(x)));
        self.max = Some(self.max.map_or(x, |m| m.max(x)));
    }

    /// Undo the effect of the header cell on the type counts.
    fn remove_header(&mut self, h: &str) {
        let t = h.trim();
        if is_null(t) {
            self.nulls = self.nulls.saturating_sub(1);
        } else {
            self.string = self.string.saturating_sub(1);
            if !self.distinct_overflow {
                self.distinct.remove(t);
            }
        }
    }

    fn kind(&self) -> &'static str {
        let typed = self.integer + self.float + self.boolean + self.date + self.string;
        if typed == 0 {
            return "empty";
        }
        // Allow a few stray values (5 %) before falling back to string.
        let dominant = |n: u64| n * 100 >= typed * 95;
        if dominant(self.integer) {
            "integer"
        } else if dominant(self.integer + self.float) {
            "number"
        } else if dominant(self.boolean) {
            "boolean"
        } else if dominant(self.date) {
            "date"
        } else {
            "string"
        }
    }

    fn to_json(&self, name: &str, rows: u64) -> Value {
        let mut m = Map::new();
        m.insert("name".into(), json!(name));
        let kind = self.kind();
        m.insert("type".into(), json!(kind));
        if rows > 0 {
            m.insert("null_ratio".into(), json!((self.nulls as f64 / rows as f64 * 1000.0).round() / 1000.0));
        }
        m.insert(
            "distinct".into(),
            if self.distinct_overflow { json!(format!(">{MAX_DISTINCT}")) } else { json!(self.distinct.len()) },
        );
        if matches!(kind, "integer" | "number") && self.numbers > 0 {
            m.insert("min".into(), json!(self.min));
            m.insert("max".into(), json!(self.max));
            m.insert("mean".into(), json!((self.sum / self.numbers as f64 * 1000.0).round() / 1000.0));
        }
        if kind == "date" {
            m.insert("min".into(), json!(self.date_min));
            m.insert("max".into(), json!(self.date_max));
        }
        if kind == "string" {
            m.insert("max_length".into(), json!(self.max_len));
        }
        Value::Object(m)
    }
}

/// A first row of distinct, non-numeric names above rows that have numbers
/// (or differ in type) is a header.
fn has_header(rows: &[Vec<String>]) -> bool {
    let Some((first, rest)) = rows.split_first() else { return false };
    let numeric = |v: &str| v.trim().replace(['_', ','], "").parse::<f64>().is_ok();
    if first.iter().any(|v| v.trim().is_empty() || numeric(v)) {
        return false;
    }
    let distinct: HashSet<&String> = first.iter().collect();
    if distinct.len() != first.len() {
        return false;
    }
    if rest.is_empty() {
        return true;
    }
    (0..first.len()).any(|i| rest.iter().filter_map(|r| r.get(i)).any(|v| numeric(v) || parse_date(v).is_some()))
        || rest.iter().take(10).all(|r| r.iter().zip(first).all(|(v, h)| v != h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialect_and_header() {
        assert_eq!(sniff_delimiter("a;b;c\n1;2;3\n"), b';');
        assert_eq!(sniff_delimiter("a,b\n\"x,y\",2\n"), b',');
        let rows = vec![vec!["id".to_string(), "name".to_string()], vec!["1".to_string(), "Ada".to_string()]];
        assert!(has_header(&rows));
        assert!(!has_header(&[vec!["1".to_string(), "2".to_string()]]));
    }

    #[test]
    fn fixed_width_columns() {
        let t = "harbour   tide  height\nSaltmere  high    4.10\nSaltmere  low     0.72\nBrackwell high    3.95\n";
        let lines = table_lines(t);
        assert_eq!(infer_spans(&lines), vec![(0, Some(9)), (10, Some(14)), (16, None)]);
        assert!(tabular(&lines));
        assert_eq!(split_fixed(lines[2], &infer_spans(&lines)), vec!["Saltmere", "low", "0.72"]);
        // Prose fills every position: one column, not a table.
        assert!(!tabular(&table_lines("The tide came in.\nIt went out again.\nGulls followed.\n")));
    }

    crate::fixture_tests!("csv", "tsv", "fixed_width");
}
