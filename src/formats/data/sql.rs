//! SQL scripts and dumps: dialect, statements by kind, tables with their
//! columns and references, rows inserted per table, views, indexes and
//! routines. `CREATE TABLE` statements are parsed with `sqlparser`; the rest
//! are classified by their leading keywords, which keeps large dumps fast.
//! dbt models (SQL with Jinja) also report their `ref()` models, `source()`
//! tables, macros called and the `config()` materialisation.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};
use sqlparser::ast::Statement;
use sqlparser::dialect::{Dialect, GenericDialect, MsSqlDialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, truncate_chars,
};

/// Extractor for SQL.
pub struct Sql;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.sql",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "sql",
        name: "SQL script",
        family: "data.sql",
        mimes: &["application/sql"],
        extensions: &["sql", "ddl", "dml", "pgsql", "psql", "mysql"],
        magic: &[],
        parent: Some("text"),
    }],
};

const MAX_TABLES: usize = 200;
const MAX_COLUMNS: usize = 100;
/// Statements longer than this are classified but not parsed.
const MAX_PARSE_STATEMENT: usize = 64 * 1024;
/// Recursion limit handed to `sqlparser` (it recurses on nested expressions).
const RECURSION_LIMIT: usize = 24;

impl Extractor for Sql {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let head = std::str::from_utf8(&probe.head[..probe.head.len().min(1024)]).ok()?;
        let dump = ["-- MySQL dump", "-- PostgreSQL database dump", "-- phpMyAdmin SQL Dump", "-- MariaDB dump"];
        dump.iter().any(|d| head.starts_with(d)).then_some(Sniff { format: "sql", confidence: 0.85 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.emit_text(TextRole::Data, &text);
        let dialect = guess_dialect(&text);
        let parser_dialect: Box<dyn Dialect> = match dialect {
            "mysql" => Box::new(MySqlDialect {}),
            "postgresql" => Box::new(PostgreSqlDialect {}),
            "sqlite" => Box::new(SQLiteDialect {}),
            "mssql" => Box::new(MsSqlDialect {}),
            _ => Box::new(GenericDialect {}),
        };
        let mut s = Summary::default();
        for (n, stmt) in split(&text).into_iter().enumerate() {
            if n % 1024 == 0 {
                cx.checkpoint()?;
            }
            s.statement(stmt, parser_dialect.as_ref());
        }
        header_facts(&text, cx);
        dbt(&text, cx);
        s.report(dialect, cx);
        Ok(())
    }
}

crate::register_extractor!(Sql);

fn guess_dialect(text: &str) -> &'static str {
    let head = &text[..floor(text, 256 * 1024)];
    let lower = head.to_ascii_lowercase();
    let score = |needles: &[&str]| needles.iter().filter(|n| lower.contains(*n)).count();
    let scores = [
        ("mysql", score(&["-- mysql dump", "-- mariadb", "engine=", "auto_increment", "`", "lock tables", "/*!40"])),
        (
            "postgresql",
            score(&["-- postgresql", "copy ", " from stdin", "::", "serial", "create extension", "$$", "owner to"]),
        ),
        ("sqlite", score(&["pragma ", "autoincrement", "begin transaction;", "sqlite_sequence"])),
        ("mssql", score(&["\ngo\n", "nvarchar", "identity(", "[dbo]", "set ansi_nulls"])),
        ("oracle", score(&["varchar2", "number(", "nvl(", "sysdate"])),
    ];
    let best = scores.iter().max_by_key(|(_, n)| *n).filter(|(_, n)| *n > 0);
    best.map_or("generic", |(d, _)| *d)
}

/// Split into statements at `;` outside strings, identifiers, comments and
/// dollar quotes. `PostgreSQL` `COPY … FROM stdin;` data runs to `\.`; `MySQL`
/// `DELIMITER` and T-SQL `GO` lines are honoured.
fn split(text: &str) -> Vec<&str> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    let mut delimiter: &[u8] = b";";
    while i < b.len() {
        let c = b[i];
        let at_line_start = i == 0 || b[i - 1] == b'\n';
        if at_line_start {
            let line_end = b[i..].iter().position(|&x| x == b'\n').map_or(b.len(), |p| i + p);
            let line = text[i..line_end].trim();
            if let Some(new) = line.get(..10).filter(|p| p.eq_ignore_ascii_case("delimiter ")).map(|_| &line[10..]) {
                push(&mut out, &text[start..i]);
                delimiter = new.trim().as_bytes();
                if delimiter.is_empty() {
                    delimiter = b";";
                }
                i = line_end;
                start = i;
                continue;
            }
            if line.eq_ignore_ascii_case("go") {
                push(&mut out, &text[start..i]);
                i = line_end;
                start = i;
                continue;
            }
        }
        match c {
            b'\'' | b'"' | b'`' => i = skip_quoted(b, i, c),
            b'[' if b.get(i + 1).is_some_and(u8::is_ascii_alphabetic) => {
                i = b[i..].iter().position(|&x| x == b']' || x == b'\n').map_or(b.len(), |p| i + p + 1);
            }
            b'-' if b.get(i + 1) == Some(&b'-') => {
                i = b[i..].iter().position(|&x| x == b'\n').map_or(b.len(), |p| i + p);
            }
            b'#' if at_line_start => i = b[i..].iter().position(|&x| x == b'\n').map_or(b.len(), |p| i + p),
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i = text[i + 2..].find("*/").map_or(b.len(), |p| i + 2 + p + 2);
            }
            b'$' => i = skip_dollar(text, i),
            _ if b[i..].starts_with(delimiter) => {
                let stmt = &text[start..i];
                i += delimiter.len();
                // `COPY t FROM stdin;` is followed by data rows up to `\.`.
                if is_copy_from_stdin(stmt) {
                    let end = text[i..].find("\n\\.").map_or(b.len(), |p| i + p + 3);
                    push(&mut out, &text[start..end]);
                    i = end;
                } else {
                    push(&mut out, stmt);
                }
                start = i;
            }
            _ => i += 1,
        }
    }
    push(&mut out, &text[start..]);
    out
}

fn push<'t>(out: &mut Vec<&'t str>, stmt: &'t str) {
    let stmt = stmt.trim();
    if !strip_leading_comments(stmt).is_empty() {
        out.push(stmt);
    }
}

fn skip_quoted(b: &[u8], start: usize, q: u8) -> usize {
    let mut i = start + 1;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 2;
        } else if b[i] == q {
            if b.get(i + 1) == Some(&q) {
                i += 2;
            } else {
                return i + 1;
            }
        } else {
            i += 1;
        }
    }
    b.len()
}

/// `$$ … $$` or `$tag$ … $tag$`; a lone `$` (parameters like `$1`) is skipped.
fn skip_dollar(text: &str, start: usize) -> usize {
    let rest = &text[start + 1..];
    let tag_len = rest.find('$').filter(|&n| rest[..n].chars().all(|c| c.is_alphanumeric() || c == '_'));
    match tag_len {
        Some(n) if !rest[..n].starts_with(|c: char| c.is_ascii_digit()) => {
            let tag = &text[start..start + n + 2];
            text[start + tag.len()..].find(tag).map_or(text.len(), |p| start + tag.len() + p + tag.len())
        }
        _ => start + 1,
    }
}

fn is_copy_from_stdin(stmt: &str) -> bool {
    let s = strip_leading_comments(stmt).to_ascii_lowercase();
    s.starts_with("copy ") && s.contains("from stdin")
}

fn strip_leading_comments(s: &str) -> &str {
    let mut s = s.trim_start();
    loop {
        if s.starts_with("--") || (s.starts_with('#') && !s.starts_with("#!")) {
            s = s.split_once('\n').map_or("", |(_, r)| r).trim_start();
        } else if let Some(rest) = s.strip_prefix("/*").filter(|_| !s.starts_with("/*!")) {
            s = rest.split_once("*/").map_or("", |(_, r)| r).trim_start();
        } else {
            return s;
        }
    }
}

#[derive(Default)]
struct Summary {
    statements: u64,
    kinds: BTreeMap<String, u64>,
    tables: Vec<Value>,
    table_names: Vec<String>,
    inserts: BTreeMap<String, u64>,
    copy_rows: BTreeMap<String, u64>,
    views: Vec<String>,
    indexes: u64,
    routines: Vec<String>,
    parse_errors: u64,
    first_error: Option<String>,
}

static NAME_AFTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^(?:create\s+(?:or\s+replace\s+)?(?:temp(?:orary)?\s+|materialized\s+|unique\s+)*(?:table|view|index|function|procedure|trigger)\s+(?:if\s+not\s+exists\s+)?|insert\s+(?:ignore\s+)?into\s+|copy\s+|replace\s+into\s+)([\w."`\[\]]+)"#)
        .expect("valid")
});
static REFERENCES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?-u:\b)references\s+([\w."`\[\]]+)"#).expect("valid"));

fn clean_name(n: &str) -> String {
    n.replace(['`', '"', '[', ']'], "")
}

impl Summary {
    fn statement(&mut self, stmt: &str, dialect: &dyn Dialect) {
        let body = strip_leading_comments(stmt);
        if body.is_empty() {
            return;
        }
        self.statements += 1;
        let kind = kind(body);
        *self.kinds.entry(kind.clone()).or_default() += 1;
        let name = NAME_AFTER.captures(body).map(|c| clean_name(&c[1]));
        match kind.as_str() {
            "create_table" => self.create_table(body, name.as_deref(), dialect),
            "insert" | "replace" => {
                if let Some(n) = name {
                    *self.inserts.entry(n).or_default() += value_rows(body);
                }
            }
            "copy" => {
                if let Some(n) = name {
                    let rows = body.lines().skip(1).filter(|l| *l != "\\." && !l.is_empty()).count() as u64;
                    *self.copy_rows.entry(n).or_default() += rows;
                }
            }
            "create_view" => self.views.extend(name.filter(|_| self.views.len() < MAX_TABLES)),
            "create_index" => self.indexes += 1,
            "create_function" | "create_procedure" | "create_trigger" => {
                self.routines.extend(name.filter(|_| self.routines.len() < MAX_TABLES));
            }
            _ => {}
        }
    }

    fn create_table(&mut self, body: &str, name: Option<&str>, dialect: &dyn Dialect) {
        let references: Vec<String> = REFERENCES.captures_iter(body).map(|c| clean_name(&c[1])).take(50).collect();
        let parsed = (body.len() <= MAX_PARSE_STATEMENT).then(|| {
            Parser::new(dialect)
                .with_recursion_limit(RECURSION_LIMIT)
                .try_with_sql(body)
                .and_then(|mut p| p.parse_statements())
        });
        let mut entry = json!({ "name": name, "references": references });
        match parsed {
            Some(Ok(stmts)) => {
                if let Some(Statement::CreateTable(ct)) = stmts.first() {
                    let cols: Vec<Value> = ct
                        .columns
                        .iter()
                        .take(MAX_COLUMNS)
                        .map(|c| json!({ "name": c.name.value, "type": c.data_type.to_string() }))
                        .collect();
                    entry["name"] = json!(clean_name(&ct.name.to_string()));
                    entry["columns"] = Value::Array(cols);
                    entry["column_count"] = json!(ct.columns.len());
                }
            }
            Some(Err(e)) => {
                self.parse_errors += 1;
                self.first_error.get_or_insert_with(|| truncate_chars(&e.to_string(), 200));
            }
            None => {}
        }
        if let Some(n) = entry["name"].as_str() {
            self.table_names.push(n.to_string());
        }
        if self.tables.len() < MAX_TABLES {
            self.tables.push(entry);
        }
    }

    fn report(&self, dialect: &str, cx: &mut Context<'_>) {
        cx.format_set("dialect", dialect);
        cx.format_set("statements", self.statements);
        cx.format_set("statement_kinds", json!(self.kinds));
        cx.format_set("table_count", self.table_names.len());
        if !self.tables.is_empty() {
            cx.format_set("tables", Value::Array(self.tables.clone()));
        }
        let mut rows = self.inserts.clone();
        for (t, n) in &self.copy_rows {
            *rows.entry(t.clone()).or_default() += n;
        }
        if !rows.is_empty() {
            cx.format_set("rows_by_table", json!(rows));
            cx.format_set("rows", rows.values().sum::<u64>());
        }
        if !self.views.is_empty() {
            cx.format_set("views", json!(self.views));
        }
        if self.indexes > 0 {
            cx.format_set("indexes", self.indexes);
        }
        if !self.routines.is_empty() {
            cx.format_set("routines", json!(self.routines));
        }
        if self.parse_errors > 0 {
            cx.format_set("create_table_parse_errors", self.parse_errors);
        }
        if let Some(e) = &self.first_error {
            cx.format_set("first_parse_error", e.clone());
        }
        if self.kinds.keys().any(|k| k == "drop" || k == "delete" || k == "truncate") {
            cx.security().risk("destructive_statements", Some("DROP / DELETE / TRUNCATE present".into()));
        }
        if self.kinds.contains_key("grant") {
            cx.security().risk("privilege_changes", Some("GRANT statements present".into()));
        }
    }
}

/// `create_table`, `insert`, `select`, … from the leading keywords.
fn kind(body: &str) -> String {
    let words: Vec<String> = body.split_whitespace().take(6).map(str::to_ascii_lowercase).collect();
    let w = |i: usize| words.get(i).map_or("", String::as_str);
    let first = w(0).trim_end_matches(';');
    if first.starts_with("/*!") {
        return "mysql_directive".into();
    }
    match first {
        "create" | "alter" => {
            let object = words
                .iter()
                .skip(1)
                .find(|x| {
                    !matches!(
                        x.as_str(),
                        "or" | "replace"
                            | "temp"
                            | "temporary"
                            | "unique"
                            | "materialized"
                            | "global"
                            | "local"
                            | "unlogged"
                            | "if"
                            | "not"
                            | "exists"
                    )
                })
                .map_or("", String::as_str);
            format!("{first}_{object}")
        }
        "with" => "select".into(),
        "" => "empty".into(),
        other if other.chars().all(|c| c.is_ascii_alphabetic() || c == '_') => other.into(),
        _ => "other".into(),
    }
}

/// Rows in `INSERT … VALUES (…), (…)`: count top-level parenthesised groups after `VALUES`.
fn value_rows(body: &str) -> u64 {
    let lower_at = body.to_ascii_lowercase().find("values");
    let Some(at) = lower_at else { return 1 };
    let b = &body.as_bytes()[at..];
    let (mut depth, mut rows, mut i) = (0i32, 0u64, 0);
    while i < b.len() {
        match b[i] {
            b'\'' | b'"' => {
                i = skip_quoted(b, i, b[i]);
                continue;
            }
            b'(' => {
                if depth == 0 {
                    rows += 1;
                }
                depth += 1;
            }
            b')' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    rows.max(1)
}

/// Facts from dump headers: database name, server version.
/// dbt models: `{{ ref('orders') }}`, `{{ source('raw', 'tides') }}`,
/// `{{ config(materialized='table') }}` and other `{{ macro(…) }}` calls.
fn dbt(text: &str, cx: &mut Context<'_>) {
    static CALL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\{\{-?\s*([\w.]+)\s*\(([^}]*)\)\s*-?\}\}").expect("valid"));
    static ARG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"['"]([^'"]+)['"]"#).expect("valid"));
    static MATERIALIZED: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"materialized\s*=\s*['"](\w+)['"]"#).expect("valid"));
    if !text.contains("{{") {
        return;
    }
    let (mut refs, mut sources, mut macros) = (Vec::new(), Vec::new(), std::collections::BTreeSet::new());
    for c in CALL.captures_iter(text) {
        let args: Vec<&str> = ARG.captures_iter(&c[2]).filter_map(|a| a.get(1)).map(|m| m.as_str()).collect();
        match &c[1] {
            "ref" => refs.extend(args.last().map(|a| (*a).to_string())),
            "source" => sources.push(args.join(".")),
            "config" => {}
            m => {
                macros.insert(m.to_string());
            }
        }
    }
    if refs.is_empty() && sources.is_empty() && !text.contains("{{ config(") {
        return;
    }
    let mut d = serde_json::Map::new();
    d.insert("refs".into(), json!(refs));
    d.insert("sources".into(), json!(sources));
    if !macros.is_empty() {
        d.insert("macros".into(), json!(macros));
    }
    if let Some(m) = MATERIALIZED.captures(text) {
        d.insert("materialized".into(), json!(&m[1]));
    }
    cx.format_set("dbt", Value::Object(d));
}

fn header_facts(text: &str, cx: &mut Context<'_>) {
    for line in text.lines().take(40).filter(|l| l.starts_with("--")) {
        let l = line.trim_start_matches('-').trim();
        for (prefix, key) in [
            ("Database: ", "database"),
            ("Server version", "server_version"),
            ("Dumped from database version ", "server_version"),
            ("Host: ", "host"),
        ] {
            if let Some(rest) = l.strip_prefix(prefix) {
                let v = rest.trim_start_matches([':', '\t', ' ']).split("    ").next().unwrap_or("").trim();
                if !v.is_empty() {
                    cx.format_set(key, truncate_chars(v, 100));
                }
            }
        }
    }
}

fn floor(text: &str, max: usize) -> usize {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dbt_models() {
        let model = b"{{ config(materialized='table') }}\nselect * from {{ ref('stg_tides') }} t\njoin {{ source('raw', 'gauges') }} g using (id)\nwhere {{ is_recent('t.read_at') }}\n";
        let r = crate::plugin::testing::report_for("tides.sql", model);
        let d = &r.format["sql"]["dbt"];
        assert_eq!(d["refs"], json!(["stg_tides"]));
        assert_eq!(d["sources"], json!(["raw.gauges"]));
        assert_eq!(d["macros"], json!(["is_recent"]));
        assert_eq!(d["materialized"], "table");
        let plain = crate::plugin::testing::report_for("t.sql", b"select 1;\n");
        assert!(plain.format["sql"].get("dbt").is_none());
    }

    #[test]
    fn splitting() {
        let sql = "INSERT INTO t VALUES ('a;b'), ('c');\n-- x; y\nCREATE FUNCTION f() RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql;\n\
                   COPY t (a) FROM stdin;\n1\n2\n\\.\nSELECT 1";
        let parts = split(sql);
        assert_eq!(parts.len(), 4, "{parts:?}");
        assert_eq!(value_rows(parts[0]), 2);
        assert!(is_copy_from_stdin(parts[2]));
        assert_eq!(kind("CREATE OR REPLACE VIEW v AS SELECT 1"), "create_view");
        assert_eq!(kind("create temporary table x (a int)"), "create_table");
        assert_eq!(split("DELIMITER //\nCREATE PROCEDURE p() BEGIN SELECT 1; END //\nDELIMITER ;\nSELECT 2;").len(), 2);
        assert_eq!(guess_dialect("CREATE TABLE `t` (id int AUTO_INCREMENT) ENGINE=InnoDB;"), "mysql");
    }

    crate::fixture_tests!("sql");
}
