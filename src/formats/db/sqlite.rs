//! SQLite databases, read-only and in-house: the header (SQLite version
//! that last wrote it, page size and count, text encoding, user version,
//! application ID, journal mode, auto-vacuum, free pages), the schema from
//! `sqlite_schema` (tables with their columns and types, indexes, views,
//! triggers, virtual tables), row counts from the table b-trees (exact when
//! the page budget allows, estimated from the tree's fan-out otherwise) and
//! the application that made the file (GeoPackage, MBTiles, browser
//! histories, Core Data, Lightroom, Anki, …, see [`super::apps`]). Also the
//! write-ahead log and rollback journal beside a database. Rows are read
//! only for the few summaries an application gives; never written,
//! nothing is executed.
//!
//! Specification: SQLite "Database File Format" (fileformat2.html).

use std::collections::HashMap;
use std::rc::Rc;

use serde_json::{Map, Value, json};

use super::apps;
use super::schema::{Table, create_table};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for SQLite databases, WAL files and journals.
pub struct Sqlite;

static META: ExtractorMeta = ExtractorMeta {
    id: "db.sqlite",
    version: 1,
    // Bounded by the page budget (`max_parse_bytes`), so every profile.
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "sqlite",
            name: "SQLite database",
            family: "db",
            mimes: &["application/vnd.sqlite3", "application/x-sqlite3"],
            extensions: &["sqlite", "sqlite3", "db", "db3", "s3db", "sl3", "lrcat", "anki2", "anki21"],
            magic: &[Magic::prefix(b"SQLite format 3\0")],
            parent: None,
        },
        FormatSpec {
            id: "geopackage",
            name: "GeoPackage",
            family: "geo",
            mimes: &["application/geopackage+sqlite3"],
            extensions: &["gpkg"],
            magic: &[],
            parent: Some("sqlite"),
        },
        FormatSpec {
            id: "mbtiles",
            name: "MBTiles tileset",
            family: "geo",
            mimes: &[],
            extensions: &["mbtiles"],
            magic: &[],
            parent: Some("sqlite"),
        },
        FormatSpec {
            id: "sqlite_wal",
            name: "SQLite write-ahead log",
            family: "db",
            mimes: &[],
            extensions: &["db-wal", "sqlite-wal", "wal"],
            magic: &[Magic::prefix(b"\x37\x7f\x06\x82"), Magic::prefix(b"\x37\x7f\x06\x83")],
            parent: None,
        },
        FormatSpec {
            id: "sqlite_journal",
            name: "SQLite rollback journal",
            family: "db",
            mimes: &[],
            extensions: &["db-journal", "sqlite-journal"],
            magic: &[Magic::prefix(b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7")],
            parent: None,
        },
    ],
};

/// Deepest b-tree followed (SQLite's own limit is 20).
const MAX_DEPTH: usize = 20;
/// Pages read per level when counting rows, at least, when the budget
/// cannot cover a level and it is sampled.
const LEVEL_SAMPLE: usize = 512;
/// Tables described in full.
const MAX_TABLES: usize = 256;
/// Most bytes of one record assembled from overflow pages.
const MAX_PAYLOAD: usize = 1 << 20;

/// A value from a record.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Val {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Val {
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Val::Int(i) => Some(*i),
            #[allow(clippy::cast_possible_truncation)] // dates stored as reals
            Val::Real(f) if f.is_finite() => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Val::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Val::Null => Value::Null,
            Val::Int(i) => (*i).into(),
            Val::Real(f) => serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number),
            Val::Text(s) => crate::plugin::truncate_chars(s, 500).into(),
            Val::Blob(b) => format!("<{} bytes>", b.len()).into(),
        }
    }
}

/// A SQLite varint: 1–9 bytes, big-endian, 7 bits each (8 in the last).
fn varint(b: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..9 {
        let x = *b.get(*at)?;
        *at += 1;
        if i == 8 {
            return Some((v << 8) | u64::from(x));
        }
        v = (v << 7) | u64::from(x & 0x7f);
        if x & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fn be(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |a, &x| a << 8 | u64::from(x))
}

/// A big-endian offset or count (at most 4 bytes) as an index.
fn be_usize(b: &[u8]) -> usize {
    b.iter().fold(0usize, |a, &x| a << 8 | usize::from(x))
}

/// Pages read on demand, within a page budget.
pub(crate) struct Pager<'s> {
    src: &'s mut dyn Source,
    pub page_size: usize,
    /// Page size less the reserved bytes at the end of each page.
    pub usable: usize,
    pub page_count: u32,
    /// 1 UTF-8, 2 UTF-16LE, 3 UTF-16BE.
    pub encoding: u32,
    cache: HashMap<u32, Rc<Vec<u8>>>,
    reads: usize,
    max_reads: usize,
    /// The budget ran out somewhere.
    pub exhausted: bool,
}

impl Pager<'_> {
    /// How many of `n` pages to read: all of them while they fit in half
    /// the budget left, else an even sample.
    fn sample_size(&self, n: usize) -> usize {
        let room = self.max_reads.saturating_sub(self.reads) / 2;
        if n <= room { n } else { room.max(LEVEL_SAMPLE).min(n) }
    }

    pub fn page(&mut self, n: u32) -> Option<Rc<Vec<u8>>> {
        if n == 0 || n > self.page_count {
            return None;
        }
        if let Some(p) = self.cache.get(&n) {
            return Some(p.clone());
        }
        if self.reads >= self.max_reads {
            self.exhausted = true;
            return None;
        }
        self.reads += 1;
        let mut buf = vec![0; self.page_size];
        let off = u64::from(n - 1) * self.page_size as u64;
        self.src.read_exact_at(off, &mut buf).ok()?;
        let p = Rc::new(buf);
        if self.cache.len() < 4096 {
            self.cache.insert(n, p.clone());
        }
        Some(p)
    }

    fn text(&self, b: &[u8]) -> String {
        match self.encoding {
            2 | 3 => {
                let units: Vec<u16> = b
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| if self.encoding == 2 { u16::from_le_bytes(*c) } else { u16::from_be_bytes(*c) })
                    .collect();
                String::from_utf16_lossy(&units)
            }
            _ => String::from_utf8_lossy(b).into_owned(),
        }
    }

    /// The values of a record.
    pub fn record(&self, p: &[u8]) -> Vec<Val> {
        let mut at = 0;
        let Some(hlen) = varint(p, &mut at) else { return Vec::new() };
        let hlen = usize::try_from(hlen).unwrap_or(usize::MAX).min(p.len());
        let mut types = Vec::new();
        while at < hlen {
            let Some(t) = varint(p, &mut at) else { break };
            types.push(t);
        }
        let mut body = hlen;
        let mut out = Vec::with_capacity(types.len());
        for t in types {
            let n = match t {
                0 | 8 | 9 | 10 | 11 => 0,
                1..=4 => usize::try_from(t).unwrap_or(0),
                5 => 6,
                6 | 7 => 8,
                t => usize::try_from((t - 12) / 2).unwrap_or(usize::MAX),
            };
            let Some(v) = p.get(body..body.saturating_add(n)) else {
                // Cut short (a payload only partly assembled).
                out.push(Val::Null);
                body = p.len();
                continue;
            };
            body += n;
            out.push(match t {
                0 | 10 | 11 => Val::Null,
                1..=6 => {
                    let shift = 64 - 8 * u32::try_from(n).unwrap_or(8);
                    #[allow(clippy::cast_possible_wrap)] // two's complement, sign-extended below
                    Val::Int(((be(v) << shift) as i64) >> shift)
                }
                7 => Val::Real(f64::from_bits(be(v))),
                8 => Val::Int(0),
                9 => Val::Int(1),
                t if t % 2 == 0 => Val::Blob(v.to_vec()),
                _ => Val::Text(self.text(v)),
            });
        }
        out
    }

    /// The payload of the cell at `off` on `page` (table leaf, index leaf or
    /// index interior), with its overflow chain, up to `want` bytes.
    fn payload(&mut self, page: &[u8], mut off: usize, kind: u8, want: usize) -> Option<Vec<u8>> {
        if kind == 2 {
            off += 4;
        }
        let total = usize::try_from(varint(page, &mut off)?).ok()?;
        if kind == 13 {
            varint(page, &mut off)?; // rowid
        }
        let u = self.usable;
        let x = if kind == 13 { u - 35 } else { ((u - 12) * 64 / 255) - 23 };
        let local = if total <= x {
            total
        } else {
            let m = ((u - 12) * 32 / 255) - 23;
            let k = m + (total - m) % (u - 4);
            if k <= x { k } else { m }
        };
        let mut out = page.get(off..off + local)?.to_vec();
        if local < total {
            let mut next = u32::try_from(be(page.get(off + local..off + local + 4)?)).ok()?;
            let goal = total.min(want).min(MAX_PAYLOAD);
            let mut hops = 0;
            while out.len() < goal && next != 0 && hops < 1 << 16 {
                let p = self.page(next)?;
                next = u32::try_from(be(&p[..4])).ok()?;
                let take = (u - 4).min(total - out.len());
                out.extend_from_slice(p.get(4..4 + take)?);
                hops += 1;
            }
        }
        Some(out)
    }

    /// Visit every row of a table b-tree (or every entry of an index
    /// b-tree) in order, until `f` returns false or the budget runs out.
    pub fn walk(&mut self, root: u32, want: usize, f: &mut dyn FnMut(&[u8]) -> bool) -> bool {
        let mut stack = vec![(root, 0usize)];
        let mut seen = 0usize;
        while let Some((n, depth)) = stack.pop() {
            seen += 1;
            if depth > MAX_DEPTH || seen > self.page_count as usize {
                return false;
            }
            let Some(page) = self.page(n) else { return false };
            let h = if n == 1 { 100 } else { 0 };
            let Some(&kind) = page.get(h) else { return false };
            let cells = be_usize(&page[h + 3..h + 5]);
            let interior = kind == 2 || kind == 5;
            let ptrs = h + if interior { 12 } else { 8 };
            if interior {
                // Children right to left on the stack: visited left first.
                let right = u32::try_from(be(&page[h + 8..h + 12])).unwrap_or(0);
                stack.push((right, depth + 1));
                for i in (0..cells).rev() {
                    let Some(c) = page.get(ptrs + 2 * i..ptrs + 2 * i + 2) else { return false };
                    let off = be_usize(c);
                    if kind == 2
                        && let Some(p) = self.payload(&page, off, kind, want)
                    {
                        // Interior index cells hold entries too; visited in
                        // key order would need interleaving, order is not needed.
                        if !f(&p) {
                            return false;
                        }
                    }
                    let Some(child) = page.get(off..off + 4).map(be) else { return false };
                    stack.push((u32::try_from(child).unwrap_or(0), depth + 1));
                }
            } else if kind == 13 || kind == 10 {
                for i in 0..cells {
                    let Some(c) = page.get(ptrs + 2 * i..ptrs + 2 * i + 2) else { return false };
                    let Some(p) = self.payload(&page, be_usize(c), kind, want) else { return false };
                    if !f(&p) {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }
        true
    }

    /// The number of rows (entries) in a b-tree and whether it is exact.
    /// Levels wider than [`LEVEL_SAMPLE`] pages are sampled evenly and the
    /// count scaled by the level's width.
    pub fn count(&mut self, root: u32) -> Option<(u64, bool)> {
        let mut level = vec![root];
        let mut factor = 1.0f64;
        for _ in 0..=MAX_DEPTH {
            let mut children = Vec::new();
            let mut cells_on_leaves = 0u64;
            let mut index_interior = 0u64;
            let mut leaves = false;
            for &n in &level {
                let page = self.page(n)?;
                let h = if n == 1 { 100 } else { 0 };
                let kind = *page.get(h)?;
                let cells = be(page.get(h + 3..h + 5)?);
                match kind {
                    13 | 10 => {
                        leaves = true;
                        cells_on_leaves += cells;
                    }
                    5 | 2 => {
                        if kind == 2 {
                            index_interior += cells;
                        }
                        for i in 0..usize::try_from(cells).unwrap_or(0) {
                            let c = page.get(h + 12 + 2 * i..h + 14 + 2 * i)?;
                            let off = be_usize(c);
                            children.push(u32::try_from(be(page.get(off..off + 4)?)).ok()?);
                        }
                        children.push(u32::try_from(be(page.get(h + 8..h + 12)?)).ok()?);
                    }
                    _ => return None,
                }
            }
            // Index interior cells are entries as well.
            let here = cells_on_leaves + index_interior;
            if leaves {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
                let rows = (here as f64 * factor).round() as u64;
                return Some((rows, (factor - 1.0).abs() < f64::EPSILON));
            }
            if index_interior > 0 {
                // Counted once per level; add them to the leaf total later.
                #[allow(clippy::cast_precision_loss)]
                let extra = index_interior as f64 * factor;
                let (rest, exact) = self.count_children(children, factor)?;
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                return Some((rest + extra.round() as u64, exact));
            }
            let take = self.sample_size(children.len());
            if take < children.len() {
                #[allow(clippy::cast_precision_loss)]
                {
                    factor *= children.len() as f64 / take as f64;
                }
                let step = children.len() / take;
                level = children.into_iter().step_by(step.max(1)).take(take).collect();
            } else {
                level = children;
            }
        }
        None
    }

    fn count_children(&mut self, children: Vec<u32>, factor: f64) -> Option<(u64, bool)> {
        let mut total = 0f64;
        let mut exact = (factor - 1.0).abs() < f64::EPSILON;
        let take = self.sample_size(children.len());
        let (sample, scale) = if take < children.len() {
            exact = false;
            #[allow(clippy::cast_precision_loss)]
            let s = children.len() as f64 / take as f64;
            let step = children.len() / take;
            (children.into_iter().step_by(step.max(1)).take(take).collect::<Vec<_>>(), s)
        } else {
            (children, 1.0)
        };
        for c in sample {
            let (n, e) = self.count(c)?;
            exact &= e;
            #[allow(clippy::cast_precision_loss)]
            {
                total += n as f64;
            }
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(((total * scale * factor).round() as u64, exact))
    }
}

/// One `sqlite_schema` row.
#[derive(Debug, Clone)]
pub(crate) struct Object {
    pub kind: String,
    pub name: String,
    pub table: String,
    pub root: u32,
    pub sql: Option<String>,
}

/// An opened database: header facts and the schema.
pub(crate) struct Db<'s> {
    pub pager: Pager<'s>,
    pub objects: Vec<Object>,
}

impl Db<'_> {
    /// The rows of table `name` (up to `max`), as values.
    pub fn rows(&mut self, name: &str, max: usize) -> Vec<Vec<Val>> {
        let Some(root) =
            self.objects.iter().find(|o| o.kind == "table" && o.name.eq_ignore_ascii_case(name)).map(|o| o.root)
        else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let pager = &mut self.pager;
        let mut payloads = Vec::new();
        pager.walk(root, 64 << 10, &mut |p| {
            payloads.push(p.to_vec());
            payloads.len() < max
        });
        for p in payloads {
            out.push(pager.record(&p));
        }
        out
    }

    /// The position of `column` in table `name`.
    pub fn column(&self, name: &str, column: &str) -> Option<usize> {
        let o = self.objects.iter().find(|o| o.kind == "table" && o.name.eq_ignore_ascii_case(name))?;
        create_table(o.sql.as_deref()?)?.columns.iter().position(|c| c.name.eq_ignore_ascii_case(column))
    }

    pub fn has_table(&self, name: &str) -> bool {
        self.objects.iter().any(|o| o.kind == "table" && o.name.eq_ignore_ascii_case(name))
    }
}

fn version_name(v: u64) -> String {
    format!("{}.{}.{}", v / 1_000_000, v / 1000 % 1000, v % 1000)
}

impl Extractor for Sqlite {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // The application ID: GeoPackage (`GPKG`, `GP10`, `GP11`), MBTiles (`MPBX`).
        let h = probe.head;
        if !h.starts_with(b"SQLite format 3\0") {
            return None;
        }
        let format = match (h.get(68..72)?, probe.extension) {
            (b"GPKG" | b"GP10" | b"GP11", _) | (_, Some("gpkg")) => "geopackage",
            (b"MPBX", _) | (_, Some("mbtiles")) => "mbtiles",
            _ => return None,
        };
        Some(Sniff { format, confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "sqlite_wal" => return wal(src, cx),
            "sqlite_journal" => return journal(src, cx),
            _ => {}
        }
        let mut h = [0u8; 100];
        src.read_exact_at(0, &mut h).map_err(|_| ExtractError::malformed("SQLite header"))?;
        let page_size = match be(&h[16..18]) {
            1 => 65536,
            n if n >= 512 && n.is_power_of_two() => usize::try_from(n).unwrap_or(4096),
            _ => return Err(ExtractError::malformed("SQLite page size")),
        };
        let u32_at = |at: usize| u32::try_from(be(&h[at..at + 4])).unwrap_or(0);
        let file_pages = u32::try_from(src.len() / page_size as u64).unwrap_or(u32::MAX);
        // The header's page count holds when it was written by 3.7.0+ in
        // step with the change counter.
        let counted = u32_at(28);
        let page_count = if counted > 0 && u32_at(24) == u32_at(92) { counted } else { file_pages };
        cx.format_set("sqlite_version", version_name(u64::from(u32_at(96))));
        cx.format_set("page_size", page_size);
        cx.format_set("page_count", page_count);
        if page_count > file_pages {
            cx.warn(format!("the header gives {page_count} pages, the file holds {file_pages}"));
        }
        let encoding = u32_at(56);
        cx.format_set(
            "encoding",
            match encoding {
                2 => "utf-16le",
                3 => "utf-16be",
                _ => "utf-8",
            },
        );
        cx.format_set("journal_mode", if h[18] == 2 { "wal" } else { "rollback" });
        if u32_at(52) != 0 {
            cx.format_set("auto_vacuum", if u32_at(64) != 0 { "incremental" } else { "full" });
        }
        cx.format_set("schema_format", u32_at(44));
        cx.format_set("user_version", u32_at(60));
        let app_id = u32_at(68);
        if app_id != 0 {
            cx.format_set("application_id", format!("0x{app_id:08x}"));
        }
        cx.format_set("free_pages", u32_at(36));
        let reserved = usize::from(h[20]);
        let max_reads = (cx.parse_limit() / page_size).max(4);
        let mut db = Db {
            pager: Pager {
                src,
                page_size,
                usable: page_size.saturating_sub(reserved).max(480),
                page_count: page_count.min(file_pages.max(1)),
                encoding,
                cache: HashMap::new(),
                reads: 0,
                max_reads,
                exhausted: false,
            },
            objects: Vec::new(),
        };
        schema(&mut db, cx)?;
        tables(&mut db, cx)?;
        apps::identify(&mut db, app_id, u32_at(60), cx);
        if db.pager.exhausted {
            cx.warn("the page budget ran out: some counts are estimates or missing");
        }
        Ok(())
    }
}

fn schema(db: &mut Db<'_>, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut rows = Vec::new();
    let complete = db.pager.walk(1, MAX_PAYLOAD, &mut |p| {
        rows.push(p.to_vec());
        rows.len() < 100_000
    });
    if rows.is_empty() && !complete {
        return Err(ExtractError::malformed("SQLite schema page"));
    }
    if !complete {
        cx.warn("the schema could not be read completely");
    }
    for p in rows {
        let v = db.pager.record(&p);
        let s = |i: usize| v.get(i).and_then(Val::as_str).unwrap_or("").to_string();
        db.objects.push(Object {
            kind: s(0),
            name: s(1),
            table: s(2),
            root: v.get(3).and_then(Val::as_i64).and_then(|r| u32::try_from(r).ok()).unwrap_or(0),
            sql: v.get(4).and_then(Val::as_str).map(str::to_string),
        });
    }
    cx.checkpoint()?;
    Ok(())
}

fn tables(db: &mut Db<'_>, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut counts = Map::new();
    for (k, key) in [("table", "tables"), ("index", "indexes"), ("view", "views"), ("trigger", "triggers")] {
        let n = db.objects.iter().filter(|o| o.kind == k && !o.name.starts_with("sqlite_autoindex")).count();
        counts.insert(key.into(), n.into());
    }
    cx.format_set("object_counts", Value::Object(counts));
    let mut list = Vec::new();
    let mut total_rows = 0u64;
    let mut all_exact = true;
    let objects = db.objects.clone();
    for (i, o) in objects.iter().filter(|o| o.kind == "table").enumerate() {
        if i >= MAX_TABLES {
            break;
        }
        let mut m = Map::new();
        m.insert("name".into(), o.name.clone().into());
        let t: Option<Table> = o.sql.as_deref().and_then(create_table);
        if let Some(t) = &t {
            if let Some(module) = &t.module {
                m.insert("virtual".into(), module.clone().into());
            }
            if t.without_rowid {
                m.insert("without_rowid".into(), true.into());
            }
            if t.strict {
                m.insert("strict".into(), true.into());
            }
            if !t.columns.is_empty() {
                m.insert("columns".into(), t.columns.iter().take(128).map(super::schema::Column::to_json).collect());
                if t.columns.len() > 128 {
                    m.insert("column_count".into(), t.columns.len().into());
                }
            }
        }
        if o.root > 0 {
            match db.pager.count(o.root) {
                Some((rows, exact)) => {
                    m.insert("rows".into(), rows.into());
                    if !exact {
                        m.insert("rows_estimated".into(), true.into());
                    }
                    total_rows += rows;
                    all_exact &= exact;
                }
                None => all_exact = false,
            }
        }
        list.push(Value::Object(m));
        cx.checkpoint()?;
    }
    if !all_exact {
        cx.format_set("rows_estimated", true);
    }
    cx.format_set("total_rows", total_rows);
    cx.format_set("tables", list);
    let named = |kind: &str| -> Vec<Value> {
        objects
            .iter()
            .filter(|o| o.kind == kind && !o.name.starts_with("sqlite_autoindex"))
            .take(MAX_TABLES)
            .map(|o| json!({ "name": o.name, "table": o.table }))
            .collect()
    };
    for (k, key) in [("index", "indexes"), ("view", "views"), ("trigger", "triggers")] {
        let v = named(k);
        if !v.is_empty() {
            cx.format_set(key, v);
        }
    }
    Ok(())
}

/// The write-ahead log: header, then frames of a page each.
fn wal(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut h = [0u8; 32];
    src.read_exact_at(0, &mut h).map_err(|_| ExtractError::malformed("WAL header"))?;
    let u32_at = |at: usize| u32::try_from(be(&h[at..at + 4])).unwrap_or(0);
    let page_size = match u32_at(8) {
        1 => 65536,
        n => n as usize,
    };
    if !(512..=65536).contains(&page_size) {
        return Err(ExtractError::malformed("WAL page size"));
    }
    cx.format_set("format_version", u32_at(4));
    cx.format_set("page_size", page_size);
    cx.format_set("checkpoint_sequence", u32_at(12));
    cx.format_set("byte_order", if h[3] == 0x83 { "big_endian" } else { "little_endian" });
    let frame = 24 + page_size as u64;
    let frames = src.len().saturating_sub(32) / frame;
    cx.format_set("frames", frames);
    // Frames whose salt matches the header belong to the current log;
    // commit frames give the database size after the transaction.
    let (salt1, salt2) = (u32_at(16), u32_at(20));
    let (mut valid, mut commits, mut pages) = (0u64, 0u64, std::collections::HashSet::new());
    let mut fh = [0u8; 24];
    for i in 0..frames.min(1 << 20) {
        if src.read_exact_at(32 + i * frame, &mut fh).is_err() {
            break;
        }
        let f = |at: usize| u32::try_from(be(&fh[at..at + 4])).unwrap_or(0);
        if f(8) != salt1 || f(12) != salt2 {
            break;
        }
        valid += 1;
        pages.insert(f(0));
        if f(4) != 0 {
            commits += 1;
        }
        if i % 4096 == 4095 {
            cx.checkpoint()?;
        }
    }
    cx.format_set("current_frames", valid);
    cx.format_set("commits", commits);
    cx.format_set("distinct_pages", pages.len());
    Ok(())
}

/// The rollback journal: a header per sector, then page records.
fn journal(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut h = [0u8; 28];
    src.read_exact_at(0, &mut h).map_err(|_| ExtractError::malformed("journal header"))?;
    let u32_at = |at: usize| u32::try_from(be(&h[at..at + 4])).unwrap_or(0);
    let records = u32_at(8);
    // -1: the record count is unknown (journal_mode=PERSIST, synchronous=OFF).
    if records == u32::MAX {
        cx.format_set("records", "unknown");
    } else {
        cx.format_set("records", records);
    }
    cx.format_set("initial_page_count", u32_at(16));
    cx.format_set("sector_size", u32_at(20));
    cx.format_set("page_size", u32_at(24));
    Ok(())
}

crate::register_extractor!(Sqlite);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        let mut at = 0;
        assert_eq!(varint(&[0x81, 0x00], &mut at), Some(128));
        let mut at = 0;
        assert_eq!(varint(&[0xff; 9], &mut at), Some(u64::MAX));
    }

    crate::fixture_tests!("sqlite", "sqlite_wal", "sqlite_journal");
}
