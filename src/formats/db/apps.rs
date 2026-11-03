//! The applications behind SQLite files, by application ID or by the
//! tables they always create, with a short summary each: GeoPackage
//! contents, MBTiles metadata, browser histories (visit counts and date
//! range, never URLs), cookie and password stores (counts only), Core
//! Data entities, Apple Photos and Messages, Lightroom catalogs, Anki
//! collections, iOS backup manifests, Android app databases, SpatiaLite and
//! Fossil repositories.

use serde_json::{Map, Value, json};

use super::sqlite::{Db, Val};
use super::unix_time;
use crate::plugin::Context;

/// Rows scanned for a date range.
const MAX_SCAN: usize = 200_000;
/// Rows of a small table (contents, metadata) read.
const MAX_SMALL: usize = 256;

/// Seconds between 1601-01-01 (Windows / WebKit) and 1970-01-01.
const WEBKIT_OFFSET: i64 = 11_644_473_600;
/// Seconds between 1970-01-01 and 2001-01-01 (Apple's reference date).
const APPLE_OFFSET: i64 = 978_307_200;

fn rows_of(db: &mut Db<'_>, table: &str) -> Option<u64> {
    let root = db.objects.iter().find(|o| o.kind == "table" && o.name.eq_ignore_ascii_case(table))?.root;
    db.pager.count(root).map(|(n, _)| n)
}

/// The smallest and largest value of an integer column, as Unix seconds
/// through `to_unix`; zero and negative values are skipped.
fn range(db: &mut Db<'_>, table: &str, column: &str, to_unix: fn(i64) -> i64) -> Option<(String, String)> {
    let col = db.column(table, column)?;
    let root = db.objects.iter().find(|o| o.kind == "table" && o.name.eq_ignore_ascii_case(table))?.root;
    let (mut lo, mut hi) = (i64::MAX, i64::MIN);
    let mut payloads = Vec::new();
    db.pager.walk(root, 4096, &mut |p| {
        payloads.push(p.to_vec());
        payloads.len() < MAX_SCAN
    });
    for p in payloads {
        let rec = db.pager.record(&p);
        // An INTEGER PRIMARY KEY column is stored as NULL: the rowid.
        if let Some(v) = rec.get(col).and_then(Val::as_i64).filter(|&v| v > 0) {
            lo = lo.min(v);
            hi = hi.max(v);
        }
    }
    (lo <= hi).then(|| (unix_time(to_unix(lo)), unix_time(to_unix(hi)))).and_then(|(a, b)| Some((a?, b?)))
}

fn put_range(app: &mut Map<String, Value>, r: Option<(String, String)>) {
    if let Some((a, b)) = r {
        app.insert("first".into(), a.into());
        app.insert("last".into(), b.into());
    }
}

fn counts(db: &mut Db<'_>, app: &mut Map<String, Value>, tables: &[(&str, &str)]) {
    for (table, key) in tables {
        if let Some(n) = rows_of(db, table) {
            app.insert((*key).into(), n.into());
        }
    }
}

/// `name → value` rows of a two-column key / value table.
fn pairs(db: &mut Db<'_>, table: &str, key: &str, value: &str) -> Vec<(String, Val)> {
    let (Some(k), Some(v)) = (db.column(table, key), db.column(table, value)) else { return Vec::new() };
    db.rows(table, MAX_SMALL)
        .into_iter()
        .filter_map(|r| Some((r.get(k)?.as_str()?.to_string(), r.get(v)?.clone())))
        .collect()
}

/// Work out the application and add `application` to the report.
#[allow(clippy::too_many_lines)] // one arm per application
pub(crate) fn identify(db: &mut Db<'_>, app_id: u32, user_version: u32, cx: &mut Context<'_>) {
    let has = |db: &Db<'_>, names: &[&str]| names.iter().all(|n| db.has_table(n));
    let mut app = Map::new();
    let name = if matches!(app_id, 0x4750_4b47 | 0x4750_3130 | 0x4750_3131) || has(db, &["gpkg_contents"]) {
        let version = match app_id {
            0x4750_3130 => "1.0".to_string(),
            0x4750_3131 => "1.1".to_string(),
            _ => format!("{}.{}.{}", user_version / 10000, user_version / 100 % 100, user_version % 100),
        };
        app.insert("version".into(), version.into());
        let cols = ["table_name", "data_type", "identifier", "srs_id", "min_x", "min_y", "max_x", "max_y"];
        let pos: Vec<Option<usize>> = cols.iter().map(|c| db.column("gpkg_contents", c)).collect();
        let contents: Vec<Value> = db
            .rows("gpkg_contents", MAX_SMALL)
            .into_iter()
            .map(|r| {
                let mut m = Map::new();
                for (c, p) in cols.iter().zip(&pos) {
                    if let Some(v) = p.and_then(|p| r.get(p)).filter(|v| **v != Val::Null) {
                        m.insert((*c).into(), v.to_json());
                    }
                }
                Value::Object(m)
            })
            .collect();
        // The extent: contents in WGS84 (srs_id 4326, GeoPackage's default).
        let mut ext: Option<[f64; 4]> = None;
        for c in &contents {
            let g = |k: &str| c.get(k).and_then(Value::as_f64);
            if c.get("srs_id").and_then(Value::as_i64) == Some(4326)
                && let (Some(w), Some(s), Some(e), Some(n)) = (g("min_x"), g("min_y"), g("max_x"), g("max_y"))
            {
                let x = ext.get_or_insert([w, s, e, n]);
                *x = [x[0].min(w), x[1].min(s), x[2].max(e), x[3].max(n)];
            }
        }
        if let Some([w, s, e, n]) = ext {
            cx.content().source("gpkg_contents").extent(w, s, e, n);
        }
        if !contents.is_empty() {
            app.insert("contents".into(), contents.into());
        }
        "geopackage"
    } else if app_id == 0x4d50_4258 || has(db, &["metadata", "tiles"]) {
        let mut meta = Map::new();
        for (k, v) in pairs(db, "metadata", "name", "value") {
            if [
                "name",
                "format",
                "bounds",
                "center",
                "minzoom",
                "maxzoom",
                "attribution",
                "description",
                "version",
                "type",
            ]
            .contains(&k.as_str())
            {
                meta.insert(k, v.to_json());
            }
        }
        if let Some(t) = meta.get("name").and_then(Value::as_str) {
            cx.content().source("db.sqlite").title(t);
        }
        if let Some(d) = meta.get("description").and_then(Value::as_str) {
            cx.content().source("db.sqlite").description(d);
        }
        if let Some(a) = meta.get("attribution").and_then(Value::as_str) {
            cx.rights().source("db.sqlite").credit(a);
        }
        // `bounds`: "west,south,east,north" in WGS84.
        let b: Vec<f64> = meta
            .get("bounds")
            .and_then(Value::as_str)
            .unwrap_or("")
            .split(',')
            .filter_map(|v| v.trim().parse().ok())
            .collect();
        if let [w, s, e, n] = b[..] {
            cx.content().source("mbtiles.metadata.bounds").extent(w, s, e, n);
        }
        app.insert("metadata".into(), Value::Object(meta));
        counts(db, &mut app, &[("tiles", "tiles")]);
        "mbtiles"
    } else if has(db, &["moz_places"]) {
        counts(
            db,
            &mut app,
            &[("moz_places", "places"), ("moz_historyvisits", "visits"), ("moz_bookmarks", "bookmarks")],
        );
        put_range(&mut app, range(db, "moz_historyvisits", "visit_date", |v| v / 1_000_000));
        "firefox_places"
    } else if has(db, &["urls", "visits"]) {
        counts(db, &mut app, &[("urls", "urls"), ("visits", "visits"), ("downloads", "downloads")]);
        put_range(&mut app, range(db, "visits", "visit_time", |v| v / 1_000_000 - WEBKIT_OFFSET));
        "chromium_history"
    } else if has(db, &["moz_cookies"]) {
        counts(db, &mut app, &[("moz_cookies", "cookies")]);
        "firefox_cookies"
    } else if has(db, &["cookies"]) && db.column("cookies", "host_key").is_some() {
        counts(db, &mut app, &[("cookies", "cookies")]);
        "chromium_cookies"
    } else if has(db, &["logins"]) && db.column("logins", "password_value").is_some() {
        // Passwords are encrypted by the browser; only the count is told.
        counts(db, &mut app, &[("logins", "logins")]);
        "chromium_login_data"
    } else if has(db, &["Z_PRIMARYKEY", "Z_METADATA"]) {
        let entities: Vec<Value> = pairs(db, "Z_PRIMARYKEY", "Z_NAME", "Z_MAX")
            .into_iter()
            .map(|(n, max)| json!({ "entity": n, "max_id": max.to_json() }))
            .collect();
        if has(db, &["ZASSET"]) || has(db, &["ZGENERICASSET"]) {
            counts(db, &mut app, &[("ZASSET", "assets"), ("ZGENERICASSET", "assets"), ("ZPERSON", "people")]);
            app.insert("entities".into(), entities.len().into());
            "apple_photos"
        } else {
            app.insert("entities".into(), entities.into());
            "core_data"
        }
    } else if has(db, &["message", "handle", "chat"]) {
        counts(db, &mut app, &[("message", "messages"), ("chat", "chats"), ("handle", "handles")]);
        // Nanoseconds since 2001 since macOS 10.13, seconds before.
        put_range(
            &mut app,
            range(db, "message", "date", |v| if v > 1 << 40 { v / 1_000_000_000 } else { v } + APPLE_OFFSET),
        );
        "apple_messages"
    } else if has(db, &["Adobe_images"]) {
        counts(
            db,
            &mut app,
            &[
                ("Adobe_images", "images"),
                ("AgLibraryCollection", "collections"),
                ("AgLibraryKeyword", "keywords"),
                ("AgLibraryFolder", "folders"),
            ],
        );
        "lightroom_catalog"
    } else if has(db, &["col", "notes", "cards"]) {
        counts(db, &mut app, &[("notes", "notes"), ("cards", "cards"), ("decks", "decks"), ("revlog", "reviews")]);
        "anki_collection"
    } else if has(db, &["Files", "Properties"]) && db.column("Files", "domain").is_some() {
        counts(db, &mut app, &[("Files", "files")]);
        "ios_backup_manifest"
    } else if has(db, &["geometry_columns", "spatial_ref_sys"])
        && db.column("geometry_columns", "f_table_name").is_some()
    {
        counts(db, &mut app, &[("geometry_columns", "geometry_columns"), ("spatial_ref_sys", "reference_systems")]);
        "spatialite"
    } else if matches!(app_id, 0x0f05_5111..=0x0f05_5113) || has(db, &["blob", "delta", "event", "config"]) {
        counts(db, &mut app, &[("blob", "artifacts"), ("event", "events")]);
        "fossil"
    } else if has(db, &["android_metadata"]) {
        if let Some(l) = db.rows("android_metadata", 1).first().and_then(|r| r.first()).and_then(Val::as_str) {
            app.insert("locale".into(), l.into());
        }
        "android_app"
    } else {
        return;
    };
    let mut out = Map::new();
    out.insert("name".into(), name.into());
    out.extend(app);
    cx.format_set("application", Value::Object(out));
}
