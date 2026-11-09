//! Line- and record-based data files with a known layout: test and coverage
//! reports, metrics, bank statements, plain-text accounting, business
//! messages, genealogy, transit feeds, quote files, directory exports and
//! two notebook formats. Each gives counts, kinds and ranges; personal and
//! financial identifiers are masked, and names in genealogies, directories
//! and statements are never copied.
//!
//! * LCOV traces (files, lines, functions and branches found / hit), TAP
//!   output (plan, passed, failed, skipped, to-do) and the Prometheus /
//!   OpenMetrics exposition format (metric families by type, label keys);
//! * bank statements: OFX / QFX (institution, account type and the last
//!   four digits of the account, currency, transactions, date range), QIF,
//!   SWIFT MT940 and ISO 20022 CAMT.052 / .053;
//! * Ledger, hledger and Beancount journals (accounts, transactions,
//!   commodities, date range);
//! * EDI X12 and UN/EDIFACT interchanges (message types, segments; the
//!   sender and receiver ids only without strict privacy);
//! * GEDCOM (version, character set, the program that wrote it,
//!   individuals, families, sources, the range of years);
//! * GTFS feeds (agencies, routes, stops, trips, service dates);
//! * fortune files and their `strfile` indexes;
//! * LDIF (entries, object classes, attributes, change records);
//! * Wolfram Mathematica notebooks (cells by style, titles, the version)
//!   and Livebook notebooks (sections, Elixir cells, dependencies).
//!
//! Specifications: the `geninfo` / LCOV tracefile format; TAP 13 / 14;
//! OpenMetrics 1.0; OFX 1.0.3 / 2.2; Quicken's QIF; SWIFT MT940; ISO 20022
//! camt.053; Ledger 3, hledger and Beancount 2 / 3 syntax; ASC X12 and
//! UN/EDIFACT syntax 4; GEDCOM 5.5.1 / 7.0; the GTFS reference; strfile(1);
//! RFC 2849 (LDIF); Wolfram's notebook expression format; Livebook's
//! `.livemd`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, TextRole, Zip,
    latin1_or_utf8, xmlwalk, zip_names,
};

/// Extractor for the record-based data files above.
pub struct Records;

macro_rules! spec {
    ($id:literal, $name:literal, $family:literal, $mime:literal, [$($ext:literal),*], [$($magic:expr),*]) => {
        FormatSpec { id: $id, name: $name, family: $family, mimes: &[$mime], extensions: &[$($ext),*], magic: &[$($magic),*], parent: None }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "data.records",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("lcov", "LCOV coverage trace", "data.csv", "text/x-lcov", ["lcov"], []),
        spec!("tap", "TAP test output", "data.csv", "text/x-tap", [], []),
        spec!(
            "prometheus",
            "Prometheus / OpenMetrics exposition",
            "data.csv",
            "text/plain; version=0.0.4",
            ["prom"],
            []
        ),
        spec!(
            "ofx",
            "OFX / QFX bank statement",
            "data.csv",
            "application/x-ofx",
            ["ofx", "qfx"],
            [Magic::prefix(b"OFXHEADER:")]
        ),
        spec!("qif", "Quicken Interchange Format", "data.csv", "application/qif", ["qif"], [Magic::prefix(b"!Type:")]),
        spec!("mt940", "SWIFT MT940 statement", "data.csv", "text/x-mt940", ["sta", "940", "mt940"], []),
        spec!("camt", "ISO 20022 CAMT statement", "data.csv", "application/xml", ["camt"], []),
        spec!(
            "ledger",
            "Ledger / hledger / Beancount journal",
            "data.csv",
            "text/x-ledger",
            ["ledger", "beancount", "bean", "hledger"],
            []
        ),
        spec!(
            "edi_x12",
            "ASC X12 EDI interchange",
            "data.csv",
            "application/EDI-X12",
            ["x12", "edi"],
            [Magic::prefix(b"ISA*"), Magic::prefix(b"ISA|")]
        ),
        spec!(
            "edifact",
            "UN/EDIFACT interchange",
            "data.csv",
            "application/EDIFACT",
            ["edifact", "edf"],
            [Magic::prefix(b"UNA:"), Magic::prefix(b"UNB+")]
        ),
        spec!(
            "gedcom",
            "GEDCOM genealogy",
            "data.csv",
            "text/vnd.familysearch.gedcom",
            ["ged", "gedcom"],
            [Magic::prefix(b"0 HEAD")]
        ),
        spec!("gtfs", "GTFS transit feed", "data.csv", "application/zip", [], []),
        spec!("fortune", "Fortune quote file", "text.plain", "text/plain", ["fortune"], []),
        spec!("ldif", "LDIF directory export", "text.contact", "text/x-ldif", ["ldif"], []),
        spec!(
            "mathematica_nb",
            "Wolfram Mathematica notebook",
            "code.notebook",
            "application/vnd.wolfram.mathematica",
            ["nb"],
            []
        ),
        spec!("livebook", "Livebook notebook", "code.notebook", "text/x-livebook", ["livemd"], []),
    ],
};

/// Names listed.
const MAX_LISTED: usize = 50;
/// Text kept.
const MAX_TEXT: usize = 1 << 20;

impl Extractor for Records {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let pick = |format: &'static str, confidence: f64| Some(Sniff { format, confidence });
        if probe.head.starts_with(b"PK\x03\x04") {
            let names = zip_names(probe, 4000);
            let has = |n: &str| names.iter().any(|x| x.rsplit('/').next() == Some(n));
            return (has("stops.txt") && has("routes.txt") && has("agency.txt"))
                .then_some(Sniff { format: "gtfs", confidence: 0.9 });
        }
        let h = &probe.head[..probe.head.len().min(8192)];
        let text = String::from_utf8_lossy(h);
        let t = text.trim_start_matches('\u{feff}');
        let lines: Vec<&str> = t.lines().take(200).collect();
        let starts = |p: &str| lines.iter().any(|l| l.starts_with(p));
        let ext = probe.extension.unwrap_or("");
        if t.starts_with("<?xml") || t.starts_with("<OFX>") {
            if t.contains("urn:iso:std:iso:20022:tech:xsd:camt.05") {
                return pick("camt", 0.95);
            }
            if t.contains("OFXHEADER=") || t.starts_with("<OFX>") {
                return pick("ofx", 0.95);
            }
            return None;
        }
        if t.starts_with("(* Content-type: application/vnd.wolfram")
            || (t.contains("Notebook[{") && t.contains("Cell["))
        {
            return pick("mathematica_nb", 0.95);
        }
        if ext == "livemd" || t.contains("<!-- livebook:") {
            return pick("livebook", 0.9);
        }
        if (lines.first().is_some_and(|l| l.starts_with("TN:")) || starts("SF:"))
            && (starts("DA:") || starts("end_of_record"))
        {
            return pick("lcov", 0.9);
        }
        if lines.first().is_some_and(|l| l.starts_with("TAP version") || l.starts_with("1.."))
            && (starts("ok ") || starts("not ok "))
        {
            return pick("tap", 0.9);
        }
        if lines.iter().filter(|l| l.starts_with("# HELP ") || l.starts_with("# TYPE ")).count() >= 2 {
            return pick("prometheus", 0.9);
        }
        if starts(":20:") && starts(":25:") && (starts(":60F:") || starts(":61:")) {
            return pick("mt940", 0.9);
        }
        if lines.first().is_some_and(|l| l.starts_with("version:") || l.starts_with("dn:"))
            && starts("dn:")
            && starts("objectClass:")
        {
            return pick("ldif", 0.9);
        }
        // Beancount directives, or Ledger transactions (a date, then
        // indented postings).
        let beancount = lines.iter().any(|l| {
            l.len() > 11
                && l.as_bytes()[4] == b'-'
                && l.as_bytes()[7] == b'-'
                && (l[10..].starts_with(" open ") || l[10..].starts_with(" * ") || l[10..].starts_with(" txn "))
        }) || t.starts_with("option \"");
        let ledger = lines.windows(2).any(|w| {
            let d = w[0].as_bytes();
            d.len() > 10
                && d[..4].iter().all(u8::is_ascii_digit)
                && matches!(d[4], b'/' | b'-')
                && w[1].starts_with([' ', '\t'])
                && w[1].trim().contains(':')
        });
        if beancount || ledger {
            return pick("ledger", 0.85);
        }
        // fortune: quotes between lines holding only `%`.
        if lines.iter().filter(|l| l.trim_end() == "%").count() >= 3 && !t.contains('\0') {
            return pick("fortune", if ext == "fortune" { 0.9 } else { 0.6 });
        }
        // strfile index: version 1 or 2, then counts, flags and the delimiter.
        if ext == "dat"
            && h.len() >= 24
            && matches!(u32::from_be_bytes([h[0], h[1], h[2], h[3]]), 1 | 2)
            && h[20] == b'%'
        {
            return pick("fortune", 0.8);
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let format = cx.format_id().to_string();
        if format == "gtfs" {
            return gtfs(src, cx);
        }
        let n = src.len().min(cx.parse_limit() as u64);
        let raw = src.read_vec(0, usize::try_from(n).unwrap_or(0))?;
        if format == "fortune" && raw.len() >= 24 && matches!(raw[..4], [0, 0, 0, 1 | 2]) {
            strfile(cx, &raw);
            return Ok(());
        }
        let text = crate::plugin::decode_text(&raw).text;
        let text = text.trim_start_matches('\u{feff}');
        match format.as_str() {
            "lcov" => lcov(cx, text),
            "tap" => tap(cx, text),
            "prometheus" => prometheus(cx, text),
            "ofx" => ofx(cx, text),
            "qif" => qif(cx, text),
            "mt940" => mt940(cx, text),
            "camt" => camt(cx, text)?,
            "ledger" => ledger(cx, text),
            "edi_x12" => x12(cx, text),
            "edifact" => edifact(cx, text),
            "gedcom" => gedcom(cx, text),
            "fortune" => fortune(cx, text),
            "ldif" => ldif(cx, text),
            "mathematica_nb" => mathematica(cx, text),
            _ => livebook(cx, text),
        }
        Ok(())
    }
}

crate::register_extractor!(Records);

fn strings(v: impl IntoIterator<Item = String>) -> Value {
    Value::Array(v.into_iter().take(MAX_LISTED).map(Value::String).collect())
}

/// An account number as the privacy mode allows: whole with
/// `--privacy off`, else its last four characters.
fn account(cx: &Context<'_>, number: &str) -> String {
    if cx.privacy_strict() { mask(number) } else { number.trim().to_string() }
}

/// Transactions listed with `--privacy off`.
const MAX_TRANSACTIONS: usize = 200;

/// An account number with all but its last four characters hidden.
fn mask(account: &str) -> String {
    let chars: Vec<char> = account.chars().filter(|c| !c.is_whitespace()).collect();
    let keep = chars.len().min(4);
    let tail: String = chars[chars.len() - keep..].iter().collect();
    format!("{}{tail}", "•".repeat(chars.len().saturating_sub(keep).min(8)))
}

fn range(mut dates: Vec<String>) -> Value {
    dates.sort();
    match (dates.first(), dates.last()) {
        (Some(a), Some(b)) => json!([a, b]),
        _ => Value::Null,
    }
}

// --- tests, coverage, metrics ---------------------------------------------------------

fn lcov(cx: &mut Context<'_>, text: &str) {
    let (mut files, mut lf, mut lh, mut fnf, mut fnh, mut brf, mut brh) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut tests = BTreeSet::new();
    let num = |v: &str| v.trim().parse::<u64>().unwrap_or(0);
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        match k {
            "TN" if !v.trim().is_empty() => _ = tests.insert(v.trim().to_string()),
            "SF" => files += 1,
            "LF" => lf += num(v),
            "LH" => lh += num(v),
            "FNF" => fnf += num(v),
            "FNH" => fnh += num(v),
            "BRF" => brf += num(v),
            "BRH" => brh += num(v),
            _ => {}
        }
    }
    let pct = |h: u64, f: u64| {
        #[allow(clippy::cast_precision_loss)]
        let p = if f == 0 { Value::Null } else { json!(((h as f64) * 1000.0 / (f as f64)).round() / 10.0) };
        p
    };
    cx.format_set("files", files);
    cx.format_set("lines", json!({ "found": lf, "hit": lh, "percent": pct(lh, lf) }));
    cx.format_set("functions", json!({ "found": fnf, "hit": fnh, "percent": pct(fnh, fnf) }));
    cx.format_set("branches", json!({ "found": brf, "hit": brh, "percent": pct(brh, brf) }));
    if !tests.is_empty() {
        cx.format_set("test_names", strings(tests));
    }
}

fn tap(cx: &mut Context<'_>, text: &str) {
    let (mut pass, mut fail, mut skip, mut todo, mut plan, mut version) = (0u64, 0u64, 0u64, 0u64, None, None);
    let mut bailed = None;
    for line in text.lines() {
        let l = line.trim_start();
        if let Some(v) = l.strip_prefix("TAP version ") {
            version = Some(v.trim().to_string());
        } else if let Some(p) = l.strip_prefix("1..") {
            plan = p.split_whitespace().next().and_then(|n| n.parse::<u64>().ok());
        } else if let Some(reason) = l.strip_prefix("Bail out!") {
            bailed = Some(reason.trim().to_string());
        } else if l.starts_with("ok") || l.starts_with("not ok") {
            // Subtests are indented: only the top level counts.
            if line.starts_with(' ') {
                continue;
            }
            let directive = l.split_once('#').map(|(_, d)| d.trim().to_ascii_uppercase()).unwrap_or_default();
            if directive.starts_with("SKIP") {
                skip += 1;
            } else if directive.starts_with("TODO") {
                todo += 1;
            } else if l.starts_with("ok") {
                pass += 1;
            } else {
                fail += 1;
            }
        }
    }
    if let Some(v) = version {
        cx.format_set("tap_version", v);
    }
    if let Some(p) = plan {
        cx.format_set("planned", p);
    }
    cx.format_set("passed", pass);
    cx.format_set("failed", fail);
    cx.format_set("skipped", skip);
    cx.format_set("todo", todo);
    if let Some(b) = bailed {
        cx.format_set("bailed_out", b);
    }
}

fn prometheus(cx: &mut Context<'_>, text: &str) {
    let mut types: BTreeMap<String, String> = BTreeMap::new();
    let (mut samples, mut labels) = (0u64, BTreeSet::new());
    let mut eof = false;
    for line in text.lines() {
        if let Some(r) = line.strip_prefix("# TYPE ") {
            let mut w = r.split_whitespace();
            if let (Some(n), Some(t)) = (w.next(), w.next()) {
                types.insert(n.to_string(), t.to_string());
            }
        } else if line.trim() == "# EOF" {
            eof = true;
        } else if !line.starts_with('#') && !line.trim().is_empty() {
            samples += 1;
            if let Some(a) = line.find('{')
                && let Some(b) = line[a..].find('}').map(|b| a + b)
            {
                for pair in line[a + 1..b].split(',') {
                    if let Some((k, _)) = pair.split_once('=')
                        && labels.len() < 1000
                    {
                        labels.insert(k.trim().to_string());
                    }
                }
            }
        }
    }
    let mut by_type: BTreeMap<&str, u64> = BTreeMap::new();
    for t in types.values() {
        *by_type.entry(t.as_str()).or_default() += 1;
    }
    cx.format_set("dialect", if eof { "OpenMetrics" } else { "Prometheus text 0.0.4" });
    cx.format_set("metric_families", types.len());
    cx.format_set("types", json!(by_type));
    cx.format_set("samples", samples);
    cx.format_set("metric_names", strings(types.into_keys()));
    cx.format_set("label_keys", strings(labels));
}

// --- bank statements -------------------------------------------------------------------

/// `20250901120000[-5:EST]` → `2025-09-01`.
fn ofx_date(v: &str) -> Option<String> {
    let d = v.trim().get(..8)?;
    d.bytes().all(|b| b.is_ascii_digit()).then(|| format!("{}-{}-{}", &d[..4], &d[4..6], &d[6..8]))
}

/// The value after `<TAG>` (SGML OFX leaves elements unclosed).
fn ofx_values<'t>(text: &'t str, tag: &str) -> Vec<&'t str> {
    let open = format!("<{tag}>");
    text.match_indices(&open)
        .map(|(p, _)| {
            let v = &text[p + open.len()..];
            v[..v.find(['<', '\r', '\n']).unwrap_or(v.len())].trim()
        })
        .collect()
}

fn ofx(cx: &mut Context<'_>, text: &str) {
    let version = text
        .find("VERSION:")
        .map(|p| text[p + 8..].lines().next().unwrap_or("").trim().to_string())
        .or_else(|| text.find("VERSION=\"").map(|p| text[p + 9..].split('"').next().unwrap_or("").to_string()));
    if let Some(v) = version {
        cx.format_set("ofx_version", v);
    }
    let first = |tag: &str| ofx_values(text, tag).first().map(|s| (*s).to_string()).filter(|s| !s.is_empty());
    if let Some(org) = first("ORG") {
        cx.format_set("institution", org);
    }
    if let Some(t) = first("ACCTTYPE") {
        cx.format_set("account_type", t);
    } else if text.contains("<CCSTMTRS>") {
        cx.format_set("account_type", "CREDITCARD");
    }
    let accounts: BTreeSet<String> = ofx_values(text, "ACCTID").into_iter().map(|a| account(cx, a)).collect();
    cx.format_set("accounts", strings(accounts));
    if let Some(c) = first("CURDEF") {
        cx.format_set("currency", c);
    }
    cx.format_set("transactions", text.matches("<STMTTRN>").count());
    let dates: Vec<String> = ofx_values(text, "DTPOSTED").into_iter().filter_map(ofx_date).collect();
    cx.format_set("date_range", range(dates));
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    for k in ofx_values(text, "TRNTYPE") {
        *kinds.entry(k.to_string()).or_default() += 1;
    }
    cx.format_set("transaction_types", json!(kinds));
    if !cx.privacy_strict() {
        if let Some(b) = ofx_values(text, "BALAMT").first() {
            cx.format_set("balance", *b);
        }
        let list: Vec<Value> = text
            .split("<STMTTRN>")
            .skip(1)
            .take(MAX_TRANSACTIONS)
            .map(|t| {
                let t = t.split("</STMTTRN>").next().unwrap_or(t);
                let one = |tag: &str| ofx_values(t, tag).first().map(|v| (*v).to_string());
                json!({
                    "date": one("DTPOSTED").and_then(|d| ofx_date(&d)),
                    "amount": one("TRNAMT"),
                    "type": one("TRNTYPE"),
                    "name": one("NAME").or_else(|| one("MEMO")),
                })
            })
            .collect();
        cx.format_set("transaction_list", list);
    }
}

fn qif(cx: &mut Context<'_>, text: &str) {
    let kind = text.lines().next().and_then(|l| l.strip_prefix("!Type:")).unwrap_or("").trim().to_string();
    cx.format_set("account_type", kind);
    let (mut records, mut dates) = (0u64, Vec::new());
    let (mut list, mut cur) = (Vec::new(), serde_json::Map::new());
    for line in text.lines() {
        if line.starts_with('^') {
            records += 1;
            if list.len() < MAX_TRANSACTIONS {
                list.push(Value::Object(std::mem::take(&mut cur)));
            }
        } else if let Some(d) = line.strip_prefix('D') {
            // `9/ 1'25`, `09/01/2025`, `2025-09-01`: kept as written, the
            // order of day and month is the program's.
            let d = d.trim().replace(' ', "0");
            cur.insert("date".into(), d.clone().into());
            dates.push(d);
        } else if let Some(t) = line.strip_prefix('T').or_else(|| line.strip_prefix('U')) {
            cur.insert("amount".into(), t.trim().into());
        } else if let Some(p) = line.strip_prefix('P') {
            cur.insert("payee".into(), p.trim().into());
        } else if let Some(m) = line.strip_prefix('M') {
            cur.insert("memo".into(), m.trim().into());
        }
    }
    cx.format_set("transactions", records);
    if let (Some(a), Some(b)) = (dates.first(), dates.last()) {
        cx.format_set("first_date", a.clone());
        cx.format_set("last_date", b.clone());
    }
    if !cx.privacy_strict() {
        cx.format_set("transaction_list", list);
    }
}

/// `YYMMDD` → `20YY-MM-DD`.
fn yymmdd(v: &str) -> Option<String> {
    let d = v.get(..6)?;
    d.bytes().all(|b| b.is_ascii_digit()).then(|| format!("20{}-{}-{}", &d[..2], &d[2..4], &d[4..6]))
}

fn mt940(cx: &mut Context<'_>, text: &str) {
    let (mut statements, mut txns, mut dates) = (0u64, 0u64, Vec::new());
    let (mut accounts, mut currencies) = (BTreeSet::new(), BTreeSet::new());
    let (mut list, mut closing): (Vec<Value>, Option<String>) = (Vec::new(), None);
    for line in text.lines() {
        if line.starts_with(":20:") {
            statements += 1;
        } else if let Some(a) = line.strip_prefix(":25:") {
            accounts.insert(account(cx, a));
        } else if let Some(b) = line.strip_prefix(":60F:").or_else(|| line.strip_prefix(":60M:")) {
            // C/D, YYMMDD, currency, amount.
            if let Some(c) = b.get(7..10) {
                currencies.insert(c.to_string());
            }
        } else if let Some(t) = line.strip_prefix(":61:") {
            txns += 1;
            dates.extend(yymmdd(t));
            // YYMMDD, an optional MMDD entry date, C / D / RC / RD, the amount.
            let rest = t.get(6..).unwrap_or("");
            let rest =
                if rest.get(..4).is_some_and(|d| d.bytes().all(|b| b.is_ascii_digit())) { &rest[4..] } else { rest };
            let sign = if rest.starts_with('D') || rest.starts_with("RC") { "-" } else { "" };
            let amount: String = rest
                .trim_start_matches(['R', 'C', 'D'])
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == ',')
                .collect();
            if list.len() < MAX_TRANSACTIONS {
                list.push(json!({ "date": yymmdd(t), "amount": format!("{sign}{}", amount.replace(',', ".")) }));
            }
        } else if let Some(info) = line.strip_prefix(":86:") {
            if let Some(Value::Object(last)) = list.last_mut() {
                last.insert("details".into(), info.trim().into());
            }
        } else if let Some(b) = line.strip_prefix(":62F:") {
            closing = Some(b.trim().to_string());
        }
    }
    cx.format_set("statements", statements);
    cx.format_set("accounts", strings(accounts));
    cx.format_set("currencies", strings(currencies));
    cx.format_set("transactions", txns);
    cx.format_set("date_range", range(dates));
    if !cx.privacy_strict() {
        if let Some(c) = closing {
            cx.format_set("closing_balance", c);
        }
        cx.format_set("transaction_list", list);
    }
}

fn camt(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut path, mut statements, mut entries) = (Vec::<String>::new(), 0u64, 0u64);
    let (mut accounts, mut currencies, mut dates) = (BTreeSet::new(), BTreeSet::new(), Vec::new());
    let mut kind = String::new();
    let strict = cx.privacy_strict();
    let (mut list, mut last_balance, mut closing, mut closing_next) =
        (Vec::<Value>::new(), None::<String>, None::<String>, false);
    xmlwalk::walk(text, cx, 2_000_000, |_, ev| match ev {
        xmlwalk::Ev::Start(name, attrs) => {
            match name {
                "Stmt" | "Rpt" | "Ntfctn" => statements += 1,
                "Ntry" => {
                    entries += 1;
                    if list.len() < MAX_TRANSACTIONS {
                        list.push(Value::Object(serde_json::Map::new()));
                    }
                }
                "Amt" | "Bal" => {
                    if let Some(c) = xmlwalk::attr(attrs, "Ccy") {
                        currencies.insert(c.to_string());
                    }
                }
                "BkToCstmrStmt" => kind = "camt.053 (statement)".into(),
                "BkToCstmrAcctRpt" => kind = "camt.052 (report)".into(),
                "BkToCstmrDbtCdtNtfctn" => kind = "camt.054 (notification)".into(),
                _ => {}
            }
            path.push(name.to_string());
        }
        xmlwalk::Ev::End(name) => {
            // A balance's type comes before its amount, inside `Bal`.
            if name == "Bal" {
                if closing_next {
                    closing = last_balance.take();
                }
                closing_next = false;
            }
            path.pop();
        }
        xmlwalk::Ev::Text(t) => {
            let at =
                |p: &[&str]| path.len() >= p.len() && path[path.len() - p.len()..].iter().zip(p).all(|(a, b)| a == b);
            if at(&["Acct", "Id", "IBAN"]) || at(&["Acct", "Id", "Othr", "Id"]) {
                accounts.insert(if strict { mask(t) } else { t.to_string() });
            } else if at(&["Ntry", "BookgDt", "Dt"]) || at(&["Ntry", "BookgDt", "DtTm"]) {
                dates.push(t.get(..10).unwrap_or(t).to_string());
                if let Some(Value::Object(e)) = list.last_mut() {
                    e.insert("date".into(), t.get(..10).unwrap_or(t).into());
                }
            } else if at(&["Ntry", "Amt"]) {
                if let Some(Value::Object(e)) = list.last_mut() {
                    e.insert("amount".into(), t.into());
                }
            } else if at(&["Ntry", "CdtDbtInd"]) {
                if let Some(Value::Object(e)) = list.last_mut() {
                    e.insert("direction".into(), t.into());
                }
            } else if path.iter().any(|p| p == "Ntry") && path.last().is_some_and(|p| p == "Ustrd") {
                if let Some(Value::Object(e)) = list.last_mut() {
                    e.insert("details".into(), t.into());
                }
            } else if at(&["Bal", "Amt"]) {
                last_balance = Some(t.to_string());
            } else if at(&["Bal", "Tp", "CdOrPrtry", "Cd"]) && t == "CLBD" {
                closing_next = true;
            }
        }
    })?;
    if !kind.is_empty() {
        cx.format_set("message", kind);
    }
    cx.format_set("statements", statements);
    cx.format_set("accounts", strings(accounts));
    cx.format_set("currencies", strings(currencies));
    cx.format_set("entries", entries);
    cx.format_set("date_range", range(dates));
    if !strict {
        if let Some(c) = closing {
            cx.format_set("closing_balance", c);
        }
        cx.format_set("transaction_list", list);
    }
    Ok(())
}

// --- plain-text accounting ---------------------------------------------------------

fn ledger(cx: &mut Context<'_>, text: &str) {
    let (mut accounts, mut commodities, mut dates) = (BTreeSet::new(), BTreeSet::new(), Vec::new());
    let (mut txns, mut beancount) = (0u64, false);
    let mut title = None;
    for line in text.lines() {
        let l = line.trim_end();
        let bytes = l.as_bytes();
        let starts_with_date =
            bytes.len() >= 10 && bytes[..4].iter().all(u8::is_ascii_digit) && matches!(bytes[4], b'-' | b'/' | b'.');
        if starts_with_date {
            let date = l[..10].replace(['/', '.'], "-");
            let rest = l[10..].trim_start();
            let word = rest.split_whitespace().next().unwrap_or("");
            match word {
                "open" | "close" | "balance" | "pad" | "note" | "document" | "price" | "event" | "commodity" => {
                    beancount = true;
                    let mut w = rest.split_whitespace().skip(1);
                    if word == "commodity" {
                        commodities.extend(w.next().map(str::to_string));
                    } else if let Some(a) = w.next().filter(|a| a.contains(':')) {
                        accounts.insert(a.to_string());
                    }
                    if word == "open" {
                        commodities.extend(w.flat_map(|c| c.split(',')).filter(|c| !c.is_empty()).map(str::to_string));
                    }
                }
                _ => {
                    txns += 1;
                    if word == "*" || word == "!" || word == "txn" {
                        beancount |= rest.contains('"');
                    }
                }
            }
            dates.push(date);
        } else if line.starts_with([' ', '\t']) {
            let t = l.trim();
            if t.starts_with(';') || t.is_empty() {
                continue;
            }
            // A posting: an account, then an optional amount and commodity.
            let account = t.split("  ").next().unwrap_or(t).split('\t').next().unwrap_or(t).trim();
            if account.contains(':') && accounts.len() < 10_000 {
                accounts.insert(account.to_string());
            }
            let amount = t[account.len()..].trim();
            let commodity: String =
                amount.chars().filter(|c| c.is_alphabetic() || matches!(c, '$' | '€' | '£' | '¥')).collect();
            if !commodity.is_empty() && commodity.len() <= 10 {
                commodities.insert(commodity);
            }
        } else if let Some(v) = l.strip_prefix("option \"title\"") {
            title = Some(v.trim().trim_matches('"').to_string());
        } else if let Some(c) = l.strip_prefix("commodity ") {
            commodities.insert(c.trim().to_string());
        } else if let Some(a) = l.strip_prefix("account ") {
            accounts.insert(a.trim().to_string());
        }
    }
    cx.format_set("dialect", if beancount { "Beancount" } else { "Ledger / hledger" });
    if let Some(t) = title {
        cx.content().title(t.clone());
        cx.format_set("title", t);
    }
    let tops: BTreeSet<String> = accounts.iter().filter_map(|a| a.split(':').next()).map(str::to_string).collect();
    cx.format_set("transactions", txns);
    cx.format_set("accounts", accounts.len());
    cx.format_set("top_level_accounts", strings(tops));
    cx.format_set("commodities", strings(commodities));
    cx.format_set("date_range", range(dates));
}

// --- EDI -----------------------------------------------------------------------------

fn x12_name(code: &str) -> Option<&'static str> {
    Some(match code {
        "810" => "Invoice",
        "820" => "Payment order / remittance advice",
        "830" => "Planning schedule",
        "832" => "Price / sales catalog",
        "835" => "Health care claim payment",
        "837" => "Health care claim",
        "846" => "Inventory inquiry / advice",
        "850" => "Purchase order",
        "855" => "Purchase order acknowledgment",
        "856" => "Ship notice / manifest",
        "860" => "Purchase order change",
        "940" => "Warehouse shipping order",
        "945" => "Warehouse shipping advice",
        "997" => "Functional acknowledgment",
        "999" => "Implementation acknowledgment",
        _ => return None,
    })
}

fn x12(cx: &mut Context<'_>, text: &str) {
    // ISA is fixed-width: the element separator is its 4th byte, the
    // segment terminator its 106th.
    let elem = text.chars().nth(3).unwrap_or('*');
    let term = text.chars().nth(105).filter(|c| !c.is_alphanumeric()).unwrap_or('~');
    let segments: Vec<Vec<&str>> =
        text.split(term).map(|s| s.trim().split(elem).collect()).filter(|s: &Vec<&str>| !s[0].is_empty()).collect();
    let mut sets: BTreeMap<String, u64> = BTreeMap::new();
    for s in &segments {
        match s[0] {
            "ISA" => {
                if let Some(v) = s.get(12) {
                    cx.format_set("version", v.trim());
                }
                if let Some(d) = s.get(9) {
                    cx.format_set(
                        "date",
                        format!(
                            "20{}-{}-{}",
                            d.get(..2).unwrap_or(""),
                            d.get(2..4).unwrap_or(""),
                            d.get(4..6).unwrap_or("")
                        ),
                    );
                }
                if s.get(15).is_some_and(|u| u.trim() == "T") {
                    cx.format_set("test_indicator", true);
                }
                if !cx.privacy_strict() {
                    if let Some(v) = s.get(6) {
                        cx.format_set("sender_id", v.trim());
                    }
                    if let Some(v) = s.get(8) {
                        cx.format_set("receiver_id", v.trim());
                    }
                }
            }
            "ST" => {
                if let Some(code) = s.get(1) {
                    let label = x12_name(code).map_or_else(|| (*code).to_string(), |n| format!("{code} {n}"));
                    *sets.entry(label).or_default() += 1;
                }
            }
            _ => {}
        }
    }
    cx.format_set("segments", segments.len());
    cx.format_set("functional_groups", segments.iter().filter(|s| s[0] == "GS").count());
    cx.format_set("transaction_sets", json!(sets));
}

fn edifact(cx: &mut Context<'_>, text: &str) {
    // `UNA:+.? '`: component, element, decimal, release, (reserved), segment.
    let (comp, elem, term) = match text.strip_prefix("UNA") {
        Some(r) if r.len() >= 6 => {
            let c: Vec<char> = r.chars().take(6).collect();
            (c[0], c[1], c[5])
        }
        _ => (':', '+', '\''),
    };
    let body = text.strip_prefix("UNA").map_or(text, |r| r.get(6..).unwrap_or(""));
    let segments: Vec<Vec<&str>> =
        body.split(term).map(|s| s.trim().split(elem).collect()).filter(|s: &Vec<&str>| !s[0].is_empty()).collect();
    let mut messages: BTreeMap<String, u64> = BTreeMap::new();
    for s in &segments {
        match s[0] {
            "UNB" => {
                if let Some(v) = s.get(1) {
                    cx.format_set("syntax", v.replace(comp, " "));
                }
                if !cx.privacy_strict() {
                    if let Some(v) = s.get(2) {
                        cx.format_set("sender_id", v.split(comp).next().unwrap_or(v));
                    }
                    if let Some(v) = s.get(3) {
                        cx.format_set("receiver_id", v.split(comp).next().unwrap_or(v));
                    }
                }
                if let Some(v) = s.get(4).and_then(|d| d.split(comp).next()) {
                    cx.format_set("date", yymmdd(v).unwrap_or_else(|| v.to_string()));
                }
            }
            "UNH" => {
                if let Some(id) = s.get(2) {
                    let parts: Vec<&str> = id.split(comp).collect();
                    let label = match parts.as_slice() {
                        [t, v, r, ..] => format!("{t} {v}{r}"),
                        _ => (*id).to_string(),
                    };
                    *messages.entry(label).or_default() += 1;
                }
            }
            _ => {}
        }
    }
    cx.format_set("segments", segments.len());
    cx.format_set("messages", json!(messages));
}

// --- GEDCOM -----------------------------------------------------------------------------

fn gedcom(cx: &mut Context<'_>, text: &str) {
    let (mut counts, mut years, mut path) = (BTreeMap::<&str, u64>::new(), Vec::<u32>::new(), Vec::<String>::new());
    // With `--privacy off`: each individual's name and birth / death year.
    let mut people: Vec<serde_json::Map<String, Value>> = Vec::new();
    for line in text.lines() {
        let mut w = line.trim().splitn(3, ' ');
        let (Some(level), Some(a)) = (w.next().and_then(|l| l.parse::<usize>().ok()), w.next()) else { continue };
        let rest = w.next().unwrap_or("");
        let tag = if a.starts_with('@') { rest.split_whitespace().next().unwrap_or("") } else { a };
        path.truncate(level);
        path.push(tag.to_string());
        let val = if a.starts_with('@') { "" } else { rest };
        match (level, tag) {
            (0, "INDI") => {
                *counts.entry("individuals").or_default() += 1;
                people.push(serde_json::Map::new());
            }
            (0, "FAM") => *counts.entry("families").or_default() += 1,
            (0, "SOUR") => *counts.entry("sources").or_default() += 1,
            (0, "OBJE") => *counts.entry("media").or_default() += 1,
            (0, "REPO") => *counts.entry("repositories").or_default() += 1,
            (0, "NOTE" | "SNOTE") => *counts.entry("notes").or_default() += 1,
            (1, "NAME") if path.first().is_some_and(|p| p == "INDI") => {
                if let Some(p) = people.last_mut().filter(|p| !p.contains_key("name")) {
                    p.insert(
                        "name".into(),
                        val.replace('/', "").split_whitespace().collect::<Vec<_>>().join(" ").into(),
                    );
                }
            }
            (2, "DATE")
                if path.first().is_some_and(|p| p == "INDI")
                    && matches!(path.get(1).map(String::as_str), Some("BIRT" | "DEAT")) =>
            {
                let year =
                    val.split_whitespace().filter_map(|t| t.parse::<u32>().ok()).rfind(|y| (100..=2200).contains(y));
                years.extend(year);
                if let (Some(p), Some(y)) = (people.last_mut(), year) {
                    let key = if path[1] == "BIRT" { "born" } else { "died" };
                    p.insert(key.into(), y.into());
                }
            }
            (_, "DATE") => years.extend(
                val.split_whitespace().filter_map(|t| t.parse::<u32>().ok()).rfind(|y| (100..=2200).contains(y)),
            ),
            _ => {}
        }
        if path.first().is_some_and(|p| p == "HEAD") {
            match path.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
                ["HEAD", "SOUR"] => cx.format_set("source_program", val),
                ["HEAD", "SOUR", "VERS"] => cx.format_set("source_version", val),
                ["HEAD", "GEDC", "VERS"] => cx.format_set("gedcom_version", val),
                ["HEAD", "CHAR"] => cx.format_set("character_set", val),
                ["HEAD", "LANG"] => cx.format_set("language", val),
                _ => {}
            }
        }
    }
    cx.format_set("records", json!(counts));
    if let (Some(a), Some(b)) = (years.iter().min(), years.iter().max()) {
        cx.format_set("year_range", json!([a, b]));
    }
    if !cx.privacy_strict() {
        cx.format_set("individuals", people.into_iter().take(500).map(Value::Object).collect::<Vec<_>>());
    }
}

// --- GTFS ----------------------------------------------------------------------------------

fn gtfs(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 1 << 16)?;
    let find =
        |name: &str| zip.entries.iter().find(|e| e.name.rsplit('/').next() == Some(name)).map(|e| e.name.clone());
    let read = |src: &mut dyn Source, cx: &mut Context<'_>, name: &str| -> Option<String> {
        let n = find(name)?;
        zip.read_text(src, &n, cx, cx.parse_limit()).and_then(Result::ok)
    };
    let rows = |t: &Option<String>| {
        t.as_ref().map_or(0, |t| t.lines().filter(|l| !l.trim().is_empty()).count().saturating_sub(1))
    };
    let column = |t: &str, col: &str| -> Vec<String> {
        let mut lines = t.lines();
        let head: Vec<&str> =
            lines.next().unwrap_or("").trim_start_matches('\u{feff}').split(',').map(str::trim).collect();
        let Some(i) = head.iter().position(|h| *h == col) else { return Vec::new() };
        lines
            .filter_map(|l| l.split(',').nth(i).map(|v| v.trim().trim_matches('"').to_string()))
            .filter(|v| !v.is_empty())
            .collect()
    };
    let agency = read(src, cx, "agency.txt");
    if let Some(a) = &agency {
        cx.format_set("agencies", strings(column(a, "agency_name")));
    }
    for (file, key) in [
        ("routes.txt", "routes"),
        ("stops.txt", "stops"),
        ("trips.txt", "trips"),
        ("stop_times.txt", "stop_times"),
        ("shapes.txt", "shape_points"),
    ] {
        let t = read(src, cx, file);
        if t.is_some() {
            cx.format_set(key, rows(&t));
        }
    }
    if let Some(cal) = read(src, cx, "calendar.txt") {
        let mut d: Vec<String> = column(&cal, "start_date");
        d.extend(column(&cal, "end_date"));
        let dates: Vec<String> =
            d.into_iter().filter(|v| v.len() == 8).map(|v| format!("{}-{}-{}", &v[..4], &v[4..6], &v[6..])).collect();
        cx.format_set("service_range", range(dates));
    }
    let files: Vec<String> = zip.entries.iter().map(|e| e.name.clone()).collect();
    cx.format_set("files", strings(files));
    Ok(())
}

// --- fortune, LDIF ----------------------------------------------------------------------------

fn fortune(cx: &mut Context<'_>, text: &str) {
    let quotes: Vec<&str> = text.split("\n%\n").map(str::trim).filter(|q| !q.is_empty() && *q != "%").collect();
    cx.format_set("quotes", quotes.len());
    if let (Some(lo), Some(hi)) = (quotes.iter().map(|q| q.len()).min(), quotes.iter().map(|q| q.len()).max()) {
        cx.format_set("shortest_bytes", lo);
        cx.format_set("longest_bytes", hi);
    }
    let mut body = String::new();
    for q in quotes {
        if body.len() > MAX_TEXT {
            break;
        }
        body.push_str(q);
        body.push('\n');
    }
    cx.emit_text(TextRole::Body, &body);
}

/// A `strfile` index (`.dat`): version, quote count, lengths, flags, delimiter.
fn strfile(cx: &mut Context<'_>, b: &[u8]) {
    let be = |at: usize| u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    cx.format_set("index", true);
    cx.format_set("version", be(0));
    cx.format_set("quotes", be(4));
    cx.format_set("longest_bytes", be(8));
    cx.format_set("shortest_bytes", be(12));
    let flags = be(16);
    for (bit, name) in [(1, "random"), (2, "ordered"), (4, "rot13")] {
        if flags & bit != 0 {
            cx.format_set(name, true);
        }
    }
    cx.format_set("delimiter", latin1_or_utf8(&b[20..21]));
}

fn ldif(cx: &mut Context<'_>, text: &str) {
    let (mut entries, mut classes, mut attrs, mut changes) =
        (0u64, BTreeMap::<String, u64>::new(), BTreeSet::new(), BTreeMap::<String, u64>::new());
    let mut version = None;
    // With `--privacy off`: each entry's DN and attribute values.
    let mut list: Vec<serde_json::Map<String, Value>> = Vec::new();
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim_start_matches(':').trim();
        let key = k.to_ascii_lowercase();
        if key == "dn" {
            if list.len() < 200 {
                let mut m = serde_json::Map::new();
                m.insert("dn".into(), v.into());
                list.push(m);
            }
        } else if key != "version"
            && let Some(m) = list.last_mut()
        {
            match m.get_mut(k) {
                Some(Value::Array(a)) => a.push(v.into()),
                Some(old) => *old = json!([old.clone(), v]),
                None => _ = m.insert(k.to_string(), v.into()),
            }
        }
        match key.as_str() {
            "version" => version = Some(v.to_string()),
            "dn" => entries += 1,
            "objectclass" => *classes.entry(v.to_string()).or_default() += 1,
            "changetype" => *changes.entry(v.to_string()).or_default() += 1,
            other if attrs.len() < 500 => _ = attrs.insert(other.split(';').next().unwrap_or(other).to_string()),
            _ => {}
        }
    }
    if let Some(v) = version {
        cx.format_set("ldif_version", v);
    }
    cx.format_set("entries", entries);
    cx.format_set("object_classes", json!(classes));
    cx.format_set("attributes", strings(attrs));
    if !changes.is_empty() {
        cx.format_set("change_records", json!(changes));
    }
    if !cx.privacy_strict() {
        cx.format_set("entry_list", list.into_iter().map(Value::Object).collect::<Vec<_>>());
    }
}

// --- notebooks ---------------------------------------------------------------------------------

fn mathematica(cx: &mut Context<'_>, text: &str) {
    if let Some(v) = text.find("(* Created By: ").map(|p| &text[p + 15..]).and_then(|r| r.split("*)").next()) {
        cx.format_set("created_by", v.trim());
    }
    // `Cell["text", "Style", …]` and `Cell[BoxData[…], "Input", …]`: the
    // style is the string after the first argument.
    let mut styles: BTreeMap<String, u64> = BTreeMap::new();
    let (mut titles, mut prose) = (Vec::new(), String::new());
    for (p, _) in text.match_indices("Cell[") {
        let rest = &text[p + 5..text.len().min(p + 5 + 4096)];
        let (first, after) = if let Some(r) = rest.strip_prefix('"') {
            let e = r.find('"').unwrap_or(r.len());
            (Some(&r[..e]), &r[e.saturating_add(1).min(r.len())..])
        } else {
            // `BoxData[…]` and the like: skip to the bracket that closes it.
            let mut depth = 0i32;
            let mut end = rest.len();
            for (i, c) in rest.char_indices() {
                match c {
                    '[' | '{' => depth += 1,
                    ']' | '}' => depth -= 1,
                    ',' if depth == 0 => {
                        end = i;
                        break;
                    }
                    _ => {}
                }
                if depth < 0 {
                    break;
                }
            }
            (None, &rest[end..])
        };
        let Some(style) = after
            .trim_start()
            .strip_prefix(',')
            .map(str::trim_start)
            .and_then(|r| r.strip_prefix('"'))
            .and_then(|r| r.split('"').next())
        else {
            continue;
        };
        if !style.chars().all(|c| c.is_ascii_alphanumeric()) || style.is_empty() {
            continue;
        }
        *styles.entry(style.to_string()).or_default() += 1;
        if let Some(t) = first {
            match style {
                "Title" | "Chapter" | "Section" | "Subsection" => {
                    if style == "Title" {
                        cx.content().title(t.to_string());
                    }
                    titles.push(t.to_string());
                }
                "Text" if prose.len() < MAX_TEXT => {
                    prose.push_str(t);
                    prose.push('\n');
                }
                _ => {}
            }
        }
    }
    cx.format_set("cells", styles.values().sum::<u64>());
    cx.format_set("cell_styles", json!(styles));
    cx.format_set("headings", strings(titles));
    cx.emit_text(TextRole::Body, &prose);
}

fn livebook(cx: &mut Context<'_>, text: &str) {
    let (mut sections, mut cells, mut deps, mut in_code) = (Vec::new(), 0u64, Vec::new(), false);
    let mut prose = String::new();
    for line in text.lines() {
        if line.starts_with("```") {
            if !in_code && line.trim_start_matches('`').trim() == "elixir" {
                cells += 1;
            }
            in_code = !in_code;
            continue;
        }
        if in_code {
            if line.contains("Mix.install") {
                // `Mix.install([{:kino, "~> 0.14"}, {:req, "~> 0.5"}])`
                for (p, _) in line.match_indices("{:") {
                    deps.extend(line[p + 2..].split([',', '}']).next().map(|d| d.trim().to_string()));
                }
            }
            continue;
        }
        if let Some(t) = line.strip_prefix("# ") {
            cx.content().title(t.trim().to_string());
        } else if let Some(t) = line.strip_prefix("## ") {
            sections.push(t.trim().to_string());
            cx.emit_heading(2, t.trim());
        } else if !line.starts_with("<!--") {
            prose.push_str(line);
            prose.push('\n');
        }
    }
    cx.format_set("sections", strings(sections));
    cx.format_set("elixir_cells", cells);
    if !deps.is_empty() {
        cx.format_set("dependencies", strings(deps));
    }
    cx.emit_text(TextRole::Body, &prose);
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!(
        "lcov",
        "tap",
        "prometheus",
        "ofx",
        "qif",
        "mt940",
        "camt",
        "ledger",
        "edi_x12",
        "edifact",
        "gedcom",
        "gtfs",
        "fortune",
        "ldif",
        "mathematica_nb",
        "livebook"
    );

    #[test]
    fn masks_and_dates() {
        assert_eq!(mask("GB29 NWBK 6016 1331 9268 19"), "••••••••6819");
        assert_eq!(mask("123"), "123");
        assert_eq!(ofx_date("20250901120000[-5:EST]").as_deref(), Some("2025-09-01"));
        assert_eq!(yymmdd("250901").as_deref(), Some("2025-09-01"));
        assert_eq!(x12_name("850"), Some("Purchase order"));
    }

    /// People's names and directory values appear only with
    /// `--privacy off` (neutral samples).
    #[test]
    fn people_follow_privacy() {
        let ged = b"0 HEAD\n1 GEDC\n2 VERS 5.5.1\n0 @I1@ INDI\n1 NAME Alpha /Beta/\n1 BIRT\n2 DATE 1900\n0 TRLR\n";
        let ldif = b"version: 1\n\ndn: uid=a,dc=example\nobjectClass: person\ncn: Gamma Delta\n";
        for (name, bytes, needle) in [("t.ged", &ged[..], "Alpha Beta"), ("t.ldif", &ldif[..], "Gamma Delta")] {
            let strict = serde_json::to_string(&crate::plugin::testing::report_for(name, bytes)).unwrap();
            assert!(!strict.contains(needle.split(' ').next().unwrap()), "{name}: name in a strict report");
            let off = serde_json::to_string(&crate::plugin::testing::report_without_privacy(name, bytes)).unwrap();
            assert!(off.contains(needle), "{name}: name missing with privacy off");
        }
    }

    /// Account numbers never reach the report whole (neutral sample).
    #[test]
    fn statements_mask_accounts() {
        let ofx = b"OFXHEADER:100\nDATA:OFXSGML\nVERSION:102\n\n<OFX><BANKMSGSRSV1><STMTTRNRS><STMTRS><CURDEF>EUR<BANKACCTFROM><BANKID>999<ACCTID>00012345678<ACCTTYPE>CHECKING</BANKACCTFROM><BANKTRANLIST><STMTTRN><TRNTYPE>DEBIT<DTPOSTED>20250901<TRNAMT>-1.00</STMTTRN></BANKTRANLIST></STMTRS></STMTTRNRS></BANKMSGSRSV1></OFX>";
        let r = crate::plugin::testing::report_for("statement.ofx", ofx);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("00012345678"), "account number leaked");
        assert_eq!(r.format["ofx"]["accounts"][0], "•••••••5678");
        assert!(r.format["ofx"].get("transaction_list").is_none());
        // `--privacy off`: the account whole, and the transactions.
        let r = crate::plugin::testing::report_without_privacy("statement.ofx", ofx);
        assert_eq!(r.format["ofx"]["accounts"][0], "00012345678");
        assert_eq!(r.format["ofx"]["transaction_list"][0]["amount"], "-1.00");
    }
}
