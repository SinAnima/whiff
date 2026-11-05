//! Steam `KeyValues` files:
//! * text VDF / ACF: app manifests (`appmanifest_*.acf`: app ID, name,
//!   install folder, build, size, last update, state, depots), library
//!   folders (libraries, apps, sizes), account lists (counted only), and
//!   any other file's root key and size;
//! * binary VDF: `shortcuts.vdf` (non-Steam games: names, tags, launch
//!   targets) and `appinfo.vdf` (version, universe, apps).
//!
//! Account names, Steam IDs and user folders are hidden unless privacy is
//! off. Specifications: Valve developer wiki (`KeyValues`); the
//! `ValvePython/vdf` and `SteamDatabase` notes on the binary forms.

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars, user_path,
};

/// Extractor for Steam `KeyValues` files.
pub struct Steam;

static META: ExtractorMeta = ExtractorMeta {
    id: "game.steam",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "steam_vdf",
            name: "Steam KeyValues (VDF / ACF)",
            family: "game",
            mimes: &[],
            extensions: &["vdf", "acf"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "steam_binary_vdf",
            name: "Steam binary KeyValues",
            family: "game",
            mimes: &[],
            extensions: &[],
            magic: &[
                Magic::prefix(b"\0shortcuts\0"),
                Magic::prefix(&[0x27, 0x44, 0x56, 0x07]),
                Magic::prefix(&[0x28, 0x44, 0x56, 0x07]),
                Magic::prefix(&[0x29, 0x44, 0x56, 0x07]),
            ],
            parent: None,
        },
    ],
};

const MAX_NODES: usize = 1_000_000;
const MAX_DEPTH: usize = 64;

/// A `KeyValues` node: a string or a block of pairs.
#[derive(Debug)]
enum Kv {
    Str(String),
    Block(Vec<(String, Kv)>),
}

impl Kv {
    fn get(&self, key: &str) -> Option<&Kv> {
        match self {
            Kv::Block(v) => v.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v),
            Kv::Str(_) => None,
        }
    }
    fn str(&self, key: &str) -> Option<&str> {
        match self.get(key)? {
            Kv::Str(s) => Some(s),
            Kv::Block(_) => None,
        }
    }
    fn pairs(&self) -> &[(String, Kv)] {
        match self {
            Kv::Block(v) => v,
            Kv::Str(_) => &[],
        }
    }
}

/// Text tokens: quoted or bare strings and braces; comments and
/// `[$CONDITION]` tags skipped.
fn tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() && out.len() < MAX_NODES * 2 {
        match b[i] {
            c if c.is_ascii_whitespace() => i += 1,
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'[' => {
                while i < b.len() && b[i] != b']' {
                    i += 1;
                }
                i += 1;
            }
            b'{' | b'}' => {
                out.push(char::from(b[i]).to_string());
                i += 1;
            }
            b'"' => {
                let mut s = Vec::new();
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        i += 1;
                        s.push(match b[i] {
                            b'n' => b'\n',
                            b't' => b'\t',
                            c => c,
                        });
                    } else {
                        s.push(b[i]);
                    }
                    i += 1;
                }
                i += 1;
                // Keep quoted braces distinct from structure.
                let mut t = String::from("\"");
                t.push_str(&String::from_utf8_lossy(&s));
                out.push(t);
            }
            _ => {
                let start = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'{' | b'}' | b'"') {
                    i += 1;
                }
                out.push(format!("\"{}", String::from_utf8_lossy(&b[start..i])));
            }
        }
    }
    out
}

fn parse_block(t: &[String], at: &mut usize, depth: usize) -> Kv {
    let mut v = Vec::new();
    while *at < t.len() {
        let tok = &t[*at];
        *at += 1;
        if tok == "}" {
            break;
        }
        let Some(key) = tok.strip_prefix('"') else { continue };
        let Some(next) = t.get(*at) else { break };
        *at += 1;
        let val = if next == "{" {
            if depth >= MAX_DEPTH {
                // Too deep: skip the block.
                let mut level = 1;
                while *at < t.len() && level > 0 {
                    level += match t[*at].as_str() {
                        "{" => 1,
                        "}" => -1,
                        _ => 0,
                    };
                    *at += 1;
                }
                Kv::Block(Vec::new())
            } else {
                parse_block(t, at, depth + 1)
            }
        } else {
            Kv::Str(truncate_chars(next.trim_start_matches('"'), 2000))
        };
        if v.len() < 100_000 {
            v.push((key.to_string(), val));
        }
    }
    Kv::Block(v)
}

fn count(kv: &Kv) -> u64 {
    kv.pairs().iter().map(|(_, v)| 1 + count(v)).sum()
}

fn unix_date(s: &str) -> Option<String> {
    super::unix_time(s.parse().ok()?)
}

/// `StateFlags` bits.
fn state_flags(v: u64) -> Vec<&'static str> {
    [
        (4, "fully installed"),
        (2, "update required"),
        (0x200, "files missing"),
        (0x400, "uninstalling"),
        (0x100_000, "update running"),
        (0x200_000, "update paused"),
        (0x400_000, "update started"),
    ]
    .into_iter()
    .filter(|(bit, _)| v & bit != 0)
    .map(|(_, n)| n)
    .collect()
}

fn text_vdf(cx: &mut Context<'_>, text: &str) {
    let t = tokens(text);
    let mut at = 0;
    let doc = parse_block(&t, &mut at, 0);
    let Some((root, body)) = doc.pairs().first() else {
        cx.format_set("key_count", 0);
        return;
    };
    cx.format_set("root", truncate_chars(root, 200));
    cx.format_set("key_count", count(&doc));
    let mut m = Map::new();
    match root.to_ascii_lowercase().as_str() {
        "appstate" => {
            for (k, out) in [
                ("appid", "app_id"),
                ("name", "name"),
                ("installdir", "install_folder"),
                ("buildid", "build_id"),
                ("SizeOnDisk", "size_on_disk"),
                ("BytesToDownload", "bytes_to_download"),
                ("Universe", "universe"),
                ("AutoUpdateBehavior", "auto_update"),
            ] {
                if let Some(v) = body.str(k) {
                    let v = v.parse::<u64>().map_or_else(|_| Value::from(v), Value::from);
                    m.insert(out.into(), v);
                }
            }
            if let Some(n) = body.str("name") {
                cx.content().title(n.to_string());
            }
            if let Some(d) = body.str("LastUpdated").and_then(unix_date) {
                cx.temporal().content_date(DateField::Modified, d.clone(), true);
                m.insert("last_updated".into(), d.into());
            }
            if let Some(f) = body.str("StateFlags").and_then(|s| s.parse::<u64>().ok()) {
                m.insert("state".into(), state_flags(f).into());
            }
            if let Some(d) = body.get("InstalledDepots") {
                m.insert("installed_depots".into(), d.pairs().len().into());
            }
            if let Some(l) = body.get("UserConfig").and_then(|u| u.str("language")) {
                m.insert("language".into(), l.into());
            }
            if !cx.privacy_strict()
                && let Some(o) = body.str("LastOwner")
            {
                m.insert("last_owner".into(), o.into());
            }
        }
        "libraryfolders" => {
            let mut libs = Vec::new();
            let mut apps = 0u64;
            for (_, lib) in body.pairs() {
                let Some(path) = lib.str("path") else { continue };
                let n = lib.get("apps").map_or(0, |a| a.pairs().len());
                apps += n as u64;
                if libs.len() < 50 {
                    let mut l = Map::new();
                    l.insert("path".into(), user_path(cx, path).into());
                    l.insert("apps".into(), n.into());
                    if let Some(s) = lib.str("totalSize").and_then(|s| s.parse::<u64>().ok()) {
                        l.insert("total_size".into(), s.into());
                    }
                    libs.push(Value::Object(l));
                }
            }
            m.insert("library_count".into(), libs.len().into());
            m.insert("app_count".into(), apps.into());
            m.insert("libraries".into(), libs.into());
        }
        "users" => {
            // Account lists: counted, never named.
            m.insert("account_count".into(), body.pairs().len().into());
        }
        _ => {
            let keys: Vec<Value> = body.pairs().iter().take(50).map(|(k, _)| truncate_chars(k, 100).into()).collect();
            m.insert("top_keys".into(), keys.into());
        }
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
}

/// Binary `KeyValues`: type byte, NUL-terminated key, value; 8 ends a map.
fn binary_kv(b: &[u8], at: &mut usize, depth: usize, nodes: &mut usize) -> Option<Kv> {
    let mut v = Vec::new();
    loop {
        let t = *b.get(*at)?;
        *at += 1;
        if t == 8 || t == 0x0B {
            return Some(Kv::Block(v));
        }
        let end = b.get(*at..)?.iter().position(|&c| c == 0)?;
        let key = String::from_utf8_lossy(&b[*at..*at + end]).into_owned();
        *at += end + 1;
        *nodes += 1;
        if *nodes > MAX_NODES || depth > MAX_DEPTH {
            return None;
        }
        let val = match t {
            0 => binary_kv(b, at, depth + 1, nodes)?,
            1 => {
                let end = b.get(*at..)?.iter().position(|&c| c == 0)?;
                let s = String::from_utf8_lossy(&b[*at..*at + end]).into_owned();
                *at += end + 1;
                Kv::Str(truncate_chars(&s, 2000))
            }
            2 | 3 | 4 | 6 => {
                let n = b.get(*at..*at + 4)?;
                *at += 4;
                Kv::Str(u32::from_le_bytes([n[0], n[1], n[2], n[3]]).to_string())
            }
            7 | 10 => {
                let n = b.get(*at..*at + 8)?;
                *at += 8;
                Kv::Str(u64::from_le_bytes(n.try_into().ok()?).to_string())
            }
            _ => return None,
        };
        v.push((key, val));
    }
}

fn binary_vdf(cx: &mut Context<'_>, b: &[u8]) -> Result<(), ExtractError> {
    if b.starts_with(b"\0shortcuts\0") {
        let mut at = 0;
        let mut nodes = 0;
        let doc = binary_kv(b, &mut at, 0, &mut nodes).ok_or(ExtractError::Malformed("binary KeyValues".into()))?;
        let list = doc.get("shortcuts").map_or(&[][..], Kv::pairs);
        cx.format_set("kind", "shortcuts");
        cx.format_set("shortcut_count", list.len());
        let mut games = Vec::new();
        let mut tags = std::collections::BTreeSet::new();
        for (_, s) in list.iter().take(200) {
            let name = s.str("AppName").or_else(|| s.str("appname")).unwrap_or("");
            let mut g = Map::new();
            g.insert("name".into(), truncate_chars(name, 200).into());
            if let Some(e) = s.str("Exe").or_else(|| s.str("exe")) {
                g.insert("target".into(), user_path(cx, e.trim_matches('"')).into());
            }
            for (_, t) in s.get("tags").map_or(&[][..], Kv::pairs) {
                if let Kv::Str(t) = t
                    && tags.len() < 100
                {
                    tags.insert(t.clone());
                }
            }
            games.push(Value::Object(g));
        }
        cx.format_set("shortcuts", games);
        if !tags.is_empty() {
            cx.format_set("tags", tags.into_iter().collect::<Vec<_>>());
        }
        return Ok(());
    }
    // appinfo.vdf: version byte 0x27–0x29, universe, then apps (v29 adds a
    // string table offset).
    let version = b[0];
    cx.format_set("kind", "appinfo");
    cx.format_set("version", version);
    let universe = u32::from_le_bytes(b.get(4..8).unwrap_or(&[0; 4]).try_into().unwrap_or_default());
    cx.format_set("universe", universe);
    let mut at = if version >= 0x29 { 16 } else { 8 };
    let mut apps = 0u64;
    while let Some(id) = b.get(at..at + 4) {
        if id == [0, 0, 0, 0] {
            break;
        }
        let Some(size) = b.get(at + 4..at + 8) else { break };
        let size = u32::from_le_bytes([size[0], size[1], size[2], size[3]]) as usize;
        apps += 1;
        at = at.saturating_add(8 + size);
        if apps >= MAX_NODES as u64 {
            break;
        }
    }
    cx.format_set("app_count", apps);
    Ok(())
}

impl Extractor for Steam {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let ext = probe.extension.unwrap_or("");
        if !matches!(ext, "vdf" | "acf") {
            return None;
        }
        let t = std::str::from_utf8(&probe.head[..probe.head.len().min(2048)]).ok()?;
        let toks = tokens(t);
        (toks.len() >= 2 && toks[0].starts_with('"') && toks[1] == "{")
            .then_some(Sniff { format: "steam_vdf", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "steam_vdf" {
            let text = cx.read_text(src)?.text;
            text_vdf(cx, &text);
            return Ok(());
        }
        let (b, _) = cx.read_bytes(src)?;
        binary_vdf(cx, &b)
    }
}

crate::register_extractor!(Steam);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyvalues() {
        let t = tokens(
            "\"AppState\"\n{\n\t\"appid\"\t\t\"480\" // c\n\t\"name\" \"Space { War\"\n\tUserConfig { language english }\n}",
        );
        let mut at = 0;
        let doc = parse_block(&t, &mut at, 0);
        let app = doc.get("AppState").unwrap();
        assert_eq!(app.str("appid"), Some("480"));
        assert_eq!(app.str("name"), Some("Space { War"));
        assert_eq!(app.get("userconfig").and_then(|u| u.str("language")), Some("english"));
        assert_eq!(unix_date("1700000000").as_deref(), Some("2023-11-14T22:13:20Z"));
    }

    crate::fixture_tests!("steam_vdf", "steam_binary_vdf");
}
