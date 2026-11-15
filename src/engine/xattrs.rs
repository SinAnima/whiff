//! Extended attributes (Unix) and alternate data streams (Windows) that say
//! where a file came from: macOS quarantine and "Where from", Finder tags,
//! XDG origin URLs, the Windows `Zone.Identifier` stream.

// The xattr decoders only run on Unix; Windows reads one stream, WASM none.
#![cfg_attr(not(unix), allow(dead_code))]

use serde_json::{Value, json};

use crate::report::{Map, Report};

/// Attributes listed per file, and bytes read per attribute.
const MAX_ATTRS: usize = 32;
const MAX_VALUE: usize = 4096;

/// Fill `security.xattrs` (and Finder tags into `content.tags`).
#[cfg(unix)]
pub(crate) fn fill(report: &mut Report, path: &std::path::Path) {
    let Ok(names) = xattr::list_deref(path) else { return };
    let mut names: Vec<String> = names.map(|n| n.to_string_lossy().into_owned()).collect();
    names.sort();
    let total = names.len();
    for name in names.into_iter().take(MAX_ATTRS) {
        let decoded = match read_capped(path, &name) {
            Some(Ok(value)) => decode(&name, &value),
            Some(Err(size)) => json!({ "bytes": size, "skipped": "too_large" }),
            None => continue,
        };
        if name == "com.apple.metadata:_kMDItemUserTags"
            && let Value::Array(tags) = &decoded
        {
            for t in tags.iter().filter_map(Value::as_str) {
                if !report.content.tags.iter().any(|x| x == t) {
                    report.content.tags.push(t.to_string());
                }
            }
        }
        report.security.xattrs.insert(name, decoded);
    }
    if total > MAX_ATTRS {
        report.security.xattrs.insert("_truncated".into(), json!({ "total": total }));
    }
}

/// The value of attribute `name`, read into a buffer of at most
/// [`MAX_VALUE`] bytes: `Err(size)` when it is larger, `None` when absent
/// or unreadable.
#[cfg(any(target_os = "android", target_os = "linux", target_os = "macos"))]
fn read_capped(path: &std::path::Path, name: &str) -> Option<Result<Vec<u8>, usize>> {
    let mut buf = vec![0u8; MAX_VALUE];
    match rustix::fs::getxattr(path, name, &mut buf[..]) {
        Ok(n) => {
            buf.truncate(n);
            Some(Ok(buf))
        }
        Err(rustix::io::Errno::RANGE) => Some(Err(rustix::fs::getxattr(path, name, &mut [0u8; 0][..]).unwrap_or(0))),
        Err(_) => None,
    }
}

/// Other Unix systems: no capped read is available, so the value is read
/// whole and cut.
#[cfg(all(unix, not(any(target_os = "android", target_os = "linux", target_os = "macos"))))]
fn read_capped(path: &std::path::Path, name: &str) -> Option<Result<Vec<u8>, usize>> {
    xattr::get_deref(path, name).ok().flatten().map(Ok)
}

/// Fill `security.xattrs["Zone.Identifier"]` from the NTFS alternate data stream.
#[cfg(windows)]
pub(crate) fn fill(report: &mut Report, path: &std::path::Path) {
    let mut ads = path.as_os_str().to_owned();
    ads.push(":Zone.Identifier");
    let mut bytes = Vec::new();
    let Ok(file) = std::fs::File::open(std::path::Path::new(&ads)) else { return };
    if std::io::Read::read_to_end(&mut std::io::Read::take(file, MAX_VALUE as u64), &mut bytes).is_err() {
        return;
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut zone = Map::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim();
            let value = match k.trim() {
                "ZoneId" => v.parse::<u64>().map_or_else(|_| json!(v), |n| json!(n)),
                _ => json!(v),
            };
            zone.insert(k.trim().to_string(), value);
        }
    }
    if let Some(name) = zone.get("ZoneId").and_then(Value::as_u64).and_then(zone_name) {
        zone.insert("zone".into(), json!(name));
    }
    report.security.xattrs.insert("Zone.Identifier".into(), Value::Object(zone));
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn fill(_: &mut Report, _: &std::path::Path) {}

/// Names of the URL security zones in `ZoneId`.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn zone_name(id: u64) -> Option<&'static str> {
    Some(match id {
        0 => "local_machine",
        1 => "intranet",
        2 => "trusted",
        3 => "internet",
        4 => "restricted",
        _ => return None,
    })
}

/// Decode one attribute value into JSON.
pub(crate) fn decode(name: &str, value: &[u8]) -> Value {
    let value = &value[..value.len().min(MAX_VALUE)];
    if name == "com.apple.quarantine"
        && let Some(q) = quarantine(value)
    {
        return q;
    }
    if name == "com.apple.lastuseddate#PS" && value.len() >= 8 {
        let secs = i64::from_le_bytes(value[..8].try_into().unwrap_or_default());
        if let Ok(ts) = jiff::Timestamp::from_second(secs) {
            return json!(ts.to_string());
        }
    }
    if value.starts_with(b"bplist00") {
        if let Ok(v) = plist::Value::from_reader(std::io::Cursor::new(value)) {
            let mut j = plist_to_json(&v, 0);
            if name == "com.apple.metadata:_kMDItemUserTags" {
                // Finder tags are `name\ncolour-index`.
                if let Value::Array(tags) = &mut j {
                    for t in tags.iter_mut() {
                        if let Some(s) = t.as_str() {
                            *t = json!(s.split('\n').next().unwrap_or(s));
                        }
                    }
                }
            }
            return j;
        }
        return json!({ "binary_bytes": value.len() });
    }
    match std::str::from_utf8(value.strip_suffix(&[0]).unwrap_or(value)) {
        Ok(s) if s.chars().all(|c| !c.is_control() || c == '\t' || c == '\n') => {
            json!(crate::text::truncate_chars(s, 512))
        }
        _ => json!({ "binary_bytes": value.len() }),
    }
}

/// `0083;66e5a1b2;Safari;F643CD5F-…` → flags, time, agent, event id.
fn quarantine(value: &[u8]) -> Option<Value> {
    let s = std::str::from_utf8(value).ok()?;
    let mut parts = s.trim_end_matches('\0').split(';');
    let flags = parts.next()?;
    let mut m = Map::new();
    m.insert("flags".into(), json!(flags));
    if let Some(t) = parts.next().and_then(|t| i64::from_str_radix(t, 16).ok())
        && let Ok(ts) = jiff::Timestamp::from_second(t)
    {
        m.insert("time".into(), json!(ts.to_string()));
    }
    if let Some(agent) = parts.next().filter(|a| !a.is_empty()) {
        m.insert("agent".into(), json!(agent));
    }
    if let Some(id) = parts.next().filter(|a| !a.is_empty()) {
        m.insert("event_id".into(), json!(id));
    }
    Some(Value::Object(m))
}

fn plist_to_json(v: &plist::Value, depth: usize) -> Value {
    if depth > 8 {
        return json!("…");
    }
    match v {
        plist::Value::Array(a) => Value::Array(a.iter().take(64).map(|x| plist_to_json(x, depth + 1)).collect()),
        plist::Value::Dictionary(d) => {
            Value::Object(d.iter().take(64).map(|(k, x)| (k.clone(), plist_to_json(x, depth + 1))).collect())
        }
        plist::Value::Boolean(b) => json!(b),
        plist::Value::Data(d) => json!({ "binary_bytes": d.len() }),
        plist::Value::Date(d) => {
            crate::engine::universal::rfc3339(std::time::SystemTime::from(*d)).map_or(Value::Null, Value::String)
        }
        plist::Value::Real(r) => json!(r),
        plist::Value::Integer(i) => i.as_signed().map_or_else(|| json!(i.as_unsigned()), |n| json!(n)),
        plist::Value::String(s) => json!(crate::text::truncate_chars(s, 512)),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_attributes() {
        let q = decode("com.apple.quarantine", b"0083;66e5a1b2;Safari;F643CD5F-0000");
        assert_eq!(q["agent"], "Safari");
        assert_eq!(q["time"], "2024-09-14T14:46:10Z");
        let mut buf = Vec::new();
        plist::Value::Array(vec![plist::Value::String("https://example.org/a.zip".into())])
            .to_writer_binary(&mut buf)
            .unwrap();
        assert_eq!(decode("com.apple.metadata:kMDItemWhereFroms", &buf), json!(["https://example.org/a.zip"]));
        let mut tags = Vec::new();
        plist::Value::Array(vec![plist::Value::String("Red\n6".into())]).to_writer_binary(&mut tags).unwrap();
        assert_eq!(decode("com.apple.metadata:_kMDItemUserTags", &tags), json!(["Red"]));
        assert_eq!(decode("user.xdg.origin.url", b"https://example.org/"), json!("https://example.org/"));
        assert_eq!(decode("x", &[0, 1, 2, 3]), json!({ "binary_bytes": 4 }));
        assert_eq!(zone_name(3), Some("internet"));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn reads_attributes_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        std::fs::write(&p, "x").unwrap();
        // Some filesystems (tmpfs without user_xattr) refuse; nothing to test then.
        if xattr::set(&p, "user.xdg.origin.url", b"https://example.org/f.txt").is_err() {
            return;
        }
        let mut r = Report::default();
        fill(&mut r, &p);
        assert_eq!(r.security.xattrs["user.xdg.origin.url"], "https://example.org/f.txt");

        // A value past the cap is measured, not read.
        if xattr::set(&p, "user.big", &vec![b'a'; MAX_VALUE + 1]).is_ok() {
            let mut r = Report::default();
            fill(&mut r, &p);
            assert_eq!(r.security.xattrs["user.big"], json!({ "bytes": MAX_VALUE + 1, "skipped": "too_large" }));
        }
    }
}
