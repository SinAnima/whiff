//! ASDF files (Advanced Scientific Data Format): the file format and
//! standard versions, the YAML tree's top-level keys and tags (ndarrays
//! with their shapes and types), the library that wrote it, and the binary
//! blocks (count, compression, sizes) and block index.
//!
//! Specification: ASDF Standard 1.6.0 ("File layout", "Blocks", "Block
//! index", core schemas `asdf`, `ndarray`, `software`).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, redact_sensitive, truncate_chars,
};

/// Extractor for ASDF files.
pub struct Asdf;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.asdf",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "asdf",
        name: "ASDF (Advanced Scientific Data Format)",
        family: "sci",
        mimes: &["application/asdf"],
        extensions: &["asdf"],
        magic: &[Magic::at(0, b"#ASDF ")],
        parent: None,
    }],
};

/// The block magic.
const BLOCK: &[u8; 4] = b"\xd3BLK";
/// Blocks walked.
const MAX_BLOCKS: usize = 100_000;

/// The YAML tree: keys, tags, ndarrays, software.
fn tree(cx: &mut Context<'_>, yaml: &str) {
    let mut keys = Vec::new();
    let mut tags: BTreeMap<String, u64> = BTreeMap::new();
    let mut arrays: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut lib: Map<String, Value> = Map::new();
    let mut in_lib = false;
    let mut current: Option<String> = None;
    let mut current_key = String::new();
    // Flow mappings may wrap: join a line with the next ones until its braces close.
    let mut logical: Vec<String> = Vec::new();
    let mut open = 0i64;
    for line in yaml.lines().take(500_000) {
        let count = |c: char| i64::try_from(line.matches(c).count()).unwrap_or(0);
        let delta = count('{') - count('}');
        match logical.last_mut() {
            Some(last) if open > 0 => {
                last.push(' ');
                last.push_str(line.trim());
            }
            _ => logical.push(line.to_string()),
        }
        open = (open + delta).max(0);
    }
    for line in &logical {
        let line = line.as_str();
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        if indent == 0
            && !t.starts_with("---")
            && !t.starts_with("...")
            && !t.starts_with('%')
            && let Some((k, _)) = t.split_once(':')
        {
            {
                current_key = k.trim().to_string();
                current = None;
                if keys.len() < 200 {
                    keys.push(truncate_chars(&current_key, 100));
                }
                in_lib = current_key == "asdf_library";
                // A flow mapping on the key's line: `{author: …, name: asdf, version: 6.0.0}`.
                if in_lib && let Some(body) = t.split_once('{').and_then(|(_, r)| r.rsplit_once('}')).map(|(b, _)| b) {
                    for pair in body.split(", ") {
                        if let Some((k, v)) = pair.split_once(':') {
                            let v = v.trim().trim_matches(['\'', '"']);
                            if matches!(k.trim(), "name" | "version" | "author" | "homepage") && !v.is_empty() {
                                lib.insert(k.trim().into(), Value::String(truncate_chars(&redact_sensitive(v), 200)));
                            }
                        }
                    }
                    in_lib = false;
                }
            }
        }
        // Tags: `!core/ndarray-1.0.0`, `!<tag:stsci.edu:asdf/core/asdf-1.1.0>`.
        let mut rest = t;
        while let Some(i) = rest.find('!') {
            let tag: String =
                rest[i + 1..].chars().take_while(|c| !c.is_whitespace() && *c != ',' && *c != '}').collect();
            let tag = tag.trim_start_matches('<').trim_end_matches('>').to_string();
            if !tag.is_empty() {
                if tag.contains("ndarray") {
                    current = Some(current_key.clone());
                }
                *tags.entry(truncate_chars(&tag, 100)).or_default() += 1;
            }
            rest = &rest[i + 1..];
        }
        if in_lib
            && indent > 0
            && let Some((k, v)) = t.split_once(':')
        {
            let v = v.trim().trim_matches(['\'', '"']);
            if matches!(k.trim(), "name" | "version" | "author" | "homepage") && !v.is_empty() {
                lib.insert(k.trim().into(), Value::String(truncate_chars(&redact_sensitive(v), 200)));
            }
        }
        if let Some(name) = &current {
            let e = arrays.entry(name.clone()).or_insert_with(|| (String::new(), String::new()));
            if let Some(shape) = t.strip_prefix("shape:") {
                e.0 = shape.trim().to_string();
            } else if let Some(dt) = t.strip_prefix("datatype:") {
                e.1 = dt.trim().to_string();
            }
        }
    }
    let arrays: Vec<String> =
        arrays.into_iter().map(|(n, (s, d))| format!("{n}: {d} {s}").trim().to_string()).collect();
    cx.format_set("tree_keys", keys);
    if !tags.is_empty() {
        let m: Map<String, Value> = tags.into_iter().map(|(k, v)| (k, v.into())).collect();
        cx.format_set("tags", Value::Object(m));
    }
    if !arrays.is_empty() {
        cx.format_set("ndarrays", arrays.into_iter().take(100).map(|a| truncate_chars(&a, 200)).collect::<Vec<_>>());
    }
    if !lib.is_empty() {
        cx.format_set("asdf_library", Value::Object(lib));
    }
}

impl Extractor for Asdf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let n = usize::try_from(len).unwrap_or(usize::MAX).min(cx.parse_limit());
        let b = src.read_vec(0, n).map_err(|_| ExtractError::malformed("header"))?;
        // The tree ends at the first block (or the end of the file).
        let tree_end = b.windows(4).position(|w| w == BLOCK).unwrap_or(b.len());
        let text = String::from_utf8_lossy(&b[..tree_end]);
        for line in text.lines().take(5) {
            if let Some(v) = line.strip_prefix("#ASDF_STANDARD ") {
                cx.format_set("standard_version", truncate_chars(v.trim(), 20));
            } else if let Some(v) = line.strip_prefix("#ASDF ") {
                cx.format_set("file_format_version", truncate_chars(v.trim(), 20));
            } else if let Some(v) = line.strip_prefix("%YAML ") {
                cx.format_set("yaml_version", truncate_chars(v.trim(), 10));
            }
        }
        tree(cx, &text);
        // Blocks: magic, header size (u16 BE), flags, compression, sizes, checksum.
        let mut at = tree_end as u64;
        let (mut blocks, mut used, mut data) = (0u64, 0u64, 0u64);
        let mut codecs = std::collections::BTreeSet::new();
        while at.checked_add(6).is_some_and(|end| end <= len) && usize::try_from(blocks).is_ok_and(|n| n < MAX_BLOCKS) {
            let h = src
                .read_vec(at, 54.min(usize::try_from(len - at).unwrap_or(54)))
                .map_err(|_| ExtractError::malformed("block"))?;
            if h.get(..4) != Some(BLOCK) {
                break;
            }
            let hsize = u64::from(u16::from_be_bytes([h[4], h[5]]));
            let get = |i: usize| h.get(i..i + 8).map_or(0, |s| u64::from_be_bytes(s.try_into().unwrap_or_default()));
            let comp = h
                .get(10..14)
                .map(|c| String::from_utf8_lossy(c).trim_end_matches('\0').to_string())
                .unwrap_or_default();
            codecs.insert(if comp.is_empty() { "none".to_string() } else { comp });
            let allocated = get(14);
            used = used.saturating_add(get(22));
            data = data.saturating_add(get(30));
            blocks += 1;
            // A block that claims more than the file holds ends the walk.
            match at.checked_add(6 + hsize).and_then(|e| e.checked_add(allocated)) {
                Some(next) if next > at => at = next,
                _ => break,
            }
        }
        cx.format_set("blocks", blocks);
        if blocks > 0 {
            cx.format_set("block_compression", codecs.into_iter().collect::<Vec<_>>());
            cx.format_set("stored_bytes", used);
            cx.format_set("data_bytes", data);
        }
        let tail =
            src.read_vec(at, usize::try_from(len.saturating_sub(at)).unwrap_or(0).min(1 << 20)).unwrap_or_default();
        if tail.starts_with(b"#ASDF BLOCK INDEX") {
            cx.format_set("block_index", true);
        }
        Ok(())
    }
}

crate::register_extractor!(Asdf);

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    #[test]
    fn huge_block_size() {
        // Found by the fuzzer: an allocated size near u64::MAX overflowed the walk.
        let mut b = b"#ASDF 1.0.0\n%YAML 1.1\n--- !core/asdf-1.1.0\n...\n".to_vec();
        b.extend(b"\xd3BLK\x00\x30");
        b.extend([0u8; 8]);
        b.extend(u64::MAX.to_be_bytes());
        b.extend([0u8; 40]);
        let r = report_for("x.asdf", &b);
        assert_eq!(r.format["asdf"]["blocks"], 1);
    }

    crate::fixture_tests!("asdf");
}
