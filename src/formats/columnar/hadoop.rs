//! Hadoop container files:
//! * SequenceFile (versions 1–6): the key and value classes, record or
//!   block compression and the codec, the file metadata, and from walking
//!   the records (through the source, bounded) the record, block and sync
//!   marker counts;
//! * Hive RCFile (`RCF` and the older SequenceFile-based form): the column
//!   count, codec and metadata, the row groups and the rows they hold.
//!
//! Record contents are not read: only the lengths that frame them.
//!
//! Specifications: Hadoop `org.apache.hadoop.io.SequenceFile` (writer and
//! reader, `WritableUtils` variable-length integers); Hive
//! `org.apache.hadoop.hive.ql.io.RCFile`.

use serde_json::{Map, Value, json};

use crate::plugin::{
    Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars,
};

/// Extractor for SequenceFile and RCFile.
pub struct Hadoop;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.hadoop",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "sequencefile",
            name: "Hadoop SequenceFile",
            family: "columnar",
            mimes: &["application/x-hadoop-sequencefile"],
            extensions: &["seq"],
            magic: &[
                Magic::prefix(b"SEQ\x04"),
                Magic::prefix(b"SEQ\x05"),
                Magic::prefix(b"SEQ\x06"),
            ],
            parent: None,
        },
        FormatSpec {
            id: "rcfile",
            name: "Hive RCFile",
            family: "columnar",
            mimes: &[],
            // `.rc` is also a Windows resource script.
            extensions: &[],
            // `RCF` or a SequenceFile header naming RCFile's key class: the sniffer.
            magic: &[],
            parent: None,
        },
    ],
};

/// The key class of RCFiles written in the SequenceFile form.
const RC_KEY: &[u8] = b"org.apache.hadoop.hive.ql.io.RCFile$KeyBuffer";
/// Records walked.
const MAX_RECORDS: u64 = 10_000_000;
/// Largest compressed RCFile key inflated to read its row count.
const MAX_KEY: usize = 1 << 20;

/// A cursor over Hadoop's big-endian `DataOutput` encodings.
struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.i..self.i.checked_add(n)?)?;
        self.i += n;
        Some(s)
    }

    fn int(&mut self) -> Option<i32> {
        Some(i32::from_be_bytes(self.bytes(4)?.try_into().ok()?))
    }

    /// `WritableUtils.readVLong`.
    fn vlong(&mut self) -> Option<i64> {
        let first = self.u8()?.cast_signed();
        if first >= -112 {
            return Some(i64::from(first));
        }
        let (negative, len) = if first < -120 { (true, -120 - i32::from(first)) } else { (false, -112 - i32::from(first)) };
        let mut v = 0i64;
        for _ in 0..len {
            v = v << 8 | i64::from(self.u8()?);
        }
        Some(if negative { !v } else { v })
    }

    /// `Text.readString`: a vint length, then UTF-8.
    fn text(&mut self) -> Option<String> {
        let n = usize::try_from(self.vlong()?).ok()?;
        Some(String::from_utf8_lossy(self.bytes(n)?).into_owned())
    }

    /// `UTF8.readString` (versions before 4): a 16-bit length.
    fn utf8(&mut self) -> Option<String> {
        let n = usize::from(u16::from_be_bytes(self.bytes(2)?.try_into().ok()?));
        Some(String::from_utf8_lossy(self.bytes(n)?).into_owned())
    }
}

impl Extractor for Hadoop {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"RCF\x01") {
            return Some(Sniff { format: "rcfile", confidence: 0.95 });
        }
        let rc = h.starts_with(b"SEQ\x06") && h.get(4..80).is_some_and(|w| w.windows(RC_KEY.len()).any(|x| x == RC_KEY));
        rc.then_some(Sniff { format: "rcfile", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, cut) = cx.read_bytes(src)?;
        let header = header(&b).ok_or_else(|| ExtractError::malformed("header cut short"))?;
        header.write(cx);
        if cut {
            cx.warn("only the start of the file was walked");
        }
        let walk = if header.rcfile { row_groups(&b, &header, cx) } else { records(&b, &header) };
        let f = cx.format();
        for (k, v) in walk {
            f.insert(k, v);
        }
        Ok(())
    }
}

crate::register_extractor!(Hadoop);

struct Header {
    rcfile: bool,
    version: u8,
    key_class: Option<String>,
    value_class: Option<String>,
    compressed: bool,
    block: bool,
    codec: Option<String>,
    metadata: Vec<(String, String)>,
    sync: [u8; 16],
    /// Where the records start.
    end: usize,
}

#[allow(clippy::many_single_char_names)] // bytes `b`, cursor `c`, header `h`, key / value `k` / `v`
fn header(b: &[u8]) -> Option<Header> {
    let mut c = Cur { b, i: 3 };
    let rcfile_magic = b.starts_with(b"RCF");
    let version = c.u8()?;
    let mut h = Header {
        rcfile: rcfile_magic,
        version,
        key_class: None,
        value_class: None,
        compressed: false,
        block: false,
        codec: None,
        metadata: Vec::new(),
        sync: [0; 16],
        end: 0,
    };
    if !rcfile_magic {
        let (k, v) = if version < 4 { (c.utf8()?, c.utf8()?) } else { (c.text()?, c.text()?) };
        h.rcfile = k.as_bytes() == RC_KEY;
        h.key_class = Some(k);
        h.value_class = Some(v);
    }
    if rcfile_magic || version > 2 {
        h.compressed = c.u8()? != 0;
    }
    if !rcfile_magic && version >= 4 {
        h.block = c.u8()? != 0;
    }
    if h.compressed && (rcfile_magic || version >= 5) {
        h.codec = Some(c.text()?);
    }
    if rcfile_magic || version >= 6 {
        let n = c.int()?;
        for _ in 0..n.clamp(0, 10_000) {
            let k = c.text()?;
            let v = c.text()?;
            h.metadata.push((k, v));
        }
    }
    if rcfile_magic || version > 1 {
        h.sync = c.bytes(16)?.try_into().ok()?;
    }
    h.end = c.i;
    Some(h)
}

impl Header {
    fn write(&self, cx: &mut Context<'_>) {
        cx.format_set("version", self.version);
        if let Some(k) = &self.key_class
            && !self.rcfile
        {
            cx.format_set("key_class", truncate_chars(k, 200));
        }
        if let Some(v) = &self.value_class
            && !self.rcfile
        {
            cx.format_set("value_class", truncate_chars(v, 200));
        }
        let compression = match (self.compressed, self.block) {
            (false, _) => "none",
            (true, false) => "record",
            (true, true) => "block",
        };
        cx.format_set("compression", if self.rcfile && self.compressed { "column" } else { compression });
        if let Some(c) = &self.codec {
            cx.format_set("codec", truncate_chars(c, 200));
        }
        if self.rcfile
            && let Some((_, n)) = self.metadata.iter().find(|(k, _)| k == "hive.io.rcfile.column.number")
            && let Ok(n) = n.parse::<u64>()
        {
            cx.format_set("columns", n);
        }
        if !self.metadata.is_empty() {
            let m: Map<String, Value> = self
                .metadata
                .iter()
                .take(50)
                .map(|(k, v)| (truncate_chars(k, 200), Value::String(truncate_chars(v, 200))))
                .collect();
            cx.format_set("metadata", Value::Object(m));
        }
    }
}

/// SequenceFile records: `int length, int key length, key, value`, with
/// `-1` and the sync marker between them; block-compressed files hold a
/// sync marker, then `vint records` and four length-prefixed buffers.
fn records(b: &[u8], h: &Header) -> Map<String, Value> {
    let mut c = Cur { b, i: h.end };
    let (mut records, mut blocks, mut syncs, mut key_bytes, mut value_bytes) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut broken = false;
    while c.i < b.len() && records < MAX_RECORDS {
        let Some(len) = c.int() else {
            broken = true;
            break;
        };
        if len == -1 {
            if c.bytes(16) != Some(&h.sync[..]) {
                broken = true;
                break;
            }
            syncs += 1;
            if h.block {
                let Some(n) = c.vlong() else { break };
                let mut ok = true;
                for _ in 0..4 {
                    ok &= c.vlong().and_then(|l| usize::try_from(l).ok()).and_then(|l| c.bytes(l)).is_some();
                }
                if !ok {
                    broken = true;
                    break;
                }
                blocks += 1;
                records += u64::try_from(n).unwrap_or(0);
            }
            continue;
        }
        let (Ok(len), Some(Ok(key))) = (usize::try_from(len), c.int().map(usize::try_from)) else {
            broken = true;
            break;
        };
        if key > len || c.bytes(len).is_none() {
            broken = true;
            break;
        }
        records += 1;
        key_bytes += key as u64;
        value_bytes += (len - key) as u64;
    }
    let mut out = Map::new();
    out.insert("records".into(), json!(records));
    if h.block {
        out.insert("blocks".into(), json!(blocks));
    } else {
        out.insert("key_bytes".into(), json!(key_bytes));
        out.insert("value_bytes".into(), json!(value_bytes));
    }
    out.insert("sync_markers".into(), json!(syncs));
    if broken {
        out.insert("records_cut_short".into(), json!(true));
    }
    out
}

/// RCFile row groups: `int record length (key + value), int key length,
/// int stored key length, key, value`, the key starting with `vint rows`.
fn row_groups(b: &[u8], h: &Header, cx: &mut Context<'_>) -> Map<String, Value> {
    let mut c = Cur { b, i: h.end };
    let (mut groups, mut rows, mut syncs) = (0u64, 0u64, 0u64);
    let mut rows_known = true;
    let mut broken = false;
    let zlib = h.codec.as_deref().is_some_and(|c| c.ends_with(".DefaultCodec"));
    while c.i < b.len() && groups < MAX_RECORDS {
        let Some(len) = c.int() else {
            broken = true;
            break;
        };
        if len == -1 {
            if c.bytes(16) != Some(&h.sync[..]) {
                broken = true;
                break;
            }
            syncs += 1;
            continue;
        }
        let parts = (usize::try_from(len), c.int().map(usize::try_from), c.int().map(usize::try_from));
        // The record length counts the key uncompressed; the key is stored
        // in `stored` bytes, then the column values.
        let (Ok(len), Some(Ok(plain)), Some(Ok(stored))) = parts else {
            broken = true;
            break;
        };
        let (Some(value), Some(key)) = (len.checked_sub(plain), c.bytes(stored)) else {
            broken = true;
            break;
        };
        if c.bytes(value).is_none() {
            broken = true;
            break;
        }
        groups += 1;
        let first = if !h.compressed {
            Some(key.to_vec())
        } else if zlib {
            cx.inflate(key, Compression::Zlib, MAX_KEY).ok()
        } else {
            None
        };
        match first.and_then(|k| Cur { b: &k, i: 0 }.vlong()) {
            Some(n) => rows += u64::try_from(n).unwrap_or(0),
            None => rows_known = false,
        }
    }
    let mut out = Map::new();
    out.insert("row_groups".into(), json!(groups));
    if rows_known {
        out.insert("rows".into(), json!(rows));
    }
    out.insert("sync_markers".into(), json!(syncs));
    if broken {
        out.insert("records_cut_short".into(), json!(true));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("sequencefile", "rcfile");

    #[test]
    fn hadoop_vints() {
        let read = |b: &[u8]| Cur { b, i: 0 }.vlong();
        assert_eq!(read(&[0x05]), Some(5));
        assert_eq!(read(&[0x90]), Some(-112));
        // 300: -114 (0x8e, two bytes follow), then 0x01 0x2c.
        assert_eq!(read(&[0x8e, 0x01, 0x2c]), Some(300));
        // -300: -122 (0x86, negative, two bytes), then !(-300) = 299.
        assert_eq!(read(&[0x86, 0x01, 0x2b]), Some(-300));
        assert_eq!(read(&[0x8f]), None);
    }
}
