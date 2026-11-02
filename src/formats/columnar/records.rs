//! TFRecord files: the record count and sizes (walking the length headers
//! through the source; header checksums verified), and the features of the
//! first records when they hold `tf.train.Example` or `SequenceExample`
//! messages (names and kinds: bytes, float, int64).
//!
//! Specification: TensorFlow "TFRecord format" (masked CRC-32C) and
//! `tensorflow/core/example/example.proto`, `feature.proto`.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::plugin::protowire::{self, Wire};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for TFRecord files.
pub struct Records;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.records",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "tfrecord",
        name: "TFRecord / RecordIO",
        family: "columnar",
        mimes: &[],
        extensions: &["tfrecord", "tfrecords", "tfrec"],
        magic: &[],
        parent: None,
    }],
};

/// Records walked.
const MAX_RECORDS: u64 = 10_000_000;
/// Records decoded as examples.
const SAMPLE: usize = 20;
/// Bytes of one sampled record.
const MAX_SAMPLE: usize = 1 << 20;

/// CRC-32C (Castagnoli), bitwise.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0x82F6_3B78 } else { crc >> 1 };
        }
    }
    !crc
}

/// The masked CRC TFRecord stores.
fn masked(data: &[u8]) -> u32 {
    let c = crc32c(data);
    c.rotate_right(15).wrapping_add(0xa282_ead8)
}

/// A record header at the start of `h`: its length, if the checksum holds.
fn header(h: &[u8]) -> Option<u64> {
    let len = h.get(..8)?;
    let crc = u32::from_le_bytes(h.get(8..12)?.try_into().ok()?);
    (masked(len) == crc).then(|| u64::from_le_bytes(len.try_into().unwrap_or_default()))
}

/// The features of a `Features` message: name → kind.
fn features(f: &[u8], out: &mut BTreeMap<String, &'static str>) {
    for entry in protowire::all(f, 1).filter_map(Wire::bytes) {
        let Some(name) = protowire::first(entry, 1).and_then(Wire::text) else { continue };
        let kind = protowire::first(entry, 2).and_then(Wire::bytes).and_then(|v| protowire::fields(v).next()).map_or(
            "empty",
            |(n, _)| match n {
                1 => "bytes",
                2 => "float",
                3 => "int64",
                _ => "other",
            },
        );
        if out.len() < 500 {
            out.insert(truncate_chars(&name, 200), kind);
        }
    }
}

impl Extractor for Records {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let len = header(probe.head)?;
        // The first record must fit the file.
        (len.saturating_add(16) <= probe.len).then_some(Sniff { format: "tfrecord", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let total = src.len();
        let mut at = 0u64;
        let (mut records, mut bytes, mut largest) = (0u64, 0u64, 0u64);
        let mut feats = BTreeMap::new();
        let mut kind = None;
        while at.checked_add(12).is_some_and(|e| e <= total) && records < MAX_RECORDS {
            if records % 4096 == 0 {
                cx.checkpoint()?;
            }
            let h = src.read_vec(at, 12).map_err(|_| ExtractError::malformed("record header"))?;
            let Some(len) = header(&h) else {
                cx.warn(format!("bad record header at offset {at}"));
                break;
            };
            let Some(end) = at.checked_add(16).and_then(|e| e.checked_add(len)).filter(|&e| e <= total) else {
                cx.warn("last record truncated");
                break;
            };
            if usize::try_from(records).is_ok_and(|r| r < SAMPLE)
                && let Ok(n) = usize::try_from(len)
                && n <= MAX_SAMPLE
                && let Ok(data) = src.read_vec(at + 12, n)
            {
                // Example {1: Features}; SequenceExample {1: context, 2: feature_lists}.
                if let Some(Wire::Bytes(f)) = protowire::first(&data, 1) {
                    features(f, &mut feats);
                    kind.get_or_insert(if protowire::first(&data, 2).is_some() {
                        "SequenceExample"
                    } else {
                        "Example"
                    });
                }
            }
            records += 1;
            bytes = bytes.saturating_add(len);
            largest = largest.max(len);
            at = end;
        }
        cx.format_set("records", records);
        cx.format_set("record_bytes", bytes);
        cx.format_set("largest_record", largest);
        if let Some(k) = kind.filter(|_| !feats.is_empty()) {
            cx.format_set("message", k);
            let m: Map<String, Value> = feats.into_iter().map(|(k, v)| (k, Value::from(v))).collect();
            cx.format_set("features", Value::Object(m));
        }
        if at < total && records >= MAX_RECORDS {
            cx.warn("record limit reached");
        }
        Ok(())
    }
}

crate::register_extractor!(Records);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_check_value() {
        // The standard check value of CRC-32C.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        let len = 5u64.to_le_bytes();
        let mut h = len.to_vec();
        h.extend(masked(&len).to_le_bytes());
        assert_eq!(header(&h), Some(5));
        h[8] ^= 1;
        assert_eq!(header(&h), None);
    }

    crate::fixture_tests!("tfrecord");
}
