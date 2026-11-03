//! `columnar` extractors (feature `data`): columnar and table formats
//! (Parquet and GeoParquet, Arrow IPC and Feather, ORC, Lance, Vortex,
//! Delta Lake and Iceberg table metadata, TFRecord, R `fst` and `qs`) and
//! machine-learning artefacts (safetensors, GGUF / GGML, ONNX, PyTorch,
//! Keras, TensorFlow Lite and SavedModel, Core ML).
//!
//! Files are read from their footers or headers through the source, never
//! loaded whole: schemas, row counts, statistics and model structure, not
//! the data or the weights.

pub(crate) mod arrow;
pub(crate) mod ml;
pub(crate) mod orc;
pub(crate) mod parquet;
pub(crate) mod rdata;
pub(crate) mod records;
pub(crate) mod store;
pub(crate) mod table;
pub(crate) mod thrift;

use serde_json::Value;

// Helpers shared with the other groups.
pub(crate) use super::archive::unix_time;
pub(crate) use super::data::binser::pickle;

/// An epoch value in `unit` (`s`, `ms`, `us`, `ns`) as RFC 3339 UTC (whole
/// seconds; values before 1970 are not reported).
pub(crate) fn epoch_text(v: i64, unit: &str) -> Option<String> {
    let secs = match unit {
        "s" => v,
        "ms" => v.div_euclid(1_000),
        "us" => v.div_euclid(1_000_000),
        "ns" => v.div_euclid(1_000_000_000),
        _ => return None,
    };
    unix_time(secs)
}

/// A float as JSON (non-finite values have no JSON number).
pub(crate) fn number(v: f64) -> Value {
    serde_json::Number::from_f64(v).map_or_else(|| Value::String(v.to_string()), Value::Number)
}

/// Element counts multiplied (tensor shapes), saturating.
pub(crate) fn product(dims: &[u64]) -> u64 {
    dims.iter().fold(1u64, |a, &d| a.saturating_mul(d))
}

/// A count as a short human figure (`1.2M`), for parameter counts.
pub(crate) fn short_count(n: u64) -> String {
    #[allow(clippy::cast_precision_loss)] // a rounded figure for display
    let f = n as f64;
    match n {
        0..1_000 => n.to_string(),
        1_000..1_000_000 => format!("{:.1}K", f / 1e3),
        1_000_000..1_000_000_000 => format!("{:.1}M", f / 1e6),
        _ => format!("{:.1}B", f / 1e9),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(epoch_text(1_756_706_400_000, "ms").as_deref(), Some("2025-09-01T06:00:00Z"));
        assert_eq!(epoch_text(1, "parsec"), None);
        assert_eq!(number(f64::NAN), Value::String("NaN".into()));
        assert_eq!(product(&[2, 3, 4]), 24);
        assert_eq!(short_count(1_234_567), "1.2M");
    }
}
