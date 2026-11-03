//! Core ML models (`.mlmodel`): specification version, the model type,
//! inputs and outputs with their feature types, the metadata (short
//! description, version, author, licence, user-defined keys), whether it
//! is updatable, and for neural networks the layers and their kinds.
//!
//! Specification: Apple coremltools `mlmodel/format/Model.proto`,
//! `FeatureTypes.proto`, `NeuralNetwork.proto`.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::histogram;
use crate::plugin::protowire::{self, Wire};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, redact_sensitive,
    truncate_chars,
};

/// Extractor for Core ML models.
pub struct CoreMl;

static META: ExtractorMeta = ExtractorMeta {
    id: "columnar.coreml",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "mlmodel",
        name: "Core ML model",
        family: "columnar",
        mimes: &[],
        extensions: &["mlmodel"],
        magic: &[],
        parent: None,
    }],
};

/// Inputs, outputs and layers listed.
const MAX_LIST: usize = 100;

/// The model type, from its oneof field number in `Model`.
fn model_type(n: u32) -> Option<&'static str> {
    Some(match n {
        200 => "pipeline_classifier",
        201 => "pipeline_regressor",
        202 => "pipeline",
        300 => "glm_regressor",
        301 => "support_vector_regressor",
        302 => "tree_ensemble_regressor",
        303 => "neural_network_regressor",
        304 => "bayesian_probit_regressor",
        400 => "glm_classifier",
        401 => "support_vector_classifier",
        402 => "tree_ensemble_classifier",
        403 => "neural_network_classifier",
        404 => "k_nearest_neighbors_classifier",
        500 => "neural_network",
        501 => "item_similarity_recommender",
        502 => "ml_program",
        555 => "custom_model",
        556 => "linked_model",
        560 => "class_confidence_thresholding",
        600 => "one_hot_encoder",
        601 => "imputer",
        602 => "feature_vectorizer",
        603 => "dict_vectorizer",
        604 => "scaler",
        606 => "categorical_mapping",
        607 => "normalizer",
        609 => "array_feature_extractor",
        610 => "non_maximum_suppression",
        900 => "identity",
        2000 => "text_classifier",
        2001 => "word_tagger",
        2002 => "vision_feature_print",
        2003 => "sound_analysis_preprocessing",
        2004 => "gazetteer",
        2005 => "word_embedding",
        2006 => "audio_feature_print",
        3000 => "serialized_model",
        _ => return None,
    })
}

/// A neural network layer kind, from its oneof field number.
fn layer_kind(n: u32) -> String {
    let s = match n {
        100 => "convolution",
        120 => "pooling",
        130 => "activation",
        140 => "inner_product",
        150 => "embedding",
        160 => "batchnorm",
        165 => "mvn",
        170 => "l2_normalize",
        175 => "softmax",
        180 => "lrn",
        190 => "crop",
        200 => "padding",
        210 => "upsample",
        211 => "resize_bilinear",
        212 => "crop_resize",
        220 => "unary",
        230 => "add",
        231 => "multiply",
        240 => "average",
        245 => "scale",
        250 => "bias",
        260 => "max",
        261 => "min",
        270 => "dot",
        280 => "reduce",
        290 => "load_constant",
        300 => "reshape",
        301 => "flatten",
        310 => "permute",
        320 => "concat",
        330 => "split",
        340 => "sequence_repeat",
        345 => "reorganize_data",
        350 => "slice",
        400 => "simple_recurrent",
        410 => "gru",
        420 => "uni_directional_lstm",
        430 => "bi_directional_lstm",
        500 => "custom",
        _ => return format!("layer {n}"),
    };
    s.to_string()
}

fn array_type(t: u64) -> &'static str {
    match t {
        65_552 => "float16",
        65_568 => "float32",
        65_600 => "float64",
        131_104 => "int32",
        131_080 => "int8",
        _ => "?",
    }
}

/// A `FeatureType` as text.
fn feature_type(t: &[u8]) -> String {
    let optional = protowire::first(t, 1000).and_then(Wire::int) == Some(1);
    let base = match protowire::fields(t).find(|(n, _)| *n != 1000) {
        Some((1, _)) => "int64".to_string(),
        Some((2, _)) => "double".to_string(),
        Some((3, _)) => "string".to_string(),
        Some((4, Wire::Bytes(img))) => {
            let w = protowire::first(img, 1).and_then(Wire::int).unwrap_or(0);
            let h = protowire::first(img, 2).and_then(Wire::int).unwrap_or(0);
            format!("image[{w}x{h}]")
        }
        Some((5, Wire::Bytes(a))) => {
            let dims: Vec<String> =
                protowire::all(a, 1).flat_map(protowire::packed).map(|d| d.to_string()).take(16).collect();
            let dt = protowire::first(a, 2).and_then(Wire::int).map_or("?", array_type);
            format!("multiarray<{dt}>[{}]", dims.join(", "))
        }
        Some((6, _)) => "dictionary".to_string(),
        Some((7, _)) => "sequence".to_string(),
        Some((8, _)) => "state".to_string(),
        _ => "?".to_string(),
    };
    if optional { format!("{base}?") } else { base }
}

fn features(d: &[u8], n: u32) -> Value {
    Value::Object(
        protowire::all(d, n)
            .filter_map(Wire::bytes)
            .take(MAX_LIST)
            .filter_map(|f| {
                let name = protowire::first(f, 1).and_then(Wire::text)?;
                let t = protowire::first(f, 3).and_then(Wire::bytes).map_or_else(|| "?".into(), feature_type);
                Some((truncate_chars(&name, 200), Value::String(t)))
            })
            .collect(),
    )
}

impl Extractor for CoreMl {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Model starts with specificationVersion (field 1, varint).
        let ok = probe.extension == Some("mlmodel") && probe.head.first() == Some(&0x08);
        ok.then_some(Sniff { format: "mlmodel", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, _) = cx.read_bytes(src)?;
        let spec = protowire::first(&b, 1)
            .and_then(Wire::int)
            .ok_or_else(|| ExtractError::malformed("specification version"))?;
        cx.format_set("specification_version", spec);
        if protowire::first(&b, 10).and_then(Wire::int) == Some(1) {
            cx.format_set("updatable", true);
        }
        let kind = protowire::fields(&b).find_map(|(n, v)| model_type(n).map(|k| (n, k, v)));
        if let Some((_, k, _)) = kind {
            cx.format_set("model_type", k);
        }
        if let Some(d) = protowire::first(&b, 2).and_then(Wire::bytes) {
            cx.format_set("inputs", features(d, 1));
            cx.format_set("outputs", features(d, 10));
            if let Some(p) = protowire::first(d, 11).and_then(Wire::text) {
                cx.format_set("predicted_feature", truncate_chars(&p, 200));
            }
            if let Some(m) = protowire::first(d, 100).and_then(Wire::bytes) {
                let text = |n| protowire::first(m, n).and_then(Wire::text).filter(|s| !s.is_empty());
                if let Some(s) = text(1) {
                    cx.format_set("short_description", truncate_chars(&s, 1000));
                    cx.content().source("coreml.shortDescription").description(truncate_chars(&s, 1000));
                }
                if let Some(s) = text(2) {
                    cx.format_set("model_version", truncate_chars(&s, 100));
                }
                if let Some(s) = text(3) {
                    cx.format_set("author", truncate_chars(&s, 200));
                    cx.content().source("coreml.author").author(truncate_chars(&s, 200));
                }
                if let Some(s) = text(4) {
                    cx.format_set("license", truncate_chars(&s, 500));
                    cx.rights().source("coreml.license").license(Some(&truncate_chars(&s, 200)), None);
                }
                let user: Map<String, Value> = protowire::all(m, 100)
                    .filter_map(Wire::bytes)
                    .take(100)
                    .filter_map(|kv| {
                        let k = protowire::first(kv, 1).and_then(Wire::text)?;
                        let v = protowire::first(kv, 2).and_then(Wire::text).unwrap_or_default();
                        Some((truncate_chars(&k, 100), Value::String(truncate_chars(&redact_sensitive(&v), 300))))
                    })
                    .collect();
                if !user.is_empty() {
                    cx.format_set("user_metadata", Value::Object(user));
                }
            }
        }
        // Neural networks (plain, classifier, regressor): layers and their kinds.
        if let Some((n, _, Wire::Bytes(net))) = kind
            && matches!(n, 303 | 403 | 500)
        {
            let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
            let mut layers = 0u64;
            for l in protowire::all(net, 1).filter_map(Wire::bytes) {
                layers += 1;
                if let Some((k, _)) = protowire::fields(l).find(|(k, _)| *k >= 100) {
                    *kinds.entry(layer_kind(k)).or_default() += 1;
                }
            }
            cx.format_set("layers", layers);
            cx.format_set("layer_kinds", histogram(kinds, 50));
        }
        Ok(())
    }
}

crate::register_extractor!(CoreMl);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_types() {
        // multiArrayType {shape: [4] (packed), dataType: FLOAT32}
        let t = [0x2a, 7, 0x0a, 1, 4, 0x10, 0xa0, 0x80, 0x04];
        assert_eq!(feature_type(&t), "multiarray<float32>[4]");
        assert_eq!(model_type(500), Some("neural_network"));
        assert_eq!(layer_kind(140), "inner_product");
    }

    crate::fixture_tests!("mlmodel");
}
