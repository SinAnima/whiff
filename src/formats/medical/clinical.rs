//! Clinical messages:
//! * HL7 version 2 (pipe-delimited): the version, message type and event,
//!   sending and receiving application and facility, message time,
//!   control and processing IDs, and the segments; patient segments are
//!   counted, never shown;
//! * FHIR JSON resources and bundles: the resource type, bundle type,
//!   entries by resource type, profiles and the FHIR version where given;
//!   personal resources (Patient, Practitioner, RelatedPerson, Person) are
//!   counted, their content never shown.
//!
//! Specifications: HL7 Version 2.5.1 chapter 2 (message structure, MSH);
//! HL7 FHIR R5 (resources, Bundle).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars,
};

/// Extractor for HL7 v2 and FHIR.
pub struct Clinical;

static META: ExtractorMeta = ExtractorMeta {
    id: "medical.clinical",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "hl7",
            name: "HL7 v2 message",
            family: "medical",
            mimes: &["x-application/hl7-v2+er7"],
            extensions: &["hl7"],
            magic: &[Magic::at(0, b"MSH|")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "fhir",
            name: "FHIR resource",
            family: "medical",
            mimes: &["application/fhir+json"],
            extensions: &[],
            magic: &[],
            parent: Some("json"),
        },
    ],
};

/// Resources that describe people.
const PERSONAL: [&str; 4] = ["Patient", "Practitioner", "RelatedPerson", "Person"];

fn hl7(cx: &mut Context<'_>, text: &str) -> Option<()> {
    let msh = text.lines().flat_map(|l| l.split('\r')).find(|l| l.starts_with("MSH"))?;
    let sep = msh.chars().nth(3)?;
    let comp = msh.chars().nth(4).unwrap_or('^');
    // MSH-1 is the separator itself, so field n is at index n - 1.
    let f: Vec<&str> = msh.split(sep).collect();
    let field = |n: usize| f.get(n - 1).map(|s| s.replace(comp, " ").trim().to_string()).filter(|s| !s.is_empty());
    for (n, key) in [
        (3, "sending_application"),
        (4, "sending_facility"),
        (5, "receiving_application"),
        (6, "receiving_facility"),
        (10, "control_id"),
        (11, "processing_id"),
        (12, "version"),
    ] {
        if let Some(v) = field(n) {
            cx.format_set(key, truncate_chars(&v, 100));
        }
    }
    if let Some(t) = f.get(8) {
        cx.format_set("message_type", truncate_chars(&t.replace(comp, "^"), 30));
    }
    if let Some(iso) = field(7).as_deref().and_then(hl7_time) {
        cx.format_set("message_time", iso.clone());
        cx.temporal().source("hl7.MSH-7").content_date(DateField::Sent, iso, false);
    }
    segments(cx, text);
    Some(())
}

/// An HL7 `DTM` (`YYYYMMDD[HHMM[SS]]`) as ISO 8601; digits only, since
/// it is sliced by byte.
fn hl7_time(ts: &str) -> Option<String> {
    let t = ts.split_whitespace().next()?;
    let t = &t[..t.bytes().take_while(u8::is_ascii_digit).count()];
    if t.len() < 8 {
        return None;
    }
    let mut iso = format!("{}-{}-{}", &t[..4], &t[4..6], &t[6..8]);
    if t.len() >= 12 {
        let _ = write!(iso, "T{}:{}", &t[8..10], &t[10..12]);
        if t.len() >= 14 {
            let _ = write!(iso, ":{}", &t[12..14]);
        }
    }
    Some(iso)
}

/// Segment counts.
fn segments(cx: &mut Context<'_>, text: &str) {
    let mut segments: BTreeMap<String, u64> = BTreeMap::new();
    let mut messages = 0u64;
    for seg in text.split(['\r', '\n']).filter(|s| s.len() >= 3) {
        // Checked as bytes first: a segment may start mid-character.
        if let Some(id) = seg.get(..3).filter(|id| id.bytes().all(|c| c.is_ascii_alphanumeric())) {
            *segments.entry(id.to_string()).or_default() += 1;
            messages += u64::from(id == "MSH");
        }
    }
    cx.format_set("messages", messages);
    if segments.contains_key("PID") {
        cx.format_set("patient_segments", segments["PID"]);
    }
    cx.format_set("segments", Value::Object(segments.into_iter().map(|(k, v)| (k, v.into())).collect::<Map<_, _>>()));
}

fn fhir(cx: &mut Context<'_>, v: &Value) {
    let kind = v.get("resourceType").and_then(Value::as_str).unwrap_or("?");
    cx.format_set("resource_type", truncate_chars(kind, 60));
    if let Some(p) = v.pointer("/meta/profile").and_then(Value::as_array) {
        cx.format_set(
            "profiles",
            p.iter().filter_map(Value::as_str).take(20).map(|s| truncate_chars(s, 200)).collect::<Vec<_>>(),
        );
    }
    if let Some(fv) = v.get("fhirVersion").and_then(Value::as_str) {
        cx.format_set("fhir_version", truncate_chars(fv, 20));
    }
    if kind == "Bundle" {
        if let Some(t) = v.get("type").and_then(Value::as_str) {
            cx.format_set("bundle_type", truncate_chars(t, 30));
        }
        let entries = v.get("entry").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        cx.format_set("entries", entries.len());
        let mut types: BTreeMap<String, u64> = BTreeMap::new();
        for e in entries.iter().take(1_000_000) {
            let t = e.pointer("/resource/resourceType").and_then(Value::as_str).unwrap_or("?");
            *types.entry(truncate_chars(t, 60)).or_default() += 1;
        }
        let personal: u64 = PERSONAL.iter().filter_map(|p| types.get(*p)).sum();
        if personal > 0 {
            cx.format_set("personal_resources", personal);
        }
        cx.format_set(
            "resource_types",
            Value::Object(types.into_iter().map(|(k, v)| (k, v.into())).collect::<Map<_, _>>()),
        );
    } else if PERSONAL.contains(&kind) {
        cx.format_set("personal_resources", 1);
    } else if let Some(s) = v.get("status").and_then(Value::as_str) {
        cx.format_set("status", truncate_chars(s, 30));
    }
}

impl Extractor for Clinical {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let json = h.trim_ascii_start().starts_with(b"{");
        let fhir = json
            && h.windows(14).any(|w| w == b"\"resourceType\"")
            && (probe.name.is_some_and(|n| n.contains(".fhir."))
                || h.windows(16).any(|w| w == b"hl7.org/fhir")
                || h.windows(8).any(|w| w == b"\"Bundle\""));
        fhir.then_some(Sniff { format: "fhir", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        if cx.format_id() == "hl7" {
            return hl7(cx, &text).ok_or_else(|| ExtractError::malformed("MSH segment"));
        }
        let v: Value = serde_json::from_str(&text).map_err(|_| ExtractError::malformed("FHIR JSON"))?;
        fhir(cx, &v);
        Ok(())
    }
}

crate::register_extractor!(Clinical);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hl7_times() {
        assert_eq!(hl7_time("202509010612").as_deref(), Some("2025-09-01T06:12"));
        assert_eq!(hl7_time("20250901061200+0100").as_deref(), Some("2025-09-01T06:12:00"));
        // Not digits (fuzz): no time, and no slicing mid-character.
        assert_eq!(hl7_time("2025氏0901"), None);
    }

    crate::fixture_tests!("hl7", "fhir");
}
