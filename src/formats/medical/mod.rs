//! `medical` extractors (feature `science`): DICOM, NIfTI and Analyze,
//! NRRD and MetaImage volumes, HL7 v2 and FHIR messages. Values that
//! identify a patient are withheld unless privacy is off.

pub(crate) mod clinical;
pub(crate) mod dicom;
pub(crate) mod volumes;

use serde_json::Value;

/// A float as JSON (non-finite values have no JSON number).
pub(crate) fn number(v: f64) -> Value {
    serde_json::Number::from_f64(v).map_or_else(|| Value::String(v.to_string()), Value::Number)
}
