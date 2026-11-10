//! `science` extractors (feature `science`): scientific array and table
//! formats (HDF5 and the layouts built on it — NetCDF-4, AnnData, Loom,
//! MATLAB 7.3 —, NetCDF classic, FITS, ASDF, Zarr), read for their structure and metadata,
//! never their data.

pub(crate) mod arrays;
pub(crate) mod asdf;
pub(crate) mod chem;
pub(crate) mod fits;
pub(crate) mod genomics;
pub(crate) mod grib;
pub(crate) mod h5;
pub(crate) mod hdf5;
pub(crate) mod instruments;
pub(crate) mod longtail;
pub(crate) mod netcdf;
pub(crate) mod ome;
pub(crate) mod stats;
pub(crate) mod textfmt;
pub(crate) mod zarr;

use serde_json::Value;

// Shared with the other groups.
pub(crate) use super::archive::unix_time;

/// A float as JSON (non-finite values have no JSON number).
pub(crate) fn number(v: f64) -> Value {
    serde_json::Number::from_f64(v).map_or_else(|| Value::String(v.to_string()), Value::Number)
}

/// Element counts multiplied (array shapes), saturating.
pub(crate) fn product(dims: &[u64]) -> u64 {
    dims.iter().fold(1u64, |a, &d| a.saturating_mul(d))
}
