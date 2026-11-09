//! `apple` extractors (feature `common`): property lists and what they
//! hold (bundle Info.plist, launchd jobs, keyed archives, configuration and
//! provisioning profiles, Shortcuts and Automator workflows, iOS backup
//! manifests), localisation tables, `.DS_Store`, bookmarks and aliases,
//! AppleDouble files, compiled asset catalogs and Xcode projects.

pub(crate) mod appledouble;
pub(crate) mod bookmark;
pub(crate) mod car;
pub(crate) mod ds_store;
pub(crate) mod plists;
pub(crate) mod strings;
pub(crate) mod watchface;
pub(crate) mod xcode;

use plist::Value as Plist;
use serde_json::Value;

// Helpers shared with the data extractors.
pub(crate) use super::archive::unix_time;
pub(crate) use super::data::schema::Schema;
use crate::plugin::{Context, proplist};

/// A little-endian field (at most 4 bytes) as an offset or count.
pub(crate) fn le_usize(b: &[u8]) -> usize {
    b.iter().take(4).rev().fold(0usize, |a, &x| a << 8 | usize::from(x))
}

/// A non-empty string under `key` of a dictionary.
pub(crate) fn get_str<'p>(p: &'p Plist, key: &str) -> Option<&'p str> {
    p.as_dictionary()?.get(key)?.as_string().filter(|s| !s.is_empty())
}

/// The strings of an array under `key`.
pub(crate) fn strings(p: &Plist, key: &str) -> Vec<String> {
    let a = p.as_dictionary().and_then(|d| d.get(key)).and_then(Plist::as_array);
    a.into_iter().flatten().filter_map(Plist::as_string).map(str::to_string).collect()
}

/// A boolean under `key`.
pub(crate) fn get_bool(p: &Plist, key: &str) -> Option<bool> {
    p.as_dictionary()?.get(key)?.as_boolean()
}

/// Copy string values of `keys` (plist key → output key) into the format section.
pub(crate) fn copy_strings(cx: &mut Context<'_>, p: &Plist, keys: &[(&str, &str)]) {
    for (key, out) in keys {
        if let Some(v) = get_str(p, key) {
            cx.format_set(out, crate::plugin::truncate_chars(v, 300));
        }
    }
}

/// Infer the shape of a plist (as JSON) into the format section's `schema`.
pub(crate) fn schema(cx: &mut Context<'_>, p: &Plist) {
    let mut s = Schema::default();
    s.add(&proplist::to_json(p, 14));
    cx.format_set("schema", s.to_json());
}

/// Count every value of a plist and its deepest nesting (iteratively).
pub(crate) fn census(p: &Plist) -> (u64, usize) {
    let mut stack = vec![(p, 0usize)];
    let (mut n, mut deepest) = (0u64, 0usize);
    while let Some((v, d)) = stack.pop() {
        n += 1;
        deepest = deepest.max(d);
        match v {
            Plist::Array(a) => stack.extend(a.iter().map(|x| (x, d + 1))),
            Plist::Dictionary(m) => stack.extend(m.values().map(|x| (x, d + 1))),
            _ => {}
        }
    }
    (n, deepest)
}

/// Top-level keys of a dictionary, as a JSON list (first 100).
pub(crate) fn top_keys(p: &Plist) -> Option<Value> {
    let d = p.as_dictionary()?;
    Some(Value::Array(d.keys().take(100).map(|k| Value::from(crate::plugin::truncate_chars(k, 100))).collect()))
}
