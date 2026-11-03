//! `cad` extractors (feature `cad`): 3D models and scenes (glTF, OBJ, STL,
//! PLY, FBX, Blender, USD, COLLADA, 3MF, …), engineering exchange formats
//! (STEP, IFC, IGES, DXF, DGN), electronics (Gerber, Excellon, `KiCad`,
//! GDSII, OASIS), G-code, lighting data and motion capture.
//!
//! Shared here: 3D bounds, histograms and rounded numbers.

#![allow(clippy::many_single_char_names, clippy::similar_names)] // coordinates and field offsets

pub(crate) mod drawing;
pub(crate) mod eda;
pub(crate) mod gcode;
pub(crate) mod gltf;
pub(crate) mod mesh;
pub(crate) mod scene;
pub(crate) mod step;

use std::collections::BTreeMap;

use serde_json::Value;

use crate::plugin::Context;

/// A float as JSON, rounded to `places` decimals (non-finite values as text).
pub(crate) fn num(v: f64, places: i32) -> Value {
    let f = 10f64.powi(places);
    let r = (v * f).round() / f;
    serde_json::Number::from_f64(r).map_or_else(|| Value::String(v.to_string()), Value::Number)
}

/// A histogram as a JSON object.
pub(crate) fn hist(m: BTreeMap<String, u64>) -> Value {
    Value::Object(m.into_iter().map(|(k, v)| (k, v.into())).collect())
}

/// Add one to `key` of a histogram that keeps at most `max` keys.
pub(crate) fn bump(m: &mut BTreeMap<String, u64>, key: &str, max: usize) {
    if let Some(n) = m.get_mut(key) {
        *n += 1;
    } else if m.len() < max {
        m.insert(key.to_string(), 1);
    }
}

/// An axis-aligned 3D bounding box.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Box3 {
    pub min: [f64; 3],
    pub max: [f64; 3],
    pub points: u64,
}

impl Default for Box3 {
    fn default() -> Self {
        Box3 { min: [f64::INFINITY; 3], max: [f64::NEG_INFINITY; 3], points: 0 }
    }
}

impl Box3 {
    /// Add a point (ignored unless every coordinate is finite).
    pub fn add(&mut self, p: [f64; 3]) {
        if p.iter().all(|v| v.is_finite()) {
            for ((lo, hi), v) in self.min.iter_mut().zip(self.max.iter_mut()).zip(p) {
                *lo = lo.min(v);
                *hi = hi.max(v);
            }
            self.points += 1;
        }
    }

    /// Points of `xyz…` triples.
    pub fn add_all(&mut self, v: &[f64]) {
        for p in v.as_chunks::<3>().0 {
            self.add([p[0], p[1], p[2]]);
        }
    }

    /// `{"min": [x, y, z], "max": [x, y, z], "size": [dx, dy, dz]}`.
    pub fn report(&self, cx: &mut Context<'_>, key: &str) {
        if self.points == 0 {
            return;
        }
        let v = |a: [f64; 3]| Value::Array(a.iter().map(|&x| num(x, 6)).collect());
        let size = [self.max[0] - self.min[0], self.max[1] - self.min[1], self.max[2] - self.min[2]];
        let mut m = serde_json::Map::new();
        m.insert("min".into(), v(self.min));
        m.insert("max".into(), v(self.max));
        m.insert("size".into(), v(size));
        cx.format_set(key, Value::Object(m));
    }
}

/// An S-expression (KiCad): a list or an atom.
#[derive(Debug, PartialEq)]
pub(crate) enum Sexp {
    List(Vec<Sexp>),
    Atom(String),
}

impl Sexp {
    /// Parse the first expression of `text` (strings unquoted, `\"`
    /// escapes resolved); deeply nested input is cut off at `max_depth`.
    pub fn parse(text: &str, max_depth: usize) -> Option<Sexp> {
        let b = text.as_bytes();
        let mut at = 0;
        Sexp::read(b, &mut at, max_depth)
    }

    fn read(b: &[u8], at: &mut usize, depth: usize) -> Option<Sexp> {
        while b.get(*at).is_some_and(u8::is_ascii_whitespace) {
            *at += 1;
        }
        match *b.get(*at)? {
            b'(' => {
                *at += 1;
                if depth == 0 {
                    return None;
                }
                let mut items = Vec::new();
                loop {
                    while b.get(*at).is_some_and(u8::is_ascii_whitespace) {
                        *at += 1;
                    }
                    match b.get(*at)? {
                        b')' => {
                            *at += 1;
                            return Some(Sexp::List(items));
                        }
                        _ => items.push(Sexp::read(b, at, depth - 1)?),
                    }
                }
            }
            b'"' => {
                *at += 1;
                let mut s = Vec::new();
                while let Some(&c) = b.get(*at) {
                    *at += 1;
                    match c {
                        b'\\' => {
                            if let Some(&e) = b.get(*at) {
                                s.push(if e == b'n' { b'\n' } else { e });
                                *at += 1;
                            }
                        }
                        b'"' => return Some(Sexp::Atom(String::from_utf8_lossy(&s).into_owned())),
                        _ => s.push(c),
                    }
                }
                None
            }
            b')' => None,
            _ => {
                let start = *at;
                while b.get(*at).is_some_and(|c| !c.is_ascii_whitespace() && *c != b'(' && *c != b')') {
                    *at += 1;
                }
                Some(Sexp::Atom(String::from_utf8_lossy(&b[start..*at]).into_owned()))
            }
        }
    }

    /// The head atom of a list: `(head …)`.
    pub fn head(&self) -> Option<&str> {
        match self {
            Sexp::List(v) => match v.first()? {
                Sexp::Atom(a) => Some(a),
                Sexp::List(_) => None,
            },
            Sexp::Atom(_) => None,
        }
    }

    /// The children of a list.
    pub fn items(&self) -> &[Sexp] {
        match self {
            Sexp::List(v) => v,
            Sexp::Atom(_) => &[],
        }
    }

    /// The first child list whose head is `name`.
    pub fn child(&self, name: &str) -> Option<&Sexp> {
        self.items().iter().find(|c| c.head() == Some(name))
    }

    /// The atom `i` of a list (0 is the head).
    pub fn atom(&self, i: usize) -> Option<&str> {
        match self.items().get(i)? {
            Sexp::Atom(a) => Some(a),
            Sexp::List(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sexp() {
        let s = Sexp::parse(r#"(kicad_pcb (version 20240108) (title_block (title "Buoy \"B7\"")))"#, 16).unwrap();
        assert_eq!(s.head(), Some("kicad_pcb"));
        assert_eq!(s.child("version").and_then(|v| v.atom(1)), Some("20240108"));
        assert_eq!(s.child("title_block").and_then(|t| t.child("title")).and_then(|t| t.atom(1)), Some("Buoy \"B7\""));
        assert!(Sexp::parse("((((x))))", 2).is_none());
        let mut b = Box3::default();
        b.add_all(&[1.0, 2.0, 3.0, -1.0, 5.0, 0.0]);
        assert_eq!((b.min, b.max), ([-1.0, 2.0, 0.0], [1.0, 5.0, 3.0]));
    }
}
