//! The Thrift compact protocol, read into a generic tree (Parquet footers
//! and page headers). Structures are bounded in depth and size; a
//! malformed value ends the read with what came before.
//!
//! Specification: Apache Thrift "Thrift Compact protocol encoding".

/// Nesting allowed.
const MAX_DEPTH: usize = 32;
/// Elements read from one list or map.
const MAX_ELEMENTS: usize = 1 << 20;
/// Values read in total.
const MAX_VALUES: usize = 4 << 20;

/// A Thrift value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TValue<'a> {
    Bool(bool),
    /// Every integer type (zig-zag decoded).
    Int(i64),
    Double(f64),
    Binary(&'a [u8]),
    List(Vec<TValue<'a>>),
    Map(Vec<(TValue<'a>, TValue<'a>)>),
    Struct(Vec<(i16, TValue<'a>)>),
}

impl<'a> TValue<'a> {
    /// Field `id` of a struct.
    pub(crate) fn get(&self, id: i16) -> Option<&TValue<'a>> {
        match self {
            Self::Struct(f) => f.iter().find(|(k, _)| *k == id).map(|(_, v)| v),
            _ => None,
        }
    }

    pub(crate) fn int(&self, id: i16) -> Option<i64> {
        match self.get(id)? {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub(crate) fn bytes(&self, id: i16) -> Option<&'a [u8]> {
        match self.get(id)? {
            Self::Binary(b) => Some(b),
            _ => None,
        }
    }

    pub(crate) fn text(&self, id: i16) -> Option<String> {
        self.bytes(id).map(|b| String::from_utf8_lossy(b).into_owned())
    }

    pub(crate) fn list(&self, id: i16) -> &[TValue<'a>] {
        match self.get(id) {
            Some(Self::List(v)) => v,
            _ => &[],
        }
    }

    /// The field ids of a struct (union members).
    pub(crate) fn ids(&self) -> Vec<i16> {
        match self {
            Self::Struct(f) => f.iter().map(|(k, _)| *k).collect(),
            _ => Vec::new(),
        }
    }
}

/// A reader over compact-protocol bytes.
pub(crate) struct Reader<'a> {
    b: &'a [u8],
    pub(crate) at: usize,
    values: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0, values: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let v = *self.b.get(self.at)?;
        self.at += 1;
        Some(v)
    }

    fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..70).step_by(7) {
            let x = self.byte()?;
            v |= u64::from(x & 0x7f).checked_shl(shift).unwrap_or(0);
            if x & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn zigzag(&mut self) -> Option<i64> {
        let v = self.varint()?;
        Some((v >> 1).cast_signed() ^ -((v & 1).cast_signed()))
    }

    fn value(&mut self, kind: u8, depth: usize) -> Option<TValue<'a>> {
        self.values += 1;
        if self.values > MAX_VALUES || depth > MAX_DEPTH {
            return None;
        }
        Some(match kind {
            1 => TValue::Bool(true),
            2 => TValue::Bool(false),
            3 => TValue::Int(i64::from(self.byte()?.cast_signed())),
            4..=6 => TValue::Int(self.zigzag()?),
            7 => {
                let raw = self.b.get(self.at..self.at + 8)?;
                self.at += 8;
                TValue::Double(f64::from_le_bytes(raw.try_into().ok()?))
            }
            8 => {
                let n = usize::try_from(self.varint()?).ok()?;
                let end = self.at.checked_add(n)?;
                let v = self.b.get(self.at..end)?;
                self.at = end;
                TValue::Binary(v)
            }
            9 | 10 => {
                let h = self.byte()?;
                let n = if h >> 4 == 15 { usize::try_from(self.varint()?).ok()? } else { usize::from(h >> 4) };
                let elem = h & 0x0f;
                let mut v = Vec::with_capacity(n.min(1024));
                for _ in 0..n.min(MAX_ELEMENTS) {
                    // Booleans in lists are one byte each.
                    v.push(if matches!(elem, 1 | 2) {
                        TValue::Bool(self.byte()? == 1)
                    } else {
                        self.value(elem, depth + 1)?
                    });
                }
                TValue::List(v)
            }
            11 => {
                let n = usize::try_from(self.varint()?).ok()?;
                let mut v = Vec::new();
                if n > 0 {
                    let kinds = self.byte()?;
                    for _ in 0..n.min(MAX_ELEMENTS) {
                        let k = self.value(kinds >> 4, depth + 1)?;
                        let x = self.value(kinds & 0x0f, depth + 1)?;
                        v.push((k, x));
                    }
                }
                TValue::Map(v)
            }
            12 => self.structure(depth + 1)?,
            _ => return None,
        })
    }

    /// A struct, up to its stop field.
    pub(crate) fn structure(&mut self, depth: usize) -> Option<TValue<'a>> {
        let mut fields = Vec::new();
        let mut last: i16 = 0;
        loop {
            let h = self.byte()?;
            if h == 0 {
                return Some(TValue::Struct(fields));
            }
            let delta = h >> 4;
            let id = if delta == 0 { i16::try_from(self.zigzag()?).ok()? } else { last.checked_add(i16::from(delta))? };
            last = id;
            let v = self.value(h & 0x0f, depth)?;
            fields.push((id, v));
        }
    }
}

/// Read one struct from `b`.
pub(crate) fn read(b: &[u8]) -> Option<TValue<'_>> {
    Reader::new(b).structure(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_structs() {
        // {1: i32 3, 2: "ab", 4: list<i32>[1, -1], 5: {1: true}}
        let b = [0x15, 0x06, 0x18, 2, b'a', b'b', 0x29, 0x25, 0x02, 0x01, 0x1c, 0x11, 0x00, 0x00];
        let v = read(&b).unwrap();
        assert_eq!(v.int(1), Some(3));
        assert_eq!(v.text(2).as_deref(), Some("ab"));
        assert_eq!(v.list(4), &[TValue::Int(1), TValue::Int(-1)]);
        assert_eq!(v.get(5).and_then(|s| s.get(1)), Some(&TValue::Bool(true)));
        // A truncated struct is rejected.
        assert!(read(&b[..5]).is_none());
    }
}
