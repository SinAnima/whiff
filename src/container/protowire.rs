//! The protobuf wire format without a schema: the fields of a message as
//! `(number, value)` pairs, for formats whose `.proto` gives the meaning of
//! the numbers (ORC, ONNX, TensorFlow, Core ML, Lance). A malformed field
//! ends the iteration.
//!
//! Specification: Protocol Buffers "Encoding" (varints, wire types 0, 1,
//! 2 and 5; groups are not supported and end the iteration).

/// One field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire<'a> {
    /// Wire type 0.
    Varint(u64),
    /// Wire type 1.
    Fixed64(u64),
    /// Wire type 2: a string, bytes, a message or a packed array.
    Bytes(&'a [u8]),
    /// Wire type 5.
    Fixed32(u32),
}

impl<'a> Wire<'a> {
    /// The value as an integer (varints and fixed values).
    #[must_use]
    pub fn int(self) -> Option<u64> {
        match self {
            Self::Varint(v) | Self::Fixed64(v) => Some(v),
            Self::Fixed32(v) => Some(u64::from(v)),
            Self::Bytes(_) => None,
        }
    }

    /// The value as bytes (wire type 2).
    #[must_use]
    pub fn bytes(self) -> Option<&'a [u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The value as text (lossy UTF-8).
    #[must_use]
    pub fn text(self) -> Option<String> {
        self.bytes().map(|b| String::from_utf8_lossy(b).into_owned())
    }
}

/// A base-128 varint at `*at` (at most ten bytes).
pub fn varint(b: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..70).step_by(7) {
        let x = *b.get(*at)?;
        *at += 1;
        v |= u64::from(x & 0x7f).checked_shl(shift).unwrap_or(0);
        if x & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// The fields of a message, in order.
pub struct Fields<'a> {
    b: &'a [u8],
    at: usize,
}

/// Iterate over the fields of the message `b`.
#[must_use]
pub fn fields(b: &[u8]) -> Fields<'_> {
    Fields { b, at: 0 }
}

impl<'a> Iterator for Fields<'a> {
    type Item = (u32, Wire<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.at >= self.b.len() {
            return None;
        }
        let key = varint(self.b, &mut self.at);
        let item = key.and_then(|key| {
            let number = u32::try_from(key >> 3).ok().filter(|&n| n > 0)?;
            let value = match key & 7 {
                0 => Wire::Varint(varint(self.b, &mut self.at)?),
                1 => {
                    let v = u64::from_le_bytes(self.b.get(self.at..self.at + 8)?.try_into().ok()?);
                    self.at += 8;
                    Wire::Fixed64(v)
                }
                2 => {
                    let n = usize::try_from(varint(self.b, &mut self.at)?).ok()?;
                    let end = self.at.checked_add(n)?;
                    let v = self.b.get(self.at..end)?;
                    self.at = end;
                    Wire::Bytes(v)
                }
                5 => {
                    let v = u32::from_le_bytes(self.b.get(self.at..self.at + 4)?.try_into().ok()?);
                    self.at += 4;
                    Wire::Fixed32(v)
                }
                _ => return None,
            };
            Some((number, value))
        });
        if item.is_none() {
            self.at = self.b.len();
        }
        item
    }
}

/// The first value of field `n`.
#[must_use]
pub fn first(b: &[u8], n: u32) -> Option<Wire<'_>> {
    fields(b).find(|(k, _)| *k == n).map(|(_, v)| v)
}

/// Every value of field `n` (repeated fields).
pub fn all(b: &[u8], n: u32) -> impl Iterator<Item = Wire<'_>> {
    fields(b).filter(move |(k, _)| *k == n).map(|(_, v)| v)
}

/// The varints of a packed repeated field (or of one unpacked value).
#[must_use]
pub fn packed(v: Wire<'_>) -> Vec<u64> {
    match v {
        Wire::Bytes(b) => {
            let mut at = 0;
            let mut out = Vec::new();
            while at < b.len() && out.len() < 1 << 20 {
                let Some(x) = varint(b, &mut at) else { break };
                out.push(x);
            }
            out
        }
        other => other.int().into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_types() {
        // 1: varint 150, 2: "hi", 3: fixed32 7, 4: packed [1, 300].
        let b = [0x08, 0x96, 0x01, 0x12, 2, b'h', b'i', 0x1d, 7, 0, 0, 0, 0x22, 3, 1, 0xac, 0x02];
        let f: Vec<_> = fields(&b).collect();
        assert_eq!(f[0], (1, Wire::Varint(150)));
        assert_eq!(f[1].1.text().as_deref(), Some("hi"));
        assert_eq!(f[2], (3, Wire::Fixed32(7)));
        assert_eq!(packed(f[3].1), vec![1, 300]);
        assert_eq!(first(&b, 2).and_then(Wire::text).as_deref(), Some("hi"));
        // A group (wire type 3) ends the walk.
        assert_eq!(fields(&[0x0b, 0x08, 1]).count(), 0);
    }
}
