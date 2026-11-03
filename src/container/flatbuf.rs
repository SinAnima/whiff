//! A reader for FlatBuffers data without its schema: tables, vtables,
//! scalars, strings, vectors and unions by offset (field numbers come from
//! the format's `.fbs`). Every access is bounds-checked; a missing or
//! out-of-range field reads as absent.
//!
//! Specification: FlatBuffers "Internals" (tables, vtables, offsets).

/// A FlatBuffer: tables, vectors and strings by offset.
#[derive(Clone, Copy)]
pub struct FlatBuf<'a>(pub &'a [u8]);

/// Elements read from one vector (a bound on hostile counts).
const MAX_VECTOR: usize = 1 << 20;

impl<'a> FlatBuf<'a> {
    /// A little-endian `u32` at `at`, as an offset.
    #[must_use]
    pub fn u32(&self, at: usize) -> Option<usize> {
        usize::try_from(u32::from_le_bytes(self.0.get(at..at.checked_add(4)?)?.try_into().ok()?)).ok()
    }

    /// A little-endian `u16` at `at`.
    #[must_use]
    pub fn u16(&self, at: usize) -> Option<usize> {
        Some(usize::from(u16::from_le_bytes(self.0.get(at..at.checked_add(2)?)?.try_into().ok()?)))
    }

    /// The root table (the offset at the start of the buffer).
    #[must_use]
    pub fn root(&self) -> Option<usize> {
        self.u32(0).filter(|&r| r < self.0.len())
    }

    /// Where field `n` of the table at `t` is stored.
    #[must_use]
    pub fn field(&self, t: usize, n: usize) -> Option<usize> {
        let soff = i64::from(i32::from_le_bytes(self.0.get(t..t.checked_add(4)?)?.try_into().ok()?));
        let vt = usize::try_from(i64::try_from(t).ok()?.checked_sub(soff)?).ok()?;
        let vsize = self.u16(vt)?;
        let slot = 4 + 2 * n;
        if slot + 2 > vsize {
            return None;
        }
        let off = self.u16(vt + slot)?;
        (off != 0).then_some(t + off)
    }

    /// Follow the offset stored at `at`.
    #[must_use]
    pub fn deref(&self, at: usize) -> Option<usize> {
        at.checked_add(self.u32(at)?).filter(|&p| p < self.0.len())
    }

    /// A string field.
    #[must_use]
    pub fn string(&self, t: usize, n: usize) -> Option<String> {
        self.string_at(self.deref(self.field(t, n)?)?)
    }

    /// The string whose length prefix is at `s`.
    #[must_use]
    pub fn string_at(&self, s: usize) -> Option<String> {
        let len = self.u32(s)?;
        Some(String::from_utf8_lossy(self.0.get(s + 4..s.checked_add(4)?.checked_add(len)?)?).into_owned())
    }

    /// A boolean field (`false` when absent).
    #[must_use]
    pub fn bool(&self, t: usize, n: usize) -> bool {
        self.field(t, n).and_then(|at| self.0.get(at)).is_some_and(|&b| b != 0)
    }

    /// An unsigned 8-bit field (also union type tags).
    #[must_use]
    pub fn u8_field(&self, t: usize, n: usize) -> Option<u8> {
        self.field(t, n).and_then(|at| self.0.get(at).copied())
    }

    /// A 16-bit field (signed values cast by the caller).
    #[must_use]
    pub fn u16_field(&self, t: usize, n: usize) -> Option<u16> {
        let at = self.field(t, n)?;
        Some(u16::from_le_bytes(self.0.get(at..at + 2)?.try_into().ok()?))
    }

    /// A 32-bit field.
    #[must_use]
    pub fn u32_field(&self, t: usize, n: usize) -> Option<u32> {
        let at = self.field(t, n)?;
        Some(u32::from_le_bytes(self.0.get(at..at + 4)?.try_into().ok()?))
    }

    /// A 64-bit field.
    #[must_use]
    pub fn u64_field(&self, t: usize, n: usize) -> Option<u64> {
        let at = self.field(t, n)?;
        Some(u64::from_le_bytes(self.0.get(at..at + 8)?.try_into().ok()?))
    }

    /// A table field.
    #[must_use]
    pub fn table(&self, t: usize, n: usize) -> Option<usize> {
        self.deref(self.field(t, n)?)
    }

    /// The start of a vector field's elements and its length.
    #[must_use]
    pub fn vector(&self, t: usize, n: usize) -> Option<(usize, usize)> {
        let v = self.deref(self.field(t, n)?)?;
        Some((v + 4, self.u32(v)?.min(MAX_VECTOR)))
    }

    /// The tables of a vector of tables.
    #[must_use]
    pub fn tables(&self, t: usize, n: usize) -> Vec<usize> {
        let Some((start, len)) = self.vector(t, n) else { return Vec::new() };
        (0..len).map_while(|i| start.checked_add(4 * i)).filter_map(|at| self.deref(at)).collect()
    }

    /// The strings of a vector of strings.
    #[must_use]
    pub fn strings(&self, t: usize, n: usize) -> Vec<String> {
        let Some((start, len)) = self.vector(t, n) else { return Vec::new() };
        (0..len).filter_map(|i| self.deref(start + 4 * i)).filter_map(|s| self.string_at(s)).collect()
    }

    /// A vector of bytes (`[ubyte]`, nested FlatBuffers).
    #[must_use]
    pub fn bytes(&self, t: usize, n: usize) -> Option<&'a [u8]> {
        let (start, len) = self.vector(t, n)?;
        self.0.get(start..start.checked_add(len)?)
    }

    /// The `i`-th element (`size` bytes each) of a vector of scalars or structs.
    #[must_use]
    pub fn element(&self, t: usize, n: usize, i: usize, size: usize) -> Option<&'a [u8]> {
        let (start, len) = self.vector(t, n)?;
        if i >= len {
            return None;
        }
        let at = start.checked_add(i.checked_mul(size)?)?;
        self.0.get(at..at.checked_add(size)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_strings_and_scalars() {
        // root offset 12 → table at 12: soffset 8 → vtable at 4 (size 8, table 12,
        // field 0 at +4, field 1 at +8).
        let mut b = vec![12, 0, 0, 0, 8, 0, 12, 0, 4, 0, 8, 0];
        b.extend(8i32.to_le_bytes());
        b.extend(8u32.to_le_bytes()); // field 0 → string at 16 + 8 = 24
        b.extend(7u32.to_le_bytes()); // field 1 = 7
        b.extend(4u32.to_le_bytes());
        b.extend(b"Tide");
        let fb = FlatBuf(&b);
        assert_eq!(fb.root(), Some(12));
        assert_eq!(fb.string(12, 0).as_deref(), Some("Tide"));
        assert_eq!(fb.u32_field(12, 1), Some(7));
        assert_eq!(fb.string(12, 2), None);
        assert_eq!(fb.u32_field(4000, 0), None);
    }
}
