use crate::ExtractError;

/// A bounds-checked little/big-endian cursor over a byte slice. Every read
/// returns [`ExtractError::Truncated`] instead of panicking.
///
/// ```
/// use whiff::io::ByteReader;
/// let mut r = ByteReader::new(b"qoif\x00\x00\x00\x10").skip(4)?;
/// assert_eq!(r.be_u32()?, 16);
/// assert!(r.u8().is_err());
/// # Ok::<(), whiff::ExtractError>(())
/// ```
#[derive(Debug, Clone)]
pub struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

macro_rules! read_int {
    ($($name:ident, $ty:ty, $from:ident;)*) => {$(
        #[doc = concat!("Read a `", stringify!($ty), "` (`", stringify!($from), "`).")]
        pub fn $name(&mut self) -> Result<$ty, ExtractError> {
            let b = self.array::<{ size_of::<$ty>() }>()?;
            Ok(<$ty>::$from(b))
        }
    )*};
}

impl<'a> ByteReader<'a> {
    /// A cursor at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current offset.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes left after the cursor.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Whether nothing is left.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Skip `n` bytes, consuming the reader (for chaining from `new`).
    pub fn skip(mut self, n: usize) -> Result<Self, ExtractError> {
        self.advance(n)?;
        Ok(self)
    }

    /// Skip `n` bytes.
    pub fn advance(&mut self, n: usize) -> Result<(), ExtractError> {
        self.bytes(n).map(|_| ())
    }

    /// Move to an absolute offset (must be within the data).
    pub fn seek(&mut self, offset: usize) -> Result<(), ExtractError> {
        if offset > self.data.len() {
            return Err(self.truncated(offset - self.pos));
        }
        self.pos = offset;
        Ok(())
    }

    /// Next `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], ExtractError> {
        if n > self.remaining() {
            return Err(self.truncated(n));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Next `N` bytes as an array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], ExtractError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    /// Everything after the cursor.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.data[self.pos..];
        self.pos = self.data.len();
        out
    }

    /// Look at the next `n` bytes without consuming them.
    pub fn peek(&self, n: usize) -> Option<&'a [u8]> {
        self.data.get(self.pos..self.pos.checked_add(n)?)
    }

    /// Consume `expected` or fail with [`ExtractError::Malformed`].
    pub fn tag(&mut self, expected: &[u8]) -> Result<(), ExtractError> {
        let got = self.bytes(expected.len())?;
        if got == expected {
            Ok(())
        } else {
            Err(ExtractError::malformed(format!("expected {expected:02x?} at offset {}", self.pos - expected.len())))
        }
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8, ExtractError> {
        Ok(self.bytes(1)?[0])
    }

    read_int! {
        be_u16, u16, from_be_bytes;
        be_u32, u32, from_be_bytes;
        be_u64, u64, from_be_bytes;
        le_u16, u16, from_le_bytes;
        le_u32, u32, from_le_bytes;
        le_u64, u64, from_le_bytes;
        be_i16, i16, from_be_bytes;
        be_i32, i32, from_be_bytes;
        le_i16, i16, from_le_bytes;
        le_i32, i32, from_le_bytes;
    }

    /// A NUL-terminated byte string (the NUL is consumed, not returned).
    pub fn cstr(&mut self) -> Result<&'a [u8], ExtractError> {
        let rest = &self.data[self.pos..];
        let end = rest.iter().position(|&b| b == 0).ok_or_else(|| self.truncated(rest.len() + 1))?;
        self.pos += end + 1;
        Ok(&rest[..end])
    }

    fn truncated(&self, needed: usize) -> ExtractError {
        ExtractError::Truncated { offset: self.pos as u64, needed: needed as u64 }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::ByteReader;
    use crate::ExtractError;

    /// A read's name, width, expected value and result.
    type Read = (&'static str, usize, Option<u64>, Result<u64, ExtractError>);

    /// Every fixed-size read, with its width and the value it should give for
    /// the first bytes of `d` (computed by shifting, not by `from_*_bytes`).
    fn reads(d: &[u8]) -> Vec<Read> {
        let be = |n: usize| d.get(..n).map(|b| b.iter().fold(0u64, |v, &x| v << 8 | u64::from(x)));
        let le = |n: usize| d.get(..n).map(|b| b.iter().rev().fold(0u64, |v, &x| v << 8 | u64::from(x)));
        let r = || ByteReader::new(d);
        vec![
            ("u8", 1, be(1), r().u8().map(u64::from)),
            ("be_u16", 2, be(2), r().be_u16().map(u64::from)),
            ("le_u16", 2, le(2), r().le_u16().map(u64::from)),
            ("be_u32", 4, be(4), r().be_u32().map(u64::from)),
            ("le_u32", 4, le(4), r().le_u32().map(u64::from)),
            ("be_u64", 8, be(8), r().be_u64()),
            ("le_u64", 8, le(8), r().le_u64()),
            // Signed reads: the same bits, reinterpreted.
            ("be_i16", 2, be(2), r().be_i16().map(|v| u64::from(v.cast_unsigned()))),
            ("le_i16", 2, le(2), r().le_i16().map(|v| u64::from(v.cast_unsigned()))),
            ("be_i32", 4, be(4), r().be_i32().map(|v| u64::from(v.cast_unsigned()))),
            ("le_i32", 4, le(4), r().le_i32().map(|v| u64::from(v.cast_unsigned()))),
        ]
    }

    #[test]
    fn every_truncation_of_every_read_fails_cleanly() {
        let full: Vec<u8> = (1..=8).collect();
        for len in 0..=full.len() {
            for (name, width, want, got) in reads(&full[..len]) {
                if len >= width {
                    assert_eq!(got.ok(), want, "{name} of {len} bytes");
                } else {
                    assert!(
                        matches!(got, Err(ExtractError::Truncated { offset: 0, needed }) if needed == width as u64),
                        "{name} of {len} bytes: {got:?}"
                    );
                }
            }
        }
    }

    /// One step of a random walk over a reader.
    #[derive(Debug, Clone)]
    enum Op {
        Bytes(usize),
        Advance(usize),
        Seek(usize),
        Peek(usize),
        U32,
        Cstr,
        Rest,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0..40usize).prop_map(Op::Bytes),
            (0..40usize).prop_map(Op::Advance),
            (0..80usize).prop_map(Op::Seek),
            (0..40usize).prop_map(Op::Peek),
            Just(Op::U32),
            Just(Op::Cstr),
            Just(Op::Rest),
        ]
    }

    proptest! {
        #[test]
        fn reads_match_slicing_and_failures_do_not_move(
            data in proptest::collection::vec(any::<u8>(), 0..64),
            ops in proptest::collection::vec(op(), 0..24),
        ) {
            let mut r = ByteReader::new(&data);
            // The model: a plain offset into `data`.
            let mut pos = 0usize;
            for op in ops {
                let before = r.position();
                prop_assert_eq!(before, pos);
                let left = data.len() - pos;
                match op {
                    Op::Bytes(n) => match r.bytes(n) {
                        Ok(b) => {
                            prop_assert!(n <= left);
                            prop_assert_eq!(b, &data[pos..pos + n]);
                            pos += n;
                        }
                        Err(e) => {
                            prop_assert!(n > left);
                            let truncated = matches!(e, ExtractError::Truncated { offset, needed }
                                if offset == pos as u64 && needed == n as u64);
                            prop_assert!(truncated);
                        }
                    },
                    Op::Advance(n) => {
                        prop_assert_eq!(r.advance(n).is_ok(), n <= left);
                        if n <= left {
                            pos += n;
                        }
                    }
                    Op::Seek(to) => {
                        prop_assert_eq!(r.seek(to).is_ok(), to <= data.len());
                        if to <= data.len() {
                            pos = to;
                        }
                    }
                    Op::Peek(n) => {
                        prop_assert_eq!(r.peek(n), data.get(pos..pos + n));
                    }
                    Op::U32 => {
                        let want = data.get(pos..pos + 4).map(|b| b.iter().fold(0u32, |v, &x| v << 8 | u32::from(x)));
                        prop_assert_eq!(r.be_u32().ok(), want);
                        if want.is_some() {
                            pos += 4;
                        }
                    }
                    Op::Cstr => {
                        let nul = data[pos..].iter().position(|&b| b == 0);
                        prop_assert_eq!(r.cstr().ok(), nul.map(|n| &data[pos..pos + n]));
                        if let Some(n) = nul {
                            pos += n + 1;
                        }
                    }
                    Op::Rest => {
                        prop_assert_eq!(r.rest(), &data[pos..]);
                        pos = data.len();
                    }
                }
                prop_assert_eq!(r.position(), pos);
                prop_assert_eq!(r.remaining(), data.len() - pos);
                prop_assert_eq!(r.is_empty(), pos == data.len());
            }
        }

        #[test]
        fn skip_then_read_equals_reading_at_the_offset(
            data in proptest::collection::vec(any::<u8>(), 0..32),
            at in 0..40usize,
        ) {
            let skipped = ByteReader::new(&data).skip(at);
            prop_assert_eq!(skipped.is_ok(), at <= data.len());
            if let Ok(mut r) = skipped {
                let mut s = ByteReader::new(&data);
                s.seek(at).unwrap();
                prop_assert_eq!(r.le_u16().ok(), s.le_u16().ok());
            }
        }
    }
}
