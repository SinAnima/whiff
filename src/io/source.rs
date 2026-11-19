use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use super::{Budget, SourceError, WINDOW};

/// A random-access, bounded view of the input.
///
/// Extractors receive `&mut dyn Source`. The convenience methods
/// ([`read_exact_at`](trait.Source.html#method.read_exact_at),
/// [`read_vec`](trait.Source.html#method.read_vec),
/// [`reader`](trait.Source.html#method.reader),
/// [`slice`](trait.Source.html#method.slice)) live on `dyn Source`.
pub trait Source: Send {
    /// Total length in bytes.
    fn len(&self) -> u64;
    /// Read up to `buf.len()` bytes at `offset`; returns the count (0 at end).
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError>;
    /// The first bytes (up to 64 KiB), pre-read.
    fn head(&self) -> &[u8];
    /// The last bytes (up to 64 KiB), pre-read: ZIP EOCD, `ID3v1`, PDF trailer…
    fn tail(&self) -> &[u8];
    /// File name, or entry name for embedded children.
    fn name_hint(&self) -> Option<&str>;
    /// The budget every read is charged to.
    fn budget(&self) -> &Budget;

    /// Whether the input is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'s> dyn Source + 's {
    /// Fill `buf` completely from `offset`, or fail with [`SourceError::OutOfBounds`].
    pub fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let end = offset.checked_add(buf.len() as u64);
        if end.is_none_or(|e| e > self.len()) {
            return Err(SourceError::OutOfBounds { offset, needed: buf.len() as u64 });
        }
        let mut done = 0;
        while done < buf.len() {
            let n = self.read_at(offset + done as u64, &mut buf[done..])?;
            if n == 0 {
                return Err(SourceError::OutOfBounds { offset, needed: buf.len() as u64 });
            }
            done += n;
        }
        Ok(())
    }

    /// Read `len` bytes at `offset` into a new vector.
    pub fn read_vec(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, SourceError> {
        let mut v = vec![0; len];
        self.read_exact_at(offset, &mut v)?;
        Ok(v)
    }

    /// The first `max` bytes (or all of a shorter input), and whether the
    /// input was longer than that.
    pub fn read_prefix(&mut self, max: usize) -> Result<(Vec<u8>, bool), SourceError> {
        let len = usize::try_from(self.len()).unwrap_or(usize::MAX);
        let n = len.min(max);
        Ok((self.read_vec(0, n)?, len > n))
    }

    /// A [`std::io::Read`] + [`std::io::Seek`] adapter, for crates that want one.
    pub fn reader(&mut self) -> BoundedReader<'_, 's> {
        BoundedReader { src: self, pos: 0 }
    }

    /// A view of `len` bytes starting at `offset` (an embedded stream).
    pub fn slice(&mut self, offset: u64, len: u64) -> Result<SubSource<'_, 's>, SourceError> {
        SubSource::new(self, offset, len)
    }
}

fn windows(src: &mut dyn Source) -> Result<(Vec<u8>, Vec<u8>), SourceError> {
    let len = src.len();
    let head_len = usize::try_from(len.min(WINDOW as u64)).unwrap_or(WINDOW);
    let head = src.read_vec(0, head_len)?;
    let tail = if len <= WINDOW as u64 { Vec::new() } else { src.read_vec(len - WINDOW as u64, WINDOW)? };
    Ok((head, tail))
}

/// A file on disk, read with seek + read.
#[derive(Debug)]
pub struct FileSource {
    file: File,
    len: u64,
    head: Vec<u8>,
    tail: Vec<u8>,
    name: Option<String>,
    budget: Budget,
}

impl FileSource {
    /// Open `path`, charging the head/tail pre-reads to `budget`.
    pub fn open(path: &Path, budget: Budget) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let mut s = Self {
            file,
            len,
            head: Vec::new(),
            tail: Vec::new(),
            name: path.file_name().map(|n| n.to_string_lossy().into_owned()),
            budget,
        };
        let (head, tail) = windows(&mut s).map_err(std::io::Error::other)?;
        s.head = head;
        s.tail = tail;
        Ok(s)
    }

    /// Stream the whole file through `f` in `chunk`-byte pieces from the
    /// open handle, checking the deadline before each piece. Not charged to
    /// the read budget: hashing has its own cap (`limits.hash_max_bytes`).
    pub(crate) fn stream(&mut self, chunk: usize, mut f: impl FnMut(&[u8])) -> Result<(), SourceError> {
        self.file.seek(SeekFrom::Start(0)).map_err(|e| SourceError::Io(e.to_string()))?;
        let mut buf = vec![0u8; chunk.max(1)];
        loop {
            self.budget.check_deadline()?;
            let n = self.file.read(&mut buf).map_err(|e| SourceError::Io(e.to_string()))?;
            if n == 0 {
                return Ok(());
            }
            f(&buf[..n]);
        }
    }
}

impl Source for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let want = usize::try_from((self.len - offset).min(buf.len() as u64)).unwrap_or(buf.len());
        self.budget.check_deadline()?;
        self.file.seek(SeekFrom::Start(offset)).map_err(|e| SourceError::Io(e.to_string()))?;
        let n = self.file.read(&mut buf[..want]).map_err(|e| SourceError::Io(e.to_string()))?;
        // Charge what was actually read: a short read costs only its bytes.
        // When the charge is refused the bytes are not handed out.
        self.budget.charge_read(n as u64)?;
        Ok(n)
    }

    fn head(&self) -> &[u8] {
        &self.head
    }

    fn tail(&self) -> &[u8] {
        if self.tail.is_empty() { &self.head } else { &self.tail }
    }

    fn name_hint(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn budget(&self) -> &Budget {
        &self.budget
    }
}

/// In-memory input: bytes, stdin, embedded children.
#[derive(Debug, Clone)]
pub struct BytesSource {
    data: Arc<[u8]>,
    name: Option<String>,
    budget: Budget,
}

impl BytesSource {
    /// Wrap `data`, optionally named.
    pub fn new(name: Option<String>, data: impl Into<Arc<[u8]>>, budget: Budget) -> Self {
        Self { data: data.into(), name, budget }
    }

    /// The whole input.
    pub fn data(&self) -> &Arc<[u8]> {
        &self.data
    }
}

impl Source for BytesSource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        let Ok(start) = usize::try_from(offset) else { return Ok(0) };
        if start >= self.data.len() || buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(self.data.len() - start);
        // In-memory reads are charged too, so runaway loops stop the same way.
        self.budget.charge_read(n as u64)?;
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }

    fn head(&self) -> &[u8] {
        &self.data[..self.data.len().min(WINDOW)]
    }

    fn tail(&self) -> &[u8] {
        &self.data[self.data.len().saturating_sub(WINDOW)..]
    }

    fn name_hint(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn budget(&self) -> &Budget {
        &self.budget
    }
}

/// A sub-range of another source.
pub struct SubSource<'p, 's> {
    parent: &'p mut (dyn Source + 's),
    offset: u64,
    len: u64,
    head: Vec<u8>,
    tail: Vec<u8>,
    budget: Budget,
}

impl<'p, 's> SubSource<'p, 's> {
    fn new(parent: &'p mut (dyn Source + 's), offset: u64, len: u64) -> Result<Self, SourceError> {
        if offset.checked_add(len).is_none_or(|end| end > parent.len()) {
            return Err(SourceError::OutOfBounds { offset, needed: len });
        }
        let budget = parent.budget().clone();
        let mut s = Self { parent, offset, len, head: Vec::new(), tail: Vec::new(), budget };
        let (head, tail) = windows(&mut s)?;
        s.head = head;
        s.tail = tail;
        Ok(s)
    }
}

impl Source for SubSource<'_, '_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        if offset >= self.len {
            return Ok(0);
        }
        let n = usize::try_from((self.len - offset).min(buf.len() as u64)).unwrap_or(buf.len());
        self.parent.read_at(self.offset + offset, &mut buf[..n])
    }

    fn head(&self) -> &[u8] {
        &self.head
    }

    fn tail(&self) -> &[u8] {
        if self.tail.is_empty() { &self.head } else { &self.tail }
    }

    fn name_hint(&self) -> Option<&str> {
        self.parent.name_hint()
    }

    fn budget(&self) -> &Budget {
        &self.budget
    }
}

/// [`std::io::Read`] + [`std::io::Seek`] over a [`Source`]. Budget and timeout
/// errors pass through as `std::io::Error`s wrapping a [`SourceError`]; they
/// convert back into the right [`ExtractError`](crate::ExtractError) with `?`.
pub struct BoundedReader<'r, 's> {
    src: &'r mut (dyn Source + 's),
    pos: u64,
}

impl Read for BoundedReader<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.src.read_at(self.pos, buf).map_err(std::io::Error::other)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for BoundedReader<'_, '_> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let target = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.src.len().checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        let target =
            target.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before start"))?;
        self.pos = target;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn file_reads_charge_the_bytes_read() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![7u8; 1 << 20]).unwrap();
        let budget = Budget::new(2 << 20, 0, None);
        let mut src = FileSource::open(f.path(), budget.clone()).unwrap();
        let before = budget.bytes_read();
        let mut buf = vec![0u8; 4096];
        let mut at = 0u64;
        while at < src.len() {
            at += src.read_at(at, &mut buf).unwrap() as u64;
        }
        assert_eq!(budget.bytes_read() - before, 1 << 20);
        // Reading past the end costs nothing.
        assert_eq!(src.read_at(1 << 20, &mut buf).unwrap(), 0);
        assert_eq!(budget.bytes_read() - before, 1 << 20);
    }

    #[test]
    fn streaming_checks_the_deadline_but_not_the_read_budget() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![7u8; 1 << 20]).unwrap();
        let budget = Budget::new(512 << 10, 0, None);
        let mut src = FileSource::open(f.path(), budget.clone()).unwrap();
        let before = budget.bytes_read();
        let mut total = 0;
        src.stream(4096, |c| total += c.len()).unwrap();
        assert_eq!(total, 1 << 20, "hashing has its own cap, not max_read_bytes");
        assert_eq!(budget.bytes_read(), before);

        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            let budget = Budget::new(u64::MAX, 0, Some(std::time::Duration::from_millis(30)));
            let mut src = FileSource::open(f.path(), budget.clone()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(40));
            assert!(matches!(src.stream(4096, |_| {}), Err(SourceError::Timeout)));
            assert_eq!(budget.limits_hit(), ["timeout"]);
        }
    }

    #[test]
    fn file_reads_stop_at_the_limit() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![7u8; 64 << 10]).unwrap();
        let budget = Budget::new(64 << 10, 0, None);
        let mut src = FileSource::open(f.path(), budget.clone()).unwrap();
        let mut buf = vec![0u8; 64 << 10];
        assert!(matches!(src.read_at(0, &mut buf), Err(SourceError::LimitExceeded("read_bytes"))));
        assert!(budget.bytes_read() <= 64 << 10);
    }
}
