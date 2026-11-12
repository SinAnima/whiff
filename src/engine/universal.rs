//! Sections every input gets: system, filesystem times, permissions,
//! size, entropy, hashes.

use std::fs::Metadata;
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

use encoding_rs::Encoding;
use sha2::Digest;

use super::{Options, Profile};
use crate::report::{EntropyScope, FileKind, Integrity, Report};
use crate::text::WcCounter;

pub(crate) fn rfc3339(t: SystemTime) -> Option<String> {
    jiff::Timestamp::try_from(t).ok().map(|ts| ts.to_string())
}

pub(crate) fn file_kind(meta: &Metadata) -> FileKind {
    let ft = meta.file_type();
    if ft.is_symlink() {
        return FileKind::Symlink;
    }
    if ft.is_dir() {
        return FileKind::Directory;
    }
    if ft.is_file() {
        return FileKind::Regular;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() {
            return FileKind::Fifo;
        }
        if ft.is_socket() {
            return FileKind::Socket;
        }
        if ft.is_block_device() {
            return FileKind::BlockDevice;
        }
        if ft.is_char_device() {
            return FileKind::CharDevice;
        }
    }
    FileKind::Other
}

/// Fill `system`, `temporal.filesystem` and `security` from file metadata.
pub(crate) fn fill_from_metadata(report: &mut Report, meta: &Metadata, path: &Path) {
    let sys = &mut report.system;
    if sys.kind != FileKind::Symlink {
        sys.kind = file_kind(meta);
    }
    if meta.is_file() {
        sys.size_bytes = Some(meta.len());
        report.physical.size_bytes = Some(meta.len());
    }
    sys.readonly = Some(meta.permissions().readonly());
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();

    let times = &mut report.temporal.filesystem;
    times.modified = meta.modified().ok().and_then(rfc3339);
    times.accessed = meta.accessed().ok().and_then(rfc3339);
    times.created = meta.created().ok().and_then(rfc3339);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        sys.device = Some(meta.dev());
        sys.inode = Some(meta.ino());
        sys.links = Some(meta.nlink());
        let allocated = meta.blocks().saturating_mul(512);
        sys.allocated_bytes = Some(allocated);
        // A file shorter than a block can be stored inline (no blocks).
        if meta.is_file() && meta.len() >= 4096 {
            sys.sparse = Some(allocated < meta.len());
        }
        sys.hidden = Some(name.starts_with('.'));
        times.changed = u32::try_from(meta.ctime_nsec())
            .ok()
            .and_then(|ns| jiff::Timestamp::new(meta.ctime(), i32::try_from(ns).unwrap_or(0)).ok())
            .map(|t| t.to_string());

        let mode = meta.mode();
        let sec = &mut report.security;
        sec.mode = Some(format!("{:04o}", mode & 0o7777));
        sec.permissions = Some(permission_string(mode));
        sec.setuid = Some(mode & 0o4000 != 0);
        sec.setgid = Some(mode & 0o2000 != 0);
        sec.sticky = Some(mode & 0o1000 != 0);
        sec.owner = Some(crate::report::Owner {
            uid: Some(meta.uid()),
            user: names::user(meta.uid()),
            gid: Some(meta.gid()),
            group: names::group(meta.gid()),
        });
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        sys.hidden = Some(meta.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0 || name.starts_with('.'));
    }
    #[cfg(not(any(unix, windows)))]
    {
        sys.hidden = Some(name.starts_with('.'));
    }
}

/// User and group names, looked up once per id.
#[cfg(unix)]
mod names {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};

    type Cache = LazyLock<Mutex<HashMap<u32, Option<String>>>>;
    static USERS: Cache = LazyLock::new(Mutex::default);
    static GROUPS: Cache = LazyLock::new(Mutex::default);

    fn cached(cache: &Cache, id: u32, lookup: impl FnOnce() -> Option<String>) -> Option<String> {
        let mut c = cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        c.entry(id).or_insert_with(lookup).clone()
    }

    pub(super) fn user(uid: u32) -> Option<String> {
        cached(&USERS, uid, || uzers::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().into_owned()))
    }

    pub(super) fn group(gid: u32) -> Option<String> {
        cached(&GROUPS, gid, || uzers::get_group_by_gid(gid).map(|g| g.name().to_string_lossy().into_owned()))
    }
}

/// `ls -l` style permission string for the low 12 mode bits.
#[cfg(unix)]
fn permission_string(mode: u32) -> String {
    let bit = |m: u32, c: char| if mode & m != 0 { c } else { '-' };
    let special = |x: u32, s: u32, lower: char, upper: char| match (mode & x != 0, mode & s != 0) {
        (true, true) => lower,
        (false, true) => upper,
        (true, false) => 'x',
        (false, false) => '-',
    };
    [
        bit(0o400, 'r'),
        bit(0o200, 'w'),
        special(0o100, 0o4000, 's', 'S'),
        bit(0o040, 'r'),
        bit(0o020, 'w'),
        special(0o010, 0o2000, 's', 'S'),
        bit(0o004, 'r'),
        bit(0o002, 'w'),
        special(0o001, 0o1000, 't', 'T'),
    ]
    .iter()
    .collect()
}

/// Streaming hasher + byte histogram + `wc`.
struct Digester {
    sha256: Option<sha2::Sha256>,
    blake3: Option<blake3::Hasher>,
    wc: Option<WcCounter>,
    histogram: [u64; 256],
    total: u64,
}

impl Digester {
    fn new(options: &Options, hash: bool, text: Option<&'static Encoding>) -> Self {
        Self {
            sha256: (hash && options.hashes.sha256).then(sha2::Sha256::new),
            blake3: (hash && options.hashes.blake3).then(blake3::Hasher::new),
            wc: text.map(WcCounter::new),
            histogram: [0; 256],
            total: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        if let Some(wc) = &mut self.wc {
            wc.feed(data, false);
        }
        if let Some(h) = &mut self.sha256 {
            h.update(data);
        }
        if let Some(h) = &mut self.blake3 {
            h.update(data);
        }
        for &b in data {
            self.histogram[b as usize] += 1;
        }
        self.total += data.len() as u64;
    }

    fn finish(self, report: &mut Report, scope: EntropyScope) {
        if let Some(mut wc) = self.wc {
            wc.feed(&[], true);
            report.physical.text = Some(wc.finish());
        }
        if let Some(h) = self.sha256 {
            report.integrity.sha256 = Some(hex(&h.finalize()));
        }
        if let Some(h) = self.blake3 {
            report.integrity.blake3 = Some(h.finalize().to_hex().to_string());
        }
        if self.total > 0 {
            report.physical.entropy = Some(entropy(&self.histogram, self.total));
            report.physical.entropy_scope = Some(scope);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Shannon entropy in bits per byte, rounded to 3 decimals.
pub(crate) fn entropy(histogram: &[u64; 256], total: u64) -> f64 {
    let total = total as f64;
    let h: f64 = histogram
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum();
    (h * 1000.0).round() / 1000.0
}

fn hashing_wanted(options: &Options, size: u64) -> Result<(), String> {
    if !options.hashes.any() {
        return Err("disabled".into());
    }
    if options.limits.hash_max_bytes == 0 {
        return Err("profile".into());
    }
    if size > options.limits.hash_max_bytes {
        return Err(format!("larger than hash_max_bytes ({})", options.limits.hash_max_bytes));
    }
    Ok(())
}

/// The encoding to count `wc` statistics in, for text input outside the
/// minimal profile.
pub(crate) fn text_encoding(report: &Report, options: &Options, size: u64) -> Option<&'static Encoding> {
    if options.profile == Profile::Minimal || size > options.limits.max_read_bytes {
        return None;
    }
    let name = report.identification.encoding.as_deref()?;
    match name {
        "us-ascii" | "utf-8" => Some(encoding_rs::UTF_8),
        other => Encoding::for_label(other.as_bytes()),
    }
}

/// Hash, measure entropy and (for text) count `wc` statistics of a file by
/// streaming it once. With neither hashing nor counting, entropy covers
/// `head` only.
pub(crate) fn integrity_for_file(
    report: &mut Report,
    path: &Path,
    size: u64,
    head: &[u8],
    options: &Options,
    text: Option<&'static Encoding>,
) {
    let hash = hashing_wanted(options, size);
    if let Err(reason) = &hash {
        report.integrity = Integrity { skipped: Some(reason.clone()), ..Integrity::default() };
        if text.is_none() {
            let mut d = Digester::new(options, false, None);
            d.update(head);
            let scope = if head.len() as u64 == size { EntropyScope::File } else { EntropyScope::Head };
            d.finish(report, scope);
            return;
        }
    }
    let mut d = Digester::new(options, hash.is_ok(), text);
    let result = std::fs::File::open(path).and_then(|mut f| {
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            d.update(&buf[..n]);
        }
    });
    match result {
        Ok(()) => d.finish(report, EntropyScope::File),
        Err(e) => {
            report.integrity.skipped = Some(format!("read error: {e}"));
            report.diagnostics.warnings.push(format!("integrity: {e}"));
        }
    }
}

/// Hash, measure entropy and (for text) count `wc` statistics of in-memory bytes.
pub(crate) fn integrity_for_bytes(
    report: &mut Report,
    data: &[u8],
    options: &Options,
    text: Option<&'static Encoding>,
) {
    let hash = match hashing_wanted(options, data.len() as u64) {
        Ok(()) => true,
        Err(reason) => {
            report.integrity.skipped = Some(reason);
            false
        }
    };
    let mut d = Digester::new(options, hash, text);
    d.update(data);
    d.finish(report, EntropyScope::File);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        let mut h = [0u64; 256];
        h[b'a' as usize] = 10;
        assert!(entropy(&h, 10).abs() < f64::EPSILON);
        let all = [1u64; 256];
        assert!((entropy(&all, 256) - 8.0).abs() < 1e-9);
    }

    #[cfg(unix)]
    #[test]
    fn permissions() {
        assert_eq!(permission_string(0o644), "rw-r--r--");
        assert_eq!(permission_string(0o4755), "rwsr-xr-x");
        assert_eq!(permission_string(0o1777), "rwxrwxrwt");
        assert_eq!(permission_string(0o2644), "rw-r-Sr--");
    }
}
