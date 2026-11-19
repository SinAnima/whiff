//! Windows registry hives (`regf`): the base block (format version, the
//! two sequence numbers and so whether the hive is dirty, last written,
//! the file name it had on its system), a bounded walk of the key tree
//! (key and value counts, depth, the newest key write time), the hive's
//! kind from its root keys (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT,
//! UsrClass.dat, Amcache, BCD …) and a few facts that are not personal:
//! the Windows product, edition, version, build and install date
//! (SOFTWARE), the current control set and time zone (SYSTEM), and how
//! many accounts a SAM holds. Value data is otherwise never reported.
//!
//! Specification: libyal "Windows NT Registry File (REGF) format"; Microsoft
//! "Registry hive file format" notes.

use serde_json::{Map, Value};

use super::{filetime, filetime_at, le, le_u32, le_usize, unix_time, user_path, utf16z};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for registry hives.
pub struct Registry;

static META: ExtractorMeta = ExtractorMeta {
    id: "forensic.registry",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "registry_hive",
        name: "Windows registry hive",
        family: "forensic",
        mimes: &[],
        extensions: &["dat", "hiv", "hve"],
        magic: &[Magic::prefix(b"regf")],
        parent: None,
    }],
};

/// Keys visited in the walk.
const MAX_KEYS: u64 = 2_000_000;
/// Deepest key path followed.
const MAX_DEPTH: usize = 512;

struct Hive {
    b: Vec<u8>,
}

impl Hive {
    /// The data of the cell at a hive-bins offset (after its size field).
    fn cell(&self, off: u32) -> Option<&[u8]> {
        let at = 4096usize.checked_add(off as usize)?;
        let size = i32::from_le_bytes(self.b.get(at..at + 4)?.try_into().ok()?);
        let n = usize::try_from(size.unsigned_abs()).ok()?.checked_sub(4)?;
        self.b.get(at + 4..at + 4 + n)
    }

    fn key(&self, off: u32) -> Option<Key<'_>> {
        let c = self.cell(off)?;
        (c.get(..2)? == b"nk").then_some(Key { c })
    }

    /// The offsets of a key's subkeys (lf, lh, li, ri lists).
    fn subkeys(&self, list: u32, out: &mut Vec<u32>, depth: usize) {
        let Some(c) = self.cell(list) else { return };
        let n = usize::from(u16::from_le_bytes([c.get(2).copied().unwrap_or(0), c.get(3).copied().unwrap_or(0)]));
        match c.get(..2) {
            Some(b"lf" | b"lh") => {
                out.extend((0..n).filter_map(|i| c.get(4 + 8 * i..8 + 8 * i).map(le_u32)));
            }
            Some(b"li") => out.extend((0..n).filter_map(|i| c.get(4 + 4 * i..8 + 4 * i).map(le_u32))),
            Some(b"ri") if depth < 8 => {
                for i in 0..n {
                    if let Some(v) = c.get(4 + 4 * i..8 + 4 * i) {
                        self.subkeys(le_u32(v), out, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }

    fn children(&self, k: &Key<'_>) -> Vec<u32> {
        let mut v = Vec::new();
        if k.subkey_count() > 0 {
            self.subkeys(k.u32(28), &mut v, 0);
        }
        v
    }

    fn child(&self, k: &Key<'_>, name: &str) -> Option<u32> {
        self.children(k).into_iter().find(|&o| self.key(o).is_some_and(|c| c.name().eq_ignore_ascii_case(name)))
    }

    fn path(&self, root: u32, path: &str) -> Option<u32> {
        let mut cur = root;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            cur = self.child(&self.key(cur)?, part)?;
        }
        Some(cur)
    }

    /// A value's type and data.
    fn value(&self, key: u32, name: &str) -> Option<(u32, Vec<u8>)> {
        let k = self.key(key)?;
        let n = k.u32(36) as usize;
        let list = self.cell(k.u32(40))?;
        for i in 0..n.min(4096) {
            let vk = self.cell(le_u32(list.get(4 * i..4 * i + 4)?))?;
            if vk.get(..2)? != b"vk" {
                continue;
            }
            let nlen = le_usize(&vk[2..4]);
            let raw = vk.get(20..20 + nlen)?;
            let vname = if le(&vk[16..18]) & 1 != 0 { super::asciiz(raw) } else { utf16z(raw) };
            if !vname.eq_ignore_ascii_case(name) {
                continue;
            }
            let size = le_u32(&vk[4..8]);
            let kind = le_u32(&vk[12..16]);
            // High bit: up to four bytes stored in the offset field itself.
            let data = if size & 0x8000_0000 != 0 {
                vk.get(8..8 + (size & 0x7fff_ffff).min(4) as usize)?.to_vec()
            } else {
                self.cell(le_u32(&vk[8..12]))?.get(..size as usize)?.to_vec()
            };
            return Some((kind, data));
        }
        None
    }

    fn string(&self, key: u32, name: &str) -> Option<String> {
        let (kind, d) = self.value(key, name)?;
        matches!(kind, 1 | 2).then(|| utf16z(&d)).filter(|s| !s.is_empty())
    }

    fn dword(&self, key: u32, name: &str) -> Option<u64> {
        let (kind, d) = self.value(key, name)?;
        (kind == 4 && d.len() >= 4).then(|| le(&d[..4]))
    }
}

struct Key<'a> {
    c: &'a [u8],
}

impl Key<'_> {
    fn u32(&self, at: usize) -> u32 {
        self.c.get(at..at + 4).map_or(0, le_u32)
    }

    fn subkey_count(&self) -> u32 {
        self.u32(20)
    }

    fn name(&self) -> String {
        let n = self.c.get(72..74).map_or(0, le_usize);
        let raw = self.c.get(76..76 + n).unwrap_or_default();
        let flags = self.c.get(2..4).map_or(0, le);
        if flags & 0x20 != 0 { super::asciiz(raw) } else { utf16z(raw) }
    }

    fn written(&self) -> u64 {
        self.c.get(4..12).map_or(0, le)
    }
}

/// The hive's kind, from the names of the root's subkeys.
fn kind(names: &[String], root: &str) -> &'static str {
    let has = |n: &str| names.iter().any(|x| x.eq_ignore_ascii_case(n));
    if has("Select") && names.iter().any(|n| n.starts_with("ControlSet")) {
        "system"
    } else if has("Microsoft") && (has("Classes") || has("Policies")) && has("Clients") {
        "software"
    } else if has("SAM") && names.len() <= 2 {
        "sam"
    } else if has("Policy") && has("RXACT") {
        "security"
    } else if has("Environment") && has("Software") {
        "ntuser"
    } else if has("Local Settings") || root.ends_with("_Classes") {
        "usrclass"
    } else if has("Root") || has("InventoryApplicationFile") {
        "amcache"
    } else if has("Objects") && has("Description") {
        "bcd"
    } else if has("DriverDatabase") {
        "drivers"
    } else if has("Software") && has("Microsoft") {
        "default"
    } else {
        "unknown"
    }
}

impl Extractor for Registry {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // base block, walk, then a summary per hive kind
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = usize::try_from(src.len().min(cx.parse_limit() as u64)).unwrap_or(0);
        let b = src.read_vec(0, len)?;
        if b.len() < 4096 {
            return Err(ExtractError::malformed("regf base block"));
        }
        let (seq1, seq2) = (le(&b[4..8]), le(&b[8..12]));
        cx.format_set("version", format!("{}.{}", le(&b[20..24]), le(&b[24..28])));
        cx.format_set("dirty", seq1 != seq2);
        if let Some(t) = filetime_at(&b, 12) {
            cx.format_set("last_written", t.clone());
            cx.temporal().source("forensic.registry").content_date(crate::plugin::DateField::Modified, t, true);
        }
        let file_type = le(&b[28..32]);
        if file_type != 0 {
            cx.format_set("file_type", if file_type == 1 || file_type == 2 { "transaction_log" } else { "other" });
        }
        let embedded = utf16z(&b[48..112]);
        if !embedded.is_empty() {
            cx.format_set("embedded_file_name", user_path(cx, &embedded));
        }
        let declared = le(&b[40..44]);
        if declared + 4096 > src.len() {
            cx.warn("the hive bins run past the end of the file");
        } else if (b.len() as u64) < declared + 4096 {
            cx.warn(format!("only the first {} bytes of the hive were read", b.len()));
        }
        let root = le_u32(&b[36..40]);
        let hive = Hive { b };
        let r = hive.key(root).ok_or_else(|| ExtractError::malformed("regf root key"))?;
        let root_name = r.name();
        cx.format_set("root_key", root_name.clone());
        let names: Vec<String> = hive.children(&r).into_iter().filter_map(|o| hive.key(o)).map(|k| k.name()).collect();
        let kind = kind(&names, &root_name);
        cx.format_set("hive", kind);
        cx.format_set("root_subkeys", names.iter().take(64).cloned().collect::<Vec<_>>());

        // The walk: counts, depth, newest write.
        let (mut keys, mut values, mut depth, mut newest) = (0u64, 0u64, 0usize, 0u64);
        let mut stack = vec![(root, 0usize)];
        let mut cut = false;
        while let Some((off, d)) = stack.pop() {
            let Some(k) = hive.key(off) else { continue };
            keys += 1;
            values += u64::from(k.u32(36));
            depth = depth.max(d);
            newest = newest.max(k.written());
            if keys >= MAX_KEYS || d >= MAX_DEPTH {
                cut = true;
                break;
            }
            stack.extend(hive.children(&k).into_iter().map(|c| (c, d + 1)));
            if keys.is_multiple_of(65_536) {
                cx.checkpoint()?;
            }
        }
        cx.format_set("keys", keys);
        cx.format_set("values", values);
        cx.format_set("max_depth", depth);
        if cut {
            cx.format_set("walk_complete", false);
        }
        if let Some(t) = filetime(newest) {
            cx.format_set("newest_key_written", t);
        }

        let mut facts = Map::new();
        match kind {
            "software" => {
                if let Some(k) = hive.path(root, "Microsoft\\Windows NT\\CurrentVersion") {
                    for (name, key) in [
                        ("ProductName", "product"),
                        ("EditionID", "edition"),
                        ("DisplayVersion", "display_version"),
                        ("CurrentBuild", "build"),
                        ("CurrentVersion", "version"),
                    ] {
                        if let Some(v) = hive.string(k, name) {
                            facts.insert(key.into(), v.into());
                        }
                    }
                    if let Some(t) = hive.dword(k, "InstallDate").and_then(|t| unix_time(i64::try_from(t).ok()?)) {
                        facts.insert("install_date".into(), t.into());
                    }
                }
            }
            "system" => {
                if let Some(cur) = hive.path(root, "Select").and_then(|s| hive.dword(s, "Current")) {
                    let set = format!("ControlSet{cur:03}");
                    facts.insert("current_control_set".into(), set.clone().into());
                    if let Some(tz) = hive
                        .path(root, &format!("{set}\\Control\\TimeZoneInformation"))
                        .and_then(|k| hive.string(k, "TimeZoneKeyName"))
                    {
                        facts.insert("time_zone".into(), tz.into());
                    }
                }
            }
            "sam" => {
                if let Some(k) = hive.path(root, "SAM\\Domains\\Account\\Users\\Names").and_then(|o| hive.key(o)) {
                    facts.insert("accounts".into(), k.subkey_count().into());
                }
            }
            "amcache" => {
                if let Some(k) = hive.path(root, "Root\\InventoryApplicationFile").and_then(|o| hive.key(o)) {
                    facts.insert("application_files".into(), k.subkey_count().into());
                }
            }
            _ => {}
        }
        if !facts.is_empty() {
            cx.format_set("windows", Value::Object(facts));
        }
        Ok(())
    }
}

crate::register_extractor!(Registry);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    crate::fixture_tests!("registry_hive");

    /// A hive with a root key, one subkey and a `REG_SZ` value on it.
    fn hive() -> Vec<u8> {
        let mut bins = Vec::new();
        let cell = |bins: &mut Vec<u8>, data: &[u8]| -> u32 {
            let off = u32::try_from(bins.len()).unwrap();
            let size = i32::try_from(data.len() + 4).unwrap();
            bins.extend((-size).to_le_bytes());
            bins.extend_from_slice(data);
            off
        };
        let nk = |name: &str, subkeys: u32, list: u32, values: u32, vlist: u32| {
            let mut k = vec![0u8; 76];
            k[..2].copy_from_slice(b"nk");
            k[2..4].copy_from_slice(&0x20u16.to_le_bytes());
            k[4..12].copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
            k[20..24].copy_from_slice(&subkeys.to_le_bytes());
            k[28..32].copy_from_slice(&list.to_le_bytes());
            k[36..40].copy_from_slice(&values.to_le_bytes());
            k[40..44].copy_from_slice(&vlist.to_le_bytes());
            k[72..74].copy_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
            k.extend(name.as_bytes());
            k
        };
        bins.extend(b"hbin");
        bins.extend([0u8; 28]);
        let data: Vec<u8> = "Saltmere\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let data_off = cell(&mut bins, &data);
        let mut vk = vec![0u8; 20];
        vk[..2].copy_from_slice(b"vk");
        vk[2..4].copy_from_slice(&9u16.to_le_bytes());
        vk[4..8].copy_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        vk[8..12].copy_from_slice(&data_off.to_le_bytes());
        vk[12..16].copy_from_slice(&1u32.to_le_bytes());
        vk[16..18].copy_from_slice(&1u16.to_le_bytes());
        vk.extend(b"Harbour\0\0");
        vk.truncate(29);
        let vk_off = cell(&mut bins, &vk);
        let vlist = cell(&mut bins, &vk_off.to_le_bytes());
        let child = cell(&mut bins, &nk("Environment", 0, 0, 1, vlist));
        let child2 = cell(&mut bins, &nk("Software", 0, 0, 0, 0));
        let mut lf = b"lf\x02\x00".to_vec();
        for c in [child, child2] {
            lf.extend(c.to_le_bytes());
            lf.extend([0; 4]);
        }
        let list = cell(&mut bins, &lf);
        let root = cell(&mut bins, &nk("ROOT", 2, list, 0, 0));
        let mut b = vec![0u8; 4096];
        b[..4].copy_from_slice(b"regf");
        b[4..8].copy_from_slice(&3u32.to_le_bytes());
        b[8..12].copy_from_slice(&2u32.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..28].copy_from_slice(&6u32.to_le_bytes());
        b[36..40].copy_from_slice(&root.to_le_bytes());
        b[40..44].copy_from_slice(&u32::try_from(bins.len()).unwrap().to_le_bytes());
        b.extend(bins);
        b
    }

    #[test]
    fn walk_and_kind() {
        let r = report_for("NTUSER.DAT", &hive());
        let f = &r.format["registry_hive"];
        assert_eq!(f["hive"], "ntuser");
        assert_eq!(f["keys"], 3);
        assert_eq!(f["values"], 1);
        assert_eq!(f["dirty"], true);
        let h = Hive { b: hive() };
        let env = h.path(le_u32(&h.b[36..40]), "Environment").unwrap();
        assert_eq!(h.string(env, "harbour").as_deref(), Some("Saltmere"));
    }
}
