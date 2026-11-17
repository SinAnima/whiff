//! The PDF file structure (ISO 32000-2 §7.5): header, cross-reference
//! tables and streams, incremental updates, object streams, and a repair
//! scan for files whose cross-reference data is missing or wrong.
//!
//! Objects are read from the source on demand, so large files are not
//! loaded into memory.

use std::collections::{HashMap, HashSet};

use super::crypt::Decryptor;
use super::filter;
use super::object::{Data, Dict, Lexer, Obj, ParseError, Token, is_white};
use crate::plugin::{Context, ExtractError, Source};

/// Where an object lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Entry {
    /// At a byte offset, with its generation.
    At(u64, u16),
    /// Inside object stream `stream`, at position `index`.
    InStream(u32, u32),
    /// Deleted by this or a newer section: an older section must not
    /// bring the object back.
    Free,
}

/// A decoded object stream: object offsets relative to `first`.
struct ObjStm {
    data: Vec<u8>,
    first: usize,
    offsets: Vec<(u32, usize)>,
}

const MAX_OBJECTS: usize = 2_000_000;
const MAX_WINDOW: usize = 64 << 20;
const MAX_CACHE: usize = 200_000;
const MAX_RESOLVE_DEPTH: usize = 16;

pub(crate) struct Doc<'s, 'c> {
    src: &'s mut dyn Source,
    pub(crate) cx: &'s mut Context<'c>,
    len: u64,
    /// Bytes before `%PDF-` (offsets in damaged files may count from there).
    base: u64,
    pub(crate) version: Option<String>,
    pub(crate) xref: HashMap<u32, Entry>,
    pub(crate) trailer: Dict,
    /// Cross-reference sections read (1 + incremental updates).
    pub(crate) sections: usize,
    pub(crate) xref_streams: bool,
    pub(crate) repaired: bool,
    pub(crate) crypt: Option<Decryptor>,
    cache: HashMap<u32, Obj>,
    objstm: HashMap<u32, Option<std::rc::Rc<ObjStm>>>,
    depth: usize,
    max_stream: usize,
    /// Numbers the current section's table marked free. Its `/XRefStm` may
    /// still place them (hybrid files list compressed objects as free).
    hidden: HashSet<u32>,
}

impl<'s, 'c> Doc<'s, 'c> {
    pub(crate) fn open(src: &'s mut dyn Source, cx: &'s mut Context<'c>) -> Result<Self, ExtractError> {
        let len = src.len();
        let head = src.head();
        let window = &head[..head.len().min(1024)];
        let start = find(window, b"%PDF-")
            .or_else(|| find(window, b"%FDF-"))
            .ok_or_else(|| ExtractError::malformed("no %PDF header"))?;
        let fdf = window[start..].starts_with(b"%FDF-");
        let version: String = head[start + 5..]
            .iter()
            .take(4)
            .take_while(|b| b.is_ascii_digit() || **b == b'.')
            .map(|&b| char::from(b))
            .collect();
        let tail = src.tail().to_vec();
        let max_stream = cx.parse_limit().min(256 << 20);
        let mut doc = Self {
            src,
            cx,
            len,
            base: start as u64,
            version: (!version.is_empty()).then_some(version),
            xref: HashMap::new(),
            trailer: Dict::default(),
            sections: 0,
            xref_streams: false,
            repaired: false,
            crypt: None,
            cache: HashMap::new(),
            objstm: HashMap::new(),
            depth: 0,
            max_stream,
            hidden: HashSet::new(),
        };
        let startxref = rfind(&tail, b"startxref").and_then(|i| {
            let mut lx = Lexer::at(&tail, i + 9);
            match lx.token() {
                Ok(Some(Token::Obj(Obj::Int(n)))) => u64::try_from(n).ok(),
                _ => None,
            }
        });
        let ok = if let Some(off) = startxref {
            match doc.read_chain(off) {
                Ok(()) => true,
                Err(ExtractError::LimitExceeded(e)) => return Err(ExtractError::LimitExceeded(e)),
                Err(e) => {
                    doc.cx.warn(format!("cross-reference data: {e}; rebuilding"));
                    false
                }
            }
        } else {
            // FDF files usually have no cross-reference table at all.
            if !fdf {
                doc.cx.warn("no startxref; rebuilding the cross-reference table");
            }
            false
        };
        if !ok || !doc.root_ok() {
            doc.repair()?;
        }
        if let Some(enc) = doc.trailer.get("Encrypt").cloned() {
            let enc = doc.resolve(&enc);
            let id = doc
                .trailer
                .get("ID")
                .and_then(Obj::as_array)
                .and_then(|a| a.first())
                .and_then(Obj::as_str)
                .map(<[u8]>::to_vec);
            if let Some(d) = enc.as_dict() {
                doc.crypt = Some(Decryptor::new(d, id.as_deref().unwrap_or_default()));
            }
        }
        Ok(doc)
    }

    fn root_ok(&mut self) -> bool {
        let Some(root) = self.trailer.get("Root").cloned() else { return false };
        self.resolve(&root).as_dict().is_some_and(|d| d.has("Pages") || d.name("Type") == Some("Catalog"))
    }

    /// Up to `n` bytes at `offset`.
    fn window(&mut self, offset: u64, n: usize) -> Result<Vec<u8>, ExtractError> {
        if offset >= self.len {
            return Ok(Vec::new());
        }
        let n = usize::try_from((self.len - offset).min(n as u64)).unwrap_or(n);
        let mut buf = vec![0u8; n];
        self.src.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }

    /// Parse with a window that grows while the parser needs more input.
    fn parse_at<T>(
        &mut self,
        offset: u64,
        initial: usize,
        mut f: impl FnMut(&mut Lexer<'_>) -> Result<T, ParseError>,
    ) -> Result<(T, usize), ExtractError> {
        let mut size = initial;
        loop {
            let buf = self.window(offset, size)?;
            let mut lx = Lexer::new(&buf);
            match f(&mut lx) {
                Ok(v) => return Ok((v, lx.pos)),
                Err(ParseError::Incomplete)
                    if (buf.len() as u64) < self.len - offset.min(self.len) && size < MAX_WINDOW =>
                {
                    size *= 4;
                }
                Err(_) => return Err(ExtractError::malformed(format!("object at offset {offset}"))),
            }
        }
    }

    // ---- cross-reference data ----------------------------------------

    fn read_chain(&mut self, first: u64) -> Result<(), ExtractError> {
        let mut seen = HashSet::new();
        let mut next = Some(first);
        while let Some(off) = next.take() {
            if !seen.insert(off) || seen.len() > 1000 {
                break;
            }
            self.cx.checkpoint()?;
            self.hidden.clear();
            let trailer = match self.read_section(off) {
                Ok(t) => t,
                // Offsets counted from a junk prefix, or a little off.
                Err(e) => match self.base.checked_add(off).filter(|_| self.base > 0).map(|o| self.read_section(o)) {
                    Some(Ok(t)) => t,
                    _ => return Err(e),
                },
            };
            self.sections += 1;
            if let Some(Obj::Int(x)) = trailer.get("XRefStm")
                && let Ok(o) = u64::try_from(*x)
            {
                let _ = self.read_section(o);
            }
            self.hidden.clear();
            if let Some(p) = trailer.get("Prev").and_then(Obj::as_int) {
                next = u64::try_from(p).ok();
            }
            for (k, v) in trailer.0 {
                if !self.trailer.has(&k)
                    && !matches!(k.as_str(), "Prev" | "XRefStm" | "W" | "Index" | "Filter" | "DecodeParms" | "Length")
                {
                    self.trailer.0.push((k, v));
                }
            }
        }
        if !self.xref.values().any(|e| *e != Entry::Free) {
            return Err(ExtractError::malformed("empty cross-reference table"));
        }
        Ok(())
    }

    /// One `xref` table + trailer, or one cross-reference stream.
    fn read_section(&mut self, off: u64) -> Result<Dict, ExtractError> {
        let probe = self.window(off, 32)?;
        let skip = probe.iter().take_while(|b| is_white(**b)).count();
        if probe[skip..].starts_with(b"xref") {
            return self.read_table(off + skip as u64 + 4);
        }
        let (num, _, obj) = self.indirect_at(off)?;
        let Obj::Stream(dict, data) = obj else { return Err(ExtractError::malformed("cross-reference stream")) };
        if dict.name("Type") != Some("XRef") {
            return Err(ExtractError::malformed(format!("object {num} is not a cross-reference stream")));
        }
        self.xref_streams = true;
        let raw = self.stream_raw(&dict, data)?;
        let data = filter::decode(&dict, raw, self.cx, self.max_stream)?;
        self.xref_stream_entries(&dict, &data)?;
        Ok(dict)
    }

    fn read_table(&mut self, off: u64) -> Result<Dict, ExtractError> {
        let mut found: Vec<(u32, Entry)> = Vec::new();
        let (trailer, _) = self.parse_at(off, 1 << 16, |lx| {
            found.clear();
            loop {
                match next(lx)? {
                    Token::Obj(Obj::Int(start)) => {
                        let Token::Obj(Obj::Int(count)) = next(lx)? else { return Err(ParseError::Invalid) };
                        if !(0..=10_000_000).contains(&count) || start < 0 {
                            return Err(ParseError::Invalid);
                        }
                        for i in 0..count {
                            let Token::Obj(o) = next(lx)? else { return Err(ParseError::Invalid) };
                            let Token::Obj(g) = next(lx)? else { return Err(ParseError::Invalid) };
                            let Token::Keyword(k) = next(lx)? else { return Err(ParseError::Invalid) };
                            // Past `u32` (or `i64`) the row names no object: skip it.
                            let Some(n) = start.checked_add(i).and_then(|n| u32::try_from(n).ok()) else { continue };
                            if found.len() >= MAX_OBJECTS {
                                continue;
                            }
                            match k.first() {
                                Some(b'f') => found.push((n, Entry::Free)),
                                Some(b'n') => {
                                    if let (Some(o), Some(g)) = (o.as_int(), g.as_int())
                                        && let (Ok(o), Ok(g)) = (u64::try_from(o), u16::try_from(g))
                                        && o > 0
                                    {
                                        found.push((n, Entry::At(o, g)));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Token::Keyword(b"trailer") => return lx.object(),
                    _ => return Err(ParseError::Invalid),
                }
            }
        })?;
        for (n, e) in found {
            if let std::collections::hash_map::Entry::Vacant(v) = self.xref.entry(n) {
                v.insert(e);
                if e == Entry::Free {
                    self.hidden.insert(n);
                }
            }
        }
        trailer.as_dict().cloned().ok_or_else(|| ExtractError::malformed("trailer"))
    }

    fn xref_stream_entries(&mut self, dict: &Dict, data: &[u8]) -> Result<(), ExtractError> {
        let w: Vec<usize> = dict
            .get("W")
            .and_then(Obj::as_array)
            .map(|a| a.iter().map(|o| o.as_int().and_then(|n| usize::try_from(n).ok()).unwrap_or(0)).collect())
            .unwrap_or_default();
        if w.len() != 3 || w.iter().any(|&x| x > 8) || w.iter().sum::<usize>() == 0 {
            return Err(ExtractError::malformed("cross-reference stream /W"));
        }
        let size = dict.int("Size").unwrap_or(0);
        let index: Vec<i64> = match dict.get("Index").and_then(Obj::as_array) {
            Some(a) => a.iter().filter_map(Obj::as_int).collect(),
            None => vec![0, size],
        };
        let width: usize = w.iter().sum();
        let mut rows = data.chunks_exact(width);
        let field = |b: &[u8]| b.iter().fold(0u64, |acc, &x| acc << 8 | u64::from(x));
        for &[start, count] in index.as_chunks::<2>().0 {
            for i in 0..count.clamp(0, 10_000_000) {
                let Some(row) = rows.next() else { return Ok(()) };
                let kind = if w[0] == 0 { 1 } else { field(&row[..w[0]]) };
                let f2 = field(&row[w[0]..w[0] + w[1]]);
                let f3 = field(&row[w[0] + w[1]..]);
                let Some(n) = start.checked_add(i).and_then(|n| u32::try_from(n).ok()) else { continue };
                if self.xref.len() >= MAX_OBJECTS {
                    return Ok(());
                }
                let entry = match kind {
                    0 => Entry::Free,
                    1 if f2 > 0 => Entry::At(f2, u16::try_from(f3).unwrap_or(0)),
                    2 => match (u32::try_from(f2), u32::try_from(f3)) {
                        (Ok(s), Ok(ix)) => Entry::InStream(s, ix),
                        _ => continue,
                    },
                    _ => continue,
                };
                // A free row of this section's table yields to its `/XRefStm`.
                if entry != Entry::Free && self.hidden.remove(&n) {
                    self.xref.insert(n, entry);
                } else {
                    self.xref.entry(n).or_insert(entry);
                }
            }
        }
        Ok(())
    }

    /// Rebuild the table by scanning for `n g obj` and `trailer`.
    fn repair(&mut self) -> Result<(), ExtractError> {
        self.repaired = true;
        let limit = self.cx.parse_limit();
        if self.len > limit as u64 {
            self.cx.warn("file larger than the parse limit; the repair scan reads only its start");
        }
        let buf = self.window(0, limit)?;
        let mut found: HashMap<u32, Entry> = HashMap::new();
        let mut trailers = Vec::new();
        let mut i = 0;
        while let Some(rel) = find(&buf[i..], b"obj") {
            let at = i + rel;
            i = at + 3;
            if at.is_multiple_of(4096) {
                self.cx.checkpoint()?;
            }
            // Must be `<digits> <digits> obj` followed by a delimiter.
            if buf.get(at + 3).is_some_and(|b| !is_white(*b) && !super::object::is_delim(*b)) {
                continue;
            }
            if let Some((n, g, start)) = header_before(&buf, at)
                && found.len() < MAX_OBJECTS
            {
                found.insert(n, Entry::At(start as u64, g));
            }
        }
        let mut j = 0;
        while let Some(rel) = find(&buf[j..], b"trailer") {
            let at = j + rel + 7;
            j = at;
            if let Ok(o) = Lexer::at(&buf, at).object()
                && let Some(d) = o.as_dict()
            {
                trailers.push(d.clone());
            }
        }
        drop(buf);
        if found.is_empty() {
            return Err(ExtractError::malformed("no objects found"));
        }
        // Prefer the repaired table: the original was wrong.
        let old = std::mem::take(&mut self.xref);
        self.xref = found;
        for (n, e) in old {
            if matches!(e, Entry::InStream(..)) {
                self.xref.entry(n).or_insert(e);
            }
        }
        self.cache.clear();
        for t in trailers.into_iter().rev() {
            for (k, v) in t.0 {
                if !self.trailer.has(&k) && matches!(k.as_str(), "Root" | "Info" | "Encrypt" | "ID" | "Size") {
                    self.trailer.0.push((k, v));
                }
            }
        }
        // Objects inside object streams, and the catalog if no trailer named it.
        let nums: Vec<u32> = self.xref.keys().copied().collect();
        let mut catalog = None;
        for n in nums {
            self.cx.checkpoint()?;
            let Some(Entry::At(off, _)) = self.xref.get(&n).copied() else { continue };
            let Ok((_, _, obj)) = self.indirect_at(off) else { continue };
            let Some(d) = obj.as_dict() else { continue };
            match d.name("Type") {
                Some("ObjStm") => {
                    if let Some(stm) = self.objstm(n) {
                        for (ix, (num, _)) in stm.offsets.iter().enumerate() {
                            self.xref.entry(*num).or_insert(Entry::InStream(n, u32::try_from(ix).unwrap_or(u32::MAX)));
                        }
                    }
                }
                Some("Catalog") if d.has("Pages") => catalog = Some(n),
                _ => {}
            }
        }
        let root_ok = self.root_ok();
        if !root_ok {
            self.trailer.0.retain(|(k, _)| k != "Root");
            let catalog = catalog.or_else(|| {
                let nums: Vec<u32> =
                    self.xref.iter().filter(|(_, e)| matches!(e, Entry::InStream(..))).map(|(n, _)| *n).collect();
                nums.into_iter().find(|&n| self.get(n).as_dict().is_some_and(|d| d.name("Type") == Some("Catalog")))
            });
            if let Some(c) = catalog {
                self.trailer.0.push(("Root".into(), Obj::Ref(c, 0)));
            }
        }
        Ok(())
    }

    // ---- objects -------------------------------------------------------

    /// The indirect object at `offset`: `(number, generation, object)`.
    fn indirect_at(&mut self, offset: u64) -> Result<(u32, u16, Obj), ExtractError> {
        let ((n, g, obj), end) = self.parse_at(offset, 4096, |lx| {
            let Some(Token::Obj(Obj::Int(n))) = lx.token()? else { return Err(ParseError::Invalid) };
            let Some(Token::Obj(Obj::Int(g))) = lx.token()? else { return Err(ParseError::Invalid) };
            if lx.token()? != Some(Token::Keyword(b"obj")) {
                return Err(ParseError::Invalid);
            }
            let obj = lx.object()?;
            Ok((n, g, obj))
        })?;
        let n = u32::try_from(n).map_err(|_| ExtractError::malformed("object number"))?;
        let g = u16::try_from(g).unwrap_or(0);
        let Obj::Dict(dict) = obj else { return Ok((n, g, obj)) };
        // `stream` + EOL, then the data.
        let after = self.window(offset + end as u64, 32)?;
        let skip = after.iter().take_while(|b| is_white(**b)).count();
        if after[skip..].starts_with(b"stream") {
            let mut p = skip + 6;
            if after.get(p) == Some(&b'\r') {
                p += 1;
            }
            if after.get(p) == Some(&b'\n') {
                p += 1;
            }
            return Ok((n, g, Obj::Stream(dict, Data::At(offset + (end + p) as u64))));
        }
        Ok((n, g, Obj::Dict(dict)))
    }

    /// Object `n` (cached), or `Null`.
    pub(crate) fn get(&mut self, n: u32) -> Obj {
        if let Some(o) = self.cache.get(&n) {
            return o.clone();
        }
        if self.depth >= MAX_RESOLVE_DEPTH {
            return Obj::Null;
        }
        self.depth += 1;
        let obj = match self.xref.get(&n).copied() {
            Some(Entry::At(off, _)) => match self.indirect_at(off) {
                Ok((found, _, obj)) if found == n => obj,
                // A wrong offset: try the start of the line before it.
                _ => Obj::Null,
            },
            Some(Entry::InStream(s, ix)) => self.in_objstm(s, ix, n),
            Some(Entry::Free) | None => Obj::Null,
        };
        self.depth -= 1;
        let obj = match (&self.crypt, obj) {
            (Some(c), o) if !matches!(self.xref.get(&n), Some(Entry::InStream(..))) => {
                c.decrypt_strings(n, self.gen_of(n), o)
            }
            (_, o) => o,
        };
        if self.cache.len() < MAX_CACHE {
            self.cache.insert(n, obj.clone());
        }
        obj
    }

    fn gen_of(&self, n: u32) -> u16 {
        match self.xref.get(&n) {
            Some(Entry::At(_, g)) => *g,
            _ => 0,
        }
    }

    fn in_objstm(&mut self, s: u32, ix: u32, n: u32) -> Obj {
        let Some(stm) = self.objstm(s) else { return Obj::Null };
        let pos = match stm.offsets.get(ix as usize) {
            Some((num, off)) if *num == n => Some(*off),
            _ => stm.offsets.iter().find(|(num, _)| *num == n).map(|(_, o)| *o),
        };
        let Some(off) = pos else { return Obj::Null };
        let mut lx = Lexer::at(&stm.data, stm.first + off);
        lx.object().unwrap_or(Obj::Null)
    }

    fn objstm(&mut self, s: u32) -> Option<std::rc::Rc<ObjStm>> {
        if let Some(cached) = self.objstm.get(&s) {
            return cached.clone();
        }
        self.objstm.insert(s, None);
        let obj = self.get(s);
        let parsed = (|| {
            let Obj::Stream(dict, data) = &obj else { return None };
            let data = self.stream_decoded(s, dict, *data, usize::MAX).ok()?;
            let first = usize::try_from(dict.int("First")?).ok()?;
            let count = usize::try_from(dict.int("N")?).ok()?.min(100_000);
            let mut lx = Lexer::new(data.get(..first)?);
            let mut offsets = Vec::with_capacity(count);
            for _ in 0..count {
                let (Ok(Some(Token::Obj(Obj::Int(num)))), Ok(Some(Token::Obj(Obj::Int(off))))) =
                    (lx.token(), lx.token())
                else {
                    break;
                };
                offsets.push((u32::try_from(num).ok()?, usize::try_from(off).ok()?));
            }
            let mut data = data;
            data.push(b'\n');
            Some(std::rc::Rc::new(ObjStm { data, first, offsets }))
        })();
        self.objstm.insert(s, parsed.clone());
        parsed
    }

    /// Follow a reference (one level; references to references are rare).
    pub(crate) fn resolve(&mut self, o: &Obj) -> Obj {
        match o {
            Obj::Ref(n, _) => match self.get(*n) {
                Obj::Ref(m, _) if m != *n => self.get(m),
                other => other,
            },
            other => other.clone(),
        }
    }

    /// `dict[key]`, resolved.
    pub(crate) fn key(&mut self, dict: &Dict, key: &str) -> Obj {
        dict.get(key).map_or(Obj::Null, |o| self.resolve(o))
    }

    // ---- streams -------------------------------------------------------

    /// The raw (still filtered and encrypted) bytes of a stream.
    fn stream_raw(&mut self, dict: &Dict, data: Data) -> Result<Vec<u8>, ExtractError> {
        let Data::At(start) = data;
        let declared = match dict.get("Length") {
            Some(Obj::Ref(n, _)) => {
                let n = *n;
                self.get(n).as_int()
            }
            Some(o) => o.as_int(),
            None => None,
        }
        .and_then(|l| u64::try_from(l).ok())
        .filter(|&l| start + l <= self.len);
        if let Some(l) = declared {
            let l = usize::try_from(l).unwrap_or(usize::MAX);
            if l > self.max_stream {
                return Err(ExtractError::LimitExceeded("pdf_stream_bytes".into()));
            }
            // Check that `endstream` follows; otherwise the length is wrong.
            let check = self.window(start + l as u64, 64)?;
            let skip = check.iter().take_while(|b| is_white(**b)).count();
            if check[skip..].starts_with(b"endstream") || check.len() < 9 {
                return self.window(start, l);
            }
        }
        // Search for `endstream`.
        let mut size = 1 << 16;
        loop {
            let buf = self.window(start, size)?;
            if let Some(end) = find(&buf, b"endstream") {
                let mut e = end;
                while e > 0 && matches!(buf[e - 1], b'\r' | b'\n') {
                    e -= 1;
                }
                let mut buf = buf;
                buf.truncate(e);
                return Ok(buf);
            }
            if (buf.len() as u64) < size as u64 || size >= self.max_stream {
                return Err(ExtractError::malformed("stream without endstream"));
            }
            size = (size * 4).min(self.max_stream);
        }
    }

    /// The decoded bytes of stream object `n` (decrypted, filters applied).
    fn stream_decoded(&mut self, n: u32, dict: &Dict, data: Data, max: usize) -> Result<Vec<u8>, ExtractError> {
        let raw = self.stream_raw(dict, data)?;
        let metadata = dict.name("Type") == Some("Metadata");
        let raw = match &self.crypt {
            // Cross-reference streams are never encrypted.
            Some(c)
                if dict.name("Type") != Some("XRef")
                    && !(metadata && (!c.encrypt_metadata || plain_xml(dict, &raw))) =>
            {
                c.decrypt_stream(n, self.gen_of(n), raw)?
            }
            _ => raw,
        };
        filter::decode(dict, raw, self.cx, max.min(self.max_stream))
    }

    /// The decoded bytes of `o` when it is (a reference to) a stream.
    pub(crate) fn stream_of(&mut self, o: &Obj, max: usize) -> Result<Vec<u8>, ExtractError> {
        let (n, obj) = match o {
            Obj::Ref(n, _) => (*n, self.get(*n)),
            other => (0, other.clone()),
        };
        let Obj::Stream(dict, data) = obj else { return Err(ExtractError::malformed("not a stream")) };
        self.stream_decoded(n, &dict, data, max)
    }

    /// Objects in use (free entries left out).
    pub(crate) fn object_count(&self) -> usize {
        self.xref.values().filter(|e| **e != Entry::Free).count()
    }

    /// Every object number in use, ascending.
    pub(crate) fn numbers(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.xref.iter().filter(|(_, e)| **e != Entry::Free).map(|(n, _)| *n).collect();
        v.sort_unstable();
        v
    }
}

/// An unfiltered metadata stream that is readable XML. Some writers leave
/// XMP unencrypted even when `/EncryptMetadata` says otherwise.
fn plain_xml(dict: &Dict, raw: &[u8]) -> bool {
    let start = raw.iter().position(|b| !is_white(*b)).unwrap_or(raw.len());
    filter::names(dict).is_empty()
        && (raw[start..].starts_with(b"<?xpacket") || raw[start..].starts_with(b"<x:xmpmeta"))
}

pub(crate) fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub(crate) fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// The next token of a cross-reference table. The buffer ending between
/// tokens before `trailer` means the window was too small, not that the
/// table is bad.
fn next<'a>(lx: &mut Lexer<'a>) -> Result<Token<'a>, ParseError> {
    lx.token()?.ok_or(ParseError::Incomplete)
}

/// For `obj` at `at`: the `n g` before it, and where `n` starts.
fn header_before(buf: &[u8], at: usize) -> Option<(u32, u16, usize)> {
    let mut i = at;
    let digits_back = |i: &mut usize| -> Option<(usize, usize)> {
        while *i > 0 && is_white(buf[*i - 1]) {
            *i -= 1;
        }
        let end = *i;
        while *i > 0 && buf[*i - 1].is_ascii_digit() {
            *i -= 1;
        }
        (*i < end && end - *i <= 10).then_some((*i, end))
    };
    if !buf.get(at.saturating_sub(1)).is_some_and(|b| is_white(*b)) {
        return None;
    }
    let (gs, ge) = digits_back(&mut i)?;
    let (ns, ne) = digits_back(&mut i)?;
    if ns > 0 && !is_white(buf[ns - 1]) && !super::object::is_delim(buf[ns - 1]) {
        return None;
    }
    let n: u32 = std::str::from_utf8(&buf[ns..ne]).ok()?.parse().ok()?;
    let g: u16 = std::str::from_utf8(&buf[gs..ge]).ok()?.parse().ok()?;
    Some((n, g, ns))
}
