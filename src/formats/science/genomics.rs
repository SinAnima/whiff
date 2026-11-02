//! Genomics formats:
//! * FASTA: sequences, total and N50 length, GC content, alphabet, the
//!   first identifiers; FASTQ: reads, bases, read lengths, GC content and
//!   the quality encoding;
//! * SAM, BAM and CRAM: the SAM header (version, sort order, references,
//!   read groups, the program chain, comments) and the records (mapped and
//!   unmapped for SAM and BAM; CRAM from its container headers, nothing
//!   decompressed but the header);
//! * VCF and BCF: file format, source, reference, contigs, INFO / FORMAT /
//!   FILTER definitions, samples (names only with privacy off), records
//!   and the chromosomes they fall on;
//! * BED and GFF / GTF: records, chromosomes, columns, feature types,
//!   sources and attribute keys.
//!
//! Specifications: SAM/BAM Format Specification (2024), CRAM 3.1, VCF 4.4
//! and BCF2, BGZF (SAMv1 §4.1); UCSC BED; GFF3 1.26; NCBI FASTA / FASTQ.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::plugin::{
    Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars,
};

/// Extractor for genomics formats.
pub struct Genomics;

static META: ExtractorMeta = ExtractorMeta {
    id: "science.genomics",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "fasta",
            name: "FASTA sequences",
            family: "sci",
            mimes: &["text/x-fasta"],
            extensions: &["fa", "fasta", "fna", "faa", "ffn", "fas"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "fastq",
            name: "FASTQ reads",
            family: "sci",
            mimes: &[],
            extensions: &["fq", "fastq"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "sam",
            name: "SAM alignments",
            family: "sci",
            mimes: &[],
            extensions: &["sam"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "bam",
            name: "BAM alignments",
            family: "sci",
            mimes: &[],
            extensions: &["bam"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "cram",
            name: "CRAM alignments",
            family: "sci",
            mimes: &[],
            extensions: &["cram"],
            magic: &[Magic::at(0, b"CRAM")],
            parent: None,
        },
        FormatSpec {
            id: "vcf_variants",
            name: "VCF variants",
            family: "sci",
            mimes: &[],
            extensions: &["vcf"],
            magic: &[Magic::at(0, b"##fileformat=VCF")],
            parent: Some("text"),
        },
        FormatSpec {
            id: "bcf",
            name: "BCF variants",
            family: "sci",
            mimes: &[],
            extensions: &["bcf"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "bed",
            name: "BED intervals",
            family: "sci",
            mimes: &[],
            extensions: &["bed"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "gff",
            name: "GFF / GTF features",
            family: "sci",
            mimes: &[],
            extensions: &["gff", "gff3", "gtf"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

/// Identifiers and names listed.
const MAX_NAMES: usize = 100;
/// Bytes decompressed from BAM / BCF.
const MAX_INFLATE: usize = 256 << 20;

/// A BGZF block: gzip with the `BC` extra subfield.
fn bgzf(h: &[u8]) -> bool {
    h.len() >= 18 && h[0] == 0x1f && h[1] == 0x8b && h[3] & 4 != 0 && h.get(12..14) == Some(b"BC")
}

fn names(v: impl IntoIterator<Item = String>) -> Vec<String> {
    v.into_iter().take(MAX_NAMES).map(|s| truncate_chars(&s, 200)).collect()
}

/// N50: the length at which half the bases are in sequences at least as long.
fn n50(mut lens: Vec<u64>) -> u64 {
    lens.sort_unstable_by(|a, b| b.cmp(a));
    let total: u64 = lens.iter().sum();
    let mut acc = 0;
    for l in lens {
        acc += l;
        if acc * 2 >= total {
            return l;
        }
    }
    0
}

#[allow(clippy::cast_precision_loss)] // a rounded percentage
fn gc(gc: u64, acgt: u64) -> Option<f64> {
    (acgt > 0).then(|| (gc as f64 * 1000.0 / acgt as f64).round() / 10.0)
}

fn fasta(cx: &mut Context<'_>, text: &str) {
    let (mut ids, mut lens) = (Vec::new(), Vec::new());
    let (mut g, mut acgt, mut other) = (0u64, 0u64, 0u64);
    let mut cur = 0u64;
    for line in text.lines() {
        if let Some(h) = line.strip_prefix('>') {
            if !ids.is_empty() || cur > 0 {
                lens.push(cur);
            }
            cur = 0;
            if ids.len() < MAX_NAMES {
                ids.push(h.split_whitespace().next().unwrap_or("").to_string());
            } else {
                ids.push(String::new());
            }
        } else if !line.starts_with(';') {
            for c in line.bytes() {
                match c.to_ascii_uppercase() {
                    b'G' | b'C' => {
                        g += 1;
                        acgt += 1;
                    }
                    b'A' | b'T' | b'U' => acgt += 1,
                    b'N' | b'-' | b'*' => {}
                    c if c.is_ascii_alphabetic() => other += 1,
                    _ => {}
                }
                cur += u64::from(!c.is_ascii_whitespace());
            }
        }
    }
    if !ids.is_empty() {
        lens.push(cur);
    }
    let total: u64 = lens.iter().sum();
    cx.format_set("sequences", ids.len());
    cx.format_set("total_length", total);
    if let (Some(a), Some(b)) = (lens.iter().min(), lens.iter().max()) {
        cx.format_set("min_length", *a);
        cx.format_set("max_length", *b);
    }
    cx.format_set("n50", n50(lens));
    let alphabet = if other * 10 > acgt {
        "protein"
    } else if text.contains(['U', 'u']) && !text.contains(['T', 't']) {
        "rna"
    } else {
        "dna"
    };
    cx.format_set("alphabet", alphabet);
    if alphabet != "protein"
        && let Some(p) = gc(g, acgt)
    {
        cx.format_set("gc_percent", p);
    }
    cx.format_set("identifiers", names(ids.into_iter().filter(|s| !s.is_empty())));
}

fn fastq(cx: &mut Context<'_>, text: &str) {
    let mut lines = text.lines();
    let (mut reads, mut bases, mut minq, mut maxq) = (0u64, 0u64, u8::MAX, 0u8);
    let (mut shortest, mut longest) = (u64::MAX, 0u64);
    let (mut g, mut acgt) = (0u64, 0u64);
    while let (Some(h), Some(seq), Some(_plus), Some(qual)) = (lines.next(), lines.next(), lines.next(), lines.next()) {
        if !h.starts_with('@') {
            break;
        }
        reads += 1;
        let n = seq.len() as u64;
        bases += n;
        shortest = shortest.min(n);
        longest = longest.max(n);
        for c in seq.bytes() {
            match c.to_ascii_uppercase() {
                b'G' | b'C' => {
                    g += 1;
                    acgt += 1;
                }
                b'A' | b'T' => acgt += 1,
                _ => {}
            }
        }
        for q in qual.bytes() {
            minq = minq.min(q);
            maxq = maxq.max(q);
        }
    }
    cx.format_set("reads", reads);
    cx.format_set("bases", bases);
    if reads > 0 {
        cx.format_set("min_length", shortest);
        cx.format_set("max_length", longest);
        // Phred+33 qualities reach below ';' (59); Phred+64 start at '@' (64).
        cx.format_set(
            "quality_encoding",
            if minq < 59 {
                "phred+33"
            } else if minq >= 64 {
                "phred+64"
            } else {
                "unknown"
            },
        );
        cx.format_set("quality_range", format!("{}..{}", minq.saturating_sub(33), maxq.saturating_sub(33)));
    }
    if let Some(p) = gc(g, acgt) {
        cx.format_set("gc_percent", p);
    }
}

/// The SAM header lines.
fn sam_header(cx: &mut Context<'_>, header: &str) {
    let mut refs = Vec::new();
    let mut ref_len = 0u64;
    let mut groups = Vec::new();
    let mut platforms = BTreeSet::new();
    let mut programs = Vec::new();
    let mut comments = 0u64;
    let field = |line: &str, tag: &str| line.split('\t').find_map(|f| f.strip_prefix(tag).map(str::to_string));
    for line in header.lines() {
        match line.get(..3) {
            Some("@HD") => {
                if let Some(v) = field(line, "VN:") {
                    cx.format_set("sam_version", truncate_chars(&v, 20));
                }
                if let Some(v) = field(line, "SO:") {
                    cx.format_set("sort_order", truncate_chars(&v, 30));
                }
            }
            Some("@SQ") => {
                if let Some(n) = field(line, "SN:") {
                    refs.push(n);
                }
                ref_len += field(line, "LN:").and_then(|l| l.parse::<u64>().ok()).unwrap_or(0);
            }
            Some("@RG") => {
                groups.push(field(line, "ID:").unwrap_or_default());
                if let Some(p) = field(line, "PL:") {
                    platforms.insert(p);
                }
            }
            Some("@PG") => {
                let name = field(line, "PN:").or_else(|| field(line, "ID:")).unwrap_or_default();
                programs.push(match field(line, "VN:") {
                    Some(v) => format!("{name} {v}"),
                    None => name,
                });
            }
            Some("@CO") => comments += 1,
            _ => {}
        }
    }
    cx.format_set("references", refs.len());
    if !refs.is_empty() {
        cx.format_set("reference_names", names(refs));
        cx.format_set("reference_length", ref_len);
    }
    if !groups.is_empty() {
        cx.format_set("read_groups", groups.len());
        if !cx.privacy_strict() {
            cx.format_set("read_group_ids", names(groups));
        }
        cx.format_set("platforms", platforms.into_iter().collect::<Vec<_>>());
    }
    if !programs.is_empty() {
        cx.format_set("programs", names(programs));
    }
    if comments > 0 {
        cx.format_set("comments", comments);
    }
}

fn sam(cx: &mut Context<'_>, text: &str) {
    let mut header = String::new();
    for l in text.lines().take_while(|l| l.starts_with('@')) {
        header.push_str(l);
        header.push('\n');
    }
    sam_header(cx, &header);
    let (mut records, mut unmapped) = (0u64, 0u64);
    for line in text.lines().filter(|l| !l.starts_with('@') && !l.is_empty()) {
        records += 1;
        let flag = line.split('\t').nth(1).and_then(|f| f.parse::<u16>().ok()).unwrap_or(0);
        unmapped += u64::from(flag & 4 != 0);
    }
    cx.format_set("records", records);
    cx.format_set("unmapped", unmapped);
}

/// Inflate a BGZF file (every member) up to the budget.
fn inflate(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(Vec<u8>, bool), ExtractError> {
    let (raw, cut) = cx.read_bytes(src)?;
    let d = cx.decompress(&raw, Codec::Gzip, MAX_INFLATE.min(cx.parse_limit().saturating_mul(8)))?;
    let partial = cut || !matches!(d.end, crate::plugin::End::Complete);
    Ok((d.data, partial))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn bam(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let (b, partial) = inflate(cx, src)?;
    if !b.starts_with(b"BAM\x01") {
        return Err(ExtractError::malformed("BAM magic"));
    }
    let l_text = usize::try_from(le32(&b, 4).ok_or_else(|| ExtractError::malformed("header"))?).unwrap_or(0);
    let header = String::from_utf8_lossy(b.get(8..8 + l_text).unwrap_or_default()).into_owned();
    sam_header(cx, &header);
    // The binary reference list follows; then the records.
    let mut at = 8 + l_text;
    let n_ref = le32(&b, at).unwrap_or(0);
    at += 4;
    for _ in 0..n_ref.min(1_000_000) {
        let Some(l) = le32(&b, at) else { break };
        at += 4 + usize::try_from(l).unwrap_or(0) + 4;
    }
    if header.lines().all(|l| !l.starts_with("@SQ")) {
        cx.format_set("references", n_ref);
    }
    let (mut records, mut unmapped) = (0u64, 0u64);
    while let Some(size) = le32(&b, at) {
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        let Some(rec) = b.get(at + 4..(at + 4).saturating_add(size)) else { break };
        records += 1;
        let flag = rec.get(14..16).map_or(0, |f| u16::from_le_bytes([f[0], f[1]]));
        unmapped += u64::from(flag & 4 != 0);
        at += 4 + size;
    }
    cx.format_set("records", records);
    cx.format_set("unmapped", unmapped);
    if partial {
        cx.format_set("records_partial", true);
    }
    Ok(())
}

/// ITF8 and LTF8 integers (CRAM).
fn itf8(b: &[u8], at: &mut usize) -> Option<i64> {
    let x = *b.get(*at)?;
    let n = x.leading_ones() as usize;
    let n = n.min(4);
    let mut v = i64::from(x & (0xff >> (n + 1)));
    if n == 4 {
        v = i64::from(x & 0x0f);
        for i in 1..4 {
            v = v << 8 | i64::from(*b.get(*at + i)?);
        }
        v = v << 4 | i64::from(*b.get(*at + 4)? & 0x0f);
        *at += 5;
        return Some(v);
    }
    for i in 1..=n {
        v = v << 8 | i64::from(*b.get(*at + i)?);
    }
    *at += n + 1;
    Some(v)
}

fn ltf8(b: &[u8], at: &mut usize) -> Option<i64> {
    let x = *b.get(*at)?;
    let n = x.leading_ones() as usize;
    let mut v = if n >= 8 { 0 } else { i64::from(x & (0xff >> (n + 1))) };
    for i in 1..=n.min(8) {
        v = v << 8 | i64::from(*b.get(*at + i)?);
    }
    *at += n.min(8) + 1;
    Some(v)
}

fn cram(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("CRAM container");
    let def = src.read_vec(0, 26).map_err(|_| bad())?;
    let (major, minor) = (def[4], def[5]);
    cx.format_set("cram_version", format!("{major}.{minor}"));
    let len = src.len();
    let mut at = 26u64;
    let (mut containers, mut records, mut bases) = (0u64, 0i64, 0i64);
    let mut header_done = false;
    while at.checked_add(4).is_some_and(|e| e <= len) && containers < 10_000_000 {
        if containers % 4096 == 0 {
            cx.checkpoint()?;
        }
        let h = src.read_vec(at, usize::try_from((len - at).min(64)).unwrap_or(0)).map_err(|_| bad())?;
        let clen = i64::from(i32::from_le_bytes(h[..4].try_into().map_err(|_| bad())?));
        let mut i = 4;
        let _ref_id = itf8(&h, &mut i);
        let _start = itf8(&h, &mut i);
        let _span = itf8(&h, &mut i);
        let n = itf8(&h, &mut i).ok_or_else(bad)?;
        if major >= 3 {
            ltf8(&h, &mut i).ok_or_else(bad)?;
            bases += ltf8(&h, &mut i).ok_or_else(bad)?;
        } else {
            itf8(&h, &mut i).ok_or_else(bad)?;
            bases += ltf8(&h, &mut i).ok_or_else(bad)?;
        }
        let _blocks = itf8(&h, &mut i);
        let landmarks = itf8(&h, &mut i).ok_or_else(bad)?;
        for _ in 0..landmarks.clamp(0, 10_000) {
            itf8(&h, &mut i).ok_or_else(bad)?;
        }
        if major >= 3 {
            i += 4; // CRC32
        }
        let body = at + i as u64;
        if header_done {
            records += n.max(0);
        } else {
            // The first container holds the SAM header block.
            header_done = true;
            let size = usize::try_from(clen.max(0)).unwrap_or(0).min(cx.parse_limit());
            let blk = src.read_vec(body, size).map_err(|_| bad())?;
            let method = *blk.first().ok_or_else(bad)?;
            let mut j = 2;
            itf8(&blk, &mut j).ok_or_else(bad)?;
            let csize = usize::try_from(itf8(&blk, &mut j).ok_or_else(bad)?).map_err(|_| bad())?;
            let rsize = usize::try_from(itf8(&blk, &mut j).ok_or_else(bad)?).map_err(|_| bad())?;
            let data = blk.get(j..j + csize).ok_or_else(bad)?;
            let raw = match method {
                0 => data.to_vec(),
                1 => cx.decompress(data, Codec::Gzip, rsize.min(16 << 20))?.data,
                2 => cx.decompress(data, Codec::Bzip2, rsize.min(16 << 20))?.data,
                3 => cx.decompress(data, Codec::Xz, rsize.min(16 << 20))?.data,
                _ => Vec::new(),
            };
            if let Some(l) = le32(&raw, 0) {
                let text = String::from_utf8_lossy(raw.get(4..4 + usize::try_from(l).unwrap_or(0)).unwrap_or_default())
                    .into_owned();
                sam_header(cx, &text);
            }
        }
        containers += 1;
        match body.checked_add(u64::try_from(clen.max(0)).unwrap_or(0)) {
            Some(next) if next > at => at = next,
            _ => break,
        }
    }
    cx.format_set("containers", containers);
    cx.format_set("records", records);
    cx.format_set("bases", bases);
    Ok(())
}

/// VCF header lines and records (text from a `.vcf` or BCF's header).
fn vcf(cx: &mut Context<'_>, text: &str, records_text: bool) {
    let mut defs: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut contigs = 0u64;
    let mut samples = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("##") {
            let (k, v) = rest.split_once('=').unwrap_or((rest, ""));
            match k {
                "fileformat" => cx.format_set("file_format", truncate_chars(v, 20)),
                "source" => cx.format_set("source", truncate_chars(v, 200)),
                "reference" => cx.format_set("reference", truncate_chars(v, 300)),
                "contig" => contigs += 1,
                "INFO" | "FORMAT" | "FILTER" | "ALT" => {
                    let id = v.split("ID=").nth(1).and_then(|s| s.split([',', '>']).next()).unwrap_or("");
                    let key = match k {
                        "INFO" => "info",
                        "FORMAT" => "format_fields",
                        "FILTER" => "filters",
                        _ => "alt",
                    };
                    defs.entry(key).or_default().push(id.to_string());
                }
                _ => {}
            }
        } else if let Some(h) = line.strip_prefix("#CHROM") {
            samples = h.split('\t').skip(9).map(str::to_string).collect();
            break;
        }
    }
    cx.format_set("contigs", contigs);
    for (k, v) in defs {
        cx.format_set(k, names(v));
    }
    cx.format_set("samples", samples.len());
    if !samples.is_empty() && !cx.privacy_strict() {
        cx.format_set("sample_names", names(samples));
    }
    if records_text {
        let mut chroms: BTreeMap<String, u64> = BTreeMap::new();
        let mut records = 0u64;
        for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            records += 1;
            if let Some(c) = line.split('\t').next()
                && (chroms.len() < 1000 || chroms.contains_key(c))
            {
                *chroms.entry(truncate_chars(c, 100)).or_default() += 1;
            }
        }
        cx.format_set("records", records);
        cx.format_set(
            "chromosomes",
            Value::Object(chroms.into_iter().take(MAX_NAMES).map(|(k, v)| (k, v.into())).collect()),
        );
    }
}

fn bcf(cx: &mut Context<'_>, src: &mut dyn Source) -> Result<(), ExtractError> {
    let (b, partial) = inflate(cx, src)?;
    if !b.starts_with(b"BCF") {
        return Err(ExtractError::malformed("BCF magic"));
    }
    cx.format_set("bcf_version", format!("{}.{}", b.get(3).copied().unwrap_or(0), b.get(4).copied().unwrap_or(0)));
    let l_text = usize::try_from(le32(&b, 5).ok_or_else(|| ExtractError::malformed("header"))?).unwrap_or(0);
    let text = String::from_utf8_lossy(b.get(9..9 + l_text).unwrap_or_default()).into_owned();
    vcf(cx, &text, false);
    // Records: shared and individual lengths, then the data.
    let mut at = 9 + l_text;
    let mut records = 0u64;
    while let (Some(shared), Some(indiv)) = (le32(&b, at), le32(&b, at + 4)) {
        let next =
            at + 8 + usize::try_from(shared).unwrap_or(usize::MAX) + usize::try_from(indiv).unwrap_or(usize::MAX);
        if next > b.len() {
            break;
        }
        records += 1;
        at = next;
    }
    cx.format_set("records", records);
    if partial {
        cx.format_set("records_partial", true);
    }
    Ok(())
}

fn bed(cx: &mut Context<'_>, text: &str) {
    let (mut records, mut cols) = (0u64, BTreeSet::new());
    let mut chroms: BTreeMap<String, u64> = BTreeMap::new();
    for line in text.lines() {
        if line.starts_with("track") {
            if let Some(n) = line.split("name=").nth(1) {
                let n = n.trim_start_matches('"');
                let n = n.split(['"', ' ']).next().unwrap_or("");
                cx.format_set("track_name", truncate_chars(n, 200));
            }
            continue;
        }
        if line.starts_with('#') || line.starts_with("browser") || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        records += 1;
        cols.insert(f.len());
        if chroms.len() < 1000 || chroms.contains_key(f[0]) {
            *chroms.entry(truncate_chars(f[0], 100)).or_default() += 1;
        }
    }
    cx.format_set("records", records);
    cx.format_set("columns", cols.into_iter().collect::<Vec<_>>());
    cx.format_set(
        "chromosomes",
        Value::Object(chroms.into_iter().take(MAX_NAMES).map(|(k, v)| (k, v.into())).collect()),
    );
}

fn gff(cx: &mut Context<'_>, text: &str) {
    let (mut records, mut regions) = (0u64, 0u64);
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut sources = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut seqids = BTreeSet::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("##gff-version") {
            cx.format_set("gff_version", truncate_chars(v.trim(), 20));
        } else if line.starts_with("##sequence-region") {
            regions += 1;
        } else if line.starts_with("##FASTA") {
            cx.format_set("embedded_fasta", true);
            break;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 8 {
            continue;
        }
        records += 1;
        if seqids.len() < 1000 {
            seqids.insert(truncate_chars(f[0], 100));
        }
        if sources.len() < 100 {
            sources.insert(truncate_chars(f[1], 100));
        }
        if types.len() < 500 || types.contains_key(f[2]) {
            *types.entry(truncate_chars(f[2], 100)).or_default() += 1;
        }
        if let Some(a) = f.get(8) {
            for kv in a.split(';').take(50) {
                // GFF3 `key=value`; GTF `key "value"`.
                let k = kv.trim().split(['=', ' ']).next().unwrap_or("");
                if !k.is_empty() && keys.len() < 200 {
                    keys.insert(truncate_chars(k, 50));
                }
            }
        }
    }
    cx.format_set("records", records);
    if regions > 0 {
        cx.format_set("sequence_regions", regions);
    }
    cx.format_set("seqids", names(seqids));
    cx.format_set("feature_types", Value::Object(types.into_iter().map(|(k, v)| (k, v.into())).collect::<Map<_, _>>()));
    cx.format_set("sources", sources.into_iter().collect::<Vec<_>>());
    cx.format_set("attribute_keys", keys.into_iter().collect::<Vec<_>>());
}

impl Extractor for Genomics {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or_default();
        let sure = |format| Some(Sniff { format, confidence: 0.98 });
        if bgzf(h) {
            return match ext {
                "bam" => sure("bam"),
                "bcf" => sure("bcf"),
                _ => None,
            };
        }
        let text = std::str::from_utf8(&h[..h.len().min(4096)]).unwrap_or("");
        let mut lines = text.lines();
        let first = lines.next().unwrap_or("");
        if first.starts_with("##fileformat=VCF") {
            return sure("vcf_variants");
        }
        if first.starts_with("##gff-version") {
            return sure("gff");
        }
        if first.starts_with("@HD\t") || first.starts_with("@SQ\t") {
            return sure("sam");
        }
        let seq = |l: &str| !l.is_empty() && l.bytes().all(|c| c.is_ascii_alphabetic() || c == b'*' || c == b'-');
        if first.starts_with('>') && lines.next().is_some_and(seq) {
            return Some(Sniff { format: "fasta", confidence: if ext.starts_with('f') { 0.95 } else { 0.85 } });
        }
        if first.starts_with('@') {
            let l: Vec<&str> = text.lines().take(4).collect();
            if l.len() == 4 && seq(l[1]) && l[2].starts_with('+') && l[3].len() == l[1].len() {
                return Some(Sniff { format: "fastq", confidence: 0.95 });
            }
        }
        let tabbed = |l: &str, n: usize| {
            l.split('\t').count() >= n && l.split('\t').nth(1).is_some_and(|c| c.parse::<u64>().is_ok())
        };
        if ext == "bed"
            && text
                .lines()
                .find(|l| !l.starts_with("track") && !l.starts_with('#') && !l.starts_with("browser"))
                .is_some_and(|l| tabbed(l, 3))
        {
            return sure("bed");
        }
        if matches!(ext, "gff" | "gff3" | "gtf")
            && text.lines().find(|l| !l.starts_with('#')).is_some_and(|l| l.split('\t').count() >= 8)
        {
            return sure("gff");
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id().to_string().as_str() {
            "bam" => bam(cx, src),
            "cram" => cram(cx, src),
            "bcf" => bcf(cx, src),
            id => {
                let text = cx.read_text(src)?.text;
                match id {
                    "fasta" => fasta(cx, &text),
                    "fastq" => fastq(cx, &text),
                    "sam" => sam(cx, &text),
                    "vcf_variants" => vcf(cx, &text, true),
                    "bed" => bed(cx, &text),
                    _ => gff(cx, &text),
                }
                Ok(())
            }
        }
    }
}

crate::register_extractor!(Genomics);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cram_integers() {
        let mut at = 0;
        assert_eq!(itf8(&[0x7f], &mut at), Some(127));
        at = 0;
        assert_eq!(itf8(&[0x81, 0x00], &mut at), Some(256));
        at = 0;
        assert_eq!(ltf8(&[0xc0, 0x01, 0x00], &mut at), Some(256));
        assert_eq!(n50(vec![2, 3, 4, 5, 6]), 5);
    }

    crate::fixture_tests!("fasta", "fastq", "sam", "bam", "cram", "vcf_variants", "bcf", "bed", "gff");
}
