//! Rich Text Format (RTF 1.0–1.9.1), read with an in-house tokenizer.
//!
//! Reads the `\info` group (title, subject, author, operator, manager,
//! company, category, keywords, comments, dates, revision and editing time,
//! statistics), user properties, the generator, code page and fonts, style
//! names and the heading outline, the body text (in the document's and each
//! font's code page, plus `\u` escapes), comments, fields and hyperlinks,
//! pictures, tracked changes and protection. Embedded OLE objects are
//! flagged and their native data becomes a child; linked and
//! auto-updating objects, DDE fields and remote includes are risks.
//!
//! Specification: Microsoft Rich Text Format (RTF) Specification 1.9.1.

use std::collections::{BTreeMap, HashMap};

use encoding_rs::Encoding;
use serde_json::{Value, json};

use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Map, Source, TextRole,
    truncate_chars,
};

/// Extractor for RTF documents.
pub struct Rtf;

static META: ExtractorMeta = ExtractorMeta {
    id: "doc.rtf",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "rtf",
        name: "Rich Text Format",
        family: "doc.rtf",
        mimes: &["application/rtf", "text/rtf"],
        extensions: &["rtf"],
        magic: &[Magic::prefix(b"{\\rtf")],
        parent: None,
    }],
};

const MAX_DEPTH: usize = 512;
const MAX_LISTED: usize = 200;

impl Extractor for Rtf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, _) = cx.read_bytes(src)?;
        let mut p = Parser::new(cx);
        p.run(&bytes)?;
        p.finish();
        Ok(())
    }
}

crate::register_extractor!(Rtf);

/// Where text in the current group goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dest {
    Body,
    /// Not text: tables, pictures, unknown `\*` destinations.
    Skip,
    FontTable,
    StyleSheet,
    Info(&'static str),
    InfoTime(&'static str),
    UserPropName,
    UserPropValue,
    Generator,
    FieldInst,
    Annotation,
    AnnotAuthor,
    ObjClass,
    ObjData,
    RevTable,
}

#[derive(Debug, Clone)]
struct State {
    dest: Dest,
    /// Fallback characters after `\uN` (`\ucN`).
    uc: usize,
    /// Code page of the current font.
    codepage: Option<u16>,
    /// Group opened an `\object`, `\field`, `\pict`, `\fonttbl` entry…
    group: Group,
    /// Inside `\info`.
    info: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    Plain,
    Object,
    Field,
    Pict,
    FontEntry,
    StyleEntry,
    Time,
    UserProp,
}

#[derive(Default)]
struct Object {
    class: Option<String>,
    kind: &'static str,
    update: bool,
    hex: Vec<u8>,
    hex_hi: Option<u8>,
}

struct Parser<'c, 'x> {
    cx: &'c mut Context<'x>,
    stack: Vec<State>,
    state: State,
    /// Document code page (`\ansicpgN`, `\mac`, `\pc`).
    codepage: u16,
    fonts: HashMap<i64, (String, Option<u16>)>,
    font_entry: Option<i64>,
    font_charset: Option<u16>,
    styles: HashMap<i64, String>,
    style_entry: Option<i64>,
    /// Pending bytes from `\'hh` or 8-bit text, decoded together.
    bytes: Vec<u8>,
    skip_fallback: usize,
    high_surrogate: Option<u16>,
    text: String,
    para: String,
    para_style: Option<i64>,
    para_outline: Option<u8>,
    paragraphs: u64,
    info: Map,
    time: BTreeMap<&'static str, i64>,
    info_text: String,
    prop_name: String,
    prop_value: String,
    user_props: Map,
    generator: String,
    field_inst: String,
    fields: BTreeMap<String, u64>,
    links: Vec<String>,
    risky_fields: Vec<(&'static str, String)>,
    comments: Vec<String>,
    comment: String,
    comment_authors: u64,
    objects: Vec<Object>,
    object: Option<Object>,
    pictures: BTreeMap<&'static str, u64>,
    revisions: u64,
    rev_authors: u64,
    protection: Vec<&'static str>,
    format: Map,
    depth_warned: bool,
}

impl<'c, 'x> Parser<'c, 'x> {
    fn new(cx: &'c mut Context<'x>) -> Self {
        Self {
            cx,
            stack: Vec::new(),
            state: State { dest: Dest::Body, uc: 1, codepage: None, group: Group::Plain, info: false },
            codepage: 1252,
            fonts: HashMap::new(),
            font_entry: None,
            font_charset: None,
            styles: HashMap::new(),
            style_entry: None,
            bytes: Vec::new(),
            skip_fallback: 0,
            high_surrogate: None,
            text: String::new(),
            para: String::new(),
            para_style: None,
            para_outline: None,
            paragraphs: 0,
            info: Map::new(),
            time: BTreeMap::new(),
            info_text: String::new(),
            prop_name: String::new(),
            prop_value: String::new(),
            user_props: Map::new(),
            generator: String::new(),
            field_inst: String::new(),
            fields: BTreeMap::new(),
            links: Vec::new(),
            risky_fields: Vec::new(),
            comments: Vec::new(),
            comment: String::new(),
            comment_authors: 0,
            objects: Vec::new(),
            object: None,
            pictures: BTreeMap::new(),
            revisions: 0,
            rev_authors: 0,
            protection: Vec::new(),
            format: Map::new(),
            depth_warned: false,
        }
    }

    fn run(&mut self, data: &[u8]) -> Result<(), ExtractError> {
        let mut i = 0usize;
        let mut ignorable = false;
        let mut steps = 0u32;
        while i < data.len() {
            steps = steps.wrapping_add(1);
            if steps.is_multiple_of(65_536) {
                self.cx.checkpoint()?;
            }
            let b = data[i];
            match b {
                b'{' => {
                    self.flush_bytes();
                    if self.stack.len() >= MAX_DEPTH {
                        if !self.depth_warned {
                            self.cx.warn("groups nested too deeply; inner groups ignored");
                            self.depth_warned = true;
                        }
                        i = skip_group(data, i);
                        continue;
                    }
                    self.stack.push(self.state.clone());
                    self.state.group = Group::Plain;
                    i += 1;
                }
                b'}' => {
                    self.flush_bytes();
                    self.end_group();
                    if let Some(s) = self.stack.pop() {
                        self.state = s;
                    }
                    i += 1;
                }
                b'\\' => {
                    let (end, word, param) = control(data, i + 1);
                    i = end;
                    match word {
                        Ctl::Symbol(b'\'') => {
                            if let Some(v) = data
                                .get(i..i + 2)
                                .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok())
                            {
                                i += 2;
                                if self.skip_fallback > 0 {
                                    self.skip_fallback -= 1;
                                } else {
                                    self.bytes.push(v);
                                }
                            }
                        }
                        Ctl::Symbol(b'*') => ignorable = true,
                        Ctl::Symbol(c) => {
                            if self.skip_fallback > 0 {
                                self.skip_fallback -= 1;
                                continue;
                            }
                            self.flush_bytes();
                            match c {
                                b'\\' | b'{' | b'}' => self.push_char(char::from(c)),
                                b'~' => self.push_char('\u{A0}'),
                                b'_' => self.push_char('\u{2011}'),
                                b'\n' | b'\r' => self.end_paragraph(),
                                b'\t' => self.push_char('\t'),
                                _ => {}
                            }
                        }
                        Ctl::Word(w) => {
                            self.flush_bytes();
                            let was_ignorable = std::mem::take(&mut ignorable);
                            if self.skip_fallback > 0 && w != b"u" {
                                // A control word counts as one fallback character.
                                self.skip_fallback -= 1;
                                continue;
                            }
                            self.word(w, param, was_ignorable);
                        }
                    }
                }
                b'\r' | b'\n' => i += 1,
                _ => {
                    // Plain text: decode runs of bytes together.
                    let start = i;
                    while i < data.len() && !matches!(data[i], b'{' | b'}' | b'\\' | b'\r' | b'\n') {
                        i += 1;
                    }
                    let mut run = &data[start..i];
                    while self.skip_fallback > 0 && !run.is_empty() {
                        self.skip_fallback -= 1;
                        run = &run[1..];
                    }
                    if self.state.dest == Dest::ObjData {
                        self.hex(run);
                    } else {
                        self.bytes.extend_from_slice(run);
                    }
                }
            }
        }
        self.flush_bytes();
        self.end_paragraph();
        Ok(())
    }

    fn set_dest(&mut self, dest: Dest) {
        self.state.dest = dest;
    }

    /// One control word.
    #[allow(clippy::too_many_lines)] // one match over the control words
    fn word(&mut self, w: &[u8], param: Option<i64>, ignorable: bool) {
        let dest = self.state.dest;
        let n = param.unwrap_or(1);
        match w {
            // ---- document ----
            b"rtf" => {
                self.format.insert("rtf_version".into(), json!(n));
            }
            b"ansicpg" => {
                if let Ok(cp) = u16::try_from(n) {
                    self.codepage = cp;
                    self.format.insert("codepage".into(), json!(cp));
                }
            }
            b"mac" => self.codepage = 10_000,
            b"pc" => self.codepage = 437,
            b"pca" => self.codepage = 850,
            b"deflang" | b"deflangfe" if !self.format.contains_key("default_language_id") => {
                self.format.insert("default_language_id".into(), json!(n));
            }
            b"fromhtml" => {
                self.format.insert("from_html".into(), json!(true));
            }
            b"fromtext" => {
                self.format.insert("from_text".into(), json!(true));
            }
            b"cocoartf" => {
                self.format.insert("cocoa_rtf".into(), json!(n));
            }
            b"uc" => self.state.uc = usize::try_from(n).unwrap_or(1).min(8),
            b"u" => {
                let v = u16::try_from(if n < 0 { n + 65_536 } else { n }).unwrap_or(0x3F);
                self.unicode(v);
                self.skip_fallback = self.state.uc;
            }
            // ---- destinations ----
            b"fonttbl" => self.set_dest(Dest::FontTable),
            b"stylesheet" => self.set_dest(Dest::StyleSheet),
            b"colortbl"
            | b"listtable"
            | b"listoverridetable"
            | b"rsidtbl"
            | b"themedata"
            | b"colorschememapping"
            | b"datastore"
            | b"latentstyles"
            | b"xmlnstbl"
            | b"mmathPr"
            | b"pgdsctbl"
            | b"filetbl"
            | b"bkmkstart"
            | b"bkmkend"
            | b"atnid"
            | b"atndate"
            | b"atnref"
            | b"datafield"
            | b"docvar"
            | b"expandedcolortbl"
            | b"wgrffmtfilter"
            | b"passwordhash"
            | b"panose"
            | b"falt"
            | b"fname"
            | b"listtext"
            | b"pntext"
            | b"pntxta"
            | b"pntxtb"
            | b"xe"
            | b"tc"
            | b"txe"
            | b"bkmkcolf"
            | b"bkmkcoll"
            | b"protusertbl"
            | b"blipuid"
            | b"shpinst"
            | b"sp"
            | b"sn"
            | b"sv"
            | b"nonshppict"
            | b"result"
            | b"objalias"
            | b"objsect"
            | b"objname"
            | b"objtime"
            | b"defchp"
            | b"defpap"
            | b"mailmerge"
            | b"keycode" => {
                self.set_dest(Dest::Skip);
            }
            b"info" => {
                self.state.info = true;
                self.set_dest(Dest::Skip);
            }
            b"title" | b"subject" | b"author" | b"manager" | b"company" | b"operator" | b"category" | b"keywords"
            | b"comment" | b"doccomm" | b"hlinkbase"
                if self.state.info =>
            {
                let key: &'static str = match w {
                    b"title" => "title",
                    b"subject" => "subject",
                    b"author" => "author",
                    b"manager" => "manager",
                    b"company" => "company",
                    b"operator" => "operator",
                    b"category" => "category",
                    b"keywords" => "keywords",
                    b"comment" => "comment",
                    b"doccomm" => "doccomm",
                    _ => "hlinkbase",
                };
                self.info_text.clear();
                self.set_dest(Dest::Info(key));
            }
            b"creatim" | b"revtim" | b"printim" | b"buptim" if self.state.info => {
                let key = match w {
                    b"creatim" => "creatim",
                    b"revtim" => "revtim",
                    b"printim" => "printim",
                    _ => "buptim",
                };
                self.time.clear();
                self.state.group = Group::Time;
                self.set_dest(Dest::InfoTime(key));
            }
            b"yr" | b"mo" | b"dy" | b"hr" | b"min" | b"sec" if matches!(dest, Dest::InfoTime(_)) => {
                let k = match w {
                    b"yr" => "yr",
                    b"mo" => "mo",
                    b"dy" => "dy",
                    b"hr" => "hr",
                    b"min" => "min",
                    _ => "sec",
                };
                self.time.insert(k, n);
            }
            b"version" | b"vern" | b"edmins" | b"nofpages" | b"nofwords" | b"nofchars" | b"nofcharsws" | b"id"
                if self.state.info =>
            {
                self.info.insert(String::from_utf8_lossy(w).into_owned(), json!(n));
            }
            b"userprops" => self.set_dest(Dest::Skip),
            b"propname" => {
                self.prop_name.clear();
                self.state.group = Group::UserProp;
                self.set_dest(Dest::UserPropName);
            }
            b"staticval" => {
                self.prop_value.clear();
                self.set_dest(Dest::UserPropValue);
            }
            b"generator" => {
                self.generator.clear();
                self.set_dest(Dest::Generator);
            }
            b"header" | b"headerl" | b"headerr" | b"headerf" | b"footer" | b"footerl" | b"footerr" | b"footerf"
            | b"footnote" => {
                self.end_paragraph();
                self.set_dest(Dest::Body);
            }
            b"annotation" => {
                self.comment.clear();
                self.set_dest(Dest::Annotation);
            }
            b"atnauthor" => {
                self.comment_authors += 1;
                self.set_dest(Dest::AnnotAuthor);
            }
            b"revtbl" => self.set_dest(Dest::RevTable),
            b"field" => self.state.group = Group::Field,
            b"fldinst" => {
                self.field_inst.clear();
                self.set_dest(Dest::FieldInst);
            }
            b"fldrslt" => self.set_dest(Dest::Body),
            b"pict" => {
                self.state.group = Group::Pict;
                self.set_dest(Dest::Skip);
            }
            b"pngblip" | b"jpegblip" | b"emfblip" | b"wmetafile" | b"macpict" | b"dibitmap" | b"wbitmap"
            | b"pmmetafile"
                if self.state.group == Group::Pict =>
            {
                let k = match w {
                    b"pngblip" => "png",
                    b"jpegblip" => "jpeg",
                    b"emfblip" => "emf",
                    b"wmetafile" => "wmf",
                    b"macpict" => "pict",
                    b"pmmetafile" => "os2_metafile",
                    _ => "bitmap",
                };
                *self.pictures.entry(k).or_default() += 1;
            }
            b"object" => {
                self.state.group = Group::Object;
                self.object = Some(Object { kind: "embedded", ..Object::default() });
                self.set_dest(Dest::Skip);
            }
            b"objemb" | b"objlink" | b"objautlink" | b"objsub" | b"objpub" | b"objicemb" | b"objhtml" | b"objocx" => {
                if let Some(o) = self.object.as_mut() {
                    o.kind = match w {
                        b"objemb" => "embedded",
                        b"objlink" => "linked",
                        b"objautlink" => "auto_linked",
                        b"objsub" => "subscriber",
                        b"objpub" => "publisher",
                        b"objicemb" => "icon_embedded",
                        b"objhtml" => "html_control",
                        _ => "activex",
                    };
                }
            }
            b"objupdate" => {
                if let Some(o) = self.object.as_mut() {
                    o.update = true;
                }
            }
            b"objclass" => self.set_dest(Dest::ObjClass),
            b"objdata" => self.set_dest(Dest::ObjData),
            // ---- fonts and styles ----
            b"f" if dest == Dest::FontTable => {
                // Font tables without a group per font: `\f0 Arial;\f1 Courier;`.
                self.end_font();
                self.font_entry = Some(n);
                self.font_charset = None;
                self.state.group = Group::FontEntry;
                self.info_text.clear();
            }
            b"fcharset" if dest == Dest::FontTable => self.font_charset = charset_codepage(n),
            b"cpg" if dest == Dest::FontTable => self.font_charset = u16::try_from(n).ok(),
            b"f" if dest == Dest::Body || dest == Dest::Annotation => {
                self.state.codepage = self.fonts.get(&n).and_then(|f| f.1);
            }
            b"s" | b"cs" | b"ds" | b"ts" if dest == Dest::StyleSheet => {
                if w == b"s" || self.style_entry.is_none() {
                    self.style_entry = Some(if w == b"s" { n } else { -1 - n });
                }
                self.state.group = Group::StyleEntry;
                self.info_text.clear();
            }
            b"s" if dest == Dest::Body => self.para_style = Some(n),
            b"outlinelevel" if dest == Dest::Body => self.para_outline = u8::try_from(n).ok(),
            b"pard" if dest == Dest::Body => {
                self.para_style = None;
                self.para_outline = None;
            }
            // ---- text ----
            b"par" | b"sect" | b"page" | b"row" | b"line" => {
                if matches!(dest, Dest::Body) {
                    self.end_paragraph();
                } else if dest == Dest::Annotation {
                    self.comment.push('\n');
                }
            }
            b"tab" | b"cell" => self.push_char('\t'),
            b"emdash" => self.push_char('\u{2014}'),
            b"endash" => self.push_char('\u{2013}'),
            b"bullet" => self.push_char('\u{2022}'),
            b"lquote" => self.push_char('\u{2018}'),
            b"rquote" => self.push_char('\u{2019}'),
            b"ldblquote" => self.push_char('\u{201C}'),
            b"rdblquote" => self.push_char('\u{201D}'),
            b"emspace" | b"enspace" | b"qmspace" => self.push_char(' '),
            // ---- tracked changes and protection ----
            b"deleted" | b"revised" if n != 0 => self.revisions += 1,
            b"revprot" => self.protection.push("revisions"),
            b"annotprot" => self.protection.push("comments"),
            b"formprot" => self.protection.push("forms"),
            b"readprot" => self.protection.push("read_only"),
            b"protlevel" => {
                self.protection.push(match n {
                    0 => "revisions",
                    1 => "comments",
                    2 => "forms",
                    _ => "read_only",
                });
            }
            _ if ignorable && !matches!(dest, Dest::Skip) => {
                // Unknown `\*` destination: its text is not document text.
                self.set_dest(Dest::Skip);
            }
            _ => {}
        }
    }

    fn end_group(&mut self) {
        let parent = self.stack.last().map(|s| s.dest);
        let leaving = self.state.dest;
        if Some(leaving) != parent {
            match leaving {
                Dest::Info(key) => {
                    let v = self.info_text.trim().to_string();
                    if !v.is_empty() && !self.info.contains_key(key) {
                        self.info.insert(key.into(), json!(truncate_chars(&v, 2000)));
                    }
                    self.info_text.clear();
                }
                Dest::InfoTime(key) => {
                    if let Some(t) = self.time_value() {
                        self.info.insert(key.into(), json!(t));
                    }
                }
                Dest::UserPropValue => {
                    if !self.prop_name.trim().is_empty() && self.user_props.len() < 100 {
                        self.user_props.insert(
                            self.prop_name.trim().to_string(),
                            json!(self.cx.redact_secrets(&truncate_chars(self.prop_value.trim(), 500))),
                        );
                    }
                }
                Dest::Generator => {
                    let g = self.generator.trim().trim_end_matches(';').trim().to_string();
                    if !g.is_empty() {
                        self.format.insert("generator".into(), json!(truncate_chars(&g, 200)));
                    }
                }
                Dest::FieldInst => {
                    let instr = std::mem::take(&mut self.field_inst);
                    self.field(&instr);
                }
                Dest::Annotation => {
                    let c = crate::plugin::squash_whitespace(&self.comment);
                    if !c.is_empty() && self.comments.len() < 1000 {
                        self.comments.push(c);
                    }
                }
                _ => {}
            }
        }
        match self.state.group {
            Group::FontEntry if self.state.dest == Dest::FontTable => self.end_font(),
            Group::StyleEntry if self.state.dest == Dest::StyleSheet => self.end_style(),
            Group::Object => {
                if let Some(o) = self.object.take()
                    && self.objects.len() < 1000
                {
                    self.objects.push(o);
                }
            }
            _ => {}
        }
        if leaving == Dest::RevTable && parent != Some(Dest::RevTable) {
            // The first entry is the "Unknown" author.
            self.rev_authors = self.rev_authors.saturating_sub(1);
        }
    }

    fn end_font(&mut self) {
        if let Some(id) = self.font_entry.take() {
            let name = self.info_text.trim().trim_end_matches(';').trim().to_string();
            if self.fonts.len() < 10_000 {
                self.fonts.insert(id, (name, self.font_charset));
            }
        }
        self.info_text.clear();
    }

    fn end_style(&mut self) {
        if let Some(id) = self.style_entry.take() {
            let name = self.info_text.trim().trim_end_matches(';').trim().to_string();
            if self.styles.len() < 10_000 && !name.is_empty() {
                self.styles.insert(id, name);
            }
        }
        self.info_text.clear();
    }

    fn time_value(&self) -> Option<String> {
        let g = |k| self.time.get(k).copied().unwrap_or(0);
        let y = g("yr");
        if !(1000..=9999).contains(&y) {
            return None;
        }
        let (mo, d) = (g("mo").clamp(1, 12), g("dy").clamp(1, 31));
        Some(format!(
            "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}",
            g("hr").clamp(0, 23),
            g("min").clamp(0, 59),
            g("sec").clamp(0, 59)
        ))
    }

    fn field(&mut self, instr: &str) {
        let instr = instr.trim();
        let Some(code) = super::field::code(instr) else { return };
        if self.fields.len() < 50 || self.fields.contains_key(&code) {
            *self.fields.entry(code).or_default() += 1;
        }
        if let Some(url) = super::field::hyperlink(instr)
            && self.links.len() < MAX_LISTED
            && !self.links.contains(&url)
        {
            self.links.push(truncate_chars(&self.cx.redact_secrets(&url), 300));
        }
        if let Some(risk) = super::field::risk(instr)
            && self.risky_fields.len() < 10
        {
            self.risky_fields.push((risk, instr.to_string()));
        }
    }

    fn hex(&mut self, run: &[u8]) {
        let Some(o) = self.object.as_mut() else { return };
        for &b in run {
            let v = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => continue,
            };
            match o.hex_hi.take() {
                Some(h) => {
                    if o.hex.len() < 256 << 20 {
                        o.hex.push(h << 4 | v);
                    }
                }
                None => o.hex_hi = Some(v),
            }
        }
    }

    fn unicode(&mut self, v: u16) {
        self.flush_bytes();
        match v {
            0xD800..=0xDBFF => self.high_surrogate = Some(v),
            0xDC00..=0xDFFF => {
                if let Some(h) = self.high_surrogate.take() {
                    let c = 0x10000 + ((u32::from(h) - 0xD800) << 10) + (u32::from(v) - 0xDC00);
                    if let Some(c) = char::from_u32(c) {
                        self.push_char(c);
                    }
                }
            }
            _ => {
                if let Some(c) = char::from_u32(u32::from(v)) {
                    self.push_char(c);
                }
            }
        }
    }

    fn flush_bytes(&mut self) {
        if self.bytes.is_empty() {
            return;
        }
        let bytes = std::mem::take(&mut self.bytes);
        let cp = self.state.codepage.unwrap_or(self.codepage);
        let text = decode(cp, &bytes);
        for c in text.chars() {
            self.push_char(c);
        }
    }

    fn push_char(&mut self, c: char) {
        match self.state.dest {
            Dest::Body => {
                if self.para.len() < 1 << 20 {
                    self.para.push(c);
                }
            }
            Dest::Info(_) | Dest::FontTable | Dest::StyleSheet => {
                if self.info_text.len() < 8192 {
                    self.info_text.push(c);
                }
            }
            Dest::UserPropName => self.prop_name.push(c),
            Dest::UserPropValue => {
                if self.prop_value.len() < 2048 {
                    self.prop_value.push(c);
                }
            }
            Dest::Generator => self.generator.push(c),
            Dest::FieldInst => {
                if self.field_inst.len() < 2048 {
                    self.field_inst.push(c);
                }
            }
            Dest::Annotation => {
                if self.comment.len() < 1 << 16 {
                    self.comment.push(c);
                }
            }
            Dest::ObjClass => {
                if let Some(o) = self.object.as_mut() {
                    let class = o.class.get_or_insert_with(String::new);
                    if class.len() < 200 {
                        class.push(c);
                    }
                }
            }
            Dest::RevTable => {
                if c == ';' {
                    self.rev_authors += 1;
                }
            }
            Dest::Skip | Dest::InfoTime(_) | Dest::AnnotAuthor | Dest::ObjData => {}
        }
    }

    fn end_paragraph(&mut self) {
        self.flush_bytes();
        let para = std::mem::take(&mut self.para);
        let line = crate::plugin::squash_whitespace(&para);
        if line.is_empty() {
            return;
        }
        self.paragraphs += 1;
        let level = self.para_outline.map(|l| l.saturating_add(1)).or_else(|| {
            let name = self.styles.get(&self.para_style?)?.to_ascii_lowercase();
            name.strip_prefix("heading ").and_then(|d| d.trim().parse::<u8>().ok())
        });
        if let Some(level) = level.filter(|l| (1..=9).contains(l)) {
            self.cx.emit_heading(level, &truncate_chars(&line, 300));
        }
        if self.text.len() < 64 << 20 {
            self.text.push_str(&line);
            self.text.push('\n');
        }
    }

    fn finish(mut self) {
        let s = |m: &Map, k: &str| m.get(k).and_then(Value::as_str).map(str::to_string);
        let info = std::mem::take(&mut self.info);
        if let Some(t) = s(&info, "title") {
            self.cx.content().source("rtf.info.title").title(&t);
            self.cx.emit_text(TextRole::Title, &t);
        }
        if let Some(d) = s(&info, "subject").or_else(|| s(&info, "doccomm")) {
            self.cx.content().source("rtf.info.subject").description(&d);
            self.cx.emit_text(TextRole::Caption, &d);
        }
        if let Some(a) = s(&info, "author") {
            self.cx.content().source("rtf.info.author").author(&a);
            self.cx.rights().source("rtf.info.author").creator(&a);
        }
        if let Some(k) = s(&info, "keywords") {
            let sep = if k.contains(';') {
                ';'
            } else if k.contains(',') {
                ','
            } else {
                ' '
            };
            for kw in k.split(sep).map(str::trim).filter(|w| !w.is_empty()).take(100) {
                self.cx.content().source("rtf.info.keywords").keyword(kw);
            }
        }
        for (key, field) in
            [("creatim", DateField::Created), ("revtim", DateField::Modified), ("printim", DateField::Printed)]
        {
            if let Some(v) = s(&info, key) {
                self.cx.temporal().source(format!("rtf.info.{key}")).content_date(field, v, false);
            }
        }
        if let Some(n) = info.get("nofpages").and_then(Value::as_u64) {
            self.cx.physical().pages(n);
        }
        if let Some(n) = info.get("nofwords").and_then(Value::as_u64) {
            self.cx.physical().words(n);
        }
        if !info.is_empty() {
            self.cx.metadata("rtf_info").extend(info);
        }
        if !self.user_props.is_empty() {
            self.cx
                .metadata("rtf_info")
                .insert("user_properties".into(), Value::Object(std::mem::take(&mut self.user_props)));
        }
        if !self.text.trim().is_empty() {
            self.cx.emit_text(TextRole::Body, &self.text);
        }
        for c in &self.comments {
            self.cx.emit_text(TextRole::Comment, c);
        }
        let mut fonts: Vec<&str> = self.fonts.values().map(|(n, _)| n.as_str()).filter(|n| !n.is_empty()).collect();
        fonts.sort_unstable();
        fonts.dedup();
        if !fonts.is_empty() {
            self.format.insert("fonts".into(), json!(fonts.iter().take(MAX_LISTED).collect::<Vec<_>>()));
        }
        if !self.styles.is_empty() {
            self.format.insert("styles".into(), json!(self.styles.len()));
        }
        self.format.insert("paragraphs".into(), json!(self.paragraphs));
        if !self.comments.is_empty() {
            self.format.insert("comments".into(), json!(self.comments.len()));
            if self.comment_authors > 0 {
                self.format.insert("comment_authors".into(), json!(self.comment_authors));
            }
        }
        if self.revisions > 0 {
            self.format.insert("tracked_changes".into(), json!(self.revisions));
        }
        if self.rev_authors > 0 {
            self.format.insert("revision_authors".into(), json!(self.rev_authors));
        }
        if !self.protection.is_empty() {
            self.protection.dedup();
            self.format.insert("protection".into(), json!(self.protection));
        }
        if !self.pictures.is_empty() {
            self.format.insert("pictures".into(), json!(self.pictures));
        }
        if !self.fields.is_empty() {
            self.format.insert("fields".into(), json!(self.fields));
        }
        if !self.links.is_empty() {
            self.cx.security().external_references(self.links.len() as u64);
            self.format.insert("links".into(), json!(self.links));
        }
        for (risk, instr) in std::mem::take(&mut self.risky_fields) {
            if risk == "dde" {
                self.cx.security().active_content("dde");
            }
            self.cx.security().risk(risk, Some(truncate_chars(&instr, 200)));
        }
        self.objects();
        let format = std::mem::take(&mut self.format);
        self.cx.format().extend(format);
    }

    fn objects(&mut self) {
        if self.objects.is_empty() {
            return;
        }
        self.cx.security().active_content("ole_objects");
        let recurse = self.cx.options().limits.max_depth > 0;
        let mut listed = Vec::new();
        for (i, o) in std::mem::take(&mut self.objects).into_iter().enumerate() {
            let native = ole1_native(&o.hex);
            let class = o.class.clone().or_else(|| native.as_ref().map(|n| n.0.clone())).unwrap_or_default();
            let mut m = Map::new();
            m.insert("kind".into(), json!(o.kind));
            if !class.is_empty() {
                m.insert("class".into(), json!(truncate_chars(&class, 100)));
            }
            if let Some((_, data)) = &native {
                m.insert("size_bytes".into(), json!(data.len()));
            }
            if o.update {
                m.insert("auto_update".into(), json!(true));
                self.cx.security().risk("auto_update_object", Some(truncate_chars(&class, 100)));
            }
            if class.starts_with("Equation") {
                self.cx.security().risk("equation_editor_object", Some(truncate_chars(&class, 100)));
            }
            if matches!(o.kind, "linked" | "auto_linked") {
                self.cx
                    .security()
                    .active_content("ole_links")
                    .risk("external_ole_link", Some(truncate_chars(&class, 100)));
            }
            if listed.len() < MAX_LISTED {
                listed.push(Value::Object(m));
            }
            if recurse
                && let Some((_, data)) = native
                && !data.is_empty()
                && self.cx.emit_child(&format!("object{}.bin", i + 1), data).is_err()
            {
                break;
            }
        }
        self.format.insert("objects".into(), Value::Array(listed));
    }
}

/// `\word[-N]` or `\X` at `i` (after the backslash): end, control, parameter.
fn control(data: &[u8], i: usize) -> (usize, Ctl<'_>, Option<i64>) {
    let Some(&c) = data.get(i) else { return (i, Ctl::Symbol(0), None) };
    if !c.is_ascii_alphabetic() {
        return (i + 1, Ctl::Symbol(c), None);
    }
    let mut j = i;
    while j < data.len() && data[j].is_ascii_alphabetic() && j - i < 32 {
        j += 1;
    }
    let word = &data[i..j];
    let num_start = j;
    if data.get(j) == Some(&b'-') {
        j += 1;
    }
    while j < data.len() && data[j].is_ascii_digit() && j - num_start < 11 {
        j += 1;
    }
    let param = std::str::from_utf8(&data[num_start..j]).ok().and_then(|s| s.parse::<i64>().ok());
    if param.is_none() {
        j = num_start;
    }
    if data.get(j) == Some(&b' ') {
        j += 1;
    }
    (j, Ctl::Word(word), param)
}

enum Ctl<'a> {
    Word(&'a [u8]),
    Symbol(u8),
}

/// The end of the group starting at `i` (for groups nested too deeply).
fn skip_group(data: &[u8], i: usize) -> usize {
    let mut depth = 0usize;
    let mut j = i;
    while j < data.len() {
        match data[j] {
            b'\\' => j += 1,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    data.len()
}

/// `\fcharsetN` → Windows code page.
fn charset_codepage(n: i64) -> Option<u16> {
    Some(match n {
        2 => 42, // Symbol: no text mapping
        77 => 10_000,
        128 => 932,
        129 => 949,
        130 => 1361,
        134 => 936,
        136 => 950,
        161 => 1253,
        162 => 1254,
        163 => 1258,
        177 => 1255,
        178 => 1256,
        186 => 1257,
        204 => 1251,
        222 => 874,
        238 => 1250,
        255 => 437,
        _ => return None,
    })
}

fn decode(cp: u16, bytes: &[u8]) -> String {
    let enc: &'static Encoding = match cp {
        42 => return String::new(),
        874 => encoding_rs::WINDOWS_874,
        932 => encoding_rs::SHIFT_JIS,
        936 => encoding_rs::GBK,
        949 => encoding_rs::EUC_KR,
        950 => encoding_rs::BIG5,
        1250 => encoding_rs::WINDOWS_1250,
        1251 => encoding_rs::WINDOWS_1251,
        1253 => encoding_rs::WINDOWS_1253,
        1254 => encoding_rs::WINDOWS_1254,
        1255 => encoding_rs::WINDOWS_1255,
        1256 => encoding_rs::WINDOWS_1256,
        1257 => encoding_rs::WINDOWS_1257,
        1258 => encoding_rs::WINDOWS_1258,
        10_000 => encoding_rs::MACINTOSH,
        65_001 => encoding_rs::UTF_8,
        866 => encoding_rs::IBM866,
        _ => encoding_rs::WINDOWS_1252,
    };
    enc.decode_without_bom_handling(bytes).0.into_owned()
}

/// An OLE 1.0 object (`\objdata`): class name and native data.
fn ole1_native(data: &[u8]) -> Option<(String, Vec<u8>)> {
    let u32_at = |i: usize| data.get(i..i + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let format_id = u32_at(4)?;
    let mut i = 8;
    let class_len = u32_at(i)?;
    let class = String::from_utf8_lossy(data.get(i + 4..i + 4 + class_len)?).trim_end_matches('\0').to_string();
    i += 4 + class_len;
    // Topic and item names.
    for _ in 0..2 {
        let n = u32_at(i)?;
        i += 4 + n;
    }
    if format_id != 2 {
        return Some((class, Vec::new()));
    }
    let size = u32_at(i)?;
    let native = data.get(i + 4..(i + 4 + size).min(data.len()))?.to_vec();
    Some((class, native))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    fn report(rtf: &str) -> crate::plugin::Report {
        crate::plugin::testing::report_for("t.rtf", rtf.as_bytes())
    }

    #[test]
    fn reads_info_styles_and_text() {
        let r = report(
            r"{\rtf1\ansi\ansicpg1252{\fonttbl{\f0\fswiss Arial;}{\f1\fcharset204 Courier;}}
{\stylesheet{\s0 Normal;}{\s1\outlinelevel0 heading 1;}}
{\info{\title Tide notes}{\author A. Keeper}{\creatim\yr2024\mo5\dy1\hr8\min30}{\nofpages3}}
{\*\generator Msftedit 5.41.21.2510;}
\pard\s1 Spring tides\par
\pard\s0 Caf\'e9 \u960?5 \f1\'c4\'e0\par
{\*\annotation{\*\atnauthor K}Check the date}
}",
        );
        assert_eq!(r.content.title.as_deref(), Some("Tide notes"));
        assert_eq!(r.content.authors, ["A. Keeper"]);
        assert_eq!(r.content.outline.len(), 1);
        assert_eq!(r.content.outline[0].text, "Spring tides");
        let f = &r.format["rtf"];
        assert_eq!(f["generator"], "Msftedit 5.41.21.2510");
        assert_eq!(r.metadata["rtf_info"]["creatim"], "2024-05-01T08:30:00");
        assert_eq!(r.physical.document.as_ref().and_then(|d| d.pages), Some(3));
        assert_eq!(f["comments"], 1);
        assert!(r.content.excerpt.as_deref().unwrap_or_default().contains("Café π5 Да"), "{:?}", r.content.excerpt);
    }

    #[test]
    fn flags_fields_and_objects() {
        let r = report(
            r#"{\rtf1\ansi
{\field{\*\fldinst HYPERLINK "https://example.org/tides"}{\fldrslt tides}}
{\field{\*\fldinst INCLUDEPICTURE "https://img.example.org/chart.png"}{\fldrslt }}
{\object\objautlink\objupdate{\*\objclass Excel.Sheet.8}{\*\objdata 01050000010000000600000045786365}}
}"#,
        );
        let kinds: Vec<&str> = r.security.risks.iter().map(|x| x.kind.as_str()).collect();
        for k in ["external_content", "auto_update_object", "external_ole_link"] {
            assert!(kinds.contains(&k), "{k} missing from {kinds:?}");
        }
        let f = &r.format["rtf"];
        assert_eq!(f["links"][0], "https://example.org/tides");
        assert_eq!(f["objects"][0]["class"], "Excel.Sheet.8");
        assert_eq!(f["objects"][0]["kind"], "auto_linked");
    }

    #[test]
    fn embedded_native_data_becomes_a_child() {
        // OLE1 header: version, FormatID 2 (embedded), class "Text", empty topic and item, 5 native bytes.
        let mut hex = String::new();
        for b in [1u8, 5, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, b'T', b'e', b'x', b't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0] {
            let _ = write!(hex, "{b:02x}");
        }
        hex.push_str("68656c6c6f");
        let r = report(&format!(r"{{\rtf1{{\object\objemb{{\*\objclass Text}}{{\*\objdata {hex}}}}}}}"));
        assert_eq!(r.format["rtf"]["objects"][0]["size_bytes"], 5);
        assert_eq!(r.embedded.len(), 1);
    }

    crate::fixture_tests!("rtf");
}
