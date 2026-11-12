//! TNEF (`winmail.dat`, `application/ms-tnef`): the message class, subject,
//! sender, dates and body that Outlook wraps around a message, and its
//! attachments, which are handed on as children.
//!
//! Specification: [MS-OXTNEF] (attribute stream, MAPI property lists).

use serde_json::json;

use super::Mail;
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
};

/// Extractor for TNEF streams.
pub struct Tnef;

const SIGNATURE: &[u8] = b"\x78\x9f\x3e\x22";

static META: ExtractorMeta = ExtractorMeta {
    id: "email.tnef",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "tnef",
        name: "TNEF (winmail.dat)",
        family: "email",
        mimes: &["application/ms-tnef", "application/vnd.ms-tnef"],
        extensions: &["tnef"],
        magic: &[Magic::prefix(SIGNATURE)],
        parent: None,
    }],
};

// Attribute ids (type in the high word).
const ATT_SUBJECT: u32 = 0x0001_8004;
const ATT_DATE_SENT: u32 = 0x0003_8005;
const ATT_DATE_RECEIVED: u32 = 0x0003_8006;
const ATT_MESSAGE_CLASS: u32 = 0x0007_8008;
const ATT_MESSAGE_ID: u32 = 0x0001_8009;
const ATT_BODY: u32 = 0x0002_800C;
const ATT_ATTACH_DATA: u32 = 0x0006_800F;
const ATT_ATTACH_TITLE: u32 = 0x0001_8010;
const ATT_ATTACH_REND_DATA: u32 = 0x0006_9002;
const ATT_MSG_PROPS: u32 = 0x0006_9003;
const ATT_ATTACHMENT: u32 = 0x0006_9005;
const ATT_TNEF_VERSION: u32 = 0x0008_9006;
const ATT_OEM_CODEPAGE: u32 = 0x0006_9007;

/// Attributes read at most.
const MAX_ATTRIBUTES: usize = 100_000;
/// Attachments handed on at most.
const MAX_ATTACHMENTS: usize = 1000;

impl Extractor for Tnef {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        probe.head.starts_with(SIGNATURE).then_some(Sniff { format: "tnef", confidence: 0.99 })
    }

    #[allow(clippy::too_many_lines)] // one attribute after another
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, cut) = cx.read_bytes(src)?;
        let mut r = ByteReader::new(&b);
        r.advance(4)?;
        let key = r.le_u16()?;
        let mut mail = Mail::default();
        let (mut attachment, mut attributes, mut bad_checksums) = (None::<Attachment>, 0usize, 0u64);
        let (mut codepage, mut version, mut class, mut rtf) = (None, None, None, None::<Vec<u8>>);
        while r.remaining() >= 11 && attributes < MAX_ATTRIBUTES {
            attributes += 1;
            if attributes % 1024 == 0 {
                cx.checkpoint()?;
            }
            let level = r.u8()?;
            let id = r.le_u32()?;
            let len = r.le_u32()? as usize;
            if len > r.remaining().saturating_sub(2) {
                cx.warn("an attribute runs past the end of the stream");
                break;
            }
            let data = r.bytes(len)?;
            let sum = r.le_u16()?;
            if data.iter().fold(0u16, |a, &x| a.wrapping_add(u16::from(x))) != sum {
                bad_checksums += 1;
            }
            if level == 2 {
                match id {
                    ATT_ATTACH_REND_DATA => {
                        if let Some(a) = attachment.take() {
                            a.push(&mut mail);
                        }
                        attachment = Some(Attachment::default());
                    }
                    ATT_ATTACH_TITLE => {
                        if let Some(a) = attachment.as_mut() {
                            a.title = Some(cstr(data));
                        }
                    }
                    ATT_ATTACH_DATA => {
                        if let Some(a) = attachment.as_mut() {
                            a.data = data.to_vec();
                        }
                    }
                    ATT_ATTACHMENT => {
                        if let Some(a) = attachment.as_mut() {
                            for (tag, v) in props(data) {
                                match (tag, v) {
                                    (0x3707 | 0x3704, Prop::Text(t)) => a.long_name = Some(t),
                                    (0x370E, Prop::Text(t)) => a.mime = Some(t),
                                    (0x3701, Prop::Binary(d)) if a.data.is_empty() => a.data = d,
                                    (0x3705, Prop::Int(5)) => a.message = true,
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
                continue;
            }
            match id {
                ATT_TNEF_VERSION if data.len() >= 4 => {
                    version = Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
                }
                ATT_OEM_CODEPAGE if data.len() >= 4 => {
                    codepage = Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
                }
                ATT_MESSAGE_CLASS => class = Some(cstr(data)),
                ATT_SUBJECT => mail.subject = Some(cstr(data)),
                ATT_MESSAGE_ID => mail.message_id = Some(cstr(data)),
                ATT_BODY => mail.text = Some(cstr(data)),
                ATT_DATE_SENT => mail.date = dtr(data).map(|d| (d, false)),
                ATT_DATE_RECEIVED => {
                    if let Some(d) = dtr(data) {
                        mail.received.push((Some(d), None));
                    }
                }
                ATT_MSG_PROPS => {
                    let (mut name, mut address) = (None, None);
                    for (tag, v) in props(data) {
                        match (tag, v) {
                            (0x0037, Prop::Text(t)) if mail.subject.is_none() => mail.subject = Some(t),
                            (0x001A, Prop::Text(t)) => class = class.or(Some(t)),
                            (0x0C1A | 0x0042, Prop::Text(t)) => name = name.or(Some(t)),
                            (0x0C1F | 0x0065, Prop::Text(t)) => address = address.or(Some(t)),
                            (0x1000, Prop::Text(t)) if mail.text.is_none() => mail.text = Some(t),
                            (0x1013, Prop::Binary(h)) => mail.html = Some(String::from_utf8_lossy(&h).into_owned()),
                            (0x1013, Prop::Text(h)) => mail.html = Some(h),
                            (0x1009, Prop::Binary(d)) => rtf = Some(d),
                            (0x1035, Prop::Text(t)) => mail.message_id = mail.message_id.take().or(Some(t)),
                            _ => {}
                        }
                    }
                    if name.is_some() || address.is_some() {
                        mail.from = Some((name, address));
                    }
                }
                _ => {}
            }
        }
        if let Some(a) = attachment.take() {
            a.push(&mut mail);
        }
        mail.format.insert("tnef_key".into(), json!(key));
        if let Some(v) = version {
            mail.format.insert("tnef_version".into(), json!(format!("{}.{}", v >> 16, v & 0xffff)));
        }
        if let Some(c) = codepage {
            mail.format.insert("codepage".into(), json!(c));
        }
        if let Some(c) = class {
            mail.format.insert("message_class".into(), json!(c));
        }
        mail.format.insert("attributes".into(), json!(attributes));
        if bad_checksums > 0 {
            mail.format.insert("bad_checksums".into(), json!(bad_checksums));
        }
        if cut {
            mail.format.insert("truncated".into(), json!(true));
        }
        if let Some(r) = rtf.and_then(|d| super::msg::lzfu(&d)) {
            mail.format.insert("body_rtf".into(), json!(true));
            mail.attachments.push(("body.rtf".into(), "text/rtf".into(), r.len(), r));
        }
        mail.write(cx);
        Ok(())
    }
}

crate::register_extractor!(Tnef);

#[derive(Default)]
struct Attachment {
    title: Option<String>,
    long_name: Option<String>,
    mime: Option<String>,
    data: Vec<u8>,
    message: bool,
}

impl Attachment {
    fn push(self, mail: &mut Mail) {
        if mail.attachments.len() >= MAX_ATTACHMENTS {
            return;
        }
        let name =
            self.long_name.or(self.title).unwrap_or_else(|| format!("attachment-{}", mail.attachments.len() + 1));
        let mime =
            if self.message { "message/rfc822".into() } else { self.mime.unwrap_or_default().to_ascii_lowercase() };
        mail.attachments.push((name, mime, self.data.len(), self.data));
    }
}

/// A NUL-terminated 8-bit string (the OEM code page; read as Latin-1).
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    b[..end].iter().map(|&c| char::from(c)).collect::<String>().trim().to_string()
}

/// A TNEF date: year, month, day, hour, minute, second, day of week (u16 each).
fn dtr(b: &[u8]) -> Option<String> {
    if b.len() < 12 {
        return None;
    }
    let word = |i: usize| u16::from_le_bytes([b[i * 2], b[i * 2 + 1]]);
    let (year, month, day, hour, minute, second) = (word(0), word(1), word(2), word(3), word(4), word(5));
    let valid = (1601..=9999).contains(&year)
        && (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour < 24
        && minute < 60
        && second < 61;
    valid.then(|| format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"))
}

/// A MAPI property value, as far as this reader needs.
enum Prop {
    Int(i64),
    Text(String),
    Binary(Vec<u8>),
    Other,
}

/// A MAPI property list: count, then (type, id, [named-property name],
/// value) entries. Stops quietly at the first malformed entry.
fn props(b: &[u8]) -> Vec<(u16, Prop)> {
    let mut out = Vec::new();
    let mut r = ByteReader::new(b);
    let Ok(count) = r.le_u32() else { return out };
    for _ in 0..count.min(10_000) {
        let Some(p) = prop(&mut r) else { break };
        out.push(p);
    }
    out
}

fn prop(r: &mut ByteReader<'_>) -> Option<(u16, Prop)> {
    let ty = r.le_u16().ok()?;
    let id = r.le_u16().ok()?;
    if id >= 0x8000 {
        r.advance(16).ok()?;
        if r.le_u32().ok()? == 0 {
            r.advance(4).ok()?;
        } else {
            let n = r.le_u32().ok()? as usize;
            r.advance(n.checked_add(3)? & !3).ok()?;
        }
    }
    let multi = ty & 0x1000 != 0;
    let base = ty & 0x0fff;
    let values = if multi || matches!(base, 0x001E | 0x001F | 0x0102 | 0x000D) { r.le_u32().ok()? } else { 1 };
    let mut first = Prop::Other;
    for i in 0..values.min(100_000) {
        let v = match base {
            0x0002 | 0x0003 | 0x000A | 0x000B | 0x0004 => {
                let v = r.le_u32().ok()?;
                Prop::Int(i64::from(v))
            }
            0x0005 | 0x0006 | 0x0007 | 0x0014 | 0x0040 => {
                r.advance(8).ok()?;
                Prop::Other
            }
            0x0048 => {
                r.advance(16).ok()?;
                Prop::Other
            }
            0x001E | 0x001F | 0x0102 | 0x000D => {
                let n = r.le_u32().ok()? as usize;
                let d = r.bytes(n).ok()?.to_vec();
                r.advance((n.checked_add(3)? & !3) - n).ok()?;
                match base {
                    0x001F => {
                        let u: Vec<u16> = d.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                        Prop::Text(String::from_utf16_lossy(&u).trim_end_matches('\0').to_string())
                    }
                    0x001E => Prop::Text(cstr(&d)),
                    _ => Prop::Binary(d),
                }
            }
            _ => return None,
        };
        if i == 0 {
            first = v;
        }
    }
    Some((id, first))
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("tnef");

    #[test]
    fn dates_and_props() {
        let d: Vec<u8> = [2025u16, 9, 1, 12, 30, 0, 1].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(dtr(&d).as_deref(), Some("2025-09-01T12:30:00"));
        // One PT_UNICODE property 0x3707 holding "a".
        let mut p = vec![1, 0, 0, 0, 0x1F, 0, 0x07, 0x37, 1, 0, 0, 0, 4, 0, 0, 0];
        p.extend([b'a', 0, 0, 0]);
        let got = props(&p);
        assert!(matches!(&got[0], (0x3707, Prop::Text(t)) if t == "a"));
        // Truncated lists stop quietly.
        assert!(props(&p[..10]).is_empty());
    }
}
