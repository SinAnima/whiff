//! Outlook messages (`.msg`, MS-OXMSG): MAPI properties in a compound
//! file. Subject, sender, recipients, dates, message class, transport
//! headers (parsed like an EML's), plain / HTML body, attachments as
//! children, and the compressed RTF body (MS-OXRTFCP) as an `.rtf` child
//! when there is no plain body.

use mail_parser::MessageParser;
use serde_json::json;

use super::Mail;
use crate::plugin::{
    Cfb, CfbEntry, CfbKind, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Source, filetime,
    truncate_chars,
};

/// Extractor for Outlook messages.
pub struct Msg;

static META: ExtractorMeta = ExtractorMeta {
    id: "email.msg",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "msg",
        name: "Outlook message",
        family: "email",
        mimes: &["application/vnd.ms-outlook"],
        // `.oft`: an Outlook template, the same format.
        extensions: &["msg", "oft"],
        magic: &[],
        parent: Some("cfb"),
    }],
};

const MAX_STREAM: usize = 32 << 20;

impl Extractor for Msg {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &crate::plugin::Probe<'_>) -> Option<crate::plugin::Sniff> {
        // `doc.ole` redirects compound files holding `__substg1.0_` streams here;
        // by name, a `.msg` compound file is one too.
        (probe.extension == Some("msg") && Cfb::is_cfb(probe.head))
            .then_some(crate::plugin::Sniff { format: "msg", confidence: 0.9 })
    }

    #[allow(clippy::too_many_lines)] // properties, recipients, bodies, attachments
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let cfb = Cfb::open(src)?;
        let root = Props::load(&cfb, src, 0, 32)?;
        let mut mail = match root.string(0x007D).filter(|h| !h.trim().is_empty()) {
            Some(headers) => {
                let mut raw = headers.into_bytes();
                raw.extend_from_slice(b"\r\n\r\n");
                MessageParser::default().parse(&raw).map(|m| super::mime::to_mail(&m, false)).unwrap_or_default()
            }
            None => Mail::default(),
        };
        // MAPI properties take precedence over the transport headers.
        if let Some(s) = root.string(0x0037) {
            mail.subject = Some(truncate_chars(s.trim(), 1000));
        }
        let sender_addr = root
            .string(0x5D01)
            .or_else(|| root.string(0x0C1F).filter(|a| a.contains('@')))
            .or_else(|| root.string(0x0065));
        let sender_name = root.string(0x0C1A).or_else(|| root.string(0x0042));
        if sender_addr.is_some() || sender_name.is_some() {
            mail.from = Some((sender_name, sender_addr));
        }
        if let Some(t) = root.time(0x0039).or_else(|| root.time(0x3007)) {
            mail.date = Some((t, true));
        }
        if let Some(t) = root.time(0x0E06) {
            mail.received.insert(0, (Some(t), None));
        }
        if let Some(id) = root.string(0x1035) {
            mail.message_id = Some(id.trim().trim_matches(['<', '>']).to_string());
        }
        if let Some(id) = root.string(0x1042) {
            mail.in_reply_to = Some(id);
        }
        if let Some(class) = root.string(0x001A) {
            mail.format.insert("message_class".into(), json!(class));
            if class.starts_with("IPM.Note.SMIME") {
                if class.contains("MultipartSigned") {
                    mail.signed = Some("smime".into());
                } else {
                    mail.encrypted = Some("smime".into());
                }
            }
        }
        if let Some(i) = root.int(0x0017) {
            mail.priority = Some(
                match i {
                    0 => "low",
                    2 => "high",
                    _ => "normal",
                }
                .into(),
            );
        }
        if let Some(t) = root.string(0x0070) {
            mail.format.insert("conversation_topic".into(), json!(truncate_chars(&t, 300)));
        }
        if let Some(n) = root.int(0x3FDE) {
            mail.format.insert("codepage".into(), json!(n));
        }
        // Recipients.
        let (mut to, mut cc, mut bcc) = (Vec::new(), Vec::new(), Vec::new());
        for (i, e) in cfb.entries.iter().enumerate() {
            if e.parent != Some(0) || e.kind != CfbKind::Storage || !e.name.starts_with("__recip_version1.0_") {
                continue;
            }
            let p = Props::load(&cfb, src, i, 8)?;
            let name = p.string(0x3001);
            let addr = p.string(0x39FE).or_else(|| p.string(0x3003).filter(|a| a.contains('@')));
            let who = (name, addr);
            match p.int(0x0C15) {
                Some(2) => cc.push(who),
                Some(3) => bcc.push(who),
                _ => to.push(who),
            }
        }
        if !to.is_empty() || !cc.is_empty() || !bcc.is_empty() {
            (mail.to, mail.cc, mail.bcc) = (to, cc, bcc);
        }
        // Bodies.
        mail.text = root.string(0x1000);
        mail.html =
            root.string(0x1013).or_else(|| root.binary(0x1013).map(|b| String::from_utf8_lossy(&b).into_owned()));
        let mut children: Vec<(String, Vec<u8>)> = Vec::new();
        if mail.text.as_deref().is_none_or(|t| t.trim().is_empty())
            && mail.html.is_none()
            && let Some(rtf) = root.binary(0x1009).and_then(|c| lzfu(&c))
        {
            mail.format.insert("body_rtf".into(), json!(true));
            children.push(("body.rtf".into(), rtf));
        }
        // Attachments.
        let mut embedded = 0u64;
        for (i, e) in cfb.entries.iter().enumerate() {
            if e.parent != Some(0) || e.kind != CfbKind::Storage || !e.name.starts_with("__attach_version1.0_") {
                continue;
            }
            cx.checkpoint()?;
            let p = Props::load(&cfb, src, i, 8)?;
            let name = p
                .string(0x3707)
                .or_else(|| p.string(0x3704))
                .or_else(|| p.string(0x3001))
                .unwrap_or_else(|| format!("attachment-{}", mail.attachments.len() + 1));
            let ctype = p.string(0x370E).unwrap_or_default().to_ascii_lowercase();
            if p.int(0x3705) == Some(5) {
                embedded += 1;
                mail.attachments.push((name, "message/rfc822".into(), 0, Vec::new()));
            } else {
                let data = p.binary(0x3701).unwrap_or_default();
                let size = data.len();
                mail.attachments.push((name, ctype, size, data));
            }
            if mail.attachments.len() >= 1000 {
                break;
            }
        }
        if embedded > 0 {
            mail.format.insert("embedded_messages".into(), json!(embedded));
        }
        mail.write(cx);
        if cx.options().limits.max_depth > 0 {
            for (name, data) in children {
                if cx.emit_child(&name, data).is_err() {
                    break;
                }
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Msg);

/// The properties of one storage: variable-size values in `__substg1.0_`
/// streams, fixed-size ones in `__properties_version1.0`.
struct Props {
    strings: Vec<(u16, String)>,
    binaries: Vec<(u16, Vec<u8>)>,
    fixed: Vec<(u16, u16, [u8; 8])>,
}

impl Props {
    fn load(cfb: &Cfb, src: &mut dyn Source, storage: usize, header: usize) -> Result<Self, ExtractError> {
        let mut p = Self { strings: Vec::new(), binaries: Vec::new(), fixed: Vec::new() };
        let kids: Vec<CfbEntry> = cfb.children(storage).filter(|e| e.kind == CfbKind::Stream).cloned().collect();
        for e in &kids {
            if e.name.eq_ignore_ascii_case("__properties_version1.0") {
                let data = cfb.read(src, e, 1 << 20)?;
                for entry in data.get(header..).unwrap_or_default().as_chunks::<16>().0.iter().take(10_000) {
                    let tag = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                    let mut v = [0u8; 8];
                    v.copy_from_slice(&entry[8..16]);
                    #[allow(clippy::cast_possible_truncation)] // the halves of a property tag
                    p.fixed.push(((tag >> 16) as u16, tag as u16, v));
                }
                continue;
            }
            let Some(hex) = e.name.strip_prefix("__substg1.0_").filter(|h| h.len() == 8) else { continue };
            let (Ok(id), Ok(kind)) = (u16::from_str_radix(&hex[..4], 16), u16::from_str_radix(&hex[4..], 16)) else {
                continue;
            };
            match kind {
                0x001F => {
                    let raw = cfb.read(src, e, MAX_STREAM)?;
                    let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                    p.strings.push((id, String::from_utf16_lossy(&units).trim_end_matches('\0').to_string()));
                }
                0x001E => {
                    let raw = cfb.read(src, e, MAX_STREAM)?;
                    p.strings.push((id, crate::plugin::latin1_or_utf8(&raw).trim_end_matches('\0').to_string()));
                }
                0x0102 => p.binaries.push((id, cfb.read(src, e, MAX_STREAM)?)),
                _ => {}
            }
        }
        Ok(p)
    }

    fn string(&self, id: u16) -> Option<String> {
        self.strings.iter().find(|(i, _)| *i == id).map(|(_, s)| s.clone()).filter(|s| !s.trim().is_empty())
    }

    fn binary(&self, id: u16) -> Option<Vec<u8>> {
        self.binaries.iter().find(|(i, _)| *i == id).map(|(_, b)| b.clone())
    }

    fn int(&self, id: u16) -> Option<i64> {
        self.fixed.iter().find(|(i, t, _)| *i == id && matches!(t, 0x0002 | 0x0003 | 0x000B | 0x0014)).map(
            |(_, t, v)| match t {
                0x0002 => i64::from(i16::from_le_bytes([v[0], v[1]])),
                0x000B => i64::from(v[0] != 0),
                0x0014 => i64::from_le_bytes(*v),
                _ => i64::from(i32::from_le_bytes([v[0], v[1], v[2], v[3]])),
            },
        )
    }

    fn time(&self, id: u16) -> Option<String> {
        self.fixed
            .iter()
            .find(|(i, t, _)| *i == id && *t == 0x0040)
            .and_then(|(_, _, v)| filetime(u64::from_le_bytes(*v)))
    }
}

/// Decompress an MS-OXRTFCP compressed RTF body (`LZFu`, or `MELA` = stored).
fn lzfu(data: &[u8]) -> Option<Vec<u8>> {
    const PREFIX: &[u8] = b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx";
    let le = |i: usize| data.get(i..i + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let raw_size = le(4)?;
    let magic = data.get(8..12)?;
    let body = data.get(16..)?;
    if magic == b"MELA" {
        return Some(body[..raw_size.min(body.len())].to_vec());
    }
    if magic != b"LZFu" {
        return None;
    }
    let mut dict = [0u8; 4096];
    dict[..PREFIX.len()].copy_from_slice(PREFIX);
    let mut write = PREFIX.len();
    let mut out = Vec::with_capacity(raw_size.min(MAX_STREAM));
    let mut i = 0;
    while i < body.len() && out.len() < raw_size.min(MAX_STREAM) {
        let control = body[i];
        i += 1;
        for bit in 0..8 {
            if i >= body.len() {
                break;
            }
            if control & (1 << bit) == 0 {
                let b = body[i];
                i += 1;
                out.push(b);
                dict[write] = b;
                write = (write + 1) % 4096;
            } else {
                let (hi, lo) = (usize::from(body[i]), usize::from(*body.get(i + 1)?));
                i += 2;
                let offset = (hi << 4) | (lo >> 4);
                let len = (lo & 0xF) + 2;
                if offset == write {
                    return Some(out);
                }
                for k in 0..len {
                    let b = dict[(offset + k) % 4096];
                    out.push(b);
                    dict[write] = b;
                    write = (write + 1) % 4096;
                }
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn fixed(entries: &[(u32, [u8; 8])], header: usize) -> Vec<u8> {
        let mut out = vec![0u8; header];
        for (tag, v) in entries {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&6u32.to_le_bytes());
            out.extend_from_slice(v);
        }
        out
    }

    #[test]
    fn reads_an_outlook_message() {
        // 2024-05-01T08:30:00Z as a FILETIME.
        let sent = ((1_714_552_200u64 + 11_644_473_600) * 10_000_000).to_le_bytes();
        let subject = utf16("Berth 5 is free on Friday");
        let sender = utf16("Harbour Office");
        let smtp = utf16("office@saltmere.example");
        let body = utf16("Berth 5 is free from Friday noon.");
        let class = utf16("IPM.Note");
        let rname = utf16("Mira Castell");
        let raddr = utf16("mira@example.org");
        let aname = utf16("berths.csv");
        let props = fixed(&[(0x0039_0040, sent)], 32);
        let rprops = fixed(&[(0x0C15_0003, [1, 0, 0, 0, 0, 0, 0, 0])], 8);
        let aprops = fixed(&[(0x3705_0003, [1, 0, 0, 0, 0, 0, 0, 0])], 8);
        let data = crate::plugin::testing::cfb(&[
            ("__properties_version1.0", &props),
            ("__substg1.0_0037001F", &subject),
            ("__substg1.0_0C1A001F", &sender),
            ("__substg1.0_5D01001F", &smtp),
            ("__substg1.0_1000001F", &body),
            ("__substg1.0_001A001F", &class),
            ("__recip_version1.0_#00000000/__properties_version1.0", &rprops),
            ("__recip_version1.0_#00000000/__substg1.0_3001001F", &rname),
            ("__recip_version1.0_#00000000/__substg1.0_39FE001F", &raddr),
            ("__attach_version1.0_#00000000/__properties_version1.0", &aprops),
            ("__attach_version1.0_#00000000/__substg1.0_3707001F", &aname),
            ("__attach_version1.0_#00000000/__substg1.0_37010102", b"berth,dries\n3,yes\n"),
        ]);
        let r = crate::plugin::testing::report_for("notice.msg", &data);
        assert_eq!(r.identification.format, "msg");
        assert_eq!(r.content.title.as_deref(), Some("Berth 5 is free on Friday"));
        let f = &r.format["msg"];
        assert_eq!(f["from"]["domain"], "saltmere.example");
        assert_eq!(f["to"][0]["domain"], "example.org");
        assert_eq!(f["message_class"], "IPM.Note");
        assert_eq!(f["attachments"][0]["name"], "berths.csv");
        assert_eq!(r.embedded.len(), 1);
        assert!(r.temporal.content.iter().any(|d| d.value.starts_with("2024-05-01T08:30:00")));
        // Without the extension, `doc.ole` finds the MAPI streams and redirects here.
        let r = crate::plugin::testing::report_for("notice.dat", &data);
        assert_eq!(r.identification.format, "msg");
        assert_eq!(r.content.title.as_deref(), Some("Berth 5 is free on Friday"));
    }

    crate::fixture_tests!("msg");

    #[test]
    fn decompresses_rtf_spec_example() {
        // MS-OXRTFCP §4.1: "{\rtf1\ansi\ansicpg1252\pard hello world}\r\n".
        let data = [
            0x2d, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x4c, 0x5a, 0x46, 0x75, 0xf1, 0xc5, 0xc7, 0xa7, 0x03, 0x00,
            0x0a, 0x00, 0x72, 0x63, 0x70, 0x67, 0x31, 0x32, 0x35, 0x42, 0x32, 0x0a, 0xf3, 0x20, 0x68, 0x65, 0x6c, 0x09,
            0x00, 0x20, 0x62, 0x77, 0x05, 0xb0, 0x6c, 0x64, 0x7d, 0x0a, 0x80, 0x0f, 0xa0,
        ];
        assert_eq!(lzfu(&data).unwrap(), b"{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n");
    }
}
