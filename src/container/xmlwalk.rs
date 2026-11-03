//! A small XML event walker for format extractors: local names (prefixes
//! dropped), attributes as pairs, text with entities resolved; bounded and
//! deadline-checked. Also the root element of an XML head, for sniffers.

use crate::error::ExtractError;
use crate::plugin::Context;

/// An XML event, with local names (prefixes dropped).
pub enum Ev<'a> {
    /// An element starts: its local name and attributes.
    Start(&'a str, &'a [(String, String)]),
    /// An element ends (empty elements give a start and an end).
    End(&'a str),
    /// Text content, trimmed, with entities resolved.
    Text(&'a str),
}

/// Walk an XML document: `f` sees starts (empty elements give a start and
/// an end), ends and text. At most `max` events; checkpoints the deadline.
pub fn walk(
    text: &str,
    cx: &mut Context<'_>,
    max: usize,
    mut f: impl FnMut(&mut Context<'_>, Ev<'_>),
) -> Result<(), ExtractError> {
    use quick_xml::events::Event;

    let local = |q: &str| -> String { q.rsplit(':').next().unwrap_or("").to_string() };
    let attrs = |e: &quick_xml::events::BytesStart<'_>| -> Vec<(String, String)> {
        e.attributes()
            .flatten()
            .take(64)
            .map(|a| {
                let v = a
                    .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    .map(std::borrow::Cow::into_owned)
                    .unwrap_or_default();
                (local(a.key.as_ref()), v)
            })
            .collect()
    };
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().check_end_names = false;
    let mut pending = String::new();
    for n in 0..max {
        if n % 4096 == 0 {
            cx.checkpoint()?;
        }
        let flush = |cx: &mut Context<'_>, pending: &mut String, f: &mut dyn FnMut(&mut Context<'_>, Ev<'_>)| {
            if !pending.trim().is_empty() {
                f(cx, Ev::Text(pending.trim()));
            }
            pending.clear();
        };
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                flush(cx, &mut pending, &mut f);
                let (name, a) = (local(e.name().as_ref()), attrs(&e));
                f(cx, Ev::Start(&name, &a));
            }
            Ok(Event::Empty(e)) => {
                flush(cx, &mut pending, &mut f);
                let (name, a) = (local(e.name().as_ref()), attrs(&e));
                f(cx, Ev::Start(&name, &a));
                f(cx, Ev::End(&name));
            }
            Ok(Event::End(e)) => {
                flush(cx, &mut pending, &mut f);
                f(cx, Ev::End(&local(e.name().as_ref())));
            }
            Ok(Event::Text(t)) => {
                if pending.len() < 1 << 20 {
                    pending.push_str(&t.xml10_content());
                }
            }
            Ok(Event::CData(t)) => {
                if pending.len() < 1 << 20 {
                    pending.push_str(&t.xml10_content());
                }
            }
            Ok(Event::GeneralRef(r)) => match &*r {
                "amp" => pending.push('&'),
                "lt" => pending.push('<'),
                "gt" => pending.push('>'),
                "quot" => pending.push('"'),
                "apos" => pending.push('\''),
                _ => {
                    if let Ok(Some(c)) = r.resolve_char_ref() {
                        pending.push(c);
                    }
                }
            },
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                cx.warn(format!("XML: {e}"));
                break;
            }
        }
    }
    Ok(())
}

/// The value of attribute `key` (local name).
pub fn attr<'a>(a: &'a [(String, String)], key: &str) -> Option<&'a str> {
    a.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// The root element's local name and namespaces of an XML head.
pub fn xml_root(head: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(&head[..head.len().min(8192)]).ok().or_else(|| {
        // A head cut inside a multi-byte character.
        let mut n = head.len().min(8192);
        while n > 0 && std::str::from_utf8(&head[..n]).is_err() {
            n -= 1;
        }
        std::str::from_utf8(&head[..n]).ok()
    })?;
    let mut rest = text.trim_start_matches('\u{feff}');
    loop {
        let i = rest.find('<')?;
        rest = &rest[i + 1..];
        if rest.starts_with('?') || rest.starts_with('!') {
            continue;
        }
        let end = rest.find('>')?;
        let tag = &rest[..end];
        let name = tag.split(|c: char| c.is_whitespace() || c == '/').next()?;
        let local = name.rsplit(':').next()?.to_string();
        return Some((local, tag.to_string()));
    }
}
