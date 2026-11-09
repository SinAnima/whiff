//! `email` extractors (feature `common`): RFC 5322 / MIME messages (EML),
//! mailboxes (mbox), web archives (MHTML), Apple Mail messages (EMLX) and
//! Outlook messages (MSG).
//!
//! Addresses go through [`Context::mailbox`](crate::plugin::Context::mailbox),
//! so the strict privacy mode keeps only their domains. Attachments become
//! children. Phishing signals are risks: a Reply-To or Return-Path on
//! another domain, a display name naming a different address, links whose
//! text names another site, failed SPF / DKIM / DMARC, risky attachment
//! names and HTML forms.

pub(crate) mod mime;
pub(crate) mod msg;
pub(crate) mod stores;
pub(crate) mod tnef;

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::plugin::{Context, DateField, Map, TextRole, risky_file_name, truncate_chars};

const MAX_LISTED: usize = 50;

/// The domain of an e-mail address, lower-cased.
pub(crate) fn domain(address: &str) -> Option<String> {
    let d = address.rsplit_once('@')?.1.trim().trim_end_matches('>').to_ascii_lowercase();
    (!d.is_empty() && d.contains('.')).then_some(d)
}

/// The registrable part of a host (last two labels; three for `co.uk`-style).
pub(crate) fn base_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host;
    }
    let n = labels.len();
    let second = labels[n - 2];
    let take = if second.len() <= 3
        && ["co", "com", "org", "net", "ac", "gov", "edu", "ne", "or"].contains(&second)
        && labels[n - 1].len() == 2
    {
        3
    } else {
        2
    };
    labels[n.saturating_sub(take)..].join(".")
}

/// The host of an `http(s)` URL.
pub(crate) fn url_host(url: &str) -> Option<String> {
    let rest = url.trim().strip_prefix("https://").or_else(|| url.trim().strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// What one message says, gathered from any of the formats.
#[derive(Default)]
pub(crate) struct Mail {
    pub(crate) subject: Option<String>,
    /// (name, address).
    pub(crate) from: Option<(Option<String>, Option<String>)>,
    pub(crate) sender: Option<(Option<String>, Option<String>)>,
    pub(crate) reply_to: Vec<(Option<String>, Option<String>)>,
    pub(crate) return_path: Option<String>,
    pub(crate) to: Vec<(Option<String>, Option<String>)>,
    pub(crate) cc: Vec<(Option<String>, Option<String>)>,
    pub(crate) bcc: Vec<(Option<String>, Option<String>)>,
    pub(crate) date: Option<(String, bool)>,
    /// Received hops, newest first: (date, by host).
    pub(crate) received: Vec<(Option<String>, Option<String>)>,
    pub(crate) message_id: Option<String>,
    pub(crate) in_reply_to: Option<String>,
    pub(crate) references: usize,
    pub(crate) client: Option<String>,
    pub(crate) list_id: Option<String>,
    pub(crate) bulk: bool,
    pub(crate) auth: BTreeMap<String, String>,
    pub(crate) dkim_domains: Vec<String>,
    pub(crate) spam: Option<String>,
    pub(crate) priority: Option<String>,
    pub(crate) text: Option<String>,
    pub(crate) html: Option<String>,
    /// (name, content type, size, data).
    pub(crate) attachments: Vec<(String, String, usize, Vec<u8>)>,
    pub(crate) parts: usize,
    pub(crate) signed: Option<String>,
    pub(crate) encrypted: Option<String>,
    pub(crate) language: Option<String>,
    pub(crate) format: Map,
}

impl Mail {
    /// Write the message into the report.
    #[allow(clippy::too_many_lines)] // one section after another
    pub(crate) fn write(mut self, cx: &mut Context<'_>) {
        if let Some(s) = &self.subject {
            cx.content().source("email.subject").title(s);
            cx.emit_text(TextRole::Title, s);
        }
        if let Some((Some(name), _)) = &self.from
            && !name.trim().is_empty()
            && !name.contains('@')
        {
            cx.content().source("email.from").author(name.trim());
        }
        if let Some((v, tz)) = &self.date {
            cx.temporal().source("email.date").content_date(DateField::Sent, v.clone(), *tz);
        }
        if let Some((Some(d), _)) = self.received.first() {
            cx.temporal().source("email.received").content_date(DateField::Received, d.clone(), true);
        }
        if let Some(l) = &self.language {
            let code = l.split(['-', '_']).next().unwrap_or(l).to_ascii_lowercase();
            if code.len() == 2 {
                cx.content().source("email.content_language").language(code, 1.0);
            }
        }
        let mb = |cx: &Context<'_>, a: &(Option<String>, Option<String>)| cx.mailbox(a.0.as_deref(), a.1.as_deref());
        let mut f = std::mem::take(&mut self.format);
        let known =
            |a: &&(Option<String>, Option<String>)| a.0.is_some() || a.1.as_deref().is_some_and(|x| x.contains('@'));
        if let Some(a) = self.from.as_ref().filter(known) {
            f.insert("from".into(), mb(cx, a));
        }
        if let Some(a) = self.sender.as_ref().filter(known) {
            f.insert("sender".into(), mb(cx, a));
        }
        for (key, list) in [("reply_to", &self.reply_to), ("to", &self.to), ("cc", &self.cc), ("bcc", &self.bcc)] {
            if list.is_empty() {
                continue;
            }
            let v: Vec<Value> = list.iter().take(MAX_LISTED).map(|a| mb(cx, a)).collect();
            f.insert(key.into(), Value::Array(v));
            if list.len() > MAX_LISTED || key != "reply_to" {
                f.insert(format!("{key}_count"), json!(list.len()));
            }
        }
        if let Some(rp) = &self.return_path {
            f.insert("return_path".into(), cx.mailbox(None, Some(rp)));
        }
        if let Some(id) = &self.message_id {
            f.insert("message_id".into(), json!(truncate_chars(id, 300)));
        }
        if let Some(id) = &self.in_reply_to {
            f.insert("in_reply_to".into(), json!(truncate_chars(id, 300)));
        }
        if self.references > 0 {
            f.insert("references".into(), json!(self.references));
        }
        if let Some(c) = &self.client {
            f.insert("client".into(), json!(truncate_chars(c, 200)));
        }
        if let Some(l) = &self.list_id {
            f.insert("list_id".into(), json!(truncate_chars(l, 200)));
        }
        if self.bulk {
            f.insert("bulk".into(), json!(true));
        }
        if !self.received.is_empty() {
            f.insert("received_hops".into(), json!(self.received.len()));
        }
        if !self.auth.is_empty() {
            f.insert("authentication".into(), json!(self.auth));
        }
        if !self.dkim_domains.is_empty() {
            f.insert("dkim_domains".into(), json!(self.dkim_domains));
        }
        if let Some(s) = &self.spam {
            f.insert("spam_status".into(), json!(truncate_chars(s, 200)));
        }
        if let Some(p) = &self.priority {
            f.insert("priority".into(), json!(p));
        }
        if self.parts > 0 {
            f.insert("mime_parts".into(), json!(self.parts));
        }
        if let Some(s) = &self.signed {
            cx.security().signed(true);
            f.insert("signature".into(), json!(s));
        }
        if let Some(e) = &self.encrypted {
            cx.security().encrypted(true);
            f.insert("encryption".into(), json!(e));
        }
        self.risks(cx, &mut f);
        // Body text: plain text, else the HTML rendered as text.
        let budget = cx.options().limits.max_text_bytes;
        let body = match (&self.text, &self.html) {
            (Some(t), _) if !t.trim().is_empty() => Some(t.clone()),
            (_, Some(h)) => Some(crate::plugin::html_text(h, budget).0),
            _ => None,
        };
        if let Some(b) = body.filter(|b| !b.trim().is_empty()) {
            cx.emit_text(TextRole::Body, &truncate_chars(&b, budget));
        }
        // Attachments: listed, and analysed as children.
        let recurse = cx.options().limits.max_depth > 0;
        let mut listed = Vec::new();
        for (name, ctype, size, data) in std::mem::take(&mut self.attachments) {
            if listed.len() < MAX_LISTED {
                listed.push(json!({ "name": truncate_chars(&name, 200), "content_type": ctype, "size_bytes": size }));
            }
            if recurse && !data.is_empty() && cx.emit_child(&name, data).is_err() {
                break;
            }
        }
        if !listed.is_empty() {
            f.insert("attachments".into(), Value::Array(listed));
        }
        cx.format().extend(f);
    }

    fn risks(&self, cx: &mut Context<'_>, f: &mut Map) {
        let from_domain = self.from.as_ref().and_then(|a| a.1.as_deref()).and_then(domain);
        if let Some(fd) = &from_domain {
            let fb = base_domain(fd);
            let other: Vec<String> = self
                .reply_to
                .iter()
                .filter_map(|a| a.1.as_deref().and_then(domain))
                .filter(|d| base_domain(d) != fb)
                .collect();
            if let Some(d) = other.first() {
                cx.security().risk("reply_to_mismatch", Some(format!("From {fd}, Reply-To {d}")));
            }
            if let Some(name) = self.from.as_ref().and_then(|a| a.0.as_deref())
                && let Some(named) = name.split_whitespace().find(|w| w.contains('@')).and_then(domain)
                && base_domain(&named) != fb
            {
                cx.security()
                    .risk("display_name_spoof", Some(format!("display name names {named}, address is at {fd}")));
            }
        }
        let failed: Vec<String> = self
            .auth
            .iter()
            .filter(|(_, v)| matches!(v.as_str(), "fail" | "softfail" | "permerror"))
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        if !failed.is_empty() {
            cx.security().risk("authentication_failure", Some(failed.join(", ")));
        }
        for (name, _, _, _) in &self.attachments {
            match risky_file_name(name) {
                Some("macro_document") => {
                    cx.security().risk("macro_attachment", Some(truncate_chars(name, 200)));
                }
                Some(kind) => {
                    cx.security().risk(
                        if kind == "double_extension" { "double_extension" } else { "executable_attachment" },
                        Some(truncate_chars(name, 200)),
                    );
                }
                None => {}
            }
        }
        if let Some(html) = &self.html {
            let links = links(html);
            let mut hosts: Vec<String> = links.iter().filter_map(|(href, _)| url_host(href)).collect();
            hosts.sort();
            hosts.dedup();
            if !links.is_empty() {
                cx.security().external_references(links.len() as u64);
                f.insert("links".into(), json!(links.len()));
                f.insert("link_hosts".into(), json!(hosts.iter().take(MAX_LISTED).collect::<Vec<_>>()));
            }
            let mismatched: Vec<String> = links
                .iter()
                .filter_map(|(href, text)| {
                    let real = url_host(href)?;
                    let shown = shown_host(text)?;
                    (base_domain(&real) != base_domain(&shown)).then(|| format!("{shown} -> {real}"))
                })
                .take(5)
                .collect();
            if !mismatched.is_empty() {
                cx.security().risk("link_text_mismatch", Some(truncate_chars(&mismatched.join(", "), 200)));
            }
            let lower = html.to_ascii_lowercase();
            if lower.contains("<form") {
                cx.security().active_content("html_form");
                if lower.contains("type=\"password\"")
                    || lower.contains("type=password")
                    || lower.contains("type='password'")
                {
                    cx.security().risk("password_form", None);
                }
            }
            if lower.contains("<script") {
                cx.security().active_content("scripts");
            }
        }
    }
}

/// A host named in link text (`https://bank.example/login`, `www.bank.example`).
fn shown_host(text: &str) -> Option<String> {
    let t = text.trim();
    if t.contains(char::is_whitespace) || !t.contains('.') {
        return None;
    }
    if let Some(h) = url_host(t) {
        return Some(h);
    }
    let host = t.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    let tld = host.rsplit('.').next()?;
    (host.starts_with("www.")
        || (tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()) && host.split('.').count() >= 2))
        .then_some(host)
}

/// `(href, text)` of the anchors in an HTML body.
pub(crate) fn links(html: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    while let Some(a) = lower[i..].find("<a") {
        let start = i + a;
        i = start + 2;
        if !lower[i..].starts_with([' ', '\n', '\t', '\r']) {
            continue;
        }
        let Some(gt) = lower[start..].find('>').map(|g| start + g) else { break };
        let tag = &html[start..gt];
        let href = attr(tag, "href");
        let close = lower[gt..].find("</a").map_or(lower.len(), |c| gt + c);
        let text = crate::plugin::html_text(&html[gt + 1..close], 2000).0;
        if let Some(h) = href
            && out.len() < 10_000
        {
            out.push((crate::plugin::decode_entities(&h).into_owned(), crate::plugin::squash_whitespace(&text)));
        }
        i = close.max(i);
    }
    out
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(p) = lower[from..].find(name) {
        let at = from + p;
        from = at + name.len();
        let before = lower[..at].chars().last();
        if !before.is_some_and(char::is_whitespace) {
            continue;
        }
        let rest = tag[from..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else { continue };
        let rest = rest.trim_start();
        let (q, body) = match rest.chars().next()? {
            q @ ('"' | '\'') => (Some(q), &rest[1..]),
            _ => (None, rest),
        };
        let end = match q {
            Some(q) => body.find(q).unwrap_or(body.len()),
            None => body.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(body.len()),
        };
        return Some(body[..end].to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_and_links() {
        assert_eq!(domain("Ana <ana@Saltmere.example>"), Some("saltmere.example".into()));
        assert_eq!(base_domain("mail.harbour.saltmere.example"), "saltmere.example");
        assert_eq!(base_domain("www.example.co.uk"), "example.co.uk");
        assert_eq!(url_host("https://user@pay.example.org:443/x"), Some("pay.example.org".into()));
        let l = links(
            r#"<p><a href="https://other.example/pay">https://saltmere.example/fees</a> <A HREF='mailto:x@y'>mail</A></p>"#,
        );
        assert_eq!(l.len(), 2);
        assert_eq!(shown_host(&l[0].1), Some("saltmere.example".into()));
        assert_eq!(shown_host("Pay now"), None);
    }
}
