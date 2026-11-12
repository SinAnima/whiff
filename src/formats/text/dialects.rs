//! XML vocabularies with a reader of their own, and DTDs:
//!
//! * DTDs: element, attribute-list, entity and notation declarations;
//!   external entities are flagged;
//! * Qt Linguist translations (`.ts`): languages, contexts, messages and
//!   how many are finished, unfinished, obsolete or vanished;
//! * SAML metadata, assertions and protocol messages, and XML Signature:
//!   entity ids, roles and endpoints, certificate subjects and validity,
//!   signature and digest algorithms; a subject's name id and attribute
//!   values only with `--privacy off`;
//! * ONIX for Books: release, sender, products, ISBNs, titles,
//!   contributors, publishers;
//! * METS, MODS and EAD library records: titles, dates, files, components;
//! * Dublin Core records and OAI-PMH responses;
//! * Apple Health exports: record types, workouts, sources and the date
//!   range; the owner's characteristics and the source names only with
//!   `--privacy off`;
//! * Android manifests in text form: package, versions, SDK levels,
//!   permissions, components and exported ones;
//! * ClickOnce deployment and application manifests and Windows
//!   side-by-side manifests: identity, publisher, dependencies, files,
//!   requested execution level;
//! * ASAM OpenDRIVE road networks and OpenSCENARIO scenarios.
//!
//! Specifications: XML 1.0 §3 (DTDs); Qt Linguist's TS DTD; OASIS SAML 2.0
//! core and metadata; W3C XML Signature 1.1; EDItEUR ONIX for Books 2.1 / 3.0;
//! Library of Congress METS, MODS and EAD; DCMI / OAI-PMH 2.0; Apple
//! HealthKit's export DTD; the Android manifest reference; Microsoft's
//! ClickOnce and application manifest schemas; ASAM OpenDRIVE 1.x and
//! OpenSCENARIO 1.x.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, der, xmlwalk,
};

/// Extractor for the XML vocabularies above.
pub struct Dialects;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*]) => {
        FormatSpec { id: $id, name: $name, family: "text.xml", mimes: &[$mime], extensions: &[$($ext),*], magic: &[], parent: Some("xml") }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "text.dialects",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "dtd",
            name: "XML document type definition",
            family: "text.xml",
            mimes: &["application/xml-dtd"],
            extensions: &["dtd"],
            magic: &[],
            parent: Some("text"),
        },
        spec!("qt_ts", "Qt Linguist translation", "application/x-linguist", []),
        spec!("saml", "SAML / XML Signature", "application/samlmetadata+xml", ["saml"]),
        spec!("onix", "ONIX for Books", "application/xml", ["onix"]),
        spec!("library_xml", "METS / MODS / EAD record", "application/xml", ["mets", "mods", "ead"]),
        spec!("dublin_core", "Dublin Core / OAI-PMH", "application/xml", []),
        spec!("apple_health", "Apple Health export", "application/xml", []),
        spec!("android_manifest", "Android manifest", "application/xml", []),
        spec!(
            "app_manifest",
            "ClickOnce / application manifest",
            "application/x-ms-application",
            ["application", "manifest"]
        ),
        spec!("opendrive", "ASAM OpenDRIVE road network", "application/xml", ["xodr"]),
        spec!("openscenario", "ASAM OpenSCENARIO scenario", "application/xml", ["xosc"]),
    ],
};

/// Events walked at most.
const MAX_EVENTS: usize = 20_000_000;
/// Names listed.
const MAX_LISTED: usize = 50;

impl Extractor for Dialects {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let pick = |format: &'static str| Some(Sniff { format, confidence: 0.93 });
        let h = &probe.head[..probe.head.len().min(16384)];
        let text = String::from_utf8_lossy(h);
        let t = text.trim_start_matches('\u{feff}').trim_start();
        let ext = probe.extension.unwrap_or("");
        let dtd_decl = ["<!ELEMENT", "<!ATTLIST", "<!ENTITY"].iter().any(|d| t.contains(d));
        let Some((root, tag)) = xmlwalk::xml_root(h) else {
            // A DTD has declarations and no root element.
            return (dtd_decl && (ext.eq_ignore_ascii_case("dtd") || t.starts_with("<!") || t.starts_with("<?xml")))
                .then_some(Sniff { format: "dtd", confidence: 0.9 });
        };
        let ns = |n: &str| tag.contains(n) || t.contains(n);
        match root.as_str() {
            "TS" if tag.contains("version") || t.contains("<context>") => pick("qt_ts"),
            "EntityDescriptor" | "EntitiesDescriptor" | "Assertion" | "Response" | "AuthnRequest" | "LogoutRequest"
            | "LogoutResponse"
                if ns("urn:oasis:names:tc:SAML") =>
            {
                pick("saml")
            }
            "Signature" if ns("www.w3.org/2000/09/xmldsig") => pick("saml"),
            "ONIXMessage" | "ONIXmessage" => pick("onix"),
            "mets" if ns("www.loc.gov/METS") => pick("library_xml"),
            "mods" | "modsCollection" if ns("www.loc.gov/mods") => pick("library_xml"),
            "ead" => pick("library_xml"),
            "OAI-PMH" => pick("dublin_core"),
            "dc" | "record" | "metadata" if ns("purl.org/dc/elements/1.1") && !ns("www.loc.gov") => pick("dublin_core"),
            "HealthData" => pick("apple_health"),
            "manifest" if ns("schemas.android.com/apk/res/android") => pick("android_manifest"),
            "assembly" if ns("urn:schemas-microsoft-com:asm.v") => pick("app_manifest"),
            "OpenDRIVE" => pick("opendrive"),
            "OpenSCENARIO" => pick("openscenario"),
            _ => None,
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, cut) = cx.read_bytes(src)?;
        let text = String::from_utf8_lossy(&bytes);
        let text = text.trim_start_matches('\u{feff}');
        if cut {
            cx.format_set("truncated", true);
        }
        match cx.format_id() {
            "dtd" => dtd(cx, text),
            "qt_ts" => qt_ts(cx, text)?,
            "saml" => saml(cx, text)?,
            "onix" => onix(cx, text)?,
            "library_xml" => library(cx, text)?,
            "dublin_core" => dublin_core(cx, text)?,
            "apple_health" => health(cx, text)?,
            "android_manifest" => android(cx, text)?,
            "app_manifest" => app_manifest(cx, text)?,
            "opendrive" => opendrive(cx, text)?,
            _ => openscenario(cx, text)?,
        }
        Ok(())
    }
}

crate::register_extractor!(Dialects);

fn strings(v: impl IntoIterator<Item = String>) -> Value {
    Value::Array(v.into_iter().take(MAX_LISTED).map(Value::String).collect())
}

fn histogram(m: BTreeMap<String, u64>) -> Value {
    let mut v: Vec<(String, u64)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Value::Object(v.into_iter().take(MAX_LISTED).map(|(k, n)| (k, json!(n))).collect())
}

fn range(mut dates: Vec<String>) -> Value {
    dates.sort();
    match (dates.first(), dates.last()) {
        (Some(a), Some(b)) => json!([a, b]),
        _ => Value::Null,
    }
}

/// Walk `text` with the element path (local names) at hand.
fn walk(
    text: &str,
    cx: &mut Context<'_>,
    mut f: impl FnMut(&mut Context<'_>, &[String], Ev<'_>),
) -> Result<(), ExtractError> {
    let mut path: Vec<String> = Vec::new();
    xmlwalk::walk(text, cx, MAX_EVENTS, |cx, ev| match ev {
        xmlwalk::Ev::Start(name, attrs) => {
            path.push(name.to_string());
            f(cx, &path, Ev::Start(attrs));
        }
        xmlwalk::Ev::End(_) => {
            f(cx, &path, Ev::End);
            path.pop();
        }
        xmlwalk::Ev::Text(t) => f(cx, &path, Ev::Text(t)),
    })
}

enum Ev<'a> {
    Start(&'a [(String, String)]),
    End,
    Text(&'a str),
}

fn at(path: &[String], tail: &[&str]) -> bool {
    path.len() >= tail.len() && path[path.len() - tail.len()..].iter().zip(tail).all(|(a, b)| a == b)
}

fn attr<'a>(a: &'a [(String, String)], k: &str) -> Option<&'a str> {
    xmlwalk::attr(a, k)
}

// --- DTD ---------------------------------------------------------------------------------

fn dtd(cx: &mut Context<'_>, text: &str) {
    let (mut elements, mut attlists, mut notations) = (Vec::new(), 0u64, 0u64);
    let (mut general, mut parameter, mut external) = (0u64, 0u64, 0u64);
    let mut rest = text;
    while let Some(p) = rest.find("<!") {
        rest = &rest[p + 2..];
        if rest.starts_with("--") {
            rest = rest.find("-->").map_or("", |e| &rest[e + 3..]);
            continue;
        }
        let end = rest.find('>').unwrap_or(rest.len());
        let decl = &rest[..end];
        let mut w = decl.split_whitespace();
        match w.next() {
            Some("ELEMENT") => elements.extend(w.next().map(str::to_string)),
            Some("ATTLIST") => attlists += 1,
            Some("NOTATION") => notations += 1,
            Some("ENTITY") => {
                if decl.split_whitespace().nth(1) == Some("%") {
                    parameter += 1;
                } else {
                    general += 1;
                }
                if decl.contains(" SYSTEM ") || decl.contains(" PUBLIC ") {
                    external += 1;
                }
            }
            _ => {}
        }
        rest = &rest[end.min(rest.len())..];
    }
    if external > 0 {
        cx.security()
            .risk("external_entity", Some(format!("{external} external entity declaration(s)")))
            .external_references(external);
    }
    cx.format_set("elements", elements.len());
    cx.format_set("element_names", strings(elements));
    cx.format_set("attribute_lists", attlists);
    cx.format_set("general_entities", general);
    cx.format_set("parameter_entities", parameter);
    cx.format_set("external_entities", external);
    cx.format_set("notations", notations);
}

// --- Qt Linguist -------------------------------------------------------------------------

fn qt_ts(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut contexts, mut messages, mut numerus) = (0u64, 0u64, 0u64);
    let mut states: BTreeMap<String, u64> = BTreeMap::new();
    let (mut sources, mut pending_type) = (String::new(), None::<String>);
    walk(text, cx, |cx, path, ev| match ev {
        Ev::Start(a) => match path.last().map(String::as_str) {
            Some("TS") => {
                for (k, key) in
                    [("version", "ts_version"), ("language", "language"), ("sourcelanguage", "source_language")]
                {
                    if let Some(v) = attr(a, k) {
                        cx.format_set(key, v);
                    }
                }
            }
            Some("context") => contexts += 1,
            Some("message") => {
                messages += 1;
                if attr(a, "numerus") == Some("yes") {
                    numerus += 1;
                }
            }
            Some("translation") => pending_type = Some(attr(a, "type").unwrap_or("finished").to_string()),
            _ => {}
        },
        Ev::Text(t) if at(path, &["message", "source"]) && sources.len() < 1 << 20 => {
            sources.push_str(t);
            sources.push('\n');
        }
        Ev::End if path.last().is_some_and(|p| p == "translation") => {
            *states.entry(pending_type.take().unwrap_or_default()).or_default() += 1;
        }
        _ => {}
    })?;
    cx.format_set("contexts", contexts);
    cx.format_set("messages", messages);
    cx.format_set("plural_messages", numerus);
    cx.format_set("translations", json!(states));
    cx.emit_text(TextRole::Data, &sources);
    Ok(())
}

// --- SAML / XML Signature ----------------------------------------------------------------

fn base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff).to_le_bytes()[0]);
            // Keep only the bits not yet written, so `acc` never overflows.
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[allow(clippy::too_many_lines)] // one element after another
fn saml(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let strict = cx.privacy_strict();
    let (mut entities, mut roles, mut certs) = (Vec::new(), BTreeMap::<String, u64>::new(), Vec::new());
    let (mut sig_algs, mut digest_algs, mut signatures) = (BTreeSet::new(), BTreeSet::new(), 0u64);
    let (mut endpoints, mut attributes, mut nameid_formats) =
        (BTreeMap::<String, u64>::new(), Vec::new(), BTreeSet::new());
    let (mut root, mut issuer, mut name_id, mut status) =
        (None::<String>, None::<String>, None::<String>, None::<String>);
    let mut attr_values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current_attr = None::<String>;
    let mut header: Vec<(&'static str, String)> = Vec::new();
    walk(text, cx, |_, path, ev| match ev {
        Ev::Start(a) => {
            let name = path.last().map_or("", String::as_str);
            if path.len() == 1 {
                root = Some(name.to_string());
                for (k, key) in [
                    ("ID", "message_id"),
                    ("IssueInstant", "issued"),
                    ("Destination", "destination"),
                    ("validUntil", "valid_until"),
                ] {
                    if let Some(v) = attr(a, k) {
                        header.push((key, v.to_string()));
                    }
                }
            }
            match name {
                "EntityDescriptor" => entities.extend(attr(a, "entityID").map(str::to_string)),
                "IDPSSODescriptor"
                | "SPSSODescriptor"
                | "AttributeAuthorityDescriptor"
                | "AuthnAuthorityDescriptor"
                | "PDPDescriptor"
                | "RoleDescriptor" => *roles.entry(name.trim_end_matches("Descriptor").into()).or_default() += 1,
                "SingleSignOnService"
                | "SingleLogoutService"
                | "AssertionConsumerService"
                | "ArtifactResolutionService" => {
                    *endpoints.entry(name.to_string()).or_default() += 1;
                }
                "SignatureMethod" => {
                    sig_algs.extend(attr(a, "Algorithm").map(|s| s.rsplit(['#', '/']).next().unwrap_or(s).to_string()));
                }
                "DigestMethod" => digest_algs
                    .extend(attr(a, "Algorithm").map(|s| s.rsplit(['#', '/']).next().unwrap_or(s).to_string())),
                "Signature" => signatures += 1,
                "NameID" => {
                    nameid_formats.extend(attr(a, "Format").map(|s| s.rsplit(':').next().unwrap_or(s).to_string()));
                }
                "Attribute" => {
                    let n = attr(a, "FriendlyName").or_else(|| attr(a, "Name")).unwrap_or("").to_string();
                    attributes.push(n.clone());
                    current_attr = Some(n);
                }
                "StatusCode" if path.len() <= 3 => {
                    status = attr(a, "Value").map(|s| s.rsplit(':').next().unwrap_or(s).to_string());
                }
                _ => {}
            }
        }
        Ev::Text(t) => {
            if at(path, &["X509Data", "X509Certificate"]) && certs.len() < 20 {
                certs.extend(base64(t).and_then(|d| der::certificate(&d)));
            } else if path.last().is_some_and(|p| p == "Issuer") && issuer.is_none() {
                issuer = Some(t.to_string());
            } else if path.last().is_some_and(|p| p == "NameID") {
                name_id = Some(t.to_string());
            } else if at(path, &["Attribute", "AttributeValue"])
                && let Some(n) = &current_attr
            {
                let v = attr_values.entry(n.clone()).or_default();
                if v.len() < 20 {
                    v.push(t.to_string());
                }
            }
        }
        Ev::End => {
            if path.last().is_some_and(|p| p == "Attribute") {
                current_attr = None;
            }
        }
    })?;
    let kind = match root.as_deref() {
        Some("EntityDescriptor" | "EntitiesDescriptor") => "SAML metadata",
        Some("Assertion") => "SAML assertion",
        Some("Response") => "SAML response",
        Some("AuthnRequest") => "SAML authentication request",
        Some("LogoutRequest" | "LogoutResponse") => "SAML logout message",
        Some("Signature") => "XML Signature",
        _ => "SAML",
    };
    cx.format_set("kind", kind);
    for (k, v) in header {
        cx.format_set(k, v);
    }
    let names = attributes;
    if !entities.is_empty() {
        cx.format_set("entity_ids", strings(entities));
    }
    if let Some(i) = issuer {
        cx.format_set("issuer", i);
    }
    if !roles.is_empty() {
        cx.format_set("roles", json!(roles));
    }
    if !endpoints.is_empty() {
        cx.format_set("endpoints", json!(endpoints));
    }
    if let Some(s) = status {
        cx.format_set("status", s);
    }
    if !nameid_formats.is_empty() {
        cx.format_set("name_id_formats", strings(nameid_formats));
    }
    if !names.is_empty() {
        cx.format_set("attribute_names", strings(names));
    }
    if !strict {
        if let Some(n) = name_id {
            cx.format_set("name_id", n);
        }
        if !attr_values.is_empty() {
            cx.format_set("attribute_values", json!(attr_values));
        }
    }
    cx.format_set("signatures", signatures);
    if !sig_algs.is_empty() {
        cx.format_set("signature_algorithms", strings(sig_algs));
    }
    if !digest_algs.is_empty() {
        cx.format_set("digest_algorithms", strings(digest_algs));
    }
    if !certs.is_empty() {
        let keep = ["subject", "issuer", "not_before", "not_after", "sha256", "key_algorithm", "key_bits"];
        let certs: Vec<Value> = certs
            .into_iter()
            .map(|c| Value::Object(c.into_iter().filter(|(k, _)| keep.contains(&k.as_str())).collect()))
            .collect();
        cx.format_set("certificates", certs);
    }
    Ok(())
}

// --- ONIX ------------------------------------------------------------------------------------

fn onix(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut products, mut contributors) = (0u64, 0u64);
    let (mut isbns, mut titles, mut publishers, mut sender) = (Vec::new(), Vec::new(), BTreeSet::new(), None::<String>);
    let (mut id_type, mut forms) = (None::<String>, BTreeMap::<String, u64>::new());
    walk(text, cx, |cx, path, ev| match ev {
        Ev::Start(a) => match path.last().map(String::as_str) {
            Some("ONIXMessage" | "ONIXmessage") => {
                cx.format_set("release", attr(a, "release").unwrap_or("2.1"));
            }
            Some("Product" | "product") => products += 1,
            Some("Contributor" | "contributor") => contributors += 1,
            _ => {}
        },
        Ev::Text(t) => {
            let last = path.last().map_or("", String::as_str);
            match last {
                "ProductIDType" | "b221" => id_type = Some(t.to_string()),
                "IDValue" | "b244" if path.iter().any(|p| p == "ProductIdentifier" || p == "productidentifier") => {
                    if matches!(id_type.as_deref(), Some("15" | "03")) && isbns.len() < MAX_LISTED {
                        isbns.push(t.to_string());
                    }
                }
                "TitleText" | "b203" if titles.len() < MAX_LISTED => titles.push(t.to_string()),
                "PublisherName" | "b081" => _ = publishers.insert(t.to_string()),
                "SenderName" | "m174" if sender.is_none() => sender = Some(t.to_string()),
                "ProductForm" | "b012" => *forms.entry(t.to_string()).or_default() += 1,
                _ => {}
            }
        }
        Ev::End => {}
    })?;
    if let Some(s) = sender {
        cx.format_set("sender", s);
    }
    cx.format_set("products", products);
    cx.format_set("isbns", strings(isbns));
    if let Some(t) = titles.first() {
        cx.content().title(t.clone());
    }
    cx.format_set("titles", strings(titles));
    cx.format_set("contributors", contributors);
    cx.format_set("publishers", strings(publishers));
    cx.format_set("product_forms", json!(forms));
    Ok(())
}

// --- METS / MODS / EAD -------------------------------------------------------------------------

fn library(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut root = String::new();
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let (mut titles, mut dates, mut names, mut genres) = (Vec::new(), Vec::new(), BTreeSet::new(), BTreeSet::new());
    let mut ids = Vec::new();
    walk(text, cx, |cx, path, ev| match ev {
        Ev::Start(a) => {
            let name = path.last().map_or("", String::as_str);
            if path.len() == 1 {
                root = name.to_string();
                if name == "mets" {
                    for (k, key) in
                        [("OBJID", "object_id"), ("LABEL", "label"), ("TYPE", "type"), ("PROFILE", "profile")]
                    {
                        if let Some(v) = attr(a, k) {
                            cx.format_set(key, v);
                        }
                    }
                }
            }
            let key = match name {
                "dmdSec" => "descriptive_sections",
                "amdSec" => "administrative_sections",
                "fileGrp" => "file_groups",
                "file" if root == "mets" => "files",
                "div" if root == "mets" => "structure_divisions",
                "agent" => "agents",
                "mods" => "records",
                "c" | "c01" | "c02" | "c03" | "c04" | "c05" | "c06" => "components",
                "dao" | "daogrp" => "digital_objects",
                _ => return,
            };
            *counts.entry(key).or_default() += 1;
        }
        Ev::Text(t) => {
            let last = path.last().map_or("", String::as_str);
            match last {
                "title" if at(path, &["titleInfo", "title"]) && titles.len() < MAX_LISTED => titles.push(t.to_string()),
                "titleproper" | "unittitle" if titles.len() < MAX_LISTED => titles.push(t.to_string()),
                "dateIssued" | "dateCreated" | "unitdate" | "date" => dates.push(t.to_string()),
                "namePart" | "persname" | "corpname" | "origination" if names.len() < MAX_LISTED => {
                    _ = names.insert(t.to_string());
                }
                "genre" => _ = genres.insert(t.to_string()),
                "eadid" | "recordIdentifier" | "identifier" if ids.len() < MAX_LISTED => ids.push(t.to_string()),
                "name" if at(path, &["agent", "name"]) && names.len() < MAX_LISTED => _ = names.insert(t.to_string()),
                _ => {}
            }
        }
        Ev::End => {}
    })?;
    let dialect = match root.as_str() {
        "mets" => "METS",
        "mods" | "modsCollection" => "MODS",
        _ => "EAD",
    };
    cx.format_set("dialect", dialect);
    if let Some(t) = titles.first() {
        cx.content().title(t.clone());
    }
    cx.format_set("titles", strings(titles));
    cx.format_set("dates", range(dates));
    cx.format_set("names", strings(names));
    if !genres.is_empty() {
        cx.format_set("genres", strings(genres));
    }
    if !ids.is_empty() {
        cx.format_set("identifiers", strings(ids));
    }
    cx.format_set("counts", json!(counts));
    Ok(())
}

// --- Dublin Core / OAI-PMH ------------------------------------------------------------------

fn dublin_core(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut dc: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let (mut records, mut headers, mut deleted, mut sets) = (0u64, 0u64, 0u64, BTreeSet::new());
    let (mut verb, mut response_date, mut token, mut oai) = (None::<String>, None::<String>, false, false);
    let mut datestamps = Vec::new();
    walk(text, cx, |_, path, ev| match ev {
        Ev::Start(a) => match path.last().map(String::as_str) {
            Some("OAI-PMH") => oai = true,
            Some("request") => verb = attr(a, "verb").map(str::to_string),
            Some("record") if oai => records += 1,
            Some("header") if oai => {
                headers += 1;
                if attr(a, "status") == Some("deleted") {
                    deleted += 1;
                }
            }
            Some("resumptionToken") => token = true,
            _ => {}
        },
        Ev::Text(t) => {
            let last = path.last().map_or("", String::as_str);
            match last {
                "responseDate" => response_date = Some(t.to_string()),
                "datestamp" => datestamps.push(t.to_string()),
                "setSpec" if sets.len() < MAX_LISTED => _ = sets.insert(t.to_string()),
                "title" | "creator" | "subject" | "description" | "publisher" | "contributor" | "date" | "type"
                | "format" | "identifier" | "source" | "language" | "relation" | "coverage" | "rights" => {
                    let v = dc.entry(last.to_string()).or_default();
                    if v.len() < 20 {
                        v.push(t.chars().take(300).collect());
                    }
                }
                _ => {}
            }
        }
        Ev::End => {}
    })?;
    if oai {
        cx.format_set("protocol", "OAI-PMH 2.0");
        if let Some(v) = verb {
            cx.format_set("verb", v);
        }
        if let Some(d) = response_date {
            cx.format_set("response_date", d);
        }
        cx.format_set("records", records.max(headers));
        cx.format_set("deleted", deleted);
        cx.format_set("datestamps", range(datestamps));
        cx.format_set("sets", strings(sets));
        cx.format_set("resumption_token", token);
    }
    if let Some(t) = dc.get("title").and_then(|t| t.first()) {
        cx.content().title(t.clone());
    }
    if let Some(d) = dc.get("description") {
        cx.emit_text(TextRole::Body, &d.join("\n"));
    }
    cx.format_set("elements", json!(dc.iter().map(|(k, v)| (k.clone(), v.len())).collect::<BTreeMap<_, _>>()));
    if !oai {
        cx.format_set("record", json!(dc));
    }
    Ok(())
}

// --- Apple Health ------------------------------------------------------------------------------

fn health(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let strict = cx.privacy_strict();
    let (mut types, mut workouts, mut sources) = (BTreeMap::new(), BTreeMap::new(), BTreeSet::new());
    let (mut dates, mut summaries, mut clinical, mut me) = (Vec::new(), 0u64, 0u64, Map::new());
    walk(text, cx, |cx, path, ev| {
        let Ev::Start(a) = ev else { return };
        match path.last().map(String::as_str) {
            Some("HealthData") => {
                if let Some(l) = attr(a, "locale") {
                    cx.format_set("locale", l);
                }
            }
            Some("ExportDate") => {
                if let Some(v) = attr(a, "value") {
                    cx.format_set("export_date", v);
                }
            }
            Some("Me") => {
                for (k, v) in a {
                    me.insert(k.trim_start_matches("HKCharacteristicTypeIdentifier").to_string(), json!(v));
                }
            }
            Some(kind @ ("Record" | "Workout")) if path.len() == 2 => {
                let t = attr(a, if kind == "Record" { "type" } else { "workoutActivityType" }).unwrap_or("");
                let t = t
                    .trim_start_matches("HKQuantityTypeIdentifier")
                    .trim_start_matches("HKCategoryTypeIdentifier")
                    .trim_start_matches("HKDataType")
                    .trim_start_matches("HKWorkoutActivityType")
                    .to_string();
                let map = if kind == "Record" { &mut types } else { &mut workouts };
                if map.len() < 500 || map.contains_key(&t) {
                    *map.entry(t).or_insert(0u64) += 1;
                }
                if let Some(d) = attr(a, "startDate") {
                    dates.push(d.get(..10).unwrap_or(d).to_string());
                    if dates.len() > 4096 {
                        dates.sort();
                        let last = dates.pop();
                        dates.truncate(1);
                        dates.extend(last);
                    }
                }
                if let Some(s) = attr(a, "sourceName")
                    && sources.len() < 200
                {
                    sources.insert(s.to_string());
                }
            }
            Some("ActivitySummary") => summaries += 1,
            Some("ClinicalRecord") => clinical += 1,
            _ => {}
        }
    })?;
    cx.format_set("records", types.values().sum::<u64>());
    cx.format_set("record_types", histogram(types));
    cx.format_set("workouts", histogram(workouts));
    cx.format_set("activity_summaries", summaries);
    cx.format_set("clinical_records", clinical);
    cx.format_set("date_range", range(dates));
    cx.format_set("sources", sources.len());
    if !strict {
        cx.format_set("source_names", strings(sources));
        if !me.is_empty() {
            cx.format_set("characteristics", Value::Object(me));
        }
    }
    Ok(())
}

// --- Android manifest -------------------------------------------------------------------------

fn android(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut permissions, mut components, mut exported) = (Vec::new(), BTreeMap::<String, u64>::new(), Vec::new());
    let (mut features, mut actions) = (BTreeSet::new(), BTreeSet::new());
    let mut flags = Map::new();
    // The component being read: kind, name, `exported` as written, and
    // whether it has an intent filter (exported by default before API 31).
    let mut current: Option<(String, String, Option<bool>, bool)> = None;
    walk(text, cx, |cx, path, ev| match ev {
        Ev::Start(a) => match path.last().map(String::as_str) {
            Some("manifest") => {
                for (k, key) in
                    [("package", "package"), ("versionCode", "version_code"), ("versionName", "version_name")]
                {
                    if let Some(v) = attr(a, k) {
                        cx.format_set(key, v);
                    }
                }
            }
            Some("uses-sdk") => {
                for (k, key) in
                    [("minSdkVersion", "min_sdk"), ("targetSdkVersion", "target_sdk"), ("maxSdkVersion", "max_sdk")]
                {
                    if let Some(v) = attr(a, k) {
                        cx.format_set(key, v);
                    }
                }
            }
            Some("uses-permission" | "uses-permission-sdk-23") => {
                permissions.extend(attr(a, "name").map(str::to_string));
            }
            Some("uses-feature") => features.extend(attr(a, "name").map(str::to_string)),
            Some("application") => {
                for k in ["label", "debuggable", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig", "name"]
                {
                    if let Some(v) = attr(a, k) {
                        flags.insert(k.to_string(), json!(v));
                    }
                }
            }
            Some(kind @ ("activity" | "activity-alias" | "service" | "receiver" | "provider")) => {
                *components.entry(kind.to_string()).or_default() += 1;
                let explicit = attr(a, "exported").map(|v| v == "true");
                current = Some((kind.to_string(), attr(a, "name").unwrap_or("").to_string(), explicit, false));
            }
            Some("intent-filter") => {
                if let Some(c) = current.as_mut() {
                    c.3 = true;
                }
            }
            Some("action") => actions.extend(attr(a, "name").map(str::to_string)),
            _ => {}
        },
        Ev::End => {
            if matches!(
                path.last().map(String::as_str),
                Some("activity" | "activity-alias" | "service" | "receiver" | "provider")
            ) && let Some((kind, name, explicit, filter)) = current.take()
                && explicit.unwrap_or(filter)
            {
                exported.push(format!("{kind} {name}"));
            }
        }
        Ev::Text(_) => {}
    })?;
    cx.format_set("permissions", strings(permissions));
    if !features.is_empty() {
        cx.format_set("features", strings(features));
    }
    if !flags.is_empty() {
        cx.format_set("application", Value::Object(flags));
    }
    cx.format_set("components", json!(components));
    cx.format_set("exported_components", strings(exported));
    cx.format_set("intent_actions", strings(actions));
    Ok(())
}

// --- ClickOnce / application manifests --------------------------------------------------------

fn app_manifest(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let (mut dependencies, mut files, mut signed, mut kind) = (Vec::new(), 0u64, false, "application manifest");
    let mut identity_done = false;
    walk(text, cx, |cx, path, ev| match ev {
        Ev::Start(a) => match path.last().map(String::as_str) {
            Some("assemblyIdentity") if !identity_done && path.len() == 2 => {
                identity_done = true;
                for (k, key) in [
                    ("name", "name"),
                    ("version", "version"),
                    ("processorArchitecture", "architecture"),
                    ("publicKeyToken", "public_key_token"),
                    ("language", "language"),
                    ("type", "type"),
                ] {
                    if let Some(v) = attr(a, k) {
                        cx.format_set(key, v);
                    }
                }
            }
            Some("assemblyIdentity") if path.iter().any(|p| p == "dependentAssembly") => {
                let n = attr(a, "name").unwrap_or("");
                let v = attr(a, "version").map(|v| format!(" {v}")).unwrap_or_default();
                dependencies.push(format!("{n}{v}"));
            }
            Some("deployment") => {
                kind = "ClickOnce deployment manifest";
                for (k, key) in [("install", "install"), ("minimumRequiredVersion", "minimum_required_version")] {
                    if let Some(v) = attr(a, k) {
                        cx.format_set(key, v);
                    }
                }
            }
            Some("deploymentProvider") => {
                if let Some(v) = attr(a, "codebase") {
                    cx.format_set("deployment_url", v);
                }
            }
            Some("description") => {
                for (k, key) in [("publisher", "publisher"), ("product", "product"), ("supportUrl", "support_url")] {
                    if let Some(v) = attr(a, k) {
                        cx.format_set(key, v);
                    }
                }
            }
            Some("entryPoint") => {
                if kind == "application manifest" {
                    kind = "ClickOnce application manifest";
                }
            }
            Some("commandLine") => {
                if let Some(v) = attr(a, "file") {
                    cx.format_set("entry_point", v);
                }
            }
            Some("file") => files += 1,
            Some("requestedExecutionLevel") => {
                if let Some(v) = attr(a, "level") {
                    cx.format_set("execution_level", v);
                }
                if let Some(v) = attr(a, "uiAccess") {
                    cx.format_set("ui_access", v == "true");
                }
            }
            Some("Signature") => signed = true,
            _ => {}
        },
        Ev::Text(t) => {
            if path.last().is_some_and(|p| p == "dpiAware" || p == "dpiAwareness") {
                cx.format_set("dpi_awareness", t);
            }
        }
        Ev::End => {}
    })?;
    cx.format_set("kind", kind);
    cx.format_set("dependencies", strings(dependencies));
    cx.format_set("files", files);
    cx.format_set("signed", signed);
    Ok(())
}

// --- OpenDRIVE / OpenSCENARIO ----------------------------------------------------------------

#[allow(clippy::cast_precision_loss)]
fn opendrive(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut length = 0f64;
    let mut georef = None::<String>;
    walk(text, cx, |cx, path, ev| match ev {
        Ev::Start(a) => {
            let name = path.last().map_or("", String::as_str);
            if name == "header" && path.len() == 2 {
                if let (Some(a1), Some(b)) = (attr(a, "revMajor"), attr(a, "revMinor")) {
                    cx.format_set("revision", format!("{a1}.{b}"));
                }
                for (k, key) in [("name", "name"), ("date", "date"), ("vendor", "vendor"), ("version", "version")] {
                    if let Some(v) = attr(a, k).filter(|v| !v.is_empty()) {
                        cx.format_set(key, v);
                    }
                }
            }
            let key = match name {
                "road" => {
                    length += attr(a, "length").and_then(|l| l.parse::<f64>().ok()).unwrap_or(0.0);
                    "roads"
                }
                "junction" => "junctions",
                "signal" => "signals",
                "object" => "objects",
                "lane" => "lanes",
                "controller" => "controllers",
                _ => return,
            };
            *counts.entry(key).or_default() += 1;
        }
        Ev::Text(t) if path.last().is_some_and(|p| p == "geoReference") => georef = Some(t.to_string()),
        _ => {}
    })?;
    cx.format_set("counts", json!(counts));
    cx.format_set("road_length_m", (length * 10.0).round() / 10.0);
    if let Some(g) = georef {
        cx.format_set("geo_reference", g);
    }
    Ok(())
}

fn openscenario(cx: &mut Context<'_>, text: &str) -> Result<(), ExtractError> {
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let (mut entities, mut catalogs) = (Vec::new(), BTreeSet::new());
    walk(text, cx, |cx, path, ev| {
        let Ev::Start(a) = ev else { return };
        let name = path.last().map_or("", String::as_str);
        match name {
            "FileHeader" => {
                if let (Some(a1), Some(b)) = (attr(a, "revMajor"), attr(a, "revMinor")) {
                    cx.format_set("revision", format!("{a1}.{b}"));
                }
                for (k, key) in [("description", "description"), ("author", "author"), ("date", "date")] {
                    if let Some(v) = attr(a, k).filter(|v| !v.is_empty()) {
                        cx.format_set(key, v);
                    }
                }
                if let Some(d) = attr(a, "description").filter(|d| !d.is_empty()) {
                    cx.content().title(d.to_string());
                }
            }
            "LogicFile" | "SceneGraphFile" => {
                if let Some(f) = attr(a, "filepath") {
                    cx.format_set(if name == "LogicFile" { "road_network" } else { "scene_graph" }, f);
                }
            }
            "ScenarioObject" => entities.extend(attr(a, "name").map(str::to_string)),
            n if n.ends_with("Catalog") && path.iter().any(|p| p == "CatalogLocations") => {
                _ = catalogs.insert(n.to_string());
            }
            "Story" => *counts.entry("stories").or_default() += 1,
            "Act" => *counts.entry("acts").or_default() += 1,
            "ManeuverGroup" => *counts.entry("maneuver_groups").or_default() += 1,
            "Maneuver" => *counts.entry("maneuvers").or_default() += 1,
            "Event" => *counts.entry("events").or_default() += 1,
            "Action" => *counts.entry("actions").or_default() += 1,
            "ParameterDeclaration" => *counts.entry("parameters").or_default() += 1,
            _ => {}
        }
    })?;
    cx.format_set("entities", strings(entities));
    if !catalogs.is_empty() {
        cx.format_set("catalogs", strings(catalogs));
    }
    cx.format_set("counts", json!(counts));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!(
        "dtd",
        "qt_ts",
        "saml",
        "onix",
        "library_xml",
        "dublin_core",
        "apple_health",
        "android_manifest",
        "app_manifest",
        "opendrive",
        "openscenario"
    );

    #[test]
    fn base64_decodes() {
        assert_eq!(base64("aGFyYm91cg==").as_deref(), Some(&b"harbour"[..]));
        assert!(base64("not*base64").is_none());
    }

    /// A SAML subject and the owner of a health export appear only with
    /// `--privacy off` (neutral samples).
    #[test]
    fn people_follow_privacy() {
        let saml = br#"<?xml version="1.0"?><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1"><saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID>alpha.beta</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>gamma</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#;
        let health = br#"<?xml version="1.0"?><HealthData locale="en"><ExportDate value="2025-01-01"/><Me HKCharacteristicTypeIdentifierDateOfBirth="1900-01-02"/><Record type="HKQuantityTypeIdentifierStepCount" sourceName="Delta" startDate="2025-01-01 08:00:00 +0000" value="10"/></HealthData>"#;
        for (name, bytes, needles) in
            [("a.xml", &saml[..], ["alpha.beta", "gamma"]), ("export.xml", &health[..], ["1900-01-02", "Delta"])]
        {
            let strict = serde_json::to_string(&crate::plugin::testing::report_for(name, bytes)).unwrap();
            let off = serde_json::to_string(&crate::plugin::testing::report_without_privacy(name, bytes)).unwrap();
            for n in needles {
                assert!(!strict.contains(n), "{name}: {n} in a strict report");
                assert!(off.contains(n), "{name}: {n} missing with privacy off");
            }
        }
    }
}
