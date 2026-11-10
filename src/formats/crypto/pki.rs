//! X.509 and its neighbours, as DER or PEM: certificates (subject, issuer,
//! serial, validity and whether it has passed, key algorithm / size /
//! curve, signature algorithm, basic constraints, key usage, extended key
//! usage, subject alternative names, SHA-256 and SHA-1 fingerprints),
//! certificate requests, revocation lists (issuer, updates, revoked
//! count), PKCS#7 / CMS signed and enveloped data (signer, digest,
//! times, chain; recipients), Microsoft catalogs (member count), PKCS#12
//! (MAC, which safes are encrypted, bag types, readable certificates) and
//! keys (PKCS#8, encrypted PKCS#8, PKCS#1, SEC1, `SubjectPublicKeyInfo`):
//! type, size, curve and how a private key is protected, never the key.
//!
//! Specifications: RFC 5280 (certificates, CRLs), RFC 2986 (PKCS#10),
//! RFC 5652 (CMS), RFC 7292 (PKCS#12), RFC 5958 / 8018 (PKCS#8, PBES2),
//! RFC 8017 (PKCS#1), RFC 5915 (SEC1 keys), RFC 7468 (PEM).

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{Pem, check_strength, hex, is_past, pem_blocks};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, der,
};

/// Extractor for certificates, keys and CMS files.
pub struct Pki;

static META: ExtractorMeta = ExtractorMeta {
    id: "crypto.pki",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pem",
            name: "PEM file",
            family: "crypto",
            mimes: &["application/x-pem-file"],
            extensions: &["pem", "crt", "cer", "csr", "crl", "p7b"],
            // `sniff`: armour that OpenPGP, OpenSSH and age claim is theirs.
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "x509",
            name: "X.509 certificate (DER)",
            family: "crypto",
            mimes: &["application/pkix-cert", "application/x-x509-ca-cert"],
            extensions: &["crt", "cer", "der"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "pkcs10",
            name: "Certificate signing request (DER)",
            family: "crypto",
            mimes: &["application/pkcs10"],
            extensions: &["csr", "req", "p10"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "x509_crl",
            name: "Certificate revocation list (DER)",
            family: "crypto",
            mimes: &["application/pkix-crl"],
            extensions: &["crl"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "pkcs7",
            name: "PKCS#7 / CMS",
            family: "crypto",
            mimes: &["application/pkcs7-mime", "application/pkcs7-signature", "application/x-pkcs7-certificates"],
            extensions: &["p7b", "p7c", "p7s", "p7m", "spc", "rsa", "dsa", "ec"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "ms_catalog",
            name: "Microsoft security catalog",
            family: "crypto",
            mimes: &["application/vnd.ms-pki.seccat"],
            // Not claimed by extension: `.cat` is also an SGML / XML catalog.
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "pkcs12",
            name: "PKCS#12 / PFX",
            family: "crypto",
            mimes: &["application/x-pkcs12"],
            extensions: &["p12", "pfx"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "der_key",
            name: "Key (DER: PKCS#8, PKCS#1, SEC1, SubjectPublicKeyInfo)",
            family: "crypto",
            mimes: &["application/pkcs8", "application/pkcs8-encrypted"],
            extensions: &["key", "p8", "pk8", "der"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Objects described in full from one file (a CA bundle has ~150).
const MAX_OBJECTS: usize = 64;
/// Revoked entries counted in a CRL before giving up.
const MAX_REVOKED: usize = 1_000_000;

/// What a DER object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Certificate,
    Request,
    Crl,
    /// CMS `ContentInfo` (signed, enveloped, …).
    Cms,
    Pkcs12,
    /// PKCS#8 `PrivateKeyInfo` / `OneAsymmetricKey`.
    Pkcs8,
    EncryptedPkcs8,
    /// PKCS#1 `RSAPrivateKey`.
    RsaPrivate,
    /// PKCS#1 `RSAPublicKey`.
    RsaPublic,
    /// SEC1 `ECPrivateKey`.
    EcPrivate,
    /// OpenSSL's `DSAPrivateKey`.
    DsaPrivate,
    Spki,
}

fn is_int(t: Option<der::Tlv<'_>>, v: u8) -> bool {
    t.is_some_and(|t| t.tag == 0x02 && t.body == [v])
}

fn is_time(t: Option<der::Tlv<'_>>) -> bool {
    t.is_some_and(|t| t.tag == 0x17 || t.tag == 0x18)
}

/// What `data` (one whole DER object) is.
fn classify(data: &[u8]) -> Option<Kind> {
    let (top, rest) = der::read(data)?;
    if top.tag != 0x30 || !rest.iter().all(|&b| b == 0) {
        return None;
    }
    let c: Vec<der::Tlv<'_>> = top.children().take(10).collect();
    let tag = |i: usize| c.get(i).map_or(0, |t| t.tag);
    let signed = c.len() == 3 && tag(0) == 0x30 && tag(1) == 0x30 && tag(2) == 0x03;
    if signed {
        let tbs: Vec<der::Tlv<'_>> = c[0].children().take(7).collect();
        let at = |i: usize| tbs.get(i).copied();
        let v = usize::from(at(0).is_some_and(|t| t.is_context(0) || t.tag == 0x02 && t.body.len() == 1));
        // TBSCertList: [version] signature issuer thisUpdate …
        if is_time(at(v + 2)) && at(v + 1).is_some_and(|t| t.tag == 0x30) {
            return Some(Kind::Crl);
        }
        // CertificationRequestInfo: version subject spki [0] attributes
        if is_int(at(0), 0) && at(2).is_some_and(|t| t.tag == 0x30) && at(3).is_some_and(|t| t.is_context(0)) {
            return Some(Kind::Request);
        }
        if der::certificate(data).is_some() {
            return Some(Kind::Certificate);
        }
        return None;
    }
    if tag(0) == 0x06 && c.len() <= 2 && der::oid(c[0].body).starts_with("1.2.840.113549.1.7.") {
        return Some(Kind::Cms);
    }
    if is_int(c.first().copied(), 3) && tag(1) == 0x30 && c[1].child(0).is_some_and(|o| o.tag == 0x06) {
        return Some(Kind::Pkcs12);
    }
    if (is_int(c.first().copied(), 0) || is_int(c.first().copied(), 1)) && tag(1) == 0x30 && tag(2) == 0x04 {
        return Some(Kind::Pkcs8);
    }
    if c.len() == 2 && tag(0) == 0x30 && tag(1) == 0x04 && c[0].child(0).is_some_and(|o| o.tag == 0x06) {
        return Some(Kind::EncryptedPkcs8);
    }
    if c.len() == 2 && tag(0) == 0x30 && tag(1) == 0x03 && c[0].child(0).is_some_and(|o| o.tag == 0x06) {
        return Some(Kind::Spki);
    }
    if is_int(c.first().copied(), 1) && tag(1) == 0x04 && c.len() <= 4 {
        return Some(Kind::EcPrivate);
    }
    let ints = c.iter().all(|t| t.tag == 0x02);
    match (ints, c.len()) {
        (true, 9 | 10) if is_int(c.first().copied(), 0) => Some(Kind::RsaPrivate),
        (true, 6) if is_int(c.first().copied(), 0) => Some(Kind::DsaPrivate),
        (true, 2) => Some(Kind::RsaPublic),
        _ => None,
    }
}

/// The DER kind a PEM label promises, if it names one.
fn label_kind(label: &str) -> Option<Kind> {
    Some(match label {
        "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => Kind::Certificate,
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => Kind::Request,
        "X509 CRL" => Kind::Crl,
        "PKCS7" | "CMS" | "PKCS #7 SIGNED DATA" => Kind::Cms,
        "PRIVATE KEY" => Kind::Pkcs8,
        "ENCRYPTED PRIVATE KEY" => Kind::EncryptedPkcs8,
        "RSA PRIVATE KEY" => Kind::RsaPrivate,
        "RSA PUBLIC KEY" => Kind::RsaPublic,
        "EC PRIVATE KEY" => Kind::EcPrivate,
        "DSA PRIVATE KEY" => Kind::DsaPrivate,
        "PUBLIC KEY" => Kind::Spki,
        _ => return None,
    })
}

fn format_of(kind: Kind) -> &'static str {
    match kind {
        Kind::Certificate => "x509",
        Kind::Request => "pkcs10",
        Kind::Crl => "x509_crl",
        Kind::Cms => "pkcs7",
        Kind::Pkcs12 => "pkcs12",
        _ => "der_key",
    }
}

/// The report, built object by object.
#[derive(Default)]
struct Out {
    types: Map<String, Value>,
    lists: Map<String, Value>,
    described: usize,
    certificates: usize,
    /// The only certificate's facts (titles the report).
    lone: Option<Map<String, Value>>,
}

impl Out {
    fn count(&mut self, kind: &str) {
        let n = self.types.get(kind).and_then(Value::as_u64).unwrap_or(0);
        self.types.insert(kind.into(), (n + 1).into());
    }

    fn push(&mut self, list: &str, item: Map<String, Value>) {
        self.described += 1;
        if let Value::Array(a) = self.lists.entry(list).or_insert_with(|| Value::Array(Vec::new())) {
            a.push(Value::Object(item));
        }
    }
}

impl Extractor for Pki {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if let Some(rest) = probe.head.strip_prefix(b"-----BEGIN ") {
            let others: [&[u8]; 6] = [b"PGP ", b"OPENSSH ", b"AGE ", b"SSH2 ", b"TSS2 ", b"TSS KEY"];
            let theirs = others.iter().any(|o| rest.starts_with(o));
            return (!theirs).then_some(Sniff { format: "pem", confidence: 0.9 });
        }
        // PEM after explanatory text (`openssl x509 -text`, `Bag Attributes`).
        if probe.head.first() != Some(&0x30) {
            let text = probe.head.get(..probe.head.len().min(16 << 10))?;
            let pem = text.windows(12).any(|w| w == b"\n-----BEGIN ") && std::str::from_utf8(text).is_ok();
            return pem.then_some(Sniff { format: "pem", confidence: 0.6 });
        }
        if probe.len > probe.head.len() as u64 {
            return large_cms(probe.head);
        }
        let kind = classify(probe.head)?;
        // Bare INTEGER sequences are too common to trust without a name.
        let weak = matches!(kind, Kind::RsaPublic | Kind::DsaPrivate | Kind::RsaPrivate | Kind::EcPrivate);
        let named = probe.extension.is_some_and(|e| ["key", "der", "pem", "p1", "pk1"].contains(&e));
        if weak && !named {
            return None;
        }
        let format = match kind {
            Kind::Cms if is_catalog(probe.head) => "ms_catalog",
            k => format_of(k),
        };
        Some(Sniff { format, confidence: 0.8 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len().min(cx.parse_limit() as u64);
        let b = src.read_vec(0, usize::try_from(len).unwrap_or(0))?;
        if len < src.len() {
            cx.warn(format!("only the first {len} bytes were read"));
        }
        let mut out = Out::default();
        if b.first() != Some(&0x30) && b.windows(11).any(|w| w == b"-----BEGIN ") {
            let text = String::from_utf8_lossy(&b);
            let (blocks, outside) = pem_blocks(&text);
            if blocks.is_empty() {
                return Err(ExtractError::malformed("no PEM block"));
            }
            cx.format_set("encoding", "pem");
            if outside {
                cx.format_set("text_outside_blocks", true);
            }
            for (i, block) in blocks.iter().enumerate() {
                pem_block(block, &mut out, cx);
                if i % 256 == 255 {
                    cx.checkpoint()?;
                }
            }
        } else {
            let kind = classify(&b).ok_or_else(|| ExtractError::malformed("not a certificate, key or CMS object"))?;
            cx.format_set("encoding", "der");
            object(kind, &b, &mut out, cx);
        }
        finish(out, cx);
        Ok(())
    }
}

fn pem_block(block: &Pem, out: &mut Out, cx: &mut Context<'_>) {
    let Some(der) = &block.der else {
        out.count("unreadable");
        cx.warn(format!("PEM block {} could not be decoded", block.label));
        return;
    };
    // Old OpenSSL encrypted keys: RFC 1421 headers over an encrypted body.
    if let Some((_, info)) = block.headers.iter().find(|(k, _)| k == "DEK-Info") {
        let mut m = Map::new();
        m.insert("format".into(), "legacy_pem".into());
        m.insert("key_algorithm".into(), legacy_algorithm(&block.label).into());
        m.insert("encrypted".into(), true.into());
        m.insert("cipher".into(), info.split(',').next().unwrap_or("").to_ascii_lowercase().into());
        cx.security().encrypted(true);
        out.count("private_key");
        out.push("private_keys", m);
        return;
    }
    let kind = label_kind(&block.label).or_else(|| classify(der));
    match kind {
        Some(k) if out.described < MAX_OBJECTS => object(k, der, out, cx),
        Some(k) => {
            out.count(type_name(k));
            if k == Kind::Certificate {
                out.certificates += 1;
            }
        }
        None => out.count(&block.label.to_ascii_lowercase().replace(' ', "_")),
    }
}

fn legacy_algorithm(label: &str) -> &'static str {
    match label {
        "RSA PRIVATE KEY" => "rsa",
        "EC PRIVATE KEY" => "ec",
        "DSA PRIVATE KEY" => "dsa",
        _ => "unknown",
    }
}

fn type_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Certificate => "certificate",
        Kind::Request => "certificate_request",
        Kind::Crl => "crl",
        Kind::Cms => "cms",
        Kind::Pkcs12 => "pkcs12",
        Kind::Spki | Kind::RsaPublic => "public_key",
        _ => "private_key",
    }
}

fn object(kind: Kind, der: &[u8], out: &mut Out, cx: &mut Context<'_>) {
    out.count(type_name(kind));
    match kind {
        Kind::Certificate => {
            // `TRUSTED CERTIFICATE` adds OpenSSL trust settings after it.
            let Some(cert) = der::read(der).and_then(|(c, _)| certificate(c.raw, cx)) else {
                cx.warn("a certificate could not be read");
                return;
            };
            out.certificates += 1;
            out.lone = (out.certificates == 1).then(|| cert.clone());
            out.push("certificates", cert);
        }
        Kind::Request => {
            if let Some(r) = request(der, cx) {
                out.push("requests", r);
            }
        }
        Kind::Crl => {
            if let Some(c) = crl(der, cx) {
                out.push("crls", c);
            }
        }
        Kind::Cms => {
            if let Some(c) = cms(der, out, cx) {
                out.push("cms", c);
            }
        }
        Kind::Pkcs12 => {
            if let Some(p) = pkcs12(der, out, cx) {
                out.push("pkcs12", p);
            }
        }
        Kind::Spki | Kind::RsaPublic => {
            if let Some(k) = public(kind, der) {
                check_strength(cx, "public key", key_alg(&k), key_bits(&k));
                out.push("public_keys", k);
            }
        }
        _ => {
            if let Some(k) = private(kind, der, cx) {
                out.push("private_keys", k);
            }
        }
    }
}

fn key_alg(m: &Map<String, Value>) -> &str {
    m.get("key_algorithm").and_then(Value::as_str).unwrap_or("")
}

fn key_bits(m: &Map<String, Value>) -> Option<u64> {
    m.get("key_bits").and_then(Value::as_u64)
}

/// Add whether a certificate's validity has ended or not yet begun.
fn validity(c: &mut Map<String, Value>) {
    if let Some(t) = c.get("not_after").and_then(Value::as_str) {
        let past = is_past(t);
        c.insert("expired".into(), past.into());
    }
    if c.get("not_before").and_then(Value::as_str).is_some_and(|t| !is_past(t)) {
        c.insert("not_yet_valid".into(), true.into());
    }
}

/// A certificate's facts plus whether it is in force.
fn certificate(der: &[u8], cx: &mut Context<'_>) -> Option<Map<String, Value>> {
    let mut c = der::certificate(der)?;
    validity(&mut c);
    let s = |c: &Map<String, Value>, k: &str| c.get(k).and_then(Value::as_str).map(str::to_string);
    let self_signed = c.get("self_signed").and_then(Value::as_bool).unwrap_or(false);
    let subject = s(&c, "subject_cn").or_else(|| s(&c, "subject")).unwrap_or_default();
    check_strength(cx, &format!("certificate {subject}"), key_alg(&c), key_bits(&c));
    // A self-signed certificate's own signature is never relied on.
    if !self_signed && let Some(alg) = s(&c, "signature_algorithm") {
        check_strength(cx, &format!("certificate {subject}"), &alg, None);
    }
    Some(c)
}

fn request(der: &[u8], cx: &mut Context<'_>) -> Option<Map<String, Value>> {
    let (top, _) = der::read(der)?;
    let info = top.child(0)?;
    let mut m = Map::new();
    m.insert("subject".into(), der::name(info.child(1)?).into());
    if let Some(k) = der::public_key(info.child(2)?) {
        k.insert_into(&mut m);
        check_strength(cx, "certificate request", &k.algorithm, k.bits);
    }
    m.insert("signature_algorithm".into(), der::named(top.child(1)?.child(0)?.body).into());
    if let Some(attrs) = info.child(3) {
        let mut names = Vec::new();
        for a in attrs.children() {
            let Some(id) = a.child(0).map(|o| der::named(o.body)) else { continue };
            if id == "extension_request"
                && let Some(exts) = a.child(1).and_then(|s| s.child(0))
            {
                der::extensions(exts, &mut m);
            }
            names.push(id);
        }
        // A challenge password is a secret: only its presence is told.
        if !names.is_empty() {
            m.insert("attributes".into(), json!(names));
        }
    }
    Some(m)
}

fn crl(der: &[u8], cx: &mut Context<'_>) -> Option<Map<String, Value>> {
    let (top, _) = der::read(der)?;
    let tbs = top.child(0)?;
    let mut f = tbs.children().peekable();
    if f.peek().is_some_and(|t| t.tag == 0x02) {
        f.next();
    }
    let _alg = f.next()?;
    let issuer = f.next()?;
    let mut m = Map::new();
    m.insert("issuer".into(), der::name(issuer).into());
    if let Some(t) = f.next().and_then(der::time) {
        m.insert("this_update".into(), t.into());
    }
    let mut revoked = 0usize;
    for t in f {
        match t.tag {
            0x17 | 0x18 => {
                if let Some(next) = der::time(t) {
                    m.insert("stale".into(), is_past(&next).into());
                    m.insert("next_update".into(), next.into());
                }
            }
            0x30 => revoked = t.children().take(MAX_REVOKED).count(),
            _ if t.is_context(0) => {
                for ext in t.child(0).iter().flat_map(der::Tlv::children) {
                    let Some(id) = ext.child(0).map(|o| der::oid(o.body)) else { continue };
                    let value = ext.children().find(|c| c.tag == 0x04).and_then(|v| der::read(v.body)).map(|v| v.0);
                    if id == "2.5.29.20"
                        && let Some(n) = value.filter(|v| v.tag == 0x02)
                    {
                        m.insert("crl_number".into(), der::serial(n).into());
                    }
                }
            }
            _ => {}
        }
    }
    m.insert("revoked".into(), revoked.into());
    let alg = der::named(top.child(1)?.child(0)?.body);
    check_strength(cx, "CRL", &alg, None);
    m.insert("signature_algorithm".into(), alg.into());
    Some(m)
}

/// A `SignedData` too large for the head (a catalog, a big certificate
/// bundle), told by its first bytes: the `ContentInfo` header, the
/// signed-data type, and the content type a few levels in.
fn large_cms(head: &[u8]) -> Option<Sniff> {
    const SIGNED_DATA: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02";
    const CTL: &[u8] = b"\x06\x09\x2b\x06\x01\x04\x01\x82\x37\x0a\x01";
    let rest = match head.get(1)? {
        0x80 => head.get(2..)?,
        &n if n > 0x80 && n <= 0x84 => head.get(2 + usize::from(n & 0x7f)..)?,
        _ => return None,
    };
    if !rest.starts_with(SIGNED_DATA) {
        return None;
    }
    let window = rest.get(..rest.len().min(96))?;
    let catalog = window.windows(CTL.len()).any(|w| w == CTL);
    Some(Sniff { format: if catalog { "ms_catalog" } else { "pkcs7" }, confidence: 0.8 })
}

fn is_catalog(der: &[u8]) -> bool {
    der::signed_data(der).is_some_and(|s| s.content_type == "certificate_trust_list")
}

fn cms(der: &[u8], out: &mut Out, cx: &mut Context<'_>) -> Option<Map<String, Value>> {
    let (ci, _) = der::read(der)?;
    let kind = der::named(ci.child(0)?.body);
    let mut m = Map::new();
    m.insert("content_type".into(), kind.clone().into());
    match kind.as_str() {
        "signed_data" => {
            let s = der::signed_data(der)?;
            m.insert("signed_content_type".into(), s.content_type.clone().into());
            let detached = s.content.is_none();
            if s.signers > 0 {
                m.insert("detached".into(), detached.into());
                cx.security().signed(true);
            }
            m.extend(s.facts());
            m.insert("signers".into(), s.signers.into());
            if s.content_type == "certificate_trust_list"
                && let Some(n) = s.content.as_deref().and_then(catalog_members)
            {
                m.insert("catalog_members".into(), n.into());
            }
            if let Some(alg) = s.digests.first() {
                check_strength(cx, "signature digest", alg, None);
            }
            // The chain: certificate facts once each, as for a bundle.
            for mut c in s.certificates {
                validity(&mut c);
                out.certificates += 1;
                out.count("certificate");
                if out.described < MAX_OBJECTS {
                    out.push("certificates", c);
                }
            }
        }
        "enveloped_data" => {
            cx.security().encrypted(true);
            let ed = ci.child(1)?.child(0)?;
            let mut parts = ed.children().skip(1);
            let mut p = parts.next()?;
            if p.is_context(0) {
                p = parts.next()?;
            }
            m.insert("recipients".into(), p.children().count().into());
            if let Some(alg) = parts.next().and_then(|e| e.child(1)).and_then(|a| a.child(0)) {
                m.insert("content_encryption".into(), der::named(alg.body).into());
            }
        }
        "encrypted_data" => {
            cx.security().encrypted(true);
        }
        _ => {}
    }
    Some(m)
}

/// The number of members of a certificate trust list (a `.cat` file's
/// hashes of the files it covers). `fields` is the list's contents, as
/// [`der::signed_data`] returns them.
fn catalog_members(mut fields: &[u8]) -> Option<usize> {
    // subjectUsage, [listIdentifier], [sequenceNumber], thisUpdate,
    // [nextUpdate], subjectAlgorithm, trustedSubjects …
    let mut seen_time = false;
    while let Some((c, rest)) = der::read(fields) {
        fields = rest;
        if c.tag == 0x17 || c.tag == 0x18 {
            seen_time = true;
        } else if seen_time && c.tag == 0x30 && c.child(0).is_some_and(|s| s.tag == 0x30) {
            return Some(c.children().count());
        }
    }
    None
}

fn pkcs12(der: &[u8], out: &mut Out, cx: &mut Context<'_>) -> Option<Map<String, Value>> {
    let (pfx, _) = der::read(der)?;
    let auth = pfx.child(1)?;
    let mut m = Map::new();
    if let Some(mac) = pfx.child(2) {
        let mut mm = Map::new();
        if let Some(alg) = mac.child(0).and_then(|d| d.child(0)).and_then(|a| a.child(0)) {
            mm.insert("digest".into(), der::named(alg.body).into());
        }
        if let Some(n) = mac.child(2).filter(|i| i.tag == 0x02 && i.body.len() <= 4) {
            mm.insert("iterations".into(), n.body.iter().fold(0u64, |a, &b| a << 8 | u64::from(b)).into());
        }
        m.insert("mac".into(), Value::Object(mm));
    }
    // authSafe: data ContentInfo whose octets are a sequence of ContentInfos.
    let safes = auth.child(1)?.child(0)?;
    let (list, _) = der::read(safes.body)?;
    let mut safe_info = Vec::new();
    let mut bags = Map::new();
    for ci in list.children() {
        let kind = der::named(ci.child(0)?.body);
        let mut s = Map::new();
        match kind.as_str() {
            "data" => {
                s.insert("encrypted".into(), false.into());
                if let Some(octets) = ci.child(1).and_then(|c| c.child(0)) {
                    bag_list(octets.body, &mut bags, out, cx);
                }
            }
            "encrypted_data" => {
                cx.security().encrypted(true);
                s.insert("encrypted".into(), true.into());
                let eci = ci.child(1).and_then(|c| c.child(0)).and_then(|ed| ed.child(1));
                if let Some(alg) = eci.and_then(|e| e.child(1)) {
                    pbe(alg, &mut s);
                }
            }
            _ => {
                s.insert("content_type".into(), kind.into());
            }
        }
        safe_info.push(Value::Object(s));
    }
    m.insert("safes".into(), Value::Array(safe_info));
    if !bags.is_empty() {
        m.insert("bags".into(), Value::Object(bags));
    }
    Some(m)
}

fn bag_list(data: &[u8], bags: &mut Map<String, Value>, out: &mut Out, cx: &mut Context<'_>) {
    let Some((list, _)) = der::read(data) else { return };
    for bag in list.children() {
        let Some(kind) = bag.child(0).map(|o| der::named(o.body)) else { continue };
        let n = bags.get(&kind).and_then(Value::as_u64).unwrap_or(0);
        bags.insert(kind.clone(), (n + 1).into());
        let value = bag.child(1).and_then(|v| v.child(0));
        match kind.as_str() {
            "certificate" => {
                // CertBag: certId, [0] { OCTET STRING certificate }
                if let Some(c) = value.and_then(|v| v.child(1)).and_then(|w| w.child(0))
                    && let Some(facts) = certificate(c.body, cx)
                {
                    out.certificates += 1;
                    out.count("certificate");
                    out.push("certificates", facts);
                }
            }
            "shrouded_key" => {
                if let Some(k) = value.and_then(|v| private(Kind::EncryptedPkcs8, v.raw, cx)) {
                    out.count("private_key");
                    out.push("private_keys", k);
                }
            }
            "key" => {
                if let Some(k) = value.and_then(|v| private(Kind::Pkcs8, v.raw, cx)) {
                    out.count("private_key");
                    out.push("private_keys", k);
                }
            }
            _ => {}
        }
    }
}

/// A password-based encryption `AlgorithmIdentifier`: scheme, KDF, cipher,
/// iterations.
fn pbe(alg: der::Tlv<'_>, m: &mut Map<String, Value>) {
    let Some(scheme) = alg.child(0).map(|o| der::named(o.body)) else { return };
    m.insert("scheme".into(), scheme.clone().into());
    let params = alg.child(1);
    let int = |t: der::Tlv<'_>| {
        (t.tag == 0x02 && t.body.len() <= 4).then(|| t.body.iter().fold(0u64, |a, &b| a << 8 | u64::from(b)))
    };
    if scheme == "pbes2" {
        let kdf = params.and_then(|p| p.child(0));
        let cipher = params.and_then(|p| p.child(1)).and_then(|c| c.child(0));
        if let Some(k) = kdf {
            if let Some(name) = k.child(0).map(|o| der::named(o.body)) {
                m.insert("kdf".into(), name.into());
            }
            // PBKDF2-params: salt, iterationCount, [keyLength], [prf]
            let kp = k.child(1);
            if let Some(n) = kp.and_then(|p| p.child(1)).and_then(int) {
                m.insert("iterations".into(), n.into());
            }
            if let Some(prf) = kp.and_then(|p| p.children().find(|c| c.tag == 0x30)).and_then(|a| a.child(0)) {
                m.insert("prf".into(), der::named(prf.body).into());
            }
        }
        if let Some(c) = cipher {
            m.insert("cipher".into(), der::named(c.body).into());
        }
    } else if let Some(n) = params.and_then(|p| p.child(1)).and_then(int) {
        m.insert("iterations".into(), n.into());
    }
}

fn public(kind: Kind, der: &[u8]) -> Option<Map<String, Value>> {
    let mut m = Map::new();
    if kind == Kind::RsaPublic {
        m.insert("format".into(), "pkcs1".into());
        m.insert("key_algorithm".into(), "rsa".into());
        let (seq, _) = der::read(der)?;
        if let Some(b) = seq.child(0).and_then(|n| der::bit_length(n.body)) {
            m.insert("key_bits".into(), b.into());
        }
    } else {
        let (spki, _) = der::read(der)?;
        m.insert("format".into(), "spki".into());
        der::public_key(spki)?.insert_into(&mut m);
        m.insert("sha256".into(), hex(&Sha256::digest(spki.raw)).into());
    }
    Some(m)
}

fn private(kind: Kind, der: &[u8], cx: &mut Context<'_>) -> Option<Map<String, Value>> {
    let (seq, _) = der::read(der)?;
    let mut m = Map::new();
    let encrypted = kind == Kind::EncryptedPkcs8;
    match kind {
        Kind::Pkcs8 => {
            m.insert("format".into(), "pkcs8".into());
            let alg = seq.child(1)?;
            // The key itself is read for its size only.
            der::key_facts(alg, seq.child(2).map(|o| o.body))?.insert_into(&mut m);
            if alg.child(0).is_some_and(|o| der::oid(o.body) == "1.2.840.10045.2.1") && !m.contains_key("key_curve") {
                // SEC1 inside PKCS#8 may name its curve itself.
                if let Some(c) = seq.child(2).and_then(|o| der::read(o.body)).and_then(|(e, _)| ec_curve(e)) {
                    m.insert("key_bits".into(), der::curve_bits(&c).into());
                    m.insert("key_curve".into(), c.into());
                }
            }
        }
        Kind::EncryptedPkcs8 => {
            m.insert("format".into(), "encrypted_pkcs8".into());
            let mut e = Map::new();
            pbe(seq.child(0)?, &mut e);
            m.insert("encryption".into(), Value::Object(e));
        }
        Kind::RsaPrivate => {
            m.insert("format".into(), "pkcs1".into());
            m.insert("key_algorithm".into(), "rsa".into());
            if let Some(b) = seq.child(1).and_then(|n| der::bit_length(n.body)) {
                m.insert("key_bits".into(), b.into());
            }
        }
        Kind::DsaPrivate => {
            m.insert("format".into(), "openssl".into());
            m.insert("key_algorithm".into(), "dsa".into());
            if let Some(b) = seq.child(1).and_then(|n| der::bit_length(n.body)) {
                m.insert("key_bits".into(), b.into());
            }
        }
        Kind::EcPrivate => {
            m.insert("format".into(), "sec1".into());
            m.insert("key_algorithm".into(), "ec".into());
            if let Some(c) = ec_curve(seq) {
                if let Some(b) = der::curve_bits(&c) {
                    m.insert("key_bits".into(), b.into());
                }
                m.insert("key_curve".into(), c.into());
            }
        }
        _ => return None,
    }
    m.insert("encrypted".into(), encrypted.into());
    if encrypted {
        cx.security().encrypted(true);
    } else {
        cx.security().risk("unprotected_key", Some(m.get("format").and_then(Value::as_str).unwrap_or("").into()));
    }
    check_strength(cx, "private key", key_alg(&m), key_bits(&m));
    Some(m)
}

/// The named curve of a SEC1 `ECPrivateKey` (`[0]` parameters).
fn ec_curve(seq: der::Tlv<'_>) -> Option<String> {
    let p = seq.children().find(|c| c.is_context(0))?.child(0)?;
    (p.tag == 0x06).then(|| der::named(p.body))
}

fn finish(out: Out, cx: &mut Context<'_>) {
    let total: u64 = out.types.values().filter_map(Value::as_u64).sum();
    cx.format_set("objects", total);
    cx.format_set("object_types", Value::Object(out.types));
    if (out.described as u64) < total && total > MAX_OBJECTS as u64 {
        cx.format_set("objects_described", out.described);
    }
    for (k, v) in out.lists {
        cx.format_set(&k, v);
    }
    if out.certificates == 1
        && let Some(c) = out.lone
    {
        let s = |k: &str| c.get(k).and_then(Value::as_str);
        if let Some(t) = s("subject_cn").or_else(|| s("subject")).filter(|t| !t.is_empty()) {
            cx.content().source("crypto.pki").title(t);
        }
        if let Some(o) = s("subject_organization") {
            cx.content().author(o);
        }
        let mut t = cx.temporal();
        t.source("crypto.pki");
        if let Some(v) = s("not_before") {
            t.content_date(DateField::Created, v, true);
        }
        if let Some(v) = s("not_after") {
            t.content_date(DateField::Expires, v, true);
        }
    }
}

crate::register_extractor!(Pki);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    fn fmt(r: &crate::plugin::Report) -> &Value {
        &r.format[&r.identification.format]
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if body.len() < 0x80 {
            v.push(u8::try_from(body.len()).unwrap());
        } else {
            v.push(0x82);
            v.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
        }
        v.extend_from_slice(body);
        v
    }

    const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    /// An RSA `PrivateKeyInfo` with a patterned 1024-bit "modulus" (not a key).
    fn pkcs8_rsa() -> Vec<u8> {
        let mut modulus = vec![0u8];
        modulus.extend([0xa5; 128]);
        let ints: Vec<u8> = [
            tlv(0x02, &[0]),
            tlv(0x02, &modulus),
            tlv(0x02, &[1, 0, 1]),
            tlv(0x02, &[7; 16]),
            tlv(0x02, &[7]),
            tlv(0x02, &[7]),
            tlv(0x02, &[7]),
            tlv(0x02, &[7]),
            tlv(0x02, &[7]),
        ]
        .concat();
        let rsa = tlv(0x30, &ints);
        tlv(0x30, &[tlv(0x02, &[0]), tlv(0x30, &[tlv(0x06, RSA), vec![5, 0]].concat()), tlv(0x04, &rsa)].concat())
    }

    fn pem(label: &str, der: &[u8]) -> Vec<u8> {
        format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", super::super::base64_encode(der) + "==")
            .into_bytes()
    }

    #[test]
    fn private_keys_give_type_and_size_only() {
        let key = pkcs8_rsa();
        assert_eq!(classify(&key), Some(Kind::Pkcs8));
        let r = report_for("a.pem", &pem("PRIVATE KEY", &key));
        let k = &fmt(&r)["private_keys"][0];
        assert_eq!(k["key_algorithm"], "rsa");
        assert_eq!(k["key_bits"], 1024);
        assert_eq!(k["encrypted"], false);
        let kinds: Vec<&str> = r.security.risks.iter().map(|r| r.kind.as_str()).collect();
        assert!(kinds.contains(&"unprotected_key") && kinds.contains(&"weak_cryptography"), "{kinds:?}");
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("a5a5") && !json.contains("pVpX"), "no key material");
    }

    #[test]
    fn sec1_and_encrypted_keys() {
        let sec1 = tlv(0x30, &[tlv(0x02, &[1]), tlv(0x04, &[9; 32]), tlv(0xa0, &tlv(0x06, P256))].concat());
        assert_eq!(classify(&sec1), Some(Kind::EcPrivate));
        let r = report_for("k.pem", &pem("EC PRIVATE KEY", &sec1));
        assert_eq!(fmt(&r)["private_keys"][0]["key_curve"], "P-256");
        assert_eq!(fmt(&r)["private_keys"][0]["key_bits"], 256);

        let pbkdf2 = tlv(
            0x30,
            &[
                tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c]),
                tlv(0x30, &[tlv(0x04, &[1; 8]), tlv(0x02, &[0x08, 0x00])].concat()),
            ]
            .concat(),
        );
        let aes = tlv(
            0x30,
            &[tlv(0x06, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a]), tlv(0x04, &[0; 16])].concat(),
        );
        let alg = tlv(
            0x30,
            &[tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d]), tlv(0x30, &[pbkdf2, aes].concat())]
                .concat(),
        );
        let enc = tlv(0x30, &[alg, tlv(0x04, &[3; 48])].concat());
        assert_eq!(classify(&enc), Some(Kind::EncryptedPkcs8));
        let r = report_for("k.pem", &pem("ENCRYPTED PRIVATE KEY", &enc));
        let e = &fmt(&r)["private_keys"][0]["encryption"];
        assert_eq!(
            (e["kdf"].as_str(), e["cipher"].as_str(), e["iterations"].as_u64()),
            (Some("pbkdf2"), Some("aes256_cbc"), Some(2048))
        );
        assert_eq!(r.security.encrypted, Some(true));
        assert_eq!(r.security.risks, []);
    }

    #[test]
    fn legacy_encrypted_pem_key() {
        let text = b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00FF\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        let r = report_for("k.pem", text);
        assert_eq!(fmt(&r)["private_keys"][0]["cipher"], "aes-256-cbc");
        assert_eq!(fmt(&r)["private_keys"][0]["encrypted"], true);
    }

    #[test]
    fn catalog_member_count() {
        let ctl_oid = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x01];
        let member = tlv(0x30, &tlv(0x04, &[0xcd; 20]));
        let ctl = tlv(
            0x30,
            &[
                tlv(0x30, &tlv(0x06, &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x01, 0x01])),
                tlv(0x04, b"harbour"),
                tlv(0x17, b"250901000000Z"),
                tlv(0x30, &[tlv(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]), vec![5, 0]].concat()),
                tlv(0x30, &[member.clone(), member.clone(), member].concat()),
            ]
            .concat(),
        );
        let encap = tlv(0x30, &[tlv(0x06, &ctl_oid), tlv(0xa0, &ctl)].concat());
        let sd = tlv(0x30, &[tlv(0x02, &[1]), tlv(0x31, &[]), encap, tlv(0x31, &[])].concat());
        let ci =
            tlv(0x30, &[tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]), tlv(0xa0, &sd)].concat());
        let r = report_for("driver.cat", &ci);
        assert_eq!(r.identification.format, "ms_catalog");
        assert_eq!(fmt(&r)["cms"][0]["catalog_members"], 3);
    }

    #[test]
    fn catalogs_are_found_by_content_not_extension() {
        let xml = b"<?xml version=\"1.0\"?>\n<catalog xmlns=\"urn:oasis:names:tc:entity:xmlns:xml:catalog\"/>\n";
        assert_ne!(report_for("docbook.cat", xml).identification.format, "ms_catalog");
        // A catalog larger than the sniffing window, by its first bytes.
        let mut head = vec![0x30, 0x83, 0x10, 0x00, 0x00];
        head.extend(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02\xa0\x83\x0f\xff\xf0\x30\x83\x0f\xff\xe0");
        head.extend(b"\x02\x01\x01\x31\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00");
        head.extend(b"\x30\x83\x0f\x00\x00\x06\x09\x2b\x06\x01\x04\x01\x82\x37\x0a\x01");
        assert_eq!(large_cms(&head).map(|s| s.format), Some("ms_catalog"));
        // Cut before the content type: any other signed data.
        assert_eq!(large_cms(&head[..46]).map(|s| s.format), Some("pkcs7"));
    }

    #[test]
    fn spki_public_key() {
        let spki = tlv(0x30, &[tlv(0x30, &[tlv(0x06, EC), tlv(0x06, P256)].concat()), tlv(0x03, &[0; 66])].concat());
        assert_eq!(classify(&spki), Some(Kind::Spki));
        let r = report_for("k.pem", &pem("PUBLIC KEY", &spki));
        assert_eq!(fmt(&r)["public_keys"][0]["key_curve"], "P-256");
        assert_eq!(r.security.risks, []);
    }

    crate::fixture_tests!("pem", "x509", "pkcs10", "x509_crl", "pkcs7", "ms_catalog", "pkcs12", "der_key");
}
