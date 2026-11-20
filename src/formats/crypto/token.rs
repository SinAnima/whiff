//! Small text formats around keys: JSON Web Tokens (JWS / JWE header, the
//! registered claims with times, the names of the others; the signature is
//! not verified), JSON Web Keys (type, curve, size, use, ID, whether the
//! private part is present), age encrypted files (recipient types and the
//! scrypt work factor), minisign and signify keys and signatures (key ID,
//! algorithm, comments, KDF) and TLS key logs (labels and session counts;
//! the secrets are never shown).
//!
//! Specifications: RFC 7515 / 7516 / 7517 / 7519 (JOSE); age v1
//! (C2SP age.md); minisign and OpenBSD `signify(1)` key formats; the
//! NSS key log format (IETF draft-ietf-tls-keylogfile).

use serde_json::{Map, Value, json};

use super::{base64, comment, is_past, pem_blocks, unix_time};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, der,
};

/// Extractor for key-adjacent text formats.
pub struct Token;

static META: ExtractorMeta = ExtractorMeta {
    id: "crypto.token",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "jwt",
            name: "JSON Web Token",
            family: "crypto",
            mimes: &["application/jwt"],
            extensions: &["jwt", "jws", "jwe"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "jwk",
            name: "JSON Web Key / key set",
            family: "crypto",
            mimes: &["application/jwk+json", "application/jwk-set+json"],
            extensions: &["jwk", "jwks"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "age",
            name: "age encrypted file",
            family: "crypto",
            mimes: &["application/x-age-encryption"],
            extensions: &["age"],
            magic: &[Magic::prefix(b"age-encryption.org/v1\n"), Magic::prefix(b"-----BEGIN AGE ENCRYPTED FILE-----")],
            parent: None,
        },
        FormatSpec {
            id: "minisign",
            name: "minisign / signify key or signature",
            family: "crypto",
            mimes: &[],
            extensions: &["minisig", "sig", "pub", "sec", "key"],
            magic: &[Magic::prefix(b"untrusted comment: ")],
            parent: None,
        },
        FormatSpec {
            id: "tls_keylog",
            name: "TLS key log",
            family: "crypto",
            mimes: &[],
            extensions: &["keylog", "sslkeylog"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Key log labels (NSS format).
const KEYLOG_LABELS: &[&str] = &[
    "CLIENT_RANDOM",
    "RSA",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EARLY_EXPORTER_SECRET",
    "EXPORTER_SECRET",
    "ECH_SECRET",
    "ECH_CONFIG",
];

/// Keys described from one set.
const MAX_KEYS: usize = 64;

fn is_b64url(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn json_part(s: &str) -> Option<Map<String, Value>> {
    match serde_json::from_slice(&base64(s)?).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// The compact JOSE parts of `text`, when it is one token.
fn jose(text: &str) -> Option<(Vec<&str>, Map<String, Value>)> {
    let t = text.trim();
    let parts: Vec<&str> = t.split('.').collect();
    if !matches!(parts.len(), 3 | 5) || !parts[0].starts_with("eyJ") {
        return None;
    }
    if !parts.iter().enumerate().all(|(i, p)| is_b64url(p) || (p.is_empty() && i > 0)) {
        return None;
    }
    let header = json_part(parts[0])?;
    header.contains_key("alg").then_some((parts, header))
}

fn is_jwk(v: &Value) -> bool {
    v.get("kty").is_some_and(Value::is_string)
        || v.get("keys").and_then(Value::as_array).is_some_and(|k| k.iter().any(|k| k.get("kty").is_some()))
}

fn keylog_line(l: &str) -> bool {
    let mut w = l.split_whitespace();
    w.next().is_some_and(|label| KEYLOG_LABELS.contains(&label)) && w.next().is_some_and(|h| h.len() >= 16)
}

impl Extractor for Token {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let text = std::str::from_utf8(probe.head.get(..probe.head.len().min(16 << 10))?).ok()?;
        let whole = probe.len == probe.head.len() as u64;
        if whole && jose(text).is_some() {
            return Some(Sniff { format: "jwt", confidence: 0.9 });
        }
        let t = text.trim_start();
        if whole && t.starts_with('{') && t.contains("\"kty\"") {
            let v: Value = serde_json::from_str(text).ok()?;
            return is_jwk(&v).then_some(Sniff { format: "jwk", confidence: 0.9 });
        }
        let first = text.lines().find(|l| !l.trim().is_empty() && !l.starts_with('#'))?;
        keylog_line(first).then_some(Sniff { format: "tls_keylog", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len().min(cx.parse_limit() as u64);
        let b = src.read_vec(0, usize::try_from(len).unwrap_or(0))?;
        let text = String::from_utf8_lossy(&b);
        match cx.format_id() {
            "jwt" => jwt(&text, cx),
            "jwk" => jwk(&text, cx),
            "age" => age(&b, cx),
            "minisign" => minisign(&text, cx),
            _ => keylog(&text, cx),
        }
    }
}

fn jwt(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (parts, header) = jose(text).ok_or_else(|| ExtractError::malformed("not a compact JWS / JWE"))?;
    let mut h = Map::new();
    for k in ["alg", "enc", "typ", "cty", "kid", "zip", "crit"] {
        if let Some(v) = header.get(k) {
            h.insert(k.into(), v.clone());
        }
    }
    // An embedded key or certificate chain is described, not copied.
    if header.contains_key("jwk") {
        h.insert("embedded_jwk".into(), true.into());
    }
    if let Some(n) = header.get("x5c").and_then(Value::as_array) {
        h.insert("x5c_certificates".into(), n.len().into());
    }
    if let Some(u) = header.get("jku").or_else(|| header.get("x5u")).and_then(Value::as_str) {
        h.insert("key_url".into(), cx.redact_secrets(u).into_owned().into());
    }
    cx.format_set("header", Value::Object(h));
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    if parts.len() == 5 {
        cx.format_set("kind", "jwe");
        cx.security().encrypted(true);
    } else {
        cx.format_set("kind", "jws");
        cx.format_set("signature_verified", false);
        if alg.eq_ignore_ascii_case("none") || parts[2].is_empty() {
            cx.format_set("unsigned", true);
            cx.security().risk("weak_cryptography", Some("JWT with alg none".into()));
        } else {
            cx.security().signed(true);
        }
        if let Some(claims) = json_part(parts[1]) {
            let claims = claims_of(&claims, cx);
            cx.format_set("claims", Value::Object(claims));
        }
    }
    // A token is a bearer credential.
    cx.security().risk("embedded_secret", Some("jwt".into()));
    Ok(())
}

fn claims_of(c: &Map<String, Value>, cx: &mut Context<'_>) -> Map<String, Value> {
    let mut m = Map::new();
    for k in ["iss", "aud"] {
        if let Some(v) = c.get(k) {
            m.insert(k.into(), v.clone());
        }
    }
    if let Some(s) = c.get("sub").and_then(Value::as_str) {
        m.insert("sub".into(), comment(cx, s).into());
    }
    for (k, name) in [("iat", "issued_at"), ("nbf", "not_before"), ("exp", "expires")] {
        if let Some(t) = c.get(k).and_then(Value::as_i64).and_then(unix_time) {
            if k == "exp" {
                m.insert("expired".into(), is_past(&t).into());
            }
            m.insert(name.into(), t.into());
        }
    }
    let other: Vec<&String> =
        c.keys().filter(|k| !["iss", "aud", "sub", "iat", "nbf", "exp"].contains(&k.as_str())).collect();
    if !other.is_empty() {
        m.insert("other_claims".into(), json!(other));
    }
    m
}

fn jwk(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let v: Value = serde_json::from_str(text).map_err(|_| ExtractError::malformed("JWK JSON"))?;
    let keys: Vec<&Value> = match v.get("keys").and_then(Value::as_array) {
        Some(k) => k.iter().collect(),
        None => vec![&v],
    };
    cx.format_set("kind", if v.get("keys").is_some() { "key_set" } else { "key" });
    cx.format_set("key_count", keys.len());
    let mut out = Vec::new();
    let mut private = 0;
    for k in keys.iter().take(MAX_KEYS) {
        let Value::Object(k) = k else { continue };
        let mut m = Map::new();
        for f in ["kty", "crv", "alg", "use", "kid", "key_ops"] {
            if let Some(v) = k.get(f) {
                m.insert(f.into(), v.clone());
            }
        }
        let bits = match k.get("kty").and_then(Value::as_str) {
            Some("RSA") => k.get("n").and_then(Value::as_str).and_then(base64).and_then(|n| der::bit_length(&n)),
            Some("oct") => k.get("k").and_then(Value::as_str).and_then(base64).map(|b| b.len() as u64 * 8),
            Some("EC" | "OKP") => k
                .get("crv")
                .and_then(Value::as_str)
                .and_then(|c| der::curve_bits(&c.to_ascii_lowercase()).or_else(|| der::curve_bits(c))),
            _ => None,
        };
        if let Some(b) = bits {
            m.insert("key_bits".into(), b.into());
        }
        // `d` (private exponent / scalar) or `k` (symmetric): secret parts.
        let secret = k.contains_key("d") || k.contains_key("k");
        m.insert("private".into(), secret.into());
        private += usize::from(secret);
        if let Some(x5c) = k.get("x5c").and_then(Value::as_array) {
            m.insert("x5c_certificates".into(), x5c.len().into());
            if let Some(c) = x5c.first().and_then(Value::as_str).and_then(base64).and_then(|d| der::certificate(&d)) {
                for f in ["subject", "not_after"] {
                    if let Some(v) = c.get(f) {
                        m.insert(format!("certificate_{f}"), v.clone());
                    }
                }
            }
        }
        if let (Some("RSA"), Some(b)) = (k.get("kty").and_then(Value::as_str), bits) {
            super::check_strength(cx, "JWK", "rsa", Some(b));
        }
        out.push(Value::Object(m));
    }
    if private > 0 {
        cx.security().risk("unprotected_key", Some(format!("jwk: {private} private")));
    }
    cx.format_set("keys", out);
    Ok(())
}

/// age v1: a header of recipient stanzas (`-> type args`), then the MAC
/// line and the payload.
fn age(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let armored;
    let data: &[u8] = if b.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----") {
        cx.format_set("armored", true);
        let (blocks, _) = pem_blocks(&String::from_utf8_lossy(b));
        armored = blocks.into_iter().find_map(|p| p.der).ok_or_else(|| ExtractError::malformed("age armour"))?;
        &armored
    } else {
        b
    };
    let header_end =
        data.windows(4).position(|w| w == b"\n---").ok_or_else(|| ExtractError::malformed("age header"))?;
    let header = String::from_utf8_lossy(&data[..header_end]);
    let mut types = Map::new();
    let mut count = 0u64;
    for line in header.lines() {
        let Some(stanza) = line.strip_prefix("-> ") else { continue };
        let mut args = stanza.split(' ');
        let kind = args.next().unwrap_or("").to_string();
        count += 1;
        if kind == "scrypt"
            && let Some(n) = args.nth(1).and_then(|n| n.parse::<u64>().ok())
        {
            cx.format_set("scrypt_work_factor", n);
        }
        let n = types.get(&kind).and_then(Value::as_u64).unwrap_or(0);
        types.insert(kind, (n + 1).into());
    }
    cx.format_set("version", "v1");
    cx.format_set("recipients", count);
    cx.format_set("recipient_types", Value::Object(types));
    let payload = data.len().saturating_sub(header_end + 4);
    cx.format_set("payload_bytes", payload);
    cx.security().encrypted(true);
    Ok(())
}

/// minisign and signify share the layout: an untrusted comment, a base64
/// line starting with the algorithm and an 8-byte key number, and for
/// minisign signatures a trusted comment.
fn minisign(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut lines = text.lines();
    let untrusted = lines.next().and_then(|l| l.strip_prefix("untrusted comment: ")).unwrap_or("");
    let body = lines.next().and_then(|l| base64(l.trim())).ok_or_else(|| ExtractError::malformed("minisign body"))?;
    let trusted = lines.next().and_then(|l| l.strip_prefix("trusted comment: "));
    // minisign signs a trusted comment too, names itself in its untrusted
    // comments and prehashes ("ED"); signify does none of these.
    let alg = String::from_utf8_lossy(body.get(..2).unwrap_or_default()).into_owned();
    let minisign = trusted.is_some() || untrusted.starts_with("minisign") || alg == "ED" || body.len() == 158;
    cx.format_set("tool", if minisign { "minisign" } else { "signify" });
    if !untrusted.is_empty() {
        cx.format_set("untrusted_comment", comment(cx, untrusted));
    }
    let algorithm = match alg.as_str() {
        "Ed" => "ed25519",
        "ED" => "ed25519_prehashed",
        _ => "unknown",
    };
    cx.format_set("algorithm", algorithm);
    // The key number, printed as minisign does (little-endian, upper case).
    let key_id = |range: std::ops::Range<usize>| {
        body.get(range).map(|k| {
            let mut k = k.to_vec();
            k.reverse();
            super::hex(&k).to_ascii_uppercase()
        })
    };
    let kind = match body.len() {
        42 => "public_key",
        74 => "signature",
        104 | 158 => "secret_key",
        _ => "unknown",
    };
    cx.format_set("kind", kind);
    match (kind, body.len()) {
        ("public_key" | "signature", _) => {
            if let Some(id) = key_id(2..10) {
                cx.format_set("key_id", id);
            }
        }
        // signify: Ed, KDF "BK", rounds, salt, checksum, key number, key.
        ("secret_key", 104) => {
            let rounds = body.get(4..8).map_or(0, |r| u32::from_be_bytes([r[0], r[1], r[2], r[3]]));
            cx.format_set("kdf", json!({ "algorithm": "bcrypt_pbkdf", "rounds": rounds }));
            if let Some(id) = key_id(32..40) {
                cx.format_set("key_id", id);
            }
            secret_protection(rounds > 0, cx);
        }
        // minisign: Ed, KDF "Sc" or zero, checksum "B2", salt, ops, mem, key.
        ("secret_key", _) => {
            let kdf = body.get(2..4).unwrap_or_default();
            let protected = kdf == b"Sc";
            let num = |r: std::ops::Range<usize>| {
                body.get(r).map_or(0, |v| v.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x)))
            };
            if protected {
                cx.format_set(
                    "kdf",
                    json!({ "algorithm": "scrypt", "opslimit": num(38..46), "memlimit": num(46..54) }),
                );
            }
            secret_protection(protected, cx);
        }
        _ => {}
    }
    if let Some(t) = trusted {
        cx.format_set("trusted_comment", comment(cx, t));
        cx.security().signed(true);
    } else if kind == "signature" {
        cx.security().signed(true);
    }
    Ok(())
}

fn secret_protection(protected: bool, cx: &mut Context<'_>) {
    cx.format_set("encrypted", protected);
    if protected {
        cx.security().encrypted(true);
    } else {
        cx.security().risk("unprotected_key", Some("minisign / signify".into()));
    }
}

/// NSS key log: one secret per line. Only labels and counts are kept.
fn keylog(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut labels = Map::new();
    let mut sessions = std::collections::HashSet::new();
    let (mut lines, mut other) = (0u64, 0u64);
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if !keylog_line(l) {
            other += 1;
            continue;
        }
        lines += 1;
        let mut w = l.split_whitespace();
        let label = w.next().unwrap_or("");
        if let Some(random) = w.next()
            && sessions.len() < 1_000_000
        {
            // Client randoms identify sessions; hashing keeps memory small.
            sessions.insert(random.to_ascii_lowercase());
        }
        let n = labels.get(label).and_then(Value::as_u64).unwrap_or(0);
        labels.insert(label.into(), (n + 1).into());
    }
    if lines == 0 {
        return Err(ExtractError::malformed("no key log line"));
    }
    cx.format_set("lines", lines);
    cx.format_set("labels", Value::Object(labels));
    cx.format_set("sessions", sessions.len());
    if other > 0 {
        cx.format_set("unrecognised_lines", other);
    }
    cx.security().risk("embedded_secret", Some("tls_key_log".into()));
    Ok(())
}

crate::register_extractor!(Token);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    fn fmt(r: &crate::plugin::Report) -> &Value {
        &r.format[&r.identification.format]
    }

    fn b64(s: &str) -> String {
        super::super::base64_encode(s.as_bytes()).replace('+', "-").replace('/', "_")
    }

    #[test]
    fn jwt_claims_without_verification() {
        let token = format!(
            "{}.{}.c2ln",
            b64(r#"{"alg":"HS256","typ":"JWT"}"#),
            b64(r#"{"iss":"https://harbour.test","sub":"tide-gauge-7","exp":946684800,"scope":"read"}"#)
        );
        let r = report_for("t.jwt", token.as_bytes());
        assert_eq!(r.identification.format, "jwt");
        assert_eq!(fmt(&r)["header"]["alg"], "HS256");
        assert_eq!(fmt(&r)["signature_verified"], false);
        assert_eq!(fmt(&r)["claims"]["expires"], "2000-01-01T00:00:00Z");
        assert_eq!(fmt(&r)["claims"]["expired"], true);
        assert_eq!(fmt(&r)["claims"]["other_claims"], json!(["scope"]));
        assert!(r.security.risks.iter().any(|x| x.kind == "embedded_secret"));
    }

    #[test]
    fn jwk_private_part_is_noticed_not_shown() {
        let text = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA","d":"c2VjcmV0","kid":"k1"},{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAA"}]}"#;
        let r = report_for("set.jwks", text.as_bytes());
        assert_eq!(fmt(&r)["key_count"], 2);
        assert_eq!(fmt(&r)["keys"][0]["key_bits"], 256);
        assert_eq!(fmt(&r)["keys"][1]["key_bits"], 128);
        assert_eq!(fmt(&r)["keys"][0]["private"], true);
        assert!(!serde_json::to_string(&r).unwrap().contains("c2VjcmV0"));
        assert!(r.security.risks.iter().any(|x| x.kind == "unprotected_key"));
    }

    #[test]
    fn keylog_counts_only() {
        let text = "# SSL/TLS secrets log file\nCLIENT_RANDOM 0011223344556677 8899aabbccddeeff00112233\n\
                    CLIENT_HANDSHAKE_TRAFFIC_SECRET 0011223344556677 ffeeddccbbaa99887766\n";
        let r = report_for("ssl.log", text.as_bytes());
        assert_eq!(r.identification.format, "tls_keylog");
        assert_eq!((fmt(&r)["lines"].as_u64(), fmt(&r)["sessions"].as_u64()), (Some(2), Some(1)));
        assert!(!serde_json::to_string(&r).unwrap().contains("8899aabb"));
    }

    #[test]
    fn unprotected_minisign_secret_key() {
        let mut body = b"Ed\0\0B2".to_vec();
        body.resize(158, 0x33);
        let text =
            format!("untrusted comment: minisign encrypted secret key\n{}\n", super::super::base64_encode(&body) + "=");
        let r = report_for("minisign.key", text.as_bytes());
        assert_eq!((fmt(&r)["tool"].as_str(), fmt(&r)["kind"].as_str()), (Some("minisign"), Some("secret_key")));
        assert_eq!(fmt(&r)["encrypted"], false);
        assert!(r.security.risks.iter().any(|x| x.kind == "unprotected_key"));
    }

    crate::fixture_tests!("jwt", "jwk", "age", "minisign", "tls_keylog");
}
