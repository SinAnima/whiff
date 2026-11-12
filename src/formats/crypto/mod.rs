//! `crypto` extractors (feature `common`): certificates, keys, signatures
//! and the files that store them. Each says what the object is (type,
//! algorithm, size, curve), who it names (subject, issuer, user IDs,
//! principals), when it is valid, how it is protected (passphrase, KDF,
//! cipher) and its public fingerprint. **Key material is never emitted**:
//! private parts are skipped unread, nothing is decrypted and no signature
//! is verified.

#![allow(clippy::many_single_char_names)] // bytes `b`, cursor `c`, wire `w`, as in the specifications

pub(crate) mod pgp;
pub(crate) mod pki;
pub(crate) mod ssh;
pub(crate) mod store;
pub(crate) mod token;
pub(crate) mod tpm;

// Helpers shared with the audio, archive and executable extractors.
pub(crate) use super::archive::unix_time;
pub(crate) use super::audio::vorbis::base64;
pub(crate) use super::bytecode::mutf8;
pub(crate) use super::exec::hex;
use crate::plugin::Context;

/// One PEM block (RFC 7468; RFC 1421 headers kept for the old encrypted
/// key form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pem {
    /// The label: `CERTIFICATE`, `PRIVATE KEY`, …
    pub label: String,
    /// `Proc-Type` / `DEK-Info` style headers, in order.
    pub headers: Vec<(String, String)>,
    /// The decoded contents (`None` when the base64 is broken).
    pub der: Option<Vec<u8>>,
}

/// Most PEM blocks read from one file.
pub(crate) const MAX_BLOCKS: usize = 4096;

/// The PEM blocks in `text`, and whether there is text outside them.
pub(crate) fn pem_blocks(text: &str) -> (Vec<Pem>, bool) {
    let mut out = Vec::new();
    let mut outside = false;
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) else {
            outside |= !line.is_empty();
            continue;
        };
        let end = format!("-----END {label}-----");
        let (mut headers, mut body, mut closed) = (Vec::new(), String::new(), false);
        for l in lines.by_ref() {
            let l = l.trim();
            if l == end {
                closed = true;
                break;
            }
            match l.split_once(": ") {
                Some((k, v)) if body.is_empty() && !k.contains(' ') => headers.push((k.to_string(), v.to_string())),
                _ => body.push_str(l),
            }
        }
        let der = if closed { base64(&body) } else { None };
        out.push(Pem { label: label.to_string(), headers, der });
        if out.len() >= MAX_BLOCKS {
            break;
        }
    }
    (out, outside)
}

/// Unpadded base64, as OpenSSH prints fingerprints.
pub(crate) fn base64_encode(b: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = c.iter().enumerate().fold(0u32, |a, (i, &x)| a | u32::from(x) << (16 - 8 * i));
        for i in 0..=c.len() {
            s.push(char::from(ABC[(n >> (18 - 6 * i)) as usize & 63]));
        }
    }
    s
}

/// `key_bits` below this are weak for RSA, DSA and DH (NIST SP 800-131A).
const MIN_FACTORING_BITS: u64 = 2048;

/// Report `weak_cryptography` for a key or signature algorithm that is
/// weak; `what` names the object in the detail.
pub(crate) fn check_strength(cx: &mut Context<'_>, what: &str, algorithm: &str, bits: Option<u64>) {
    let weak = match algorithm {
        "rsa" | "rsa_pss" | "dsa" | "dh" | "elgamal" => bits.is_some_and(|b| b < MIN_FACTORING_BITS),
        "md5_rsa" | "sha1_rsa" | "sha1_ecdsa" | "sha1_dsa" | "md2_rsa" | "md5" | "sha1" => true,
        _ => false,
    };
    if weak {
        let detail = match bits {
            Some(b) => format!("{what}: {algorithm} {b} bits"),
            None => format!("{what}: {algorithm}"),
        };
        cx.security().risk("weak_cryptography", Some(detail));
    }
}

/// Whether an RFC 3339 time is in the past.
pub(crate) fn is_past(t: &str) -> bool {
    t.parse::<jiff::Timestamp>().is_ok_and(|t| t < jiff::Timestamp::now())
}

/// A free-text comment or label (SSH key comments, user IDs): kept unless
/// it holds personal data and privacy is strict.
pub(crate) fn comment(cx: &Context<'_>, s: &str) -> String {
    let s = crate::plugin::truncate_chars(s.trim(), 200);
    if cx.privacy_strict() { crate::plugin::redact_sensitive(&s).into_owned() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_blocks_with_headers_and_text() {
        let text = "Bag Attributes\n    friendlyName: x\n-----BEGIN X509 CRL-----\nAAEC\nAw==\n-----END X509 CRL-----\n\
                    -----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n\
                    -----END RSA PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nAAAA\n";
        let (blocks, outside) = pem_blocks(text);
        assert!(outside);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].der.as_deref(), Some(&[0, 1, 2, 3][..]));
        assert_eq!(blocks[1].headers[0], ("Proc-Type".into(), "4,ENCRYPTED".into()));
        assert_eq!(blocks[2].der, None, "unterminated");
    }

    #[test]
    fn base64_round_trip() {
        for s in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(base64(&base64_encode(s)).unwrap(), s);
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fo"), "Zm8");
    }
}
