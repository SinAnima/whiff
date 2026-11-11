//! TPM keys:
//! * TPM 2.0 key files (`TSS2 PRIVATE KEY`, PEM or DER; the format of the
//!   OpenSSL TPM 2 engine and provider, `tpm2-tss-engine`, systemd and
//!   GnuTLS): the kind (loadable, importable, sealed data), whether an
//!   authorisation value is needed, policies, the parent (owner, endorsement
//!   or a persistent handle), the description, and from the public area the
//!   algorithm, key size or curve, name algorithm, object attributes and
//!   the key's TPM name;
//! * TPM 1.2 key blobs (`TSS KEY BLOB`): recognised, not decoded;
//! * `tpm2-tools` context files (`.ctx`): the hierarchy, saved handle and
//!   sequence.
//!
//! The private part is wrapped by the TPM that created the key and only
//! that TPM can use it; it is never read.
//!
//! Specifications: "ASN.1 Specification for TPM 2.0 Key Files"
//! (draft-bottomley-tpm2-keys); TCG "TPM 2.0 Library, Part 2: Structures"
//! (`TPMT_PUBLIC`, `TPMA_OBJECT`, algorithm, curve and handle constants);
//! `tpm2-tools` `lib/files.c` (context file header).

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{comment, hex, pem_blocks};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, der,
};

/// Extractor for TPM key files.
pub struct Tpm;

static META: ExtractorMeta = ExtractorMeta {
    id: "crypto.tpm",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "tpm2_key",
            name: "TPM 2.0 key file",
            family: "crypto",
            mimes: &["application/x-tpm2-key"],
            extensions: &["tss"],
            // PEM or DER: both forms are recognised by the sniffer.
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "tpm2_context",
            name: "TPM 2.0 context (tpm2-tools)",
            family: "crypto",
            mimes: &[],
            extensions: &["ctx"],
            magic: &[Magic::prefix(b"\xba\xdc\xc0\xde\x00\x00\x00")],
            parent: None,
        },
    ],
};

/// `id-loadablekey`, `id-importablekey`, `id-sealedkey` (2.23.133.10.1.3–5).
const KINDS: [(&str, &str); 3] =
    [("2.23.133.10.1.3", "loadable"), ("2.23.133.10.1.4", "importable"), ("2.23.133.10.1.5", "sealed")];

/// `TPMA_OBJECT` bits.
const ATTRIBUTES: [(u32, &str); 11] = [
    (1 << 1, "fixed_tpm"),
    (1 << 2, "st_clear"),
    (1 << 4, "fixed_parent"),
    (1 << 5, "sensitive_data_origin"),
    (1 << 6, "user_with_auth"),
    (1 << 7, "admin_with_policy"),
    (1 << 10, "no_dictionary_attack"),
    (1 << 11, "encrypted_duplication"),
    (1 << 16, "restricted"),
    (1 << 17, "decrypt"),
    (1 << 18, "sign"),
];

/// `TPM_ALG_ID` names.
fn algorithm(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0001 => "rsa",
        0x0004 => "sha1",
        0x0005 => "hmac",
        0x0006 => "aes",
        0x0008 => "keyedhash",
        0x000a => "xor",
        0x000b => "sha256",
        0x000c => "sha384",
        0x000d => "sha512",
        0x0010 => "null",
        0x0012 => "sm3_256",
        0x0014 => "rsassa",
        0x0015 => "rsaes",
        0x0016 => "rsapss",
        0x0017 => "oaep",
        0x0018 => "ecdsa",
        0x0019 => "ecdh",
        0x001a => "ecdaa",
        0x001b => "sm2",
        0x001c => "ecschnorr",
        0x0020 => "kdf1_sp800_56a",
        0x0022 => "kdf1_sp800_108",
        0x0023 => "ecc",
        0x0025 => "symcipher",
        0x0026 => "camellia",
        0x0043 => "cfb",
        _ => return None,
    })
}

fn alg(id: u16) -> String {
    algorithm(id).map_or_else(|| format!("0x{id:04x}"), str::to_string)
}

/// `TPM_ECC_CURVE` names and sizes.
fn curve(id: u16) -> Option<(&'static str, u64)> {
    Some(match id {
        0x0001 => ("nist_p192", 192),
        0x0002 => ("nist_p224", 224),
        0x0003 => ("nist_p256", 256),
        0x0004 => ("nist_p384", 384),
        0x0005 => ("nist_p521", 521),
        0x0010 => ("bn_p256", 256),
        0x0011 => ("bn_p638", 638),
        0x0020 => ("sm2_p256", 256),
        _ => return None,
    })
}

/// A parent or saved handle: a hierarchy, or a persistent / transient object.
fn handle(h: u64) -> String {
    match h {
        0x4000_0001 => "owner".into(),
        0x4000_0007 => "null".into(),
        0x4000_000b => "endorsement".into(),
        0x4000_000c => "platform".into(),
        _ => format!("0x{h:08x}"),
    }
}

impl Extractor for Tpm {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"-----BEGIN TSS2 PRIVATE KEY-----") || h.starts_with(b"-----BEGIN TSS KEY BLOB-----") {
            return Some(Sniff { format: "tpm2_key", confidence: 0.95 });
        }
        // The DER form: SEQUENCE { OID 2.23.133.10.1.x, … }.
        let (seq, _) = der::read(probe.head)?;
        let oid = seq.child(0).filter(|t| t.tag == 0x06)?;
        KINDS.iter().any(|(o, _)| der::oid(oid.body) == *o).then_some(Sniff { format: "tpm2_key", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, _) = cx.read_bytes(src)?;
        if cx.format_id() == "tpm2_context" {
            return context(&b, cx);
        }
        let der_bytes = if b.starts_with(b"-----BEGIN ") {
            cx.format_set("encoding", "pem");
            let (blocks, _) = pem_blocks(&String::from_utf8_lossy(&b));
            let block = blocks.into_iter().next().ok_or_else(|| ExtractError::malformed("no PEM block"))?;
            if block.label == "TSS KEY BLOB" {
                cx.format_set("tpm_version", "1.2");
                return Ok(());
            }
            block.der.ok_or_else(|| ExtractError::malformed("PEM body is not base64"))?
        } else {
            cx.format_set("encoding", "der");
            b
        };
        cx.format_set("tpm_version", "2.0");
        key(&der_bytes, cx).ok_or_else(|| ExtractError::malformed("not a TPMKey structure"))
    }
}

crate::register_extractor!(Tpm);

/// `TPMKey ::= SEQUENCE { type, [0] emptyAuth, [1] policy, [2] secret,
/// [3] authPolicy, [4] description, [5] rsaParent, parent, pubkey, privkey }`.
fn key(b: &[u8], cx: &mut Context<'_>) -> Option<()> {
    let (seq, _) = der::read(b)?;
    let mut items = seq.children();
    let oid = der::oid(items.next().filter(|t| t.tag == 0x06)?.body);
    let kind = KINDS.iter().find(|(o, _)| *o == oid).map_or("unknown", |(_, k)| k);
    cx.format_set("key_kind", kind);
    let mut empty_auth = false;
    let mut parent = None;
    let mut octets = Vec::new();
    for t in items {
        match t.tag {
            0xa0 => empty_auth = t.child(0).and_then(|v| v.body.first().copied()).is_some_and(|v| v != 0),
            0xa1 => {
                cx.format_set("policies", t.child(0).map_or(0, |s| s.children().count()));
            }
            0xa2 => {
                cx.format_set("imported_secret", true);
            }
            0xa3 => {
                cx.format_set("auth_policies", t.child(0).map_or(0, |s| s.children().count()));
            }
            0xa4 => {
                if let Some(d) = t.child(0) {
                    let d = comment(cx, &der::string(d));
                    cx.format_set("description", d);
                }
            }
            0xa5 => {
                cx.format_set("rsa_parent", t.child(0).and_then(|v| v.body.first().copied()).is_some_and(|v| v != 0));
            }
            0x02 => parent = Some(t.body.iter().fold(0u64, |a, &x| a << 8 | u64::from(x))),
            0x04 => octets.push(t.body),
            _ => {}
        }
    }
    cx.format_set("empty_auth", empty_auth);
    if let Some(p) = parent {
        cx.format_set("parent", handle(p & 0xffff_ffff));
    }
    let public = octets.first()?;
    // TPM2B_PUBLIC: a 16-bit size, then TPMT_PUBLIC.
    let size = usize::from(u16::from_be_bytes([*public.first()?, *public.get(1)?]));
    let area = public.get(2..2 + size)?;
    let mut facts = Map::new();
    public_area(area, &mut facts);
    let f = cx.format();
    for (k, v) in facts {
        f.insert(k, v);
    }
    Some(())
}

/// What `TPMT_PUBLIC` says about the key.
fn public_area(a: &[u8], out: &mut Map<String, Value>) -> Option<()> {
    let mut c = Be { b: a, i: 0 };
    let ty = c.u16()?;
    let name_alg = c.u16()?;
    let attrs = c.u32()?;
    out.insert("key_algorithm".into(), json!(alg(ty)));
    out.insert("name_algorithm".into(), json!(alg(name_alg)));
    let set: Vec<&str> = ATTRIBUTES.iter().filter(|(bit, _)| attrs & bit != 0).map(|(_, n)| *n).collect();
    out.insert("attributes".into(), json!(set));
    let policy = c.u16()?;
    c.skip(usize::from(policy))?;
    if policy > 0 {
        out.insert("auth_policy".into(), json!(true));
    }
    // The TPM name: the name algorithm, then the digest of TPMT_PUBLIC.
    if name_alg == 0x000b {
        out.insert("tpm_name".into(), json!(format!("000b{}", hex(&Sha256::digest(a)))));
    }
    // Parameters: the symmetric definition of restricted (storage) keys first.
    let symmetric = |c: &mut Be<'_>, out: &mut Map<String, Value>| -> Option<()> {
        let s = c.u16()?;
        if s != 0x0010 {
            let bits = c.u16()?;
            let mode = c.u16()?;
            out.insert("symmetric".into(), json!(format!("{}{bits}_{}", alg(s), alg(mode))));
        }
        Some(())
    };
    let scheme = |c: &mut Be<'_>, out: &mut Map<String, Value>| -> Option<()> {
        let s = c.u16()?;
        if s != 0x0010 {
            let hash = c.u16()?;
            out.insert("scheme".into(), json!(format!("{}_{}", alg(s), alg(hash))));
        }
        Some(())
    };
    match ty {
        0x0001 => {
            symmetric(&mut c, out)?;
            scheme(&mut c, out)?;
            out.insert("key_bits".into(), json!(c.u16()?));
            let e = c.u32()?;
            out.insert("rsa_exponent".into(), json!(if e == 0 { 65537 } else { e }));
        }
        0x0023 => {
            symmetric(&mut c, out)?;
            scheme(&mut c, out)?;
            let id = c.u16()?;
            match curve(id) {
                Some((name, bits)) => {
                    out.insert("key_curve".into(), json!(name));
                    out.insert("key_bits".into(), json!(bits));
                }
                None => {
                    out.insert("key_curve".into(), json!(format!("0x{id:04x}")));
                }
            }
        }
        0x0008 => {
            let s = c.u16()?;
            out.insert(
                "scheme".into(),
                json!(match s {
                    0x0005 => format!("hmac_{}", alg(c.u16()?)),
                    0x000a => format!("xor_{}", alg(c.u16()?)),
                    _ => alg(s),
                }),
            );
        }
        0x0025 => symmetric(&mut c, out)?,
        _ => {}
    }
    Some(())
}

/// A big-endian cursor (TPM structures are big-endian).
struct Be<'a> {
    b: &'a [u8],
    i: usize,
}

impl Be<'_> {
    fn u16(&mut self) -> Option<u16> {
        let v = self.b.get(self.i..self.i + 2)?;
        self.i += 2;
        Some(u16::from_be_bytes([v[0], v[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let v = self.b.get(self.i..self.i + 4)?;
        self.i += 4;
        Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.b.get(self.i..self.i.checked_add(n)?)?;
        self.i += n;
        Some(())
    }
}

/// `tpm2-tools` context file: magic, version, then `TPMS_CONTEXT`
/// (sequence, saved handle, hierarchy, context blob).
fn context(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut c = Be { b, i: 4 };
    let short = || ExtractError::malformed("context header cut short");
    let version = c.u32().ok_or_else(short)?;
    cx.format_set("file_version", version);
    let hierarchy = c.u32().ok_or_else(short)?;
    let saved = c.u32().ok_or_else(short)?;
    let hi = c.u32().ok_or_else(short)?;
    let lo = c.u32().ok_or_else(short)?;
    let blob = c.u16().ok_or_else(short)?;
    cx.format_set("hierarchy", handle(u64::from(hierarchy)));
    let kind = match saved >> 24 {
        0x80 => "transient",
        0x02 => "session",
        0x03 => "policy_session",
        0x81 => "persistent",
        _ => "other",
    };
    cx.format_set("saved_handle", json!({ "handle": format!("0x{saved:08x}"), "kind": kind }));
    cx.format_set("sequence", u64::from(hi) << 32 | u64::from(lo));
    cx.format_set("context_blob_bytes", blob);
    if c.skip(usize::from(blob)).is_none() {
        cx.warn("context blob cut short");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("tpm2_key", "tpm2_context");
}
