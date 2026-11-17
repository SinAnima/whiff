//! The standard security handler (ISO 32000-2 §7.6.4), revisions 2–6:
//! RC4 and AES-128 / AES-256. Only the **empty user password** is tried,
//! which opens the many files that are encrypted just to set permissions.
//! Files that need a password are reported as encrypted and left unread.

use md5::{Digest, Md5};
use sha2::{Sha256, Sha384, Sha512};

use super::object::{Dict, Obj};
use crate::plugin::ExtractError;

const PAD: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00,
    0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Method {
    None,
    Rc4,
    Aes128,
    Aes256,
}

/// Encryption parameters and, when the empty password works, the file key.
#[derive(Debug, Clone)]
pub(crate) struct Decryptor {
    pub(crate) filter: String,
    pub(crate) sub_filter: Option<String>,
    pub(crate) v: i64,
    pub(crate) r: i64,
    pub(crate) bits: i64,
    pub(crate) permissions: Option<i32>,
    pub(crate) encrypt_metadata: bool,
    pub(crate) method: &'static str,
    key: Option<Vec<u8>>,
    strings: Method,
    streams: Method,
}

impl Decryptor {
    pub(crate) fn new(enc: &Dict, id: &[u8]) -> Self {
        let v = enc.int("V").unwrap_or(0);
        let r = enc.int("R").unwrap_or(0);
        let filter = enc.name("Filter").unwrap_or("").to_string();
        let encrypt_metadata = enc.get("EncryptMetadata").and_then(Obj::as_bool).unwrap_or(true);
        #[allow(clippy::cast_possible_truncation)] // /P is a 32-bit signed field
        let permissions = enc.int("P").map(|p| p as i32);
        let cf = |name: Option<&str>| -> Method {
            match name {
                None | Some("Identity") => {
                    if name.is_none() && v < 4 {
                        Method::Rc4
                    } else {
                        Method::None
                    }
                }
                Some(n) => {
                    let cfm = enc
                        .get("CF")
                        .and_then(Obj::as_dict)
                        .and_then(|d| d.get(n))
                        .and_then(Obj::as_dict)
                        .and_then(|d| d.name("CFM"));
                    match cfm {
                        Some("AESV2") => Method::Aes128,
                        Some("AESV3") => Method::Aes256,
                        Some("V2") => Method::Rc4,
                        _ => Method::None,
                    }
                }
            }
        };
        let (strings, streams) = if v >= 4 {
            (cf(Some(enc.name("StrF").unwrap_or("Identity"))), cf(Some(enc.name("StmF").unwrap_or("Identity"))))
        } else {
            (Method::Rc4, Method::Rc4)
        };
        let bits = match v {
            1 => 40,
            5 | 6 => 256,
            _ => enc.int("Length").unwrap_or(40),
        };
        let method = match streams.max(strings) {
            Method::Aes256 => "AES-256",
            Method::Aes128 => "AES-128",
            Method::Rc4 => "RC4",
            Method::None => "none",
        };
        let mut d = Self {
            filter,
            sub_filter: enc.name("SubFilter").map(str::to_string),
            v,
            r,
            bits,
            permissions,
            encrypt_metadata,
            method,
            key: None,
            strings,
            streams,
        };
        if d.filter == "Standard" {
            d.key = standard_key(enc, id, v, r, bits, permissions.unwrap_or(0), encrypt_metadata);
        }
        d
    }

    /// Whether the empty user password opened the file.
    pub(crate) fn opened(&self) -> bool {
        self.key.is_some()
    }

    fn object_key(key: &[u8], m: Method, n: u32, g: u16) -> Vec<u8> {
        if m == Method::Aes256 {
            return key.to_vec();
        }
        let mut h = Md5::new();
        h.update(key);
        h.update(&n.to_le_bytes()[..3]);
        h.update(g.to_le_bytes());
        if m == Method::Aes128 {
            h.update(b"sAlT");
        }
        let digest = h.finalize();
        digest[..(key.len() + 5).min(16)].to_vec()
    }

    fn decrypt(&self, m: Method, n: u32, g: u16, data: &[u8]) -> Option<Vec<u8>> {
        let key = self.key.as_ref()?;
        Some(match m {
            Method::None => data.to_vec(),
            Method::Rc4 => rc4(&Self::object_key(key, m, n, g), data),
            Method::Aes128 | Method::Aes256 => {
                let k = Self::object_key(key, m, n, g);
                if data.len() < 32 || !data.len().is_multiple_of(16) {
                    // Empty strings are stored as the IV alone.
                    return Some(Vec::new());
                }
                let mut out = aes_cbc_decrypt(&Aes::new(&k)?, data[..16].try_into().ok()?, &data[16..]);
                unpad(&mut out);
                out
            }
        })
    }

    /// Decrypt every string inside `obj` (object `n`, generation `g`).
    pub(crate) fn decrypt_strings(&self, n: u32, g: u16, obj: Obj) -> Obj {
        if self.key.is_none() || self.strings == Method::None {
            return obj;
        }
        self.walk(n, g, obj, 0)
    }

    fn walk(&self, n: u32, g: u16, obj: Obj, depth: usize) -> Obj {
        if depth > 32 {
            return obj;
        }
        match obj {
            Obj::Str(s) => Obj::Str(self.decrypt(self.strings, n, g, &s).unwrap_or(s)),
            Obj::Array(a) => Obj::Array(a.into_iter().map(|o| self.walk(n, g, o, depth + 1)).collect()),
            Obj::Dict(mut d) => {
                // Signature /Contents are not encrypted.
                let sig = d.name("Type") == Some("Sig");
                for (k, v) in &mut d.0 {
                    if !(sig && k == "Contents") {
                        *v = self.walk(n, g, std::mem::replace(v, Obj::Null), depth + 1);
                    }
                }
                Obj::Dict(d)
            }
            Obj::Stream(mut d, data) => {
                for (_, v) in &mut d.0 {
                    *v = self.walk(n, g, std::mem::replace(v, Obj::Null), depth + 1);
                }
                Obj::Stream(d, data)
            }
            other => other,
        }
    }

    /// Decrypt a stream's bytes, or fail when the password is unknown.
    pub(crate) fn decrypt_stream(&self, n: u32, g: u16, data: Vec<u8>) -> Result<Vec<u8>, ExtractError> {
        if self.streams == Method::None {
            return Ok(data);
        }
        self.decrypt(self.streams, n, g, &data)
            .ok_or_else(|| ExtractError::Unsupported("encrypted stream (password required)".into()))
    }
}

/// The file key from the empty user password, if it is the right one.
#[allow(clippy::many_single_char_names)] // the names of ISO 32000 algorithm 2 (O, U, P, R, V)
fn standard_key(enc: &Dict, id: &[u8], v: i64, r: i64, bits: i64, p: i32, encrypt_metadata: bool) -> Option<Vec<u8>> {
    let o = enc.get("O").and_then(Obj::as_str)?;
    let u = enc.get("U").and_then(Obj::as_str)?;
    if r >= 5 {
        let ue = enc.get("UE").and_then(Obj::as_str)?;
        if u.len() < 48 || ue.len() < 32 {
            return None;
        }
        let check = if r == 5 { sha256(&[&u[32..40]]) } else { hash_2b(b"", &u[32..40], b"") };
        if check[..32] != u[..32] {
            return None;
        }
        let k = if r == 5 { sha256(&[&u[40..48]]) } else { hash_2b(b"", &u[40..48], b"") };
        let aes = Aes::new(&k[..32])?;
        return Some(aes_cbc_decrypt(&aes, &[0; 16], &ue[..32]));
    }
    let n = if r == 2 { 5 } else { usize::try_from(bits / 8).ok()?.clamp(5, 16) };
    let _ = v;
    let mut h = Md5::new();
    h.update(PAD);
    h.update(&o[..o.len().min(32)]);
    h.update(p.to_le_bytes());
    h.update(id);
    if r >= 4 && !encrypt_metadata {
        h.update([0xFF; 4]);
    }
    let mut key = h.finalize().to_vec();
    if r >= 3 {
        for _ in 0..50 {
            key = Md5::digest(&key[..n]).to_vec();
        }
    }
    key.truncate(n);
    // Check the key against /U (algorithms 4 and 5).
    let ok = if r == 2 {
        rc4(&key, &PAD) == u[..u.len().min(32)]
    } else {
        let mut h = Md5::new();
        h.update(PAD);
        h.update(id);
        let mut x = rc4(&key, &h.finalize());
        for i in 1..=19u8 {
            let k: Vec<u8> = key.iter().map(|b| b ^ i).collect();
            x = rc4(&k, &x);
        }
        u.len() >= 16 && x[..16] == u[..16]
    };
    ok.then_some(key)
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// Algorithm 2.B (revision 6 hash).
fn hash_2b(password: &[u8], salt: &[u8], udata: &[u8]) -> Vec<u8> {
    let mut k = sha256(&[password, salt, udata]);
    let mut round = 0u32;
    loop {
        let mut k1 = Vec::with_capacity(64 * (password.len() + k.len() + udata.len()));
        for _ in 0..64 {
            k1.extend_from_slice(password);
            k1.extend_from_slice(&k);
            k1.extend_from_slice(udata);
        }
        let Some(aes) = Aes::new(&k[..16]) else { return k };
        let e = aes_cbc_encrypt(&aes, k[16..32].try_into().unwrap_or([0; 16]), &k1);
        let sum: u32 = e[..16].iter().map(|&b| u32::from(b)).sum();
        k = match sum % 3 {
            0 => Sha256::digest(&e).to_vec(),
            1 => Sha384::digest(&e).to_vec(),
            _ => Sha512::digest(&e).to_vec(),
        };
        round += 1;
        if round >= 64 && u32::from(*e.last().unwrap_or(&0)) + 32 <= round - 1 + 1 {
            break;
        }
        if round > 2048 {
            break;
        }
    }
    k.truncate(32);
    k
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = std::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len().max(1)]);
        s.swap(i, usize::from(j));
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[usize::from(i)]);
            s.swap(usize::from(i), usize::from(j));
            b ^ s[usize::from(s[usize::from(i)].wrapping_add(s[usize::from(j)]))]
        })
        .collect()
}

// ---- AES (FIPS-197), table-free, for 128- and 256-bit keys -------------

struct Aes {
    rounds: usize,
    w: Vec<[u8; 16]>,
}

const fn sbox() -> [u8; 256] {
    // Generated from the multiplicative inverse in GF(2^8) and the affine map.
    let mut s = [0u8; 256];
    let (mut p, mut q) = (1u8, 1u8);
    loop {
        // p *= 3
        p = p ^ (p << 1) ^ (if p & 0x80 != 0 { 0x1B } else { 0 });
        // q /= 3
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        s[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    s[0] = 0x63;
    s
}

const SBOX: [u8; 256] = sbox();

#[allow(clippy::cast_possible_truncation)] // i < 256
const fn inv_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

const INV_SBOX: [u8; 256] = inv_sbox();

fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1B } else { 0 }
}

fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    r
}

impl Aes {
    fn new(key: &[u8]) -> Option<Self> {
        let nk = match key.len() {
            16 => 4,
            32 => 8,
            _ => return None,
        };
        let rounds = nk + 6;
        let mut words: Vec<[u8; 4]> = key.as_chunks::<4>().0.to_vec();
        let mut rcon = 1u8;
        for i in nk..4 * (rounds + 1) {
            let mut t = words[i - 1];
            if i % nk == 0 {
                t = [
                    SBOX[usize::from(t[1])] ^ rcon,
                    SBOX[usize::from(t[2])],
                    SBOX[usize::from(t[3])],
                    SBOX[usize::from(t[0])],
                ];
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = t.map(|b| SBOX[usize::from(b)]);
            }
            let prev = words[i - nk];
            words.push([prev[0] ^ t[0], prev[1] ^ t[1], prev[2] ^ t[2], prev[3] ^ t[3]]);
        }
        let w = words
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| {
                let mut k = [0u8; 16];
                for (j, word) in c.iter().enumerate() {
                    k[4 * j..4 * j + 4].copy_from_slice(word);
                }
                k
            })
            .collect();
        Some(Self { rounds, w })
    }

    fn encrypt(&self, block: &mut [u8; 16]) {
        xor(block, &self.w[0]);
        for r in 1..=self.rounds {
            for b in block.iter_mut() {
                *b = SBOX[usize::from(*b)];
            }
            shift_rows(block);
            if r != self.rounds {
                for c in 0..4 {
                    let col = [block[4 * c], block[4 * c + 1], block[4 * c + 2], block[4 * c + 3]];
                    for i in 0..4 {
                        block[4 * c + i] =
                            mul(col[i], 2) ^ mul(col[(i + 1) % 4], 3) ^ col[(i + 2) % 4] ^ col[(i + 3) % 4];
                    }
                }
            }
            xor(block, &self.w[r]);
        }
    }

    fn decrypt(&self, block: &mut [u8; 16]) {
        xor(block, &self.w[self.rounds]);
        for r in (0..self.rounds).rev() {
            inv_shift_rows(block);
            for b in block.iter_mut() {
                *b = INV_SBOX[usize::from(*b)];
            }
            xor(block, &self.w[r]);
            if r != 0 {
                for c in 0..4 {
                    let col = [block[4 * c], block[4 * c + 1], block[4 * c + 2], block[4 * c + 3]];
                    for i in 0..4 {
                        block[4 * c + i] = mul(col[i], 14)
                            ^ mul(col[(i + 1) % 4], 11)
                            ^ mul(col[(i + 2) % 4], 13)
                            ^ mul(col[(i + 3) % 4], 9);
                    }
                }
            }
        }
    }
}

fn xor(block: &mut [u8; 16], k: &[u8; 16]) {
    for (b, k) in block.iter_mut().zip(k) {
        *b ^= k;
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[4 * c + r] = t[4 * ((c + r) % 4) + r];
        }
    }
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[4 * ((c + r) % 4) + r] = t[4 * c + r];
        }
    }
}

/// Remove PKCS#7 padding: only when every padding byte holds the pad length,
/// so a wrong key or damaged data keeps its bytes.
fn unpad(out: &mut Vec<u8>) {
    let Some(&last) = out.last() else { return };
    let pad = usize::from(last);
    if (1..=16).contains(&pad) && out.len() >= pad && out[out.len() - pad..].iter().all(|&b| b == last) {
        out.truncate(out.len() - pad);
    }
}

fn aes_cbc_decrypt(aes: &Aes, iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.as_chunks::<16>().0 {
        let mut block = *chunk;
        let cipher = block;
        aes.decrypt(&mut block);
        xor(&mut block, &prev);
        out.extend_from_slice(&block);
        prev = cipher;
    }
    out
}

fn aes_cbc_encrypt(aes: &Aes, iv: [u8; 16], data: &[u8]) -> Vec<u8> {
    let mut prev = iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.as_chunks::<16>().0 {
        let mut block = *chunk;
        xor(&mut block, &prev);
        aes.encrypt(&mut block);
        out.extend_from_slice(&block);
        prev = block;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn aes_fips197_vectors() {
        let plain: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        for (key, expect) in [
            ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
        ] {
            let aes = Aes::new(&hex(key)).unwrap();
            let mut b = plain;
            aes.encrypt(&mut b);
            assert_eq!(b.to_vec(), hex(expect));
            aes.decrypt(&mut b);
            assert_eq!(b, plain);
        }
    }

    #[test]
    fn padding_is_removed_only_when_every_byte_matches() {
        let unpadded = |mut v: Vec<u8>| {
            unpad(&mut v);
            v
        };
        assert_eq!(unpadded(b"notes\x02\x02".to_vec()), b"notes");
        // A last byte of 2 after a byte that is not 2 is data, not padding.
        assert_eq!(unpadded(b"notes\x01\x02".to_vec()), b"notes\x01\x02");
        let mut block = vec![0x10; 16];
        block[14] = 0x0f;
        assert_eq!(unpadded(block.clone()), block);
        assert_eq!(unpadded(vec![0x10; 16]), b"");
        // Through AES-CBC: a whole padding block comes off, data stays.
        let aes = Aes::new(&[7; 16]).unwrap();
        let mut plain = b"Harbour notes\x01\x02\x02".to_vec();
        plain.extend_from_slice(&[0x10; 16]);
        let enc = aes_cbc_encrypt(&aes, [3; 16], &plain);
        assert_eq!(unpadded(aes_cbc_decrypt(&aes, &[3; 16], &enc)), b"Harbour notes\x01\x02\x02");
    }

    #[test]
    fn rc4_known_vector() {
        assert_eq!(rc4(b"Key", b"Plaintext"), hex("bbf316e8d940af0ad3"));
    }
}
