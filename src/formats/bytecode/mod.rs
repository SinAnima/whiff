//! `bytecode` extractors (feature `common`): compiled code for a virtual
//! machine. Each reports the runtime and the version it targets (Java
//! release, Android API level, Python version, Lua / Erlang / Ruby / OCaml
//! release), what the file defines (class, module or function names, with
//! counts), what it depends on (referenced packages, modules and imports),
//! the source file it was compiled from and whether debug information is
//! kept. Nothing is executed, unmarshalled into live objects or
//! decompiled; Python's `marshal` stream is walked, never loaded.
//!
//! .NET assemblies are PE files: their metadata tables are read by
//! [`cli`] from the `exec.pe` extractor.

#![allow(clippy::many_single_char_names)] // bytes `b`, cursor `c`, pool `p`, as in the specifications

pub(crate) mod cli;
pub(crate) mod dex;
pub(crate) mod java;
pub(crate) mod longtail;
pub(crate) mod python;
pub(crate) mod vm;

// Helpers shared with the archive, executable and package extractors.
pub(crate) use super::archive::unix_time;
pub(crate) use super::exec::{hex, names, uleb};
pub(crate) use super::package::java::java_release;
use crate::plugin::Context;

/// Java's modified UTF-8 (class files, DEX): NUL as `C0 80` and characters
/// outside the BMP as surrogate pairs of three bytes each.
pub(crate) fn mutf8(b: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(b) {
        return s.to_string();
    }
    let mut units = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let (unit, n) = if c < 0x80 {
            (u16::from(c), 1)
        } else if c & 0xe0 == 0xc0 && i + 1 < b.len() {
            ((u16::from(c & 0x1f) << 6) | u16::from(b[i + 1] & 0x3f), 2)
        } else if c & 0xf0 == 0xe0 && i + 2 < b.len() {
            ((u16::from(c & 0x0f) << 12) | (u16::from(b[i + 1] & 0x3f) << 6) | u16::from(b[i + 2] & 0x3f), 3)
        } else {
            (0xfffd, 1)
        };
        units.push(unit);
        i += n;
    }
    String::from_utf16_lossy(&units)
}

/// A JVM internal name (`java/util/List`) or descriptor (`Ljava/util/List;`)
/// in source form (`java.util.List`); arrays keep their `[]`.
pub(crate) fn java_name(s: &str) -> String {
    let dims = s.bytes().take_while(|&c| c == b'[').count();
    let base = &s[dims..];
    let base = match base.strip_prefix('L').and_then(|b| b.strip_suffix(';')) {
        Some(b) => b,
        None if dims > 0 => match base {
            "Z" => "boolean",
            "B" => "byte",
            "C" => "char",
            "S" => "short",
            "I" => "int",
            "J" => "long",
            "F" => "float",
            "D" => "double",
            "V" => "void",
            other => other,
        },
        None => base,
    };
    let mut out = base.replace('/', ".");
    for _ in 0..dims {
        out.push_str("[]");
    }
    out
}

/// The package of a source-form class name (`java.util.List` → `java.util`).
pub(crate) fn package_of(class: &str) -> Option<&str> {
    class.rsplit_once('.').map(|(p, _)| p)
}

/// A source path as the report shows it: only the file name when privacy
/// is strict, since build paths often name a user's home folder.
pub(crate) fn source_path(cx: &Context<'_>, path: &str) -> String {
    if cx.privacy_strict() { path.rsplit(['/', '\\']).next().unwrap_or(path).to_string() } else { path.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modified_utf8_decodes_nul_and_surrogates() {
        assert_eq!(mutf8(b"tide"), "tide");
        assert_eq!(mutf8(b"a\xc0\x80b"), "a\0b");
        // U+1F30A (water wave) as a CESU-8 surrogate pair.
        assert_eq!(mutf8(b"\xed\xa0\xbc\xed\xbc\x8a"), "\u{1f30a}");
    }

    #[test]
    fn java_names_in_source_form() {
        assert_eq!(java_name("java/util/List"), "java.util.List");
        assert_eq!(java_name("Ljava/lang/String;"), "java.lang.String");
        assert_eq!(java_name("[[I"), "int[][]");
        assert_eq!(java_name("[Ljava/lang/Object;"), "java.lang.Object[]");
        assert_eq!(java_name("Tides"), "Tides");
        assert_eq!(package_of("java.util.List"), Some("java.util"));
    }
}
