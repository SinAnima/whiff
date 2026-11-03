//! Licence texts, SPDX identifiers and copyright notices.

use std::sync::LazyLock;

use regex::Regex;

/// Phrases that identify a licence text, checked in order (most specific
/// first). All phrases of a row must occur (case-insensitive).
const TEXTS: &[(&str, &[&str])] = &[
    ("OFL-1.1", &["sil open font license", "1.1"]),
    ("OFL-1.0", &["sil open font license"]),
    ("UFL-1.0", &["ubuntu font licen"]),
    ("AGPL-3.0", &["gnu affero general public license", "version 3"]),
    ("LGPL-3.0", &["gnu lesser general public license", "version 3"]),
    ("LGPL-2.1", &["gnu lesser general public license", "version 2.1"]),
    ("GPL-3.0", &["gnu general public license", "version 3"]),
    ("GPL-2.0", &["gnu general public license", "version 2"]),
    ("Apache-2.0", &["apache license", "version 2.0"]),
    ("MPL-2.0", &["mozilla public license", "2.0"]),
    ("EPL-2.0", &["eclipse public license", "2.0"]),
    ("BSL-1.0", &["boost software license"]),
    ("Unlicense", &["this is free and unencumbered software released into the public domain"]),
    ("CC0-1.0", &["cc0 1.0 universal"]),
    ("CC-BY-SA-4.0", &["creative commons attribution-sharealike 4.0"]),
    ("CC-BY-4.0", &["creative commons attribution 4.0"]),
    ("BSD-3-Clause", &["redistribution and use in source and binary forms", "neither the name"]),
    ("BSD-2-Clause", &["redistribution and use in source and binary forms"]),
    ("ISC", &["permission to use, copy, modify, and/or distribute this software for any purpose"]),
    ("MIT", &["permission is hereby granted, free of charge, to any person obtaining a copy"]),
    ("Zlib", &["this software is provided 'as-is', without any express or implied", "altered source versions"]),
];

/// The SPDX id of the licence whose text `text` contains, if recognised.
/// Only the first 16 KiB are examined.
pub fn identify_license(text: &str) -> Option<&'static str> {
    let mut end = text.len().min(16 * 1024);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let lower = super::squash_whitespace(&text[..end]).to_lowercase();
    TEXTS.iter().find(|(_, phrases)| phrases.iter().all(|p| lower.contains(p))).map(|(id, _)| *id)
}

static SPDX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+\-() ]+?)\s*(?:\*/|-->|$)").expect("valid"));

static COPYRIGHT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^[\s#/*;!-]*((?:copyright|\(c\)|©)\s*(?:\(c\)|©)?\s*(?:\d{4}|[A-Z])[^\n]{0,160})").expect("valid")
});

/// The expression of an `SPDX-License-Identifier:` tag in the first 8 KiB.
pub fn spdx_identifier(text: &str) -> Option<String> {
    let head = &text[..floor(text, 8 * 1024)];
    head.lines().find_map(|l| SPDX.captures(l)).map(|c| c[1].trim().to_string())
}

/// The first copyright notice in the first 8 KiB, without comment markers.
pub fn find_copyright(text: &str) -> Option<String> {
    let head = &text[..floor(text, 8 * 1024)];
    COPYRIGHT.captures(head).map(|c| c[1].trim().trim_end_matches(['*', '/', '-', '>']).trim().to_string())
}

fn floor(text: &str, max: usize) -> usize {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn licences_and_notices() {
        let mit = "MIT License\n\nCopyright (c) 2026 Ada Lovelace\n\nPermission is hereby granted, free of charge, to any \
                   person obtaining a copy of this software";
        assert_eq!(identify_license(mit), Some("MIT"));
        assert_eq!(find_copyright(mit).as_deref(), Some("Copyright (c) 2026 Ada Lovelace"));
        assert_eq!(identify_license("Apache License\n  Version 2.0, January 2004"), Some("Apache-2.0"));
        assert_eq!(identify_license("hello"), None);
        assert_eq!(
            spdx_identifier("// SPDX-License-Identifier: MIT OR Apache-2.0\nfn main() {}").as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(spdx_identifier("/* SPDX-License-Identifier: GPL-2.0-only */").as_deref(), Some("GPL-2.0-only"));
        assert_eq!(
            find_copyright("# Copyright 2024 The Authors.\nimport os").as_deref(),
            Some("Copyright 2024 The Authors.")
        );
        assert_eq!(find_copyright("no notice"), None);
    }
}
