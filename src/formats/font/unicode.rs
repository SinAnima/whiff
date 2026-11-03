//! Unicode coverage of a `cmap` table and the scripts it covers.

use std::collections::BTreeMap;

use super::{be16, be32};

/// Code points read from one subtable (format 4 walks every code).
const MAX_CODES: u32 = 0x11_0000;

/// Scripts by code point range (Unicode 16 blocks, grouped by script;
/// punctuation, symbols and combining marks shared by scripts are `Common`).
const SCRIPTS: &[(u32, u32, &str)] = &[
    (0x0000, 0x001F, "Common"),
    (0x0020, 0x0040, "Common"),
    (0x0041, 0x005A, "Latin"),
    (0x005B, 0x0060, "Common"),
    (0x0061, 0x007A, "Latin"),
    (0x007B, 0x00BF, "Common"),
    (0x00C0, 0x024F, "Latin"),
    (0x0250, 0x02AF, "Latin"),
    (0x02B0, 0x036F, "Common"),
    (0x0370, 0x03FF, "Greek"),
    (0x0400, 0x052F, "Cyrillic"),
    (0x0530, 0x058F, "Armenian"),
    (0x0590, 0x05FF, "Hebrew"),
    (0x0600, 0x06FF, "Arabic"),
    (0x0700, 0x074F, "Syriac"),
    (0x0750, 0x077F, "Arabic"),
    (0x0780, 0x07BF, "Thaana"),
    (0x07C0, 0x07FF, "NKo"),
    (0x0800, 0x083F, "Samaritan"),
    (0x0840, 0x085F, "Mandaic"),
    (0x0860, 0x086F, "Syriac"),
    (0x0870, 0x08FF, "Arabic"),
    (0x0900, 0x097F, "Devanagari"),
    (0x0980, 0x09FF, "Bengali"),
    (0x0A00, 0x0A7F, "Gurmukhi"),
    (0x0A80, 0x0AFF, "Gujarati"),
    (0x0B00, 0x0B7F, "Oriya"),
    (0x0B80, 0x0BFF, "Tamil"),
    (0x0C00, 0x0C7F, "Telugu"),
    (0x0C80, 0x0CFF, "Kannada"),
    (0x0D00, 0x0D7F, "Malayalam"),
    (0x0D80, 0x0DFF, "Sinhala"),
    (0x0E00, 0x0E7F, "Thai"),
    (0x0E80, 0x0EFF, "Lao"),
    (0x0F00, 0x0FFF, "Tibetan"),
    (0x1000, 0x109F, "Myanmar"),
    (0x10A0, 0x10FF, "Georgian"),
    (0x1100, 0x11FF, "Hangul"),
    (0x1200, 0x139F, "Ethiopic"),
    (0x13A0, 0x13FF, "Cherokee"),
    (0x1400, 0x167F, "Canadian Aboriginal"),
    (0x1680, 0x169F, "Ogham"),
    (0x16A0, 0x16FF, "Runic"),
    (0x1700, 0x177F, "Philippine"),
    (0x1780, 0x17FF, "Khmer"),
    (0x1800, 0x18AF, "Mongolian"),
    (0x18B0, 0x18FF, "Canadian Aboriginal"),
    (0x1900, 0x194F, "Limbu"),
    (0x1950, 0x19DF, "Tai"),
    (0x19E0, 0x19FF, "Khmer"),
    (0x1A00, 0x1A1F, "Buginese"),
    (0x1A20, 0x1AAF, "Tai Tham"),
    (0x1AB0, 0x1AFF, "Common"),
    (0x1B00, 0x1B7F, "Balinese"),
    (0x1B80, 0x1BBF, "Sundanese"),
    (0x1BC0, 0x1BFF, "Batak"),
    (0x1C00, 0x1C4F, "Lepcha"),
    (0x1C50, 0x1C7F, "Ol Chiki"),
    (0x1C80, 0x1C8F, "Cyrillic"),
    (0x1C90, 0x1CBF, "Georgian"),
    (0x1CC0, 0x1CFF, "Common"),
    (0x1D00, 0x1DBF, "Latin"),
    (0x1DC0, 0x1DFF, "Common"),
    (0x1E00, 0x1EFF, "Latin"),
    (0x1F00, 0x1FFF, "Greek"),
    (0x2000, 0x2BFF, "Common"),
    (0x2C00, 0x2C5F, "Glagolitic"),
    (0x2C60, 0x2C7F, "Latin"),
    (0x2C80, 0x2CFF, "Coptic"),
    (0x2D00, 0x2D2F, "Georgian"),
    (0x2D30, 0x2D7F, "Tifinagh"),
    (0x2D80, 0x2DDF, "Ethiopic"),
    (0x2DE0, 0x2DFF, "Cyrillic"),
    (0x2E00, 0x2E7F, "Common"),
    (0x2E80, 0x2FDF, "Han"),
    (0x2FF0, 0x303F, "Common"),
    (0x3040, 0x309F, "Hiragana"),
    (0x30A0, 0x30FF, "Katakana"),
    (0x3100, 0x312F, "Bopomofo"),
    (0x3130, 0x318F, "Hangul"),
    (0x3190, 0x319F, "Han"),
    (0x31A0, 0x31BF, "Bopomofo"),
    (0x31C0, 0x31EF, "Han"),
    (0x31F0, 0x31FF, "Katakana"),
    (0x3200, 0x33FF, "Common"),
    (0x3400, 0x4DBF, "Han"),
    (0x4DC0, 0x4DFF, "Common"),
    (0x4E00, 0x9FFF, "Han"),
    (0xA000, 0xA4CF, "Yi"),
    (0xA4D0, 0xA4FF, "Lisu"),
    (0xA500, 0xA63F, "Vai"),
    (0xA640, 0xA69F, "Cyrillic"),
    (0xA6A0, 0xA6FF, "Bamum"),
    (0xA700, 0xA71F, "Common"),
    (0xA720, 0xA7FF, "Latin"),
    (0xA800, 0xA82F, "Syloti Nagri"),
    (0xA830, 0xA83F, "Common"),
    (0xA840, 0xA87F, "Phags-pa"),
    (0xA880, 0xA8DF, "Saurashtra"),
    (0xA8E0, 0xA8FF, "Devanagari"),
    (0xA900, 0xA92F, "Kayah Li"),
    (0xA930, 0xA95F, "Rejang"),
    (0xA960, 0xA97F, "Hangul"),
    (0xA980, 0xA9DF, "Javanese"),
    (0xA9E0, 0xA9FF, "Myanmar"),
    (0xAA00, 0xAA5F, "Cham"),
    (0xAA60, 0xAA7F, "Myanmar"),
    (0xAA80, 0xAADF, "Tai Viet"),
    (0xAAE0, 0xAAFF, "Meetei Mayek"),
    (0xAB00, 0xAB2F, "Ethiopic"),
    (0xAB30, 0xAB6F, "Latin"),
    (0xAB70, 0xABBF, "Cherokee"),
    (0xABC0, 0xABFF, "Meetei Mayek"),
    (0xAC00, 0xD7FF, "Hangul"),
    (0xE000, 0xF8FF, "Private Use"),
    (0xF900, 0xFAFF, "Han"),
    (0xFB00, 0xFB12, "Latin"),
    (0xFB13, 0xFB1C, "Armenian"),
    (0xFB1D, 0xFB4F, "Hebrew"),
    (0xFB50, 0xFDFF, "Arabic"),
    (0xFE00, 0xFE6F, "Common"),
    (0xFE70, 0xFEFF, "Arabic"),
    (0xFF00, 0xFF20, "Common"),
    (0xFF21, 0xFF3A, "Latin"),
    (0xFF3B, 0xFF40, "Common"),
    (0xFF41, 0xFF5A, "Latin"),
    (0xFF5B, 0xFF64, "Common"),
    (0xFF65, 0xFF9F, "Katakana"),
    (0xFFA0, 0xFFDF, "Hangul"),
    (0xFFE0, 0xFFFF, "Common"),
    (0x10000, 0x1CFFF, "Historic"),
    (0x1D000, 0x1D7FF, "Common"),
    (0x1D800, 0x1EFFF, "Historic"),
    (0x1F000, 0x1FAFF, "Emoji and symbols"),
    (0x1FB00, 0x1FFFF, "Common"),
    (0x20000, 0x3FFFF, "Han"),
    (0xE0000, 0xE01EF, "Common"),
    (0xF0000, 0x0010_FFFF, "Private Use"),
];

/// Code points per script, most covered first.
pub(super) fn scripts(ranges: &[(u32, u32)]) -> Vec<(&'static str, u64)> {
    let mut by: BTreeMap<&str, u64> = BTreeMap::new();
    for &(a, b) in ranges {
        for &(s, e, name) in SCRIPTS {
            let (lo, hi) = (a.max(s), b.min(e));
            if lo <= hi {
                *by.entry(name).or_default() += u64::from(hi - lo + 1);
            }
        }
    }
    let mut v: Vec<_> = by.into_iter().collect();
    v.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(y.0)));
    v
}

/// The mapped code points of the best Unicode subtable, as sorted, merged
/// ranges (a code mapped to glyph 0 is not covered), and whether the font
/// uses the Windows symbol encoding.
pub(super) fn coverage(cmap: &[u8]) -> (Vec<(u32, u32)>, bool) {
    let mut best: Option<(u8, usize)> = None;
    let mut symbol = false;
    let records = be16(cmap, 2).map_or(0, usize::from);
    for i in 0..records.min(200) {
        let r = 4 + 8 * i;
        let (Some(platform), Some(encoding), Some(off)) = (be16(cmap, r), be16(cmap, r + 2), be32(cmap, r + 4)) else {
            break;
        };
        let Ok(off) = usize::try_from(off) else { continue };
        let Some(fmt) = be16(cmap, off) else { continue };
        let rank = match (platform, encoding, fmt) {
            (3, 10, 12 | 13) | (0, 4 | 6, 12 | 13) => 0,
            (3, 1, 4) | (0, 3, 4) => 1,
            (0, _, 4 | 6) => 2,
            (3, 0, 4) => 3,
            (1, 0, 0 | 6) => 4,
            _ => continue,
        };
        if platform == 3 && encoding == 0 {
            symbol = true;
        }
        if best.is_none_or(|(r, _)| rank < r) {
            best = Some((rank, off));
        }
    }
    let Some((_, off)) = best else { return (Vec::new(), symbol) };
    let t = &cmap[off..];
    let mut codes: Vec<(u32, u32)> = Vec::new();
    let mut push = |a: u32, b: u32| {
        if let Some(last) = codes.last_mut()
            && last.1 + 1 >= a
            && a >= last.0
        {
            last.1 = last.1.max(b);
        } else {
            codes.push((a, b));
        }
    };
    match be16(t, 0) {
        Some(0) => {
            for (code, &g) in (0u32..).zip(t.get(6..262).unwrap_or_default()) {
                if g != 0 {
                    push(code, code);
                }
            }
        }
        Some(4) => format4(t, &mut push),
        Some(6) => {
            let (Some(first), Some(count)) = (be16(t, 6), be16(t, 8)) else { return (Vec::new(), symbol) };
            for i in 0..u32::from(count) {
                let Ok(at) = usize::try_from(10 + 2 * i) else { break };
                if be16(t, at).is_some_and(|g| g != 0) {
                    push(u32::from(first) + i, u32::from(first) + i);
                }
            }
        }
        Some(12 | 13) => {
            let groups = be32(t, 12).unwrap_or(0).min(1 << 20);
            let is13 = be16(t, 0) == Some(13);
            for i in 0..groups {
                let Ok(at) = usize::try_from(16 + 12 * u64::from(i)) else { break };
                let (Some(a), Some(b), Some(g)) = (be32(t, at), be32(t, at + 4), be32(t, at + 8)) else { break };
                if a > b || b >= MAX_CODES {
                    continue;
                }
                // Format 12 maps a..=b to g, g+1, …: only `a` can hit glyph 0.
                let a = if g == 0 && !is13 { a + 1 } else { a };
                if (!is13 || g != 0) && a <= b {
                    push(a, b);
                }
            }
        }
        _ => {}
    }
    codes.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(codes.len());
    for (a, b) in codes {
        match merged.last_mut() {
            Some(last) if a <= last.1.saturating_add(1) => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    (merged, symbol)
}

/// Format 4: segments of `end`, `start`, `delta` and `range offset`.
fn format4(t: &[u8], push: &mut impl FnMut(u32, u32)) {
    let Some(seg2) = be16(t, 6).map(usize::from) else { return };
    let ends = 14;
    let starts = ends + seg2 + 2;
    let deltas = starts + seg2;
    let offsets = deltas + seg2;
    for s in 0..seg2 / 2 {
        let (Some(end), Some(start), Some(delta), Some(ro)) =
            (be16(t, ends + 2 * s), be16(t, starts + 2 * s), be16(t, deltas + 2 * s), be16(t, offsets + 2 * s))
        else {
            break;
        };
        if start > end {
            continue;
        }
        let mut run: Option<(u32, u32)> = None;
        for code in start..=end {
            if code == 0xFFFF {
                break;
            }
            let glyph = if ro == 0 {
                code.wrapping_add(delta)
            } else {
                let at = offsets + 2 * s + usize::from(ro) + 2 * usize::from(code - start);
                match be16(t, at) {
                    Some(0) | None => 0,
                    Some(g) => g.wrapping_add(delta),
                }
            };
            let c = u32::from(code);
            if glyph == 0 {
                if let Some((a, b)) = run.take() {
                    push(a, b);
                }
            } else {
                run = Some(run.map_or((c, c), |(a, _)| (a, c)));
            }
        }
        if let Some((a, b)) = run {
            push(a, b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_counts() {
        let s = scripts(&[(0x41, 0x5A), (0x391, 0x391), (0x4E00, 0x4E09)]);
        assert_eq!(s, vec![("Latin", 26), ("Han", 10), ("Greek", 1)]);
    }

    #[test]
    fn format4_skips_glyph_zero() {
        // One segment 0x41..=0x43 through the glyph array (0 for 0x42),
        // then the 0xFFFF end segment.
        let mut t = vec![0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0];
        t.extend([0, 0x43, 0xFF, 0xFF, 0, 0, 0, 0x41, 0xFF, 0xFF, 0, 0, 0, 1, 0, 4, 0, 0]);
        t.extend([0, 5, 0, 0, 0, 6]);
        let mut got = Vec::new();
        format4(&t, &mut |a, b| got.push((a, b)));
        assert_eq!(got, vec![(0x41, 0x41), (0x43, 0x43)]);
    }
}
