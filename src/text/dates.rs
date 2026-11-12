//! Lenient date parsing for dates found in content (front matter, feeds,
//! logs, HTML meta tags).

use jiff::civil::{Date, DateTime};
use jiff::fmt::strtime;
use jiff::fmt::temporal::Pieces;
use jiff::{Timestamp, tz::Offset};

/// Parse a date or date-time in one of the common notations.
///
/// Returns the value in the form `temporal.content` expects plus whether the
/// source carried a zone: RFC 3339 with its original offset (`tz_known`), or a
/// civil `YYYY-MM-DDTHH:MM:SS` / `YYYY-MM-DD` (not `tz_known`).
pub fn parse_date(s: &str) -> Option<(String, bool)> {
    let s = s.trim().trim_matches('"');
    if s.len() < 6 || s.len() > 64 {
        return None;
    }
    let iso = normalise_iso(s);
    if let Ok(ts) = iso.parse::<Timestamp>() {
        let offset = Pieces::parse(iso.as_str()).ok().and_then(|p| p.to_numeric_offset()).unwrap_or(Offset::UTC);
        return Some((with_offset(ts, offset), true));
    }
    if let Ok(dt) = iso.parse::<DateTime>()
        && iso.contains('T')
    {
        return Some((dt.strftime("%Y-%m-%dT%H:%M:%S").to_string(), false));
    }
    if let Ok(d) = iso.parse::<Date>() {
        return Some((d.to_string(), false));
    }
    if let Ok(z) = jiff::fmt::rfc2822::parse(s) {
        return Some((with_offset(z.timestamp(), z.offset()), true));
    }
    for fmt in ["%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S %z", "%a %b %d %H:%M:%S %Y %z"] {
        if let Ok(tm) = strtime::parse(fmt, s)
            && let (Ok(ts), Some(off)) = (tm.to_timestamp(), tm.offset())
        {
            return Some((with_offset(ts, off), true));
        }
    }
    for fmt in ["%a %b %d %H:%M:%S %Y", "%Y/%m/%d %H:%M:%S", "%d %b %Y %H:%M:%S"] {
        if let Ok(dt) = strtime::parse(fmt, s).and_then(|tm| tm.to_datetime()) {
            return Some((dt.strftime("%Y-%m-%dT%H:%M:%S").to_string(), false));
        }
    }
    let cleaned = s.replace(',', "");
    for fmt in ["%B %d %Y", "%b %d %Y", "%d %B %Y", "%d %b %Y", "%Y/%m/%d", "%Y.%m.%d"] {
        if let Ok(d) = strtime::parse(fmt, &cleaned).and_then(|tm| tm.to_date()) {
            return Some((d.to_string(), false));
        }
    }
    None
}

/// `2026-10-16 09:30` → `2026-10-16T09:30`; `…Z`, `…+0200` kept parseable.
fn normalise_iso(s: &str) -> String {
    let mut t = s.to_string();
    let b = t.as_bytes();
    if b.len() > 11 && b[4] == b'-' && b[7] == b'-' && b[10] == b' ' && b[11].is_ascii_digit() {
        t.replace_range(10..11, "T");
    }
    // `+0200` → `+02:00`
    let b = t.as_bytes();
    let n = b.len();
    if n > 5 && t.contains('T') && matches!(b[n - 5], b'+' | b'-') && b[n - 4..].iter().all(u8::is_ascii_digit) {
        t.insert(n - 2, ':');
    }
    if let Some(stripped) = t.strip_suffix(" UTC").or_else(|| t.strip_suffix(" GMT")) {
        t = format!("{stripped}Z");
    }
    t
}

fn with_offset(ts: Timestamp, offset: Offset) -> String {
    let s = ts.display_with_offset(offset).to_string();
    // jiff writes `Z`-less offsets; keep fractional seconds out for readability.
    match s.find('.') {
        Some(dot) => {
            let end = s[dot..].find(['+', '-', 'Z']).map_or(s.len(), |i| dot + i);
            format!("{}{}", &s[..dot], &s[end..])
        }
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_date;

    #[test]
    fn parse_date_forms() {
        assert_eq!(parse_date("2026-01-02T03:04:05+02:00"), Some(("2026-01-02T03:04:05+02:00".into(), true)));
        assert_eq!(parse_date("Fri, 16 Oct 2026 09:30:00 GMT"), Some(("2026-10-16T09:30:00+00:00".into(), true)));
        assert_eq!(parse_date("2026-10-16 09:30"), Some(("2026-10-16T09:30:00".into(), false)));
        assert_eq!(parse_date("October 16, 2026"), Some(("2026-10-16".into(), false)));
        assert_eq!(parse_date("soon"), None);
    }

    #[test]
    fn notations() {
        let cases = [
            ("2026-10-16T09:30:00Z", Some(("2026-10-16T09:30:00+00:00", true))),
            ("2026-10-16T09:30:00.123+0530", Some(("2026-10-16T09:30:00+05:30", true))),
            ("2026-10-16 09:30:00 UTC", Some(("2026-10-16T09:30:00+00:00", true))),
            ("10/Oct/2026:13:55:36 -0700", Some(("2026-10-10T13:55:36-07:00", true))),
            ("2026-10-16T09:30:00", Some(("2026-10-16T09:30:00", false))),
            ("2026-10-16", Some(("2026-10-16", false))),
            ("16 Oct 2026", Some(("2026-10-16", false))),
            ("2026/10/16", Some(("2026-10-16", false))),
            ("not a date", None),
            ("12", None),
        ];
        for (input, want) in cases {
            assert_eq!(parse_date(input), want.map(|(v, tz)| (v.to_string(), tz)), "{input}");
        }
    }
}
