//! Secrets and personal data: patterns that are **counted** and, for
//! secrets, **redacted**. Values are never written to a report.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::{Regex, RegexSet};

/// What a pattern finds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Credentials and key material: counted and redacted everywhere.
    Secret,
    /// Personal data: counted; redacted from derived text (excerpt, summary).
    Personal,
}

struct Pattern {
    kind: &'static str,
    category: Category,
    re: Regex,
    check: fn(&str) -> bool,
}

fn always(_: &str) -> bool {
    true
}

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    use Category::{Personal, Secret};
    // Word boundaries are ASCII (`(?-u:\b)`): Unicode ones keep the regex
    // engine off its fast DFA for any non-ASCII text.
    let p = |kind, category, re: &str, check| Pattern { kind, category, re: Regex::new(re).expect("valid"), check };
    vec![
        p(
            "private_key",
            Secret,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
            always,
        ),
        p("aws_access_key_id", Secret, r"(?-u:\b)(?:AKIA|ASIA)[0-9A-Z]{16}(?-u:\b)", always),
        p(
            "github_token",
            Secret,
            r"(?-u:\b)(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})(?-u:\b)",
            always,
        ),
        p("slack_token", Secret, r"(?-u:\b)xox[abposr]-[A-Za-z0-9-]{10,}", always),
        p("google_api_key", Secret, r"(?-u:\b)AIza[0-9A-Za-z_-]{35}(?-u:\b)", always),
        p("stripe_secret_key", Secret, r"(?-u:\b)[rs]k_live_[0-9A-Za-z]{20,}", always),
        p("anthropic_api_key", Secret, r"(?-u:\b)sk-ant-[A-Za-z0-9_-]{20,}", always),
        p("openai_api_key", Secret, r"(?-u:\b)sk-(?:proj-)?[A-Za-z0-9_-]{40,}", always),
        p("jwt", Secret, r"(?-u:\b)eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", always),
        p("url_credentials", Secret, r"(?-u:\b)[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]+@[^\s/]+", always),
        p(
            "credential_assignment",
            Secret,
            r#"(?i)(?-u:\b)[\w.-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']?[^\s"',;]{6,}"#,
            not_placeholder,
        ),
        p(
            "email",
            Personal,
            r"(?-u:\b)[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?-u:\b)",
            always,
        ),
        // International (`+44 20 7946 0958`) or with a bracketed area code (`(555) 123-4567`).
        p(
            "phone",
            Personal,
            r"(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)|\d{1,4})|\(\d{2,4}\))[ .-]?\d{3,4}[ .-]?\d{3,4}(?-u:\b)",
            always,
        ),
        p("iban", Personal, r"(?-u:\b)[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?(?-u:\b)", iban_valid),
        p("payment_card", Personal, r"(?-u:\b)(?:\d[ -]?){12,18}\d(?-u:\b)", luhn_valid),
    ]
});

/// All patterns at once: one pass tells which kinds occur at all, so the
/// individual patterns only run where they can match.
static SET: LazyLock<RegexSet> =
    LazyLock::new(|| RegexSet::new(PATTERNS.iter().map(|p| p.re.as_str())).expect("valid"));

/// The `user@` of a URL.
static USERINFO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://[^/\s@]+@").expect("valid"));

fn not_placeholder(m: &str) -> bool {
    let value = m.rsplit(['=', ':']).next().unwrap_or("").trim_matches(|c: char| c == '"' || c == '\'' || c == ' ');
    let lower = value.to_ascii_lowercase();
    !(lower.starts_with("${")
        || lower.starts_with('<')
        || lower.starts_with("{{")
        || lower.starts_with('$')
        || lower.starts_with("%(")
        || ["changeme", "xxxxxx", "password", "secret", "example", "redacted", "******"]
            .iter()
            .any(|p| lower.contains(p)))
}

fn luhn_valid(m: &str) -> bool {
    let digits: Vec<u32> = m.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) || digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

fn iban_valid(m: &str) -> bool {
    let s: String = m.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&s.len()) {
        return false;
    }
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut rem: u32 = 0;
    for c in rearranged.chars() {
        let Some(v) = c.to_digit(36) else { return false };
        for d in v.to_string().chars() {
            rem = (rem * 10 + d.to_digit(10).unwrap_or(0)) % 97;
        }
    }
    rem == 1
}

/// Counts per kind, split by category.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counts {
    /// Secrets by kind.
    pub secrets: BTreeMap<String, u64>,
    /// Personal data by kind.
    pub personal: BTreeMap<String, u64>,
}

impl Counts {
    /// Add the matches found in `text`.
    pub fn scan(&mut self, text: &str) {
        let count = |text: &str, category: Category, map: &mut BTreeMap<String, u64>| {
            let hits = SET.matches(text);
            for (_, p) in PATTERNS.iter().enumerate().filter(|(i, p)| p.category == category && hits.matched(*i)) {
                let n = p.re.find_iter(text).filter(|m| (p.check)(m.as_str())).count() as u64;
                if n > 0 {
                    *map.entry(p.kind.to_string()).or_default() += n;
                }
            }
        };
        count(text, Category::Secret, &mut self.secrets);
        // Personal data is looked for after secrets and URL user names are
        // blanked out, so `user:pass@host` and `postgres://app@db` are not
        // also counted as e-mail addresses.
        let cleaned = redact(text, Category::Secret);
        let cleaned = if cleaned.contains("://") {
            USERINFO.replace_all(&cleaned, "$scheme://")
        } else {
            Cow::Borrowed(&*cleaned)
        };
        count(&cleaned, Category::Personal, &mut self.personal);
    }
}

/// How far past a `BEGIN … PRIVATE KEY` line the matching `END` line is
/// looked for. Real keys are a few KiB.
const PEM_SPAN: usize = 64 * 1024;

/// Whether any secret pattern occurs in `text` (a cheap pre-check).
pub fn has_secret(text: &str) -> bool {
    SET.matches(text).iter().any(|i| PATTERNS[i].category == Category::Secret)
}

/// Replace matches of the given category with `[redacted:<kind>]`. A
/// private key is redacted from its `BEGIN` line through its `END` line.
pub fn redact(text: &str, category: Category) -> Cow<'_, str> {
    let hits = SET.matches(text);
    let mut out = Cow::Borrowed(text);
    for (_, p) in PATTERNS.iter().enumerate().filter(|(i, p)| p.category == category && hits.matched(*i)) {
        if p.kind == "private_key" {
            if let Some(r) = redact_pem(&out, &p.re) {
                out = Cow::Owned(r);
            }
            continue;
        }
        let replaced = p.re.replace_all(&out, |caps: &regex::Captures<'_>| {
            let m = &caps[0];
            if (p.check)(m) { format!("[redacted:{}]", p.kind) } else { m.to_string() }
        });
        if let Cow::Owned(s) = replaced {
            out = Cow::Owned(s);
        }
    }
    out
}

/// Replace each private-key block, from the `BEGIN` line matched by `begin`
/// to the end of its `END … -----` line, with `[redacted:private_key]`.
/// Without an `END` line (the text was cut), the base64 and header lines
/// that follow are redacted.
fn redact_pem(text: &str, begin: &Regex) -> Option<String> {
    let mut out = String::new();
    let mut last = 0;
    for m in begin.find_iter(text) {
        if m.start() < last {
            continue;
        }
        out.push_str(&text[last..m.start()]);
        out.push_str("[redacted:private_key]");
        last = pem_end(text, m.end());
    }
    (last > 0).then(|| {
        out.push_str(&text[last..]);
        out
    })
}

/// Where the key block whose `BEGIN` line ends at `from` ends.
fn pem_end(text: &str, from: usize) -> usize {
    let mut limit = (from + PEM_SPAN).min(text.len());
    while !text.is_char_boundary(limit) {
        limit -= 1;
    }
    let window = &text[from..limit];
    if let Some(i) = window.find("-----END ")
        && let Some(j) = window[i + 9..].find("-----")
    {
        return from + i + 9 + j + 5;
    }
    // No END line: take the lines that look like key material.
    let mut end = from;
    for line in window.split_inclusive('\n') {
        let t = line.trim();
        let material = t.is_empty()
            || t.starts_with("Proc-Type:")
            || t.starts_with("DEK-Info:")
            || t.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b));
        if !material {
            break;
        }
        end += line.len();
    }
    end
}

/// Whether a configuration key name suggests its value is a secret
/// (`password`, `api_key`, `DB_TOKEN`, `client-secret`, …).
pub fn is_secret_key(key: &str) -> bool {
    const NEEDLES: [&str; 13] = [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "credential",
        "auth_key",
        "authorization",
        "cookie",
    ];
    let k = key.to_ascii_lowercase().replace(['-', '.', ' '], "_");
    NEEDLES.iter().any(|n| k.contains(n)) || k == "pwd" || k.ends_with("_pwd") || k.ends_with("_pass")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "compiles the secret patterns: over 5 min under Miri")]
    fn counts_and_redacts() {
        let text = "key AKIAABCDEFGHIJKLMNOP and mail bob@example.com or alice@example.org; \
                    card 4111 1111 1111 1111, not 1234 5678 9012 3456; \
                    db postgres://admin:hunter2@db.internal/app password=changeme token: s3cr3tValue1";
        let mut c = Counts::default();
        c.scan(text);
        assert_eq!(c.secrets.get("aws_access_key_id"), Some(&1));
        assert_eq!(c.secrets.get("url_credentials"), Some(&1));
        assert_eq!(c.secrets.get("credential_assignment"), Some(&1), "{:?}", c.secrets);
        assert_eq!(c.personal.get("email"), Some(&2));
        assert_eq!(c.personal.get("payment_card"), Some(&1));
        let r = redact(text, Category::Secret);
        assert!(r.contains("[redacted:aws_access_key_id]"));
        assert!(!r.contains("hunter2"));
        assert!(r.contains("bob@example.com"));
        assert!(matches!(redact("nothing here", Category::Secret), Cow::Borrowed(_)));
    }

    #[test]
    #[cfg_attr(miri, ignore = "compiles the secret patterns: over 5 min under Miri")]
    fn private_key_bodies_are_redacted() {
        let body = "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu";
        let pem =
            format!("before\n-----BEGIN RSA PRIVATE KEY-----\n{body}\n{body}\n-----END RSA PRIVATE KEY-----\nafter");
        let r = redact(&pem, Category::Secret);
        assert_eq!(r, "before\n[redacted:private_key]\nafter");
        // Cut before the END line: the key lines still go.
        let cut = format!("-----BEGIN PRIVATE KEY-----\n{body}\n{body}\nplain words here");
        let r = redact(&cut, Category::Secret);
        assert!(!r.contains(body), "{r}");
        assert!(r.ends_with("plain words here"), "{r}");
        assert!(has_secret(&pem) && !has_secret("nothing"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "compiles the secret patterns: over 5 min under Miri")]
    fn checks() {
        assert!(iban_valid("GB82 WEST 1234 5698 7654 32"));
        assert!(!iban_valid("GB82 WEST 1234 5698 7654 33"));
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("0000000000000000"));
        assert!(is_secret_key("DB_PASSWORD"));
        assert!(is_secret_key("client-secret"));
        assert!(is_secret_key("GITHUB_TOKEN"));
        assert!(!is_secret_key("name"));
        assert!(!is_secret_key("port"));
        assert!(!is_secret_key("author"));
        let mut c = Counts::default();
        c.scan("call +44 20 7946 0958 or (555) 123-4567, not 2026-10-16 or 4111 1111 1111");
        assert_eq!(c.personal.get("phone"), Some(&2), "{:?}", c.personal);
        let mut c = Counts::default();
        c.scan("url = \"postgres://app@db.internal/harbour\"");
        assert!(c.personal.is_empty(), "{:?}", c.personal);
    }
}
