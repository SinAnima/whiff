//! Analyzers over the text extractors emit: language, keywords and tags,
//! summary, excerpt, and the privacy scan that counts and redacts.

use serde_json::Value;

use super::sensitive::{Category, Counts, redact};
use super::words::Lexicon;
use super::{keywords, lang, squash_whitespace, summary, truncate_chars};
use crate::plugin::{Analyzer, AnalyzerStage, ExtractError, Options, Profile, Report, TextStore};
use crate::report::Language as ReportLanguage;

/// Prose shorter than this (in words) gets no keywords or summary.
const MIN_WORDS: usize = 20;
const MAX_KEYWORDS: usize = 15;
const MAX_TAGS: usize = 20;
const EXCERPT_CHARS: usize = 400;

fn record(report: &mut Report, field: &str, source: &str) {
    if let Some(map) = report.diagnostics.provenance.as_mut() {
        map.entry(field.to_string()).or_insert_with(|| Value::String(source.to_string()));
    }
}

fn lexicon(report: &Report) -> Lexicon {
    Lexicon::for_language(report.content.language.as_ref().map(|l| l.code.as_str()))
}

fn enough_words(text: &str) -> bool {
    text.split_whitespace().nth(MIN_WORDS - 1).is_some()
}

/// `content.language` from the prose, unless an extractor declared it.
pub struct DetectLanguage;

impl Analyzer for DetectLanguage {
    fn id(&self) -> &'static str {
        "text.language"
    }

    fn stage(&self) -> AnalyzerStage {
        AnalyzerStage::Language
    }

    fn run(&self, report: &mut Report, text: &TextStore, _: &Options) -> Result<(), ExtractError> {
        if report.content.language.is_some() {
            return Ok(());
        }
        if let Some(d) = lang::detect(&text.prose()) {
            report.content.language = Some(ReportLanguage { code: d.code.to_string(), confidence: d.confidence });
            record(report, "content.language", self.id());
        }
        Ok(())
    }
}

crate::register_analyzer!(DetectLanguage);

/// `content.keywords` (declared first, then YAKE), `content.keyword_frequency`
/// and `content.tags` (declared tags and keywords plus the top extracted ones).
pub struct Keywords;

impl Analyzer for Keywords {
    fn id(&self) -> &'static str {
        "text.keywords"
    }

    fn stage(&self) -> AnalyzerStage {
        AnalyzerStage::Text
    }

    fn run(&self, report: &mut Report, text: &TextStore, _: &Options) -> Result<(), ExtractError> {
        let prose = text.prose();
        let lex = lexicon(report);
        let declared = report.content.keywords.clone();
        let extracted = if enough_words(&prose) { keywords::extract(&prose, &lex, 10) } else { Vec::new() };

        let content = &mut report.content;
        let before = content.keywords.len();
        merge(&mut content.keywords, extracted.iter().cloned(), &lex, MAX_KEYWORDS);
        let added_keywords = content.keywords.len() > before;
        let before = content.tags.len();
        merge(&mut content.tags, declared.into_iter().chain(extracted.into_iter().take(5)), &lex, MAX_TAGS);
        let added_tags = content.tags.len() > before;
        let added_frequency = content.keyword_frequency.is_empty() && enough_words(&prose) && {
            content.keyword_frequency = keywords::frequency(&prose, &lex, 20);
            !content.keyword_frequency.is_empty()
        };
        for (added, field) in [
            (added_keywords, "content.keywords"),
            (added_tags, "content.tags"),
            (added_frequency, "content.keyword_frequency"),
        ] {
            if added {
                record(report, field, self.id());
            }
        }
        Ok(())
    }
}

crate::register_analyzer!(Keywords);

/// Append `items` not already present (compared by stems), up to `cap`.
fn merge(list: &mut Vec<String>, items: impl IntoIterator<Item = String>, lex: &Lexicon, cap: usize) {
    let key = |s: &str| s.to_lowercase().split_whitespace().map(|w| lex.stem(w).into_owned()).collect::<Vec<_>>();
    let mut keys: Vec<Vec<String>> = list.iter().map(|s| key(s)).collect();
    for item in items {
        if list.len() >= cap {
            break;
        }
        let k = key(&item);
        if !k.is_empty() && !keys.contains(&k) {
            keys.push(k);
            list.push(item);
        }
    }
}

/// `content.summary` by `TextRank` (`full` and `llm` profiles).
pub struct Summary;

impl Analyzer for Summary {
    fn id(&self) -> &'static str {
        "text.summary"
    }

    fn stage(&self) -> AnalyzerStage {
        AnalyzerStage::Text
    }

    fn run(&self, report: &mut Report, text: &TextStore, options: &Options) -> Result<(), ExtractError> {
        if !matches!(options.profile, Profile::Full | Profile::Llm) || report.content.summary.is_some() {
            return Ok(());
        }
        let prose = text.prose();
        if !enough_words(&prose) {
            return Ok(());
        }
        let sentences = if prose.len() > 64 * 1024 { 5 } else { 3 };
        if let Some(s) = summary::summarize(&prose, &lexicon(report), sentences) {
            report.content.summary = Some(s);
            record(report, "content.summary", self.id());
        }
        Ok(())
    }
}

crate::register_analyzer!(Summary);

/// `content.excerpt`: the start of the body text.
pub struct Excerpt;

impl Analyzer for Excerpt {
    fn id(&self) -> &'static str {
        "text.excerpt"
    }

    fn stage(&self) -> AnalyzerStage {
        AnalyzerStage::Text
    }

    fn run(&self, report: &mut Report, text: &TextStore, _: &Options) -> Result<(), ExtractError> {
        if report.content.excerpt.is_some() {
            return Ok(());
        }
        let mut body = text.body();
        if body.trim().is_empty() {
            body = text.prose();
        }
        let squashed = squash_whitespace(&truncate_chars(&body, EXCERPT_CHARS * 4));
        if !squashed.is_empty() {
            report.content.excerpt = Some(truncate_chars(&squashed, EXCERPT_CHARS));
            record(report, "content.excerpt", self.id());
        }
        Ok(())
    }
}

crate::register_analyzer!(Excerpt);

/// Counts secrets and personal data in all emitted text, flags secrets as a
/// risk, and redacts them from every string in the report. Personal data is
/// also redacted from derived text (excerpt, summary, keywords, tags).
pub struct Privacy;

impl Analyzer for Privacy {
    fn id(&self) -> &'static str {
        "privacy.scan"
    }

    fn stage(&self) -> AnalyzerStage {
        AnalyzerStage::Privacy
    }

    fn run(&self, report: &mut Report, text: &TextStore, _: &Options) -> Result<(), ExtractError> {
        let mut counts = Counts::default();
        for chunk in text.chunks() {
            counts.scan(&chunk.text);
        }
        let sec = &mut report.security;
        for (k, v) in counts.secrets {
            *sec.secrets.entry(k).or_default() += v;
        }
        for (k, v) in counts.personal {
            *sec.personal_data.entry(k).or_default() += v;
        }
        if !sec.secrets.is_empty() && !sec.risks.iter().any(|r| r.kind == "embedded_secret") {
            let kinds: Vec<&str> = sec.secrets.keys().map(String::as_str).collect();
            sec.risks.push(crate::report::Risk::new("embedded_secret", Some(kinds.join(", ")), self.id()));
        }

        redact_value_tree(&mut report.metadata);
        redact_value_tree(&mut report.format);
        let c = &mut report.content;
        for s in [&mut c.title, &mut c.description].into_iter().flatten() {
            redact_in_place(s, Category::Secret);
        }
        for h in &mut c.outline {
            redact_in_place(&mut h.text, Category::Secret);
        }
        for s in [&mut c.summary, &mut c.excerpt].into_iter().flatten() {
            redact_in_place(s, Category::Secret);
            redact_in_place(s, Category::Personal);
        }
        for s in c.keywords.iter_mut().chain(c.tags.iter_mut()).chain(c.keyword_frequency.iter_mut().map(|(w, _)| w)) {
            redact_in_place(s, Category::Secret);
            redact_in_place(s, Category::Personal);
        }
        Ok(())
    }
}

crate::register_analyzer!(Privacy);

fn redact_in_place(s: &mut String, category: Category) {
    if let std::borrow::Cow::Owned(r) = redact(s, category) {
        *s = r;
    }
}

/// Redact secrets in every string of a JSON tree, without recursion.
fn redact_value_tree(map: &mut crate::report::Map) {
    let mut stack: Vec<&mut Value> = map.values_mut().collect();
    while let Some(v) = stack.pop() {
        match v {
            Value::String(s) => redact_in_place(s, Category::Secret),
            Value::Array(a) => stack.extend(a.iter_mut()),
            Value::Object(o) => stack.extend(o.values_mut()),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::TextRole;

    fn store(parts: &[(TextRole, &str)]) -> TextStore {
        let mut t = TextStore::with_limit(1 << 20);
        for (role, text) in parts {
            t.push(*role, text);
        }
        t
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds the secret and language tables: over 5 min under Miri")]
    fn analyzers_fill_content() {
        let body = "Fishing boats return to the harbour at dusk. The harbour master counts the boats. \
            Fishing boats unload their catch while gulls circle above the harbour. \
            In the morning the fishing fleet leaves again, and the harbour is quiet. \
            Tourists photograph the boats; the harbour cafe serves fish soup. Write to harbour@example.com.";
        let text = store(&[(TextRole::Title, "Harbour life"), (TextRole::Body, body)]);
        let mut r = Report::default();
        r.content.keywords.push("seascape".into());
        let options = Options { profile: Profile::Full, ..Options::default() };
        for a in [&DetectLanguage as &dyn Analyzer, &Keywords, &Summary, &Excerpt, &Privacy] {
            a.run(&mut r, &text, &options).unwrap();
        }
        assert_eq!(r.content.language.as_ref().map(|l| l.code.as_str()), Some("en"));
        assert_eq!(r.content.keywords[0], "seascape");
        assert!(r.content.keywords.len() > 3);
        assert!(r.content.tags.contains(&"seascape".to_string()));
        assert_eq!(r.content.keyword_frequency[0].0, "harbour");
        assert!(r.content.summary.is_some());
        let excerpt = r.content.excerpt.as_deref().unwrap();
        assert!(excerpt.starts_with("Fishing boats"));
        assert_eq!(r.security.personal_data.get("email"), Some(&1));
        assert!(!format!("{:?}", r.content).contains("harbour@example.com"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "compiles the secret patterns: 4 min under Miri")]
    fn secrets_are_flagged_and_redacted() {
        let text = store(&[(TextRole::Data, "AWS_KEY=AKIAABCDEFGHIJKLMNOP")]);
        let mut r = Report::default();
        r.format.insert("env".into(), serde_json::json!({ "values": ["AKIAABCDEFGHIJKLMNOP"] }));
        Privacy.run(&mut r, &text, &Options::default()).unwrap();
        assert_eq!(r.security.secrets.get("aws_access_key_id"), Some(&1));
        assert_eq!(r.security.risks[0].kind, "embedded_secret");
        assert_eq!(r.format["env"]["values"][0], "[redacted:aws_access_key_id]");
    }

    #[test]
    fn summary_only_in_full_and_llm() {
        let long = "Rust programs are fast and memory safe. ".repeat(10);
        let text = store(&[(TextRole::Body, &long)]);
        let mut r = Report::default();
        Summary.run(&mut r, &text, &Options::default()).unwrap();
        assert!(r.content.summary.is_none());
    }
}
