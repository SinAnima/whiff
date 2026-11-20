use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::plugin::Cost;

/// How much work to do per file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Profile {
    /// Stat, detection, and header-cost extractors. No hashing, no text
    /// analysis, no embedded files.
    Minimal,
    /// All metadata extractors, hashes, bounded text analysis.
    #[default]
    Standard,
    /// Everything, including payload decoding and deeper recursion.
    Full,
    /// `standard` plus a summary. The library still returns the full
    /// [`Report`](crate::Report); the CLI prints its compact LLM view
    /// ([`Report::llm_view`](crate::Report::llm_view)) instead.
    Llm,
}

impl Profile {
    /// Most expensive extractor cost this profile runs.
    pub fn max_cost(self) -> Cost {
        match self {
            Self::Minimal => Cost::Header,
            Self::Standard | Self::Llm => Cost::Scan,
            Self::Full => Cost::Decode,
        }
    }

    /// Default limits for this profile (`llm` has `standard`'s):
    ///
    /// | [`Limits`] field | `minimal` | `standard`, `llm` | `full` |
    /// |---|---|---|---|
    /// | `max_read_bytes` | 256 KiB | 256 MiB | 4 GiB |
    /// | `max_decompressed_bytes` | 1 MiB | 256 MiB | 1 GiB |
    /// | `max_depth` | 0 | 1 | 3 |
    /// | `max_children` | 0 | 50 | 200 |
    /// | `file_timeout` | 2 s | 30 s | 120 s |
    /// | `extractor_timeout` | 1 s | 5 s | 30 s |
    /// | `max_text_bytes` | 0 | 1 MiB | 16 MiB |
    /// | `hash_max_bytes` | 0 (no hashing) | 2 GiB | 16 GiB |
    /// | `max_parse_bytes` | 256 KiB | 16 MiB | 256 MiB |
    ///
    /// ```
    /// use whiff::Profile;
    ///
    /// let limits = Profile::Full.limits();
    /// assert_eq!(limits.max_depth, 3);
    /// assert_eq!(limits.file_timeout, Some(std::time::Duration::from_secs(120)));
    /// ```
    pub fn limits(self) -> Limits {
        const KIB: u64 = 1024;
        const MIB: u64 = 1024 * KIB;
        const GIB: u64 = 1024 * MIB;
        const MIB_USIZE: usize = 1024 * 1024;
        match self {
            Self::Minimal => Limits {
                max_read_bytes: 256 * KIB,
                max_decompressed_bytes: MIB,
                max_depth: 0,
                max_children: 0,
                file_timeout: Some(Duration::from_secs(2)),
                extractor_timeout: Some(Duration::from_secs(1)),
                max_text_bytes: 0,
                hash_max_bytes: 0,
                max_parse_bytes: 256 * KIB,
                slow_sniff: Some(SLOW_SNIFF),
            },
            Self::Standard | Self::Llm => Limits {
                max_read_bytes: 256 * MIB,
                max_decompressed_bytes: 256 * MIB,
                max_depth: 1,
                max_children: 50,
                file_timeout: Some(Duration::from_secs(30)),
                extractor_timeout: Some(Duration::from_secs(5)),
                max_text_bytes: MIB_USIZE,
                hash_max_bytes: 2 * GIB,
                max_parse_bytes: 16 * MIB,
                slow_sniff: Some(SLOW_SNIFF),
            },
            Self::Full => Limits {
                max_read_bytes: 4 * GIB,
                max_decompressed_bytes: GIB,
                max_depth: 3,
                max_children: 200,
                file_timeout: Some(Duration::from_secs(120)),
                extractor_timeout: Some(Duration::from_secs(30)),
                max_text_bytes: 16 * MIB_USIZE,
                hash_max_bytes: 16 * GIB,
                max_parse_bytes: 256 * MIB,
                slow_sniff: Some(SLOW_SNIFF),
            },
        }
    }
}

impl std::str::FromStr for Profile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "minimal" => Ok(Self::Minimal),
            "standard" => Ok(Self::Standard),
            "full" => Ok(Self::Full),
            "llm" => Ok(Self::Llm),
            other => Err(format!("unknown profile `{other}` (expected minimal, standard, full or llm)")),
        }
    }
}

/// A sniffer slower than this is skipped for the rest of the input (its
/// embedded files included). Sniffers see only the head and tail windows,
/// so a well-behaved one takes microseconds.
pub(crate) const SLOW_SNIFF: Duration = Duration::from_millis(50);

/// Resource limits for one root input and everything embedded in it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Bytes extractors may read in total.
    pub max_read_bytes: u64,
    /// Bytes decompression may produce in total (zip-bomb guard).
    pub max_decompressed_bytes: u64,
    /// Recursion depth for embedded children (0 = no recursion).
    pub max_depth: u32,
    /// Children analysed per container.
    pub max_children: u32,
    /// Deadline for the whole file.
    pub file_timeout: Option<Duration>,
    /// Deadline per extractor / decoder / analyzer.
    pub extractor_timeout: Option<Duration>,
    /// Text kept for the text analyzers.
    pub max_text_bytes: usize,
    /// Files larger than this are not hashed (0 = never hash).
    pub hash_max_bytes: u64,
    /// Bytes a structured parser (JSON, YAML, HTML, SQL, …) loads into memory;
    /// larger inputs are parsed in part or only scanned.
    pub max_parse_bytes: u64,
    /// A sniffer slower than this is skipped for the rest of the input
    /// (`None` = never). Wall-clock time, so the crate's own snapshot tests
    /// turn it off: a loaded machine would otherwise change their reports.
    pub(crate) slow_sniff: Option<Duration>,
}

impl Default for Limits {
    fn default() -> Self {
        Profile::Standard.limits()
    }
}

impl Limits {
    /// The same limits with the slow-sniffer check off, for snapshot tests.
    #[must_use]
    pub(crate) fn without_slow_sniff(mut self) -> Self {
        self.slow_sniff = None;
        self
    }
    /// Set [`Limits::max_depth`].
    #[must_use]
    pub fn max_depth(mut self, n: u32) -> Self {
        self.max_depth = n;
        self
    }
    /// Set [`Limits::max_read_bytes`].
    #[must_use]
    pub fn max_read_bytes(mut self, n: u64) -> Self {
        self.max_read_bytes = n;
        self
    }
    /// Set [`Limits::file_timeout`].
    #[must_use]
    pub fn file_timeout(mut self, t: Option<Duration>) -> Self {
        self.file_timeout = t;
        self
    }
    /// Set [`Limits::extractor_timeout`].
    #[must_use]
    pub fn extractor_timeout(mut self, t: Option<Duration>) -> Self {
        self.extractor_timeout = t;
        self
    }
    /// Set [`Limits::max_decompressed_bytes`].
    #[must_use]
    pub fn max_decompressed_bytes(mut self, n: u64) -> Self {
        self.max_decompressed_bytes = n;
        self
    }
    /// Set [`Limits::max_children`].
    #[must_use]
    pub fn max_children(mut self, n: u32) -> Self {
        self.max_children = n;
        self
    }
    /// Set [`Limits::max_text_bytes`].
    #[must_use]
    pub fn max_text_bytes(mut self, n: usize) -> Self {
        self.max_text_bytes = n;
        self
    }
    /// Set [`Limits::hash_max_bytes`].
    #[must_use]
    pub fn hash_max_bytes(mut self, n: u64) -> Self {
        self.hash_max_bytes = n;
        self
    }
    /// Set [`Limits::max_parse_bytes`].
    #[must_use]
    pub fn max_parse_bytes(mut self, n: u64) -> Self {
        self.max_parse_bytes = n;
        self
    }
}

/// Which hashes to compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Hashes {
    /// SHA-256.
    pub sha256: bool,
    /// BLAKE3.
    pub blake3: bool,
}

impl Default for Hashes {
    fn default() -> Self {
        Self { sha256: true, blake3: true }
    }
}

impl Hashes {
    /// No hashing.
    pub const NONE: Self = Self { sha256: false, blake3: false };

    /// Whether any hash is enabled.
    pub fn any(self) -> bool {
        self.sha256 || self.blake3
    }
}

/// How personal data found in a file is reported. Secrets are a separate
/// switch, [`Redaction`]; personal data is counted in
/// `security.personal_data` under either mode.
///
/// | | [`Redaction::On`] (default) | [`Redaction::Off`] |
/// |---|---|---|
/// | **[`Privacy::Strict`]** (default) | personal data masked, secrets redacted | personal data masked, secrets as found |
/// | **[`Privacy::Off`]** | personal data as found, secrets redacted | everything as found |
///
/// ```
/// use whiff::{Engine, Privacy};
///
/// let text: &[u8] = b"Write to the harbour master at berths@example.org.";
/// let strict = Engine::new().extract_bytes(Some("note.txt"), text);
/// assert!(!strict.content.excerpt.unwrap().contains("berths@example.org"));
/// assert_eq!(strict.security.personal_data["email"], 1);
///
/// let off = Engine::builder().privacy(Privacy::Off).build().extract_bytes(Some("note.txt"), text);
/// assert!(off.content.excerpt.unwrap().contains("berths@example.org"));
/// assert_eq!(off.security.personal_data["email"], 1);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Privacy {
    /// Personal data is counted, and masked where it is listed: e-mail
    /// addresses in message headers, contacts and calendars keep only their
    /// domain; phone numbers, account numbers, birthdays and infrastructure
    /// values (host names, IP addresses, directory values) are counted or
    /// hidden; profile folders in paths lose the user name; e-mail
    /// addresses, phone numbers, card numbers and IBANs are replaced with
    /// `[redacted:<kind>]` in the excerpt, summary, keywords and tags.
    /// People's names (authors, senders, contacts) are kept.
    #[default]
    Strict,
    /// Full details: addresses and phone numbers as found, whole account
    /// numbers and transactions, people's names in genealogies and
    /// directories, infrastructure values, and personal data in the
    /// excerpt, summary, keywords and tags. Secrets follow [`Redaction`].
    Off,
}

impl std::str::FromStr for Privacy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "strict" => Ok(Self::Strict),
            "off" => Ok(Self::Off),
            other => Err(format!("unknown privacy mode `{other}` (expected strict or off)")),
        }
    }
}

/// Whether secrets (private keys, API keys and tokens, passwords, and
/// credentials in URLs) are replaced with `[redacted:<kind>]` in the
/// report. Under either mode they are counted in `security.secrets` and
/// raise the `embedded_secret` risk. See [`Privacy`] for the four
/// combinations.
///
/// ```
/// use whiff::{Engine, Redaction};
///
/// let text: &[u8] = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLF";
/// let on = Engine::new().extract_bytes(Some("config.ini"), text);
/// assert!(!serde_json::to_string(&on)?.contains("AKIAIOSFODNN7EXAMPLF"));
///
/// let off = Engine::builder().redaction(Redaction::Off).build().extract_bytes(Some("config.ini"), text);
/// assert!(serde_json::to_string(&off)?.contains("AKIAIOSFODNN7EXAMPLF"));
/// assert!(off.security.risks.iter().any(|r| r.kind == "embedded_secret"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Redaction {
    /// Secrets are redacted everywhere in the report.
    #[default]
    On,
    /// Secrets are left as found (still counted and flagged).
    Off,
}

impl std::str::FromStr for Redaction {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "on" => Ok(Self::On),
            "off" => Ok(Self::Off),
            other => Err(format!("unknown redaction mode `{other}` (expected on or off)")),
        }
    }
}

/// Everything that controls an extraction.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Options {
    /// Profile.
    pub profile: Profile,
    /// Limits. `Options::default()` has the `standard` profile's; changing
    /// `profile` here does not change them (the builder's
    /// [`profile`](crate::EngineBuilder::profile) does).
    pub limits: Limits,
    /// Hashes to compute.
    pub hashes: Hashes,
    /// Run only extractors whose id or group matches (`image`, `image.jpeg`).
    pub only: Vec<String>,
    /// Never run extractors whose id or group matches.
    pub skip: Vec<String>,
    /// Force this format id instead of detecting.
    pub format: Option<String>,
    /// Record which source set each normalised field.
    pub provenance: bool,
    /// How personal data is reported.
    pub privacy: Privacy,
    /// Whether secrets are redacted.
    pub redaction: Redaction,
}

impl Options {
    /// Whether the extractor/decoder/analyzer `id` may run under `only`/`skip`.
    pub fn allows(&self, id: &str) -> bool {
        let matches = |pat: &String| id == pat || id.strip_prefix(pat.as_str()).is_some_and(|r| r.starts_with('.'));
        (self.only.is_empty() || self.only.iter().any(matches)) && !self.skip.iter().any(matches)
    }
}
