use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::plugin::Cost;

/// How much work to do per file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Stat, detection, headers only. No hashing, no text analysis.
    Minimal,
    /// All metadata extractors, hashes, bounded text analysis.
    #[default]
    Standard,
    /// Everything, including payload decoding and deeper recursion.
    Full,
    /// `standard` plus a summary; the CLI prints the compact LLM view
    /// ([`Report::llm_view`](crate::Report::llm_view)) instead of the report.
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

    /// Default limits for this profile.
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

/// Resource limits for one root input and everything embedded in it.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl Default for Limits {
    fn default() -> Self {
        Profile::Standard.limits()
    }
}

impl Limits {
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
}

/// Which hashes to compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// How personal data found in a file is reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Privacy {
    /// Personal data is counted, not listed: e-mail addresses in message
    /// headers, contacts and calendars are reduced to their domain, phone
    /// numbers and birthdays are counted. Names are kept.
    #[default]
    Strict,
    /// Full details: addresses and phone numbers as found, whole account
    /// numbers and transactions, people's names in genealogies and
    /// directories, infrastructure values. Secrets are redacted either way.
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

/// Everything that controls an extraction.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Profile.
    pub profile: Profile,
    /// Limits (defaults come from the profile).
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
}

impl Options {
    /// Whether the extractor/decoder/analyzer `id` may run under `only`/`skip`.
    pub fn allows(&self, id: &str) -> bool {
        let matches = |pat: &String| id == pat || id.strip_prefix(pat.as_str()).is_some_and(|r| r.starts_with('.'));
        (self.only.is_empty() || self.only.iter().any(matches)) && !self.skip.iter().any(matches)
    }
}
