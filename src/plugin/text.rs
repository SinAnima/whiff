/// What a piece of emitted text is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TextRole {
    /// Running body text.
    Body,
    /// The document title.
    Title,
    /// A heading of the given level (1 = top).
    Heading(u8),
    /// Caption or alt text.
    Caption,
    /// Comment / annotation.
    Comment,
    /// Text found in metadata fields.
    Metadata,
    /// Source code.
    Code,
    /// Raw structured data (configuration values, CSV cells, log lines):
    /// scanned for secrets and personal data, but not treated as prose.
    Data,
}

impl TextRole {
    /// Whether the language, keyword and summary analyzers read this role.
    pub fn is_prose(self) -> bool {
        matches!(self, Self::Body | Self::Title | Self::Heading(_) | Self::Caption)
    }
}

/// One emitted piece of text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TextChunk {
    /// Role.
    pub role: TextRole,
    /// Text.
    pub text: String,
}

/// Text collected from extractors for the text analyzers, capped in size.
#[derive(Debug, Clone, Default)]
pub struct TextStore {
    chunks: Vec<TextChunk>,
    bytes: usize,
    limit: usize,
    truncated: bool,
}

impl TextStore {
    /// A store accepting at most `limit` bytes.
    pub fn with_limit(limit: usize) -> Self {
        Self { limit, ..Self::default() }
    }

    /// Add text; anything beyond the limit is dropped (cut on a char boundary).
    /// A title, caption or comment identical to one already stored is skipped:
    /// the same field often arrives from several metadata blocks.
    pub fn push(&mut self, role: TextRole, text: &str) {
        if matches!(role, TextRole::Title | TextRole::Caption | TextRole::Comment)
            && self.chunks.iter().any(|c| c.role == role && c.text == text)
        {
            return;
        }
        let room = self.limit.saturating_sub(self.bytes);
        if room == 0 {
            if !text.is_empty() {
                self.truncated = true;
            }
            return;
        }
        let mut end = text.len().min(room);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        if end < text.len() {
            self.truncated = true;
        }
        if end > 0 {
            self.bytes += end;
            self.chunks.push(TextChunk { role, text: text[..end].to_string() });
        }
    }

    /// All chunks in emission order.
    pub fn chunks(&self) -> &[TextChunk] {
        &self.chunks
    }

    /// Chunks with the given role.
    pub fn by_role(&self, role: TextRole) -> impl Iterator<Item = &str> {
        self.chunks.iter().filter(move |c| c.role == role).map(|c| c.text.as_str())
    }

    /// Prose chunks (see [`TextRole::is_prose`]) joined by blank lines.
    pub fn prose(&self) -> String {
        let mut out = String::new();
        for c in self.chunks.iter().filter(|c| c.role.is_prose()) {
            if !out.is_empty() {
                out.push_str("\n\n");
            }
            out.push_str(&c.text);
        }
        out
    }

    /// Body chunks only, joined by blank lines.
    pub fn body(&self) -> String {
        self.by_role(TextRole::Body).collect::<Vec<_>>().join("\n\n")
    }

    /// Total bytes stored.
    pub fn len(&self) -> usize {
        self.bytes
    }

    /// Whether nothing was stored.
    pub fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    /// Whether text was dropped because of the limit.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}
