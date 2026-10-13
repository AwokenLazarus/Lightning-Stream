use thiserror::Error;

/// A state, funding or request the protocol refuses. `code` is the wire error code (the 402
/// `error` field, or a control endpoint's `{"error": code}`).
///
/// On the paying side `code` and `msg` are this side's own words, and what the other side wrote is
/// kept apart in `seller`: a payer that shows an error to an agent shows `seller` only as untrusted
/// text. `Display` never prints it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{}", if .msg.is_empty() { .code.clone() } else { format!("{}: {}", .code, .msg) })]
pub struct ChannelError {
    pub code: String,
    pub msg: String,
    /// What the seller answered when it refused, as it wrote it (cut to [`SELLER_TEXT_MAX`]
    /// characters). Untrusted: never part of `code` or `msg`.
    pub seller: Option<String>,
}

/// The most of a seller's refusal an error carries, in characters.
pub const SELLER_TEXT_MAX: usize = 2000;

impl ChannelError {
    pub fn new(code: &str, msg: impl Into<String>) -> Self {
        Self { code: code.to_string(), msg: msg.into(), seller: None }
    }

    pub fn code(code: &str) -> Self {
        Self { code: code.to_string(), msg: String::new(), seller: None }
    }

    /// The same error, carrying what the seller answered (kept out of `code` and `msg`).
    pub fn with_seller(mut self, text: &str) -> Self {
        self.seller = Some(text.chars().take(SELLER_TEXT_MAX).collect());
        self
    }
}

impl From<xbt_primitives::Error> for ChannelError {
    fn from(e: xbt_primitives::Error) -> Self {
        ChannelError::new("bad_request", e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ChannelError>;

/// `ChannelError::new(code, msg)` as an `Err`.
pub(crate) fn fail<T>(code: &str, msg: impl Into<String>) -> Result<T> {
    Err(ChannelError::new(code, msg))
}
