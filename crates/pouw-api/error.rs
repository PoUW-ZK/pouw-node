//! The error body of every endpoint and the HTTP status of each class of error.

use serde::{Deserialize, Serialize};

/// `{"error": {...}}`, the body of every non-2xx answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

/// Contents of [`ErrorBody`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// Lowercase `snake_case`, see [`code`] and the reason codes of node-events.md.
    pub code: String,
    /// For people, at most 1024 characters.
    pub message: String,
    /// Machine-readable extras of some codes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<ErrorDetails>,
}

/// Extras of an [`ErrorDetail`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetails {
    /// With [`code::CURSOR_EXPIRED`]: the oldest retained event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_seq: Option<u64>,
}

impl ErrorBody {
    /// A body with no details.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }
}

/// Error codes the API layer itself produces. Rule violations carry the reason code
/// of the rejected transaction or block instead.
pub mod code {
    /// The request does not decode (bad id, borsh, JSON or parameter).
    pub const MALFORMED: &str = "malformed";
    /// No such transaction, block, circuit or account.
    pub const NOT_FOUND: &str = "not_found";
    /// A block or header range over its cap.
    pub const RANGE_TOO_LARGE: &str = "range_too_large";
    /// The event cursor is older than the retained log.
    pub const CURSOR_EXPIRED: &str = "cursor_expired";
    /// The node loop has no room for the request; retry later.
    pub const BUSY: &str = "busy";
}

/// Class of an error, which fixes its HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// 400, the request does not decode.
    Malformed,
    /// 404, an unknown id.
    NotFound,
    /// 410, an expired event cursor.
    Gone,
    /// 422, rejected by the rules.
    Rejected,
    /// 503, the node loop's request queue is full.
    Busy,
}

impl ErrorClass {
    /// HTTP status code.
    pub fn status(self) -> u16 {
        match self {
            ErrorClass::Malformed => 400,
            ErrorClass::NotFound => 404,
            ErrorClass::Gone => 410,
            ErrorClass::Rejected => 422,
            ErrorClass::Busy => 503,
        }
    }
}
