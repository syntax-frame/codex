use codex_context_engine::AttachmentKind;
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CodexAdapterError {
    #[error("unsupported message role {role}")]
    UnsupportedRole { role: String },
    #[error("could not resolve {kind:?} content to an application-owned attachment")]
    UnresolvedAttachment { kind: AttachmentKind },
    #[error("resolved attachment {field} must not be empty")]
    EmptyAttachmentField { field: &'static str },
    #[error("{kind} requires a call id or response item id")]
    MissingCallId { kind: &'static str },
    #[error("raw JSON does not decode to the supplied response item")]
    RawPayloadMismatch,
    #[error("raw JSON is required to preserve {kind} without loss")]
    RawPayloadRequired { kind: &'static str },
    #[error("could not {operation} provider JSON: {message}")]
    ProviderJson {
        operation: &'static str,
        message: String,
    },
    #[error("a compaction event must have a positive sequence")]
    InvalidCompactionSequence,
}
