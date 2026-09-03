use codex_context_engine::AttachmentKind;
use codex_context_engine::ProviderLineage;
use codex_context_engine::ToolPhase;
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CodexAdapterError {
    #[error("unsupported message role {role}")]
    UnsupportedRole { role: String },
    #[error("could not resolve {kind:?} content to an application-owned attachment")]
    UnresolvedAttachment { kind: AttachmentKind },
    #[error("resolved attachment {field} must not be empty")]
    EmptyAttachmentField { field: &'static str },
    #[error("no attachment materializer is configured for {kind:?} content")]
    MissingAttachmentMaterializer { kind: AttachmentKind },
    #[error("could not materialize application-owned attachment {attachment_id}")]
    UnmaterializedAttachment { attachment_id: String },
    #[error("materialized attachment source must not be empty")]
    EmptyMaterializedAttachment,
    #[error("Codex does not support portable {kind:?} attachments in message content")]
    UnsupportedAttachment { kind: AttachmentKind },
    #[error("{kind} requires a call id or response item id")]
    MissingCallId { kind: &'static str },
    #[error("routed message {item_id} has no recipient")]
    MissingRouteRecipient { item_id: String },
    #[error("routed message {item_id} contains non-text content")]
    UnsupportedRoutedContent { item_id: String },
    #[error("tool record {call_id} ({name}, {phase:?}) is not representable by Codex")]
    UnsupportedToolRecord {
        call_id: String,
        name: String,
        phase: ToolPhase,
    },
    #[error("tool record {call_id} has invalid {field}: {message}")]
    InvalidToolData {
        call_id: String,
        field: &'static str,
        message: String,
    },
    #[error("opaque item {item_id} belongs to an incompatible provider lineage")]
    IncompatibleLineage {
        item_id: String,
        expected: ProviderLineage,
        actual: ProviderLineage,
    },
    #[error("opaque item {item_id} says it is {declared_kind}, but contains {actual_kind}")]
    OpaqueKindMismatch {
        item_id: String,
        declared_kind: String,
        actual_kind: String,
    },
    #[error("opaque item {item_id} requires the raw Codex request transport")]
    RawTransportRequired { item_id: String },
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

impl CodexAdapterError {
    pub(crate) fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::UnsupportedRole { .. } => "unsupported_role",
            Self::UnresolvedAttachment { .. } => "unresolved_attachment",
            Self::EmptyAttachmentField { .. } => "empty_attachment_field",
            Self::MissingAttachmentMaterializer { .. } => "missing_attachment_materializer",
            Self::UnmaterializedAttachment { .. } => "unmaterialized_attachment",
            Self::EmptyMaterializedAttachment => "empty_materialized_attachment",
            Self::UnsupportedAttachment { .. } => "unsupported_attachment",
            Self::MissingCallId { .. } => "missing_call_id",
            Self::MissingRouteRecipient { .. } => "missing_route_recipient",
            Self::UnsupportedRoutedContent { .. } => "unsupported_routed_content",
            Self::UnsupportedToolRecord { .. } => "unsupported_tool_record",
            Self::InvalidToolData { .. } => "invalid_tool_data",
            Self::IncompatibleLineage { .. } => "incompatible_lineage",
            Self::OpaqueKindMismatch { .. } => "opaque_kind_mismatch",
            Self::RawTransportRequired { .. } => "raw_transport_required",
            Self::RawPayloadMismatch => "raw_payload_mismatch",
            Self::RawPayloadRequired { .. } => "raw_payload_required",
            Self::ProviderJson { .. } => "provider_json",
            Self::InvalidCompactionSequence => "invalid_compaction_sequence",
        }
    }
}
