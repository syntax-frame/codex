use codex_context_engine::AttachmentKind;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolvedAttachment {
    pub attachment_id: String,
    pub media_type: String,
}

/// Resolves provider-facing media URLs into application-owned attachment references.
pub trait AttachmentResolver: Send + Sync {
    fn resolve(&self, source: &str, kind: &AttachmentKind) -> Option<ResolvedAttachment>;
}
