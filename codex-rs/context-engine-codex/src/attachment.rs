use codex_context_engine::AttachmentKind;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolvedAttachment {
    pub attachment_id: String,
    pub media_type: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MaterializedAttachment {
    /// Provider-ready URL or data URL produced from application-owned bytes.
    pub source: String,
}

/// Resolves provider-facing media URLs into application-owned attachment references.
pub trait AttachmentResolver: Send + Sync {
    fn resolve(&self, source: &str, kind: &AttachmentKind) -> Option<ResolvedAttachment>;
}

/// Materializes an application-owned attachment for a specific provider request.
///
/// The context journal never stores this provider-facing source. Implementations
/// may return a short-lived URL or an in-memory data URL for the current request.
pub trait AttachmentMaterializer: Send + Sync {
    fn materialize(
        &self,
        attachment_id: &str,
        media_type: &str,
        kind: &AttachmentKind,
    ) -> Option<MaterializedAttachment>;
}
