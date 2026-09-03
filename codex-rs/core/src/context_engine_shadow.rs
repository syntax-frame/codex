use std::sync::LazyLock;

use codex_context_engine::AttachmentKind;
use codex_context_engine::ProviderLineage;
use codex_context_engine_codex::AttachmentMaterializer;
use codex_context_engine_codex::AttachmentResolver;
use codex_context_engine_codex::CodexContextAdapter;
use codex_context_engine_codex::CodexInputParityStage;
use codex_context_engine_codex::MaterializedAttachment;
use codex_context_engine_codex::ResolvedAttachment;
use codex_protocol::models::ResponseItem;
use tracing::trace;
use tracing::warn;

static SHADOW_ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("CODEX_CONTEXT_ENGINE_SHADOW")
        .ok()
        .is_some_and(|value| !matches!(value.as_str(), "" | "0" | "false" | "off"))
});

/// Runs the neutral context projection beside the authoritative history path.
/// It never changes request input and reports only counts and classifications.
pub(crate) fn audit_model_input(
    conversation_id: &str,
    provider: &str,
    model: &str,
    input: &[ResponseItem],
) {
    if !*SHADOW_ENABLED {
        return;
    }

    let attachments = EphemeralShadowAttachments;
    let adapter = CodexContextAdapter::new(ProviderLineage {
        provider: provider.to_string(),
        protocol: "responses".to_string(),
        lineage_id: format!("shadow:{provider}:{model}"),
    })
    .with_attachment_resolver(&attachments)
    .with_attachment_materializer(&attachments);
    let report = adapter.audit_response_items(conversation_id, input);
    if report.is_equivalent() {
        trace!(
            source_items = report.source_items,
            compared_items = report.compared_items,
            ignored_items = report.ignored_items,
            "context engine shadow projection matched"
        );
        return;
    }

    let import_failures = report
        .failures
        .iter()
        .filter(|failure| failure.stage == CodexInputParityStage::Import)
        .count();
    let export_failures = report
        .failures
        .iter()
        .filter(|failure| failure.stage == CodexInputParityStage::Export)
        .count();
    let comparison_failures = report
        .failures
        .iter()
        .filter(|failure| failure.stage == CodexInputParityStage::Compare)
        .count();
    warn!(
        source_items = report.source_items,
        compared_items = report.compared_items,
        ignored_items = report.ignored_items,
        import_failures,
        export_failures,
        comparison_failures,
        "context engine shadow projection diverged"
    );
}

/// This codec exists only for the in-memory shadow pass. The application-owned
/// attachment store will supply durable IDs and fresh provider sources when the
/// neutral path becomes authoritative.
struct EphemeralShadowAttachments;

impl AttachmentResolver for EphemeralShadowAttachments {
    fn resolve(&self, source: &str, kind: &AttachmentKind) -> Option<ResolvedAttachment> {
        Some(ResolvedAttachment {
            attachment_id: source.to_string(),
            media_type: match kind {
                AttachmentKind::Image => "image/*",
                AttachmentKind::Audio => "audio/*",
                AttachmentKind::File => "application/octet-stream",
            }
            .to_string(),
        })
    }
}

impl AttachmentMaterializer for EphemeralShadowAttachments {
    fn materialize(
        &self,
        attachment_id: &str,
        _media_type: &str,
        _kind: &AttachmentKind,
    ) -> Option<MaterializedAttachment> {
        Some(MaterializedAttachment {
            source: attachment_id.to_string(),
        })
    }
}
