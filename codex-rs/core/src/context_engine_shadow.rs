use std::fs;
use std::path::Path;
use std::sync::LazyLock;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use codex_context_engine::AttachmentKind;
use codex_context_engine::ProviderLineage;
use codex_context_engine_codex::AttachmentMaterializer;
use codex_context_engine_codex::AttachmentResolver;
use codex_context_engine_codex::CodexContextAdapter;
use codex_context_engine_codex::CodexInputParityStage;
use codex_context_engine_codex::MaterializedAttachment;
use codex_context_engine_codex::ResolvedAttachment;
use codex_protocol::models::ResponseItem;
use serde::Deserialize;
use serde::Serialize;
use tracing::trace;
use tracing::warn;

const PARITY_REPORT_FILENAME: &str = ".agentapp-context-parity-v1.json";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct ContextEngineParityReport {
    schema_version: u8,
    generated_at_unix_ms: i64,
    equivalent: bool,
    source_items: usize,
    compared_items: usize,
    ignored_items: usize,
    import_failures: usize,
    export_failures: usize,
    comparison_failures: usize,
}

static SHADOW_ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("CODEX_CONTEXT_ENGINE_SHADOW")
        .ok()
        .is_some_and(|value| !matches!(value.as_str(), "" | "0" | "false" | "off"))
});

/// Runs the neutral context projection beside the authoritative history path.
/// It never changes request input and reports only counts and classifications.
pub(crate) fn audit_model_input(
    codex_home: &Path,
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
    let equivalent = report.is_equivalent();
    let persisted_report = ContextEngineParityReport {
        schema_version: 1,
        generated_at_unix_ms: unix_time_millis(),
        equivalent,
        source_items: report.source_items,
        compared_items: report.compared_items,
        ignored_items: report.ignored_items,
        import_failures,
        export_failures,
        comparison_failures,
    };
    if let Err(error) = write_parity_report(codex_home, &persisted_report) {
        warn!(
            error = %error,
            "context engine shadow parity report write failed"
        );
    }

    if equivalent {
        trace!(
            source_items = report.source_items,
            compared_items = report.compared_items,
            ignored_items = report.ignored_items,
            "context engine shadow projection matched"
        );
        return;
    }

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

fn unix_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn write_parity_report(
    codex_home: &Path,
    report: &ContextEngineParityReport,
) -> std::io::Result<()> {
    let encoded = serde_json::to_vec(report).map_err(std::io::Error::other)?;
    let destination = codex_home.join(PARITY_REPORT_FILENAME);
    let temporary = codex_home.join(format!(
        "{PARITY_REPORT_FILENAME}.tmp-{}-{}",
        std::process::id(),
        report.generated_at_unix_ms
    ));
    fs::write(&temporary, encoded)?;
    if let Err(error) = fs::rename(&temporary, destination) {
        let _ = fs::remove_file(temporary);
        return Err(error);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_report_is_atomic_and_content_free() {
        let home = tempfile::tempdir().expect("temporary Codex home");
        let report = ContextEngineParityReport {
            schema_version: 1,
            generated_at_unix_ms: 1_725_000_000_000,
            equivalent: true,
            source_items: 8,
            compared_items: 7,
            ignored_items: 1,
            import_failures: 0,
            export_failures: 0,
            comparison_failures: 0,
        };

        write_parity_report(home.path(), &report).expect("write parity report");

        let bytes = fs::read(home.path().join(PARITY_REPORT_FILENAME)).expect("read parity report");
        let decoded: ContextEngineParityReport =
            serde_json::from_slice(&bytes).expect("decode parity report");
        assert_eq!(decoded, report);
        let object =
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("decode JSON object");
        assert_eq!(object.as_object().map(|value| value.len()), Some(9));
        assert!(!String::from_utf8_lossy(&bytes).contains("conversation"));
        assert!(!String::from_utf8_lossy(&bytes).contains("provider"));
    }
}
