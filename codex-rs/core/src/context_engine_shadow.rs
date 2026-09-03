use std::collections::BTreeMap;
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
use codex_context_engine_codex::CodexInputParityReport;
use codex_context_engine_codex::CodexInputParityStage;
use codex_context_engine_codex::MaterializedAttachment;
use codex_context_engine_codex::ResolvedAttachment;
use codex_protocol::models::ResponseItem;
use serde::Deserialize;
use serde::Serialize;
use tracing::trace;
use tracing::warn;

const PARITY_REPORT_FILENAME: &str = ".agentapp-context-parity-v1.json";
const ROUTE_ENVIRONMENT_VARIABLE: &str = "CODEX_CONTEXT_ENGINE_ROUTE";
const MAX_FAILURE_CLASSIFICATIONS: usize = 32;
const RESERVED_FAILURE_STAGE_ROLLUPS: usize = 3;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct ContextEngineFailureClassification {
    stage: String,
    item_kind: String,
    reason_code: String,
    count: usize,
}

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
    route_status: String,
    route_failures: usize,
    failure_classifications: Vec<ContextEngineFailureClassification>,
}

static SHADOW_ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("CODEX_CONTEXT_ENGINE_SHADOW")
        .ok()
        .is_some_and(|value| !matches!(value.as_str(), "" | "0" | "false" | "off"))
});

static ROUTE_ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var(ROUTE_ENVIRONMENT_VARIABLE)
        .ok()
        .is_some_and(|value| !matches!(value.as_str(), "" | "0" | "false" | "off"))
});

/// Reconstructs provider input through the neutral Context Engine only when
/// every item is exactly equal after reconstruction. Any unsupported or lossy
/// item keeps the complete original request authoritative for this sampling
/// step. The persisted report contains counts and classifications only.
pub(crate) fn prepare_model_input(
    codex_home: &Path,
    conversation_id: &str,
    provider: &str,
    model: &str,
    input: Vec<ResponseItem>,
) -> Vec<ResponseItem> {
    if !*SHADOW_ENABLED && !*ROUTE_ENABLED {
        return input;
    }

    let attachments = EphemeralShadowAttachments;
    let adapter = CodexContextAdapter::new(ProviderLineage {
        provider: provider.to_string(),
        protocol: "responses".to_string(),
        lineage_id: format!("shadow:{provider}:{model}"),
    })
    .with_attachment_resolver(&attachments)
    .with_attachment_materializer(&attachments);
    let report = adapter.audit_response_items(conversation_id, &input);
    let import_failures = report.failure_count(CodexInputParityStage::Import);
    let export_failures = report.failure_count(CodexInputParityStage::Export);
    let comparison_failures = report.failure_count(CodexInputParityStage::Compare);
    let equivalent = report.is_equivalent();
    let failure_classifications = failure_classifications(&report);
    let (routed_input, route_status, route_failures) = if !*ROUTE_ENABLED {
        (None, "disabled", 0)
    } else if !equivalent {
        (None, "fallback", report.failures.len().max(1))
    } else {
        match adapter.rebuild_response_items_exact(conversation_id, &input) {
            Ok(rebuilt) => (Some(rebuilt), "used", 0),
            Err(route_report) => (None, "fallback", route_report.failures.len().max(1)),
        }
    };
    let persisted_report = ContextEngineParityReport {
        schema_version: 3,
        generated_at_unix_ms: unix_time_millis(),
        equivalent,
        source_items: report.source_items,
        compared_items: report.compared_items,
        ignored_items: report.ignored_items,
        import_failures,
        export_failures,
        comparison_failures,
        route_status: route_status.to_string(),
        route_failures,
        failure_classifications,
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
    } else {
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

    match route_status {
        "used" => trace!(
            source_items = report.source_items,
            "context engine exact input route used"
        ),
        "fallback" => warn!(
            source_items = report.source_items,
            route_failures, "context engine exact input route fell back to current input"
        ),
        _ => {}
    }

    routed_input.unwrap_or(input)
}

fn failure_classifications(
    report: &CodexInputParityReport,
) -> Vec<ContextEngineFailureClassification> {
    let mut counts = BTreeMap::<(&str, &str, &str), usize>::new();
    for failure in &report.failures {
        let key = (
            failure.stage.as_str(),
            failure.item_kind,
            failure.reason_code,
        );
        let count = counts.entry(key).or_default();
        *count = count.saturating_add(1);
    }

    let mut ranked = counts.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|(left_key, left_count), (right_key, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_key.cmp(right_key))
    });
    if ranked.len() <= MAX_FAILURE_CLASSIFICATIONS {
        return ranked
            .into_iter()
            .map(
                |((stage, item_kind, reason_code), count)| ContextEngineFailureClassification {
                    stage: stage.to_string(),
                    item_kind: item_kind.to_string(),
                    reason_code: reason_code.to_string(),
                    count,
                },
            )
            .collect();
    }

    let direct_limit = MAX_FAILURE_CLASSIFICATIONS - RESERVED_FAILURE_STAGE_ROLLUPS;
    let omitted = ranked.split_off(direct_limit);
    let mut omitted_by_stage = BTreeMap::<&str, usize>::new();
    for ((stage, _, _), count) in omitted {
        let stage_count = omitted_by_stage.entry(stage).or_default();
        *stage_count = stage_count.saturating_add(count);
    }
    let mut classifications = ranked
        .into_iter()
        .map(
            |((stage, item_kind, reason_code), count)| ContextEngineFailureClassification {
                stage: stage.to_string(),
                item_kind: item_kind.to_string(),
                reason_code: reason_code.to_string(),
                count,
            },
        )
        .collect::<Vec<_>>();
    classifications.extend(omitted_by_stage.into_iter().map(|(stage, count)| {
        ContextEngineFailureClassification {
            stage: stage.to_string(),
            item_kind: "other".to_string(),
            reason_code: "classification_limit".to_string(),
            count,
        }
    }));
    classifications
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
    use codex_context_engine_codex::CodexInputParityFailure;

    #[test]
    fn parity_report_is_atomic_and_content_free() {
        let home = tempfile::tempdir().expect("temporary Codex home");
        let report = ContextEngineParityReport {
            schema_version: 3,
            generated_at_unix_ms: 1_725_000_000_000,
            equivalent: true,
            source_items: 8,
            compared_items: 7,
            ignored_items: 1,
            import_failures: 0,
            export_failures: 0,
            comparison_failures: 0,
            route_status: "used".to_string(),
            route_failures: 0,
            failure_classifications: Vec::new(),
        };

        write_parity_report(home.path(), &report).expect("write parity report");

        let bytes = fs::read(home.path().join(PARITY_REPORT_FILENAME)).expect("read parity report");
        let decoded: ContextEngineParityReport =
            serde_json::from_slice(&bytes).expect("decode parity report");
        assert_eq!(decoded, report);
        let object =
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("decode JSON object");
        assert_eq!(object.as_object().map(serde_json::Map::len), Some(12));
        assert!(!String::from_utf8_lossy(&bytes).contains("conversation"));
        assert!(!String::from_utf8_lossy(&bytes).contains("provider"));
    }

    #[test]
    fn failure_classification_excludes_dynamic_reason_text() {
        let report = CodexInputParityReport {
            source_items: 2,
            compared_items: 0,
            ignored_items: 0,
            failures: vec![
                CodexInputParityFailure {
                    index: 0,
                    stage: CodexInputParityStage::Import,
                    item_kind: "reasoning",
                    reason_code: "raw_payload_required",
                    reason: "private provider detail A".to_string(),
                },
                CodexInputParityFailure {
                    index: 1,
                    stage: CodexInputParityStage::Import,
                    item_kind: "reasoning",
                    reason_code: "raw_payload_required",
                    reason: "private provider detail B".to_string(),
                },
            ],
        };

        let classifications = failure_classifications(&report);
        assert_eq!(
            classifications,
            vec![ContextEngineFailureClassification {
                stage: "import".to_string(),
                item_kind: "reasoning".to_string(),
                reason_code: "raw_payload_required".to_string(),
                count: 2,
            }]
        );
        let encoded = serde_json::to_string(&classifications).expect("encode classifications");
        assert!(!encoded.contains("private provider detail"));
    }
}
