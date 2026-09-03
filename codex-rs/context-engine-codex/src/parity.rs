use codex_context_engine::ContextEventPayload;
use codex_context_engine::ModelContextItem;
use codex_context_engine::ModelContextPayload;
use codex_context_engine::project_context;
use codex_protocol::models::AgentMessageInputContent;
use codex_protocol::models::ResponseItem;

use crate::AdaptedRolloutItem;
use crate::CodexAdapterError;
use crate::CodexContextAdapter;
use crate::EventMetadata;
use crate::PreparedCodexInputItem;
use crate::codec::restore_local_only_fields;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CodexInputParityStage {
    Import,
    Export,
    Compare,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CodexInputParityFailure {
    pub index: usize,
    pub stage: CodexInputParityStage,
    /// Stable provider-item classification. Prompt contents are never included.
    pub item_kind: &'static str,
    /// Stable content-free failure classification.
    pub reason_code: &'static str,
    /// Adapter classification only. Prompt contents are never included.
    pub reason: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CodexInputParityReport {
    pub source_items: usize,
    pub compared_items: usize,
    pub ignored_items: usize,
    pub failures: Vec<CodexInputParityFailure>,
}

impl CodexInputParityReport {
    pub fn is_equivalent(&self) -> bool {
        self.failures.is_empty()
            && self.source_items == self.compared_items.saturating_add(self.ignored_items)
    }

    pub fn failure_count(&self, stage: CodexInputParityStage) -> usize {
        self.failures
            .iter()
            .filter(|failure| failure.stage == stage)
            .count()
    }
}

impl CodexInputParityStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Export => "export",
            Self::Compare => "compare",
        }
    }
}

impl CodexContextAdapter<'_> {
    /// Audits the current typed Codex prompt through the neutral contract.
    ///
    /// This method never changes the supplied prompt and never includes message
    /// or tool payloads in its report. It is suitable for a shadow path before
    /// the neutral projection becomes authoritative.
    pub fn audit_response_items(
        &self,
        conversation_id: &str,
        items: &[ResponseItem],
    ) -> CodexInputParityReport {
        let mut report = CodexInputParityReport {
            source_items: items.len(),
            compared_items: 0,
            ignored_items: 0,
            failures: Vec::new(),
        };

        for (index, source) in items.iter().enumerate() {
            let sequence = u64::try_from(index)
                .unwrap_or(u64::MAX - 1)
                .saturating_add(1);
            let metadata = EventMetadata {
                event_id: format!("shadow:{index}"),
                conversation_id: conversation_id.to_string(),
                turn_id: source.turn_id().map(ToString::to_string),
                sequence,
            };
            let adapted = match self.adapt_response_item(metadata, source, None) {
                Ok(adapted) => adapted,
                Err(error) => {
                    report.failures.push(adapter_failure(
                        index,
                        CodexInputParityStage::Import,
                        source,
                        error,
                    ));
                    continue;
                }
            };
            let AdaptedRolloutItem::Event(event) = adapted else {
                report.ignored_items = report.ignored_items.saturating_add(1);
                continue;
            };
            let model_item = event_to_model_item(*event);
            let prepared = match self.prepare_model_input_item(&model_item) {
                Ok(prepared) => prepared,
                Err(error) => {
                    report.failures.push(adapter_failure(
                        index,
                        CodexInputParityStage::Export,
                        source,
                        error,
                    ));
                    continue;
                }
            };
            let Some(mut rebuilt) = prepared.response_item().cloned() else {
                report.failures.push(CodexInputParityFailure {
                    index,
                    stage: CodexInputParityStage::Export,
                    item_kind: response_item_kind(source),
                    reason_code: "raw_transport_required",
                    reason: "raw Codex request transport required".to_string(),
                });
                continue;
            };
            restore_local_only_fields(source, &mut rebuilt);
            report.compared_items = report.compared_items.saturating_add(1);

            let equivalent = if matches!(
                prepared,
                PreparedCodexInputItem::Typed {
                    original_json: Some(_),
                    ..
                }
            ) {
                source == &rebuilt
            } else {
                normalize_semantic(source.clone()) == normalize_semantic(rebuilt)
            };
            if !equivalent {
                report.failures.push(CodexInputParityFailure {
                    index,
                    stage: CodexInputParityStage::Compare,
                    item_kind: response_item_kind(source),
                    reason_code: "projection_mismatch",
                    reason: format!(
                        "{} item changed across the neutral projection",
                        response_item_kind(source)
                    ),
                });
            }
        }

        report
    }

    /// Rebuilds the current Codex prompt through the neutral contract and
    /// returns it only when every reconstructed item is exactly equal to its
    /// source item. Request-control records are retained verbatim because they
    /// intentionally do not belong to durable model context.
    ///
    /// The source item supplies only its transient Codex transport envelope
    /// (provider item id and internal turn id). The neutral payload still owns
    /// the reconstructed message/tool/provider content. This is the migration
    /// bridge used while the existing Codex rollout remains authoritative.
    pub fn rebuild_response_items_exact(
        &self,
        conversation_id: &str,
        items: &[ResponseItem],
    ) -> Result<Vec<ResponseItem>, CodexInputParityReport> {
        let mut rebuilt_items = vec![None; items.len()];
        let mut events = Vec::with_capacity(items.len());
        let mut event_source_indices = Vec::with_capacity(items.len());
        let mut report = CodexInputParityReport {
            source_items: items.len(),
            compared_items: 0,
            ignored_items: 0,
            failures: Vec::new(),
        };

        for (index, source) in items.iter().enumerate() {
            let sequence = u64::try_from(index)
                .unwrap_or(u64::MAX - 1)
                .saturating_add(1);
            let metadata = EventMetadata {
                event_id: format!("route:{index}"),
                conversation_id: conversation_id.to_string(),
                turn_id: source.turn_id().map(ToString::to_string),
                sequence,
            };
            let adapted = match self.adapt_response_item(metadata, source, None) {
                Ok(adapted) => adapted,
                Err(error) => {
                    report.failures.push(adapter_failure(
                        index,
                        CodexInputParityStage::Import,
                        source,
                        error,
                    ));
                    continue;
                }
            };
            let AdaptedRolloutItem::Event(event) = adapted else {
                report.ignored_items = report.ignored_items.saturating_add(1);
                rebuilt_items[index] = Some(source.clone());
                continue;
            };
            event_source_indices.push(index);
            events.push(*event);
        }

        if !report.failures.is_empty() {
            return Err(report);
        }

        let projection = match project_context(&events, &self.lineage) {
            Ok(projection) => projection,
            Err(error) => {
                report.failures.push(CodexInputParityFailure {
                    index: event_source_indices.first().copied().unwrap_or(0),
                    stage: CodexInputParityStage::Export,
                    item_kind: "context",
                    reason_code: "projection_failed",
                    reason: format!("neutral context projection failed: {error}"),
                });
                return Err(report);
            }
        };
        if projection.checkpoint_id.is_some()
            || !projection.excluded_opaque_event_ids.is_empty()
            || projection.model_context.len() != events.len()
        {
            report.failures.push(CodexInputParityFailure {
                index: event_source_indices.first().copied().unwrap_or(0),
                stage: CodexInputParityStage::Export,
                item_kind: "context",
                reason_code: "projection_changed_input_set",
                reason: "neutral context projection changed the exact input set".to_string(),
            });
            return Err(report);
        }

        for ((model_item, event), source_index) in projection
            .model_context
            .iter()
            .zip(events.iter())
            .zip(event_source_indices.iter().copied())
        {
            if model_item.source_sequence != Some(event.sequence) {
                report.failures.push(CodexInputParityFailure {
                    index: source_index,
                    stage: CodexInputParityStage::Export,
                    item_kind: response_item_kind(&items[source_index]),
                    reason_code: "projection_changed_ordering",
                    reason: "neutral context projection changed input ordering".to_string(),
                });
                continue;
            }
            let source = &items[source_index];
            let prepared = match self.prepare_model_input_item(model_item) {
                Ok(prepared) => prepared,
                Err(error) => {
                    report.failures.push(adapter_failure(
                        source_index,
                        CodexInputParityStage::Export,
                        source,
                        error,
                    ));
                    continue;
                }
            };
            let Some(mut rebuilt) = prepared.response_item().cloned() else {
                report.failures.push(CodexInputParityFailure {
                    index: source_index,
                    stage: CodexInputParityStage::Export,
                    item_kind: response_item_kind(source),
                    reason_code: "raw_transport_required",
                    reason: "raw Codex request transport required".to_string(),
                });
                continue;
            };

            // Codex keeps decrypted reasoning text in memory but deliberately
            // excludes it from provider serialization. Restore that transient
            // field only after the neutral provider payload has round-tripped.
            restore_local_only_fields(source, &mut rebuilt);

            // Provider item ids and Codex's internal turn marker are transport
            // metadata, not portable conversation semantics. Keep them from
            // the live rollout until a lineage-scoped envelope is persisted by
            // the Context Engine in a later cutover phase.
            rebuilt.set_id(source.id().cloned());
            if let Some(turn_id) = source.turn_id() {
                rebuilt.set_turn_id_if_missing(turn_id);
            }
            report.compared_items = report.compared_items.saturating_add(1);
            if source != &rebuilt {
                report.failures.push(CodexInputParityFailure {
                    index: source_index,
                    stage: CodexInputParityStage::Compare,
                    item_kind: response_item_kind(source),
                    reason_code: "reconstruction_mismatch",
                    reason: format!(
                        "{} item was not exactly reconstructable",
                        response_item_kind(source)
                    ),
                });
                continue;
            }
            rebuilt_items[source_index] = Some(rebuilt);
        }

        if !report.is_equivalent() || rebuilt_items.iter().any(Option::is_none) {
            return Err(report);
        }
        Ok(rebuilt_items.into_iter().flatten().collect())
    }
}

fn adapter_failure(
    index: usize,
    stage: CodexInputParityStage,
    source: &ResponseItem,
    error: CodexAdapterError,
) -> CodexInputParityFailure {
    CodexInputParityFailure {
        index,
        stage,
        item_kind: response_item_kind(source),
        reason_code: error.diagnostic_code(),
        reason: error.to_string(),
    }
}

fn event_to_model_item(event: codex_context_engine::ContextEvent) -> ModelContextItem {
    let (id, payload) = match event.payload {
        ContextEventPayload::Message(message) => (event.id, ModelContextPayload::Message(message)),
        ContextEventPayload::Tool(tool) => (event.id, ModelContextPayload::Tool(tool)),
        ContextEventPayload::ProviderOpaque(opaque) => (
            opaque.provider_item_id.clone(),
            ModelContextPayload::ProviderOpaque(opaque),
        ),
        ContextEventPayload::Compaction(_) => {
            unreachable!("a response item cannot adapt directly into a checkpoint")
        }
    };
    ModelContextItem {
        id,
        source_sequence: Some(event.sequence),
        payload,
    }
}

fn normalize_semantic(mut item: ResponseItem) -> ResponseItem {
    item.set_id(None);
    item.clear_internal_chat_message_metadata_passthrough();
    item
}

fn response_item_kind(item: &ResponseItem) -> &'static str {
    match item {
        ResponseItem::AdditionalTools { .. } => "additional_tools",
        ResponseItem::Message { .. } => "message",
        ResponseItem::AgentMessage { content, .. }
            if content
                .iter()
                .all(|part| matches!(part, AgentMessageInputContent::InputText { .. })) =>
        {
            "agent_message"
        }
        ResponseItem::AgentMessage { .. } => "encrypted_agent_message",
        ResponseItem::Reasoning { .. } => "reasoning",
        ResponseItem::LocalShellCall { .. } => "local_shell_call",
        ResponseItem::FunctionCall { .. } => "function_call",
        ResponseItem::ToolSearchCall { .. } => "tool_search_call",
        ResponseItem::FunctionCallOutput { .. } => "function_call_output",
        ResponseItem::CustomToolCall { .. } => "custom_tool_call",
        ResponseItem::CustomToolCallOutput { .. } => "custom_tool_call_output",
        ResponseItem::ToolSearchOutput { .. } => "tool_search_output",
        ResponseItem::WebSearchCall { .. } => "web_search_call",
        ResponseItem::ImageGenerationCall { .. } => "image_generation_call",
        ResponseItem::Compaction { .. } => "compaction",
        ResponseItem::CompactionTrigger { .. } => "compaction_trigger",
        ResponseItem::ContextCompaction { .. } => "context_compaction",
        ResponseItem::Other => "unknown",
    }
}
