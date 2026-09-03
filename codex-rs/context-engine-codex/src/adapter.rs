use codex_context_engine::AttachmentKind;
use codex_context_engine::CompactionMode;
use codex_context_engine::ContentPart;
use codex_context_engine::ContextCheckpoint;
use codex_context_engine::ContextEvent;
use codex_context_engine::ContextEventPayload;
use codex_context_engine::Message;
use codex_context_engine::MessageDelivery;
use codex_context_engine::MessagePhase;
use codex_context_engine::MessageRole;
use codex_context_engine::MessageRoute;
use codex_context_engine::MessageVisibility;
use codex_context_engine::ModelContextItem;
use codex_context_engine::ModelContextPayload;
use codex_context_engine::OpaquePayload;
use codex_context_engine::ProviderLineage;
use codex_context_engine::ProviderOpaqueItem;
use codex_context_engine::ToolPhase;
use codex_context_engine::ToolRecord;
use codex_protocol::models::AgentMessageInputContent;
use codex_protocol::models::ContentItem;
use codex_protocol::models::LocalShellStatus;
use codex_protocol::models::MessagePhase as CodexMessagePhase;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::CompactedItem;
use codex_protocol::protocol::InterAgentCommunication;
use codex_protocol::protocol::RolloutItem;
use serde::Serialize;
use serde_json::json;

use crate::AdaptedRolloutItem;
use crate::AttachmentMaterializer;
use crate::AttachmentResolver;
use crate::CodexAdapterError;
use crate::EventMetadata;
use crate::IgnoredRolloutItem;
use crate::PreparedCodexInputItem;
use crate::codec::event_payload_to_model;
use crate::codec::from_slice;
use crate::codec::message_role;
use crate::codec::opaque_kind;
use crate::codec::output_phase;
use crate::codec::to_value;
use crate::codec::to_vec;

pub struct CodexContextAdapter<'a> {
    pub(crate) lineage: ProviderLineage,
    attachments: Option<&'a dyn AttachmentResolver>,
    pub(crate) attachment_materializer: Option<&'a dyn AttachmentMaterializer>,
}

impl<'a> CodexContextAdapter<'a> {
    pub fn new(lineage: ProviderLineage) -> Self {
        Self {
            lineage,
            attachments: None,
            attachment_materializer: None,
        }
    }

    pub fn with_attachment_resolver(mut self, resolver: &'a dyn AttachmentResolver) -> Self {
        self.attachments = Some(resolver);
        self
    }

    pub fn with_attachment_materializer(
        mut self,
        materializer: &'a dyn AttachmentMaterializer,
    ) -> Self {
        self.attachment_materializer = Some(materializer);
        self
    }

    pub fn lineage(&self) -> &ProviderLineage {
        &self.lineage
    }

    /// Prepares provider input while retaining original opaque JSON alongside
    /// typed records supported by the current Codex request path.
    pub fn prepare_model_input(
        &self,
        items: &[ModelContextItem],
    ) -> Result<Vec<PreparedCodexInputItem>, CodexAdapterError> {
        items
            .iter()
            .map(|item| self.prepare_model_input_item(item))
            .collect()
    }

    /// Produces input for the current typed Codex request path.
    ///
    /// Unknown future provider records require a raw request transport and are
    /// rejected here instead of degrading to `ResponseItem::Other`.
    pub fn prepare_response_items(
        &self,
        items: &[ModelContextItem],
    ) -> Result<Vec<ResponseItem>, CodexAdapterError> {
        self.prepare_model_input(items)?
            .into_iter()
            .map(PreparedCodexInputItem::into_response_item)
            .collect()
    }

    /// Adapts a provider response item. Supplying the original JSON preserves
    /// opaque state byte-for-byte and is mandatory for unknown future variants.
    pub fn adapt_response_item(
        &self,
        metadata: EventMetadata,
        item: &ResponseItem,
        raw_json: Option<&[u8]>,
    ) -> Result<AdaptedRolloutItem, CodexAdapterError> {
        let Some(payload) = self.response_payload(item, raw_json, &metadata.event_id)? else {
            return Ok(AdaptedRolloutItem::Ignored(
                IgnoredRolloutItem::RequestControl,
            ));
        };
        Ok(AdaptedRolloutItem::Event(Box::new(
            metadata.into_event(payload),
        )))
    }

    /// Adapts records already decoded from the current Codex rollout. Records
    /// that only restore runtime or presentation state are classified explicitly.
    pub fn adapt_rollout_item(
        &self,
        metadata: EventMetadata,
        item: &RolloutItem,
    ) -> Result<AdaptedRolloutItem, CodexAdapterError> {
        match item {
            RolloutItem::ResponseItem(item) => self.adapt_response_item(metadata, item, None),
            RolloutItem::InterAgentCommunication(communication) => {
                let payload = self.inter_agent_payload(communication, &metadata.event_id)?;
                Ok(AdaptedRolloutItem::Event(Box::new(
                    metadata.into_event(payload),
                )))
            }
            RolloutItem::Compacted(compacted) => Ok(AdaptedRolloutItem::Event(Box::new(
                self.compaction_event(metadata, compacted)?,
            ))),
            RolloutItem::SessionMeta(_) => Ok(AdaptedRolloutItem::Ignored(
                IgnoredRolloutItem::SessionMetadata,
            )),
            RolloutItem::InterAgentCommunicationMetadata { .. } => Ok(AdaptedRolloutItem::Ignored(
                IgnoredRolloutItem::DeliveryMetadata,
            )),
            RolloutItem::RemoteExecutionProtocolMarker(_)
            | RolloutItem::RemoteExecutionLaunchIntent(_)
            | RolloutItem::RemoteExecutionWriteRequest(_)
            | RolloutItem::RemoteExecutionWriteIntent(_)
            | RolloutItem::RemoteExecutionSessionPrepared(_)
            | RolloutItem::RemoteExecutionSessionCommitted(_)
            | RolloutItem::RemoteExecutionSessionAcknowledged(_)
            | RolloutItem::RemoteExecutionSessionReleased(_) => Ok(AdaptedRolloutItem::Ignored(
                IgnoredRolloutItem::RemoteExecutionPersistence,
            )),
            RolloutItem::TurnContext(_) => Ok(AdaptedRolloutItem::Ignored(
                IgnoredRolloutItem::TurnReferenceContext,
            )),
            RolloutItem::WorldState(_) => {
                Ok(AdaptedRolloutItem::Ignored(IgnoredRolloutItem::WorldState))
            }
            RolloutItem::EventMsg(_) => Ok(AdaptedRolloutItem::Ignored(
                IgnoredRolloutItem::PresentationEvent,
            )),
        }
    }

    fn response_payload(
        &self,
        item: &ResponseItem,
        raw_json: Option<&[u8]>,
        fallback_id: &str,
    ) -> Result<Option<ContextEventPayload>, CodexAdapterError> {
        let payload = match item {
            ResponseItem::Message {
                role,
                content,
                phase,
                ..
            } => ContextEventPayload::Message(self.message(role, content, phase.as_ref(), None)?),
            ResponseItem::AgentMessage {
                author,
                recipient,
                content,
                ..
            } if content
                .iter()
                .all(|part| matches!(part, AgentMessageInputContent::InputText { .. })) =>
            {
                ContextEventPayload::Message(Message {
                    role: MessageRole::Assistant,
                    visibility: MessageVisibility::ModelOnly,
                    content: content
                        .iter()
                        .map(|part| match part {
                            AgentMessageInputContent::InputText { text } => {
                                ContentPart::Text { text: text.clone() }
                            }
                            AgentMessageInputContent::EncryptedContent { .. } => unreachable!(),
                        })
                        .collect(),
                    phase: Some(MessagePhase::Commentary),
                    route: Some(MessageRoute {
                        author: author.clone(),
                        recipients: vec![recipient.clone()],
                        delivery: None,
                    }),
                })
            }
            ResponseItem::LocalShellCall {
                id,
                call_id,
                status,
                action,
                ..
            } => ContextEventPayload::Tool(ToolRecord {
                call_id: call_id
                    .as_deref()
                    .or_else(|| id.as_ref().map(codex_protocol::ResponseItemId::as_str))
                    .ok_or(CodexAdapterError::MissingCallId {
                        kind: "local_shell_call",
                    })?
                    .to_string(),
                name: "local_shell".to_string(),
                phase: match status {
                    LocalShellStatus::InProgress => ToolPhase::Requested,
                    LocalShellStatus::Completed => ToolPhase::Completed,
                    LocalShellStatus::Incomplete => ToolPhase::Failed,
                },
                data: json!({
                    "kind": "local_shell",
                    "action": to_value(action, "serialize local shell action")?,
                }),
            }),
            ResponseItem::FunctionCall {
                name,
                namespace,
                arguments,
                call_id,
                ..
            } => ContextEventPayload::Tool(ToolRecord {
                call_id: call_id.clone(),
                name: name.clone(),
                phase: ToolPhase::Requested,
                data: json!({
                    "kind": "function",
                    "namespace": namespace,
                    "arguments": arguments,
                }),
            }),
            ResponseItem::FunctionCallOutput {
                call_id, output, ..
            } => ContextEventPayload::Tool(ToolRecord {
                call_id: call_id.clone(),
                name: "function_call".to_string(),
                phase: output_phase(output.success),
                data: json!({
                    "kind": "function",
                    "output": to_value(&output.body, "serialize function output")?,
                    "success": output.success,
                }),
            }),
            ResponseItem::CustomToolCall {
                call_id,
                name,
                namespace,
                input,
                ..
            } => ContextEventPayload::Tool(ToolRecord {
                call_id: call_id.clone(),
                name: name.clone(),
                phase: ToolPhase::Requested,
                data: json!({
                    "kind": "custom",
                    "namespace": namespace,
                    "input": input,
                }),
            }),
            ResponseItem::CustomToolCallOutput {
                call_id,
                name,
                output,
                ..
            } => ContextEventPayload::Tool(ToolRecord {
                call_id: call_id.clone(),
                name: name.clone().unwrap_or_else(|| "custom_tool".to_string()),
                phase: output_phase(output.success),
                data: json!({
                    "kind": "custom",
                    "output": to_value(&output.body, "serialize custom tool output")?,
                    "success": output.success,
                }),
            }),
            ResponseItem::CompactionTrigger { .. } => return Ok(None),
            item => ContextEventPayload::ProviderOpaque(self.opaque_response_item(
                item,
                raw_json,
                fallback_id,
                opaque_kind(item),
            )?),
        };
        Ok(Some(payload))
    }

    fn message(
        &self,
        role: &str,
        content: &[ContentItem],
        phase: Option<&CodexMessagePhase>,
        route: Option<MessageRoute>,
    ) -> Result<Message, CodexAdapterError> {
        let role = message_role(role)?;
        let visibility = match role {
            MessageRole::User | MessageRole::Assistant => MessageVisibility::TranscriptAndModel,
            MessageRole::Developer | MessageRole::System => MessageVisibility::ModelOnly,
        };
        let content = content
            .iter()
            .map(|part| self.content_part(part))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Message {
            role,
            visibility,
            content,
            phase: phase.map(|phase| match phase {
                CodexMessagePhase::Commentary => MessagePhase::Commentary,
                CodexMessagePhase::FinalAnswer => MessagePhase::FinalAnswer,
            }),
            route,
        })
    }

    fn content_part(&self, item: &ContentItem) -> Result<ContentPart, CodexAdapterError> {
        match item {
            ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                Ok(ContentPart::Text { text: text.clone() })
            }
            ContentItem::InputImage { image_url, .. } => {
                self.attachment_part(image_url, AttachmentKind::Image)
            }
            ContentItem::InputAudio { audio_url } => {
                self.attachment_part(audio_url, AttachmentKind::Audio)
            }
        }
    }

    fn attachment_part(
        &self,
        source: &str,
        kind: AttachmentKind,
    ) -> Result<ContentPart, CodexAdapterError> {
        let resolved = self
            .attachments
            .and_then(|resolver| resolver.resolve(source, &kind))
            .ok_or_else(|| CodexAdapterError::UnresolvedAttachment { kind: kind.clone() })?;
        if resolved.attachment_id.is_empty() {
            return Err(CodexAdapterError::EmptyAttachmentField {
                field: "attachment_id",
            });
        }
        if resolved.media_type.is_empty() {
            return Err(CodexAdapterError::EmptyAttachmentField {
                field: "media_type",
            });
        }
        Ok(ContentPart::Attachment {
            attachment_id: resolved.attachment_id,
            media_type: resolved.media_type,
            kind,
        })
    }

    fn inter_agent_payload(
        &self,
        communication: &InterAgentCommunication,
        fallback_id: &str,
    ) -> Result<ContextEventPayload, CodexAdapterError> {
        if communication.encrypted_content.is_some() {
            return Ok(ContextEventPayload::ProviderOpaque(
                self.opaque_serialized(
                    communication,
                    communication
                        .id
                        .as_ref()
                        .map_or(fallback_id, |id| id.as_str()),
                    "codex.inter_agent_communication",
                )?,
            ));
        }
        let mut recipients = vec![communication.recipient.to_string()];
        recipients.extend(
            communication
                .other_recipients
                .iter()
                .map(ToString::to_string),
        );
        Ok(ContextEventPayload::Message(Message {
            role: MessageRole::Assistant,
            visibility: MessageVisibility::ModelOnly,
            content: vec![ContentPart::Text {
                text: communication.content.clone(),
            }],
            phase: Some(MessagePhase::Commentary),
            route: Some(MessageRoute {
                author: communication.author.to_string(),
                recipients,
                delivery: Some(if communication.trigger_turn {
                    MessageDelivery::TriggerTurn
                } else {
                    MessageDelivery::QueueOnly
                }),
            }),
        }))
    }

    fn compaction_event(
        &self,
        metadata: EventMetadata,
        compacted: &CompactedItem,
    ) -> Result<ContextEvent, CodexAdapterError> {
        let through_sequence = metadata
            .sequence
            .checked_sub(1)
            .ok_or(CodexAdapterError::InvalidCompactionSequence)?;
        let replacement = match &compacted.replacement_history {
            Some(items) => items
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    let fallback_id = format!("{}:replacement:{index}", metadata.event_id);
                    match self.response_payload(item, None, &fallback_id) {
                        Ok(Some(payload)) => Some(event_payload_to_model(payload, fallback_id)),
                        Ok(None) => None,
                        Err(error) => Some(Err(error)),
                    }
                })
                .collect::<Result<Vec<_>, _>>()?,
            None => vec![ModelContextItem {
                id: format!("{}:summary", metadata.event_id),
                source_sequence: None,
                payload: ModelContextPayload::Message(Message {
                    role: MessageRole::Assistant,
                    visibility: MessageVisibility::ModelOnly,
                    content: vec![ContentPart::Text {
                        text: compacted.message.clone(),
                    }],
                    phase: None,
                    route: None,
                }),
            }],
        };
        let provider_native = replacement
            .iter()
            .any(|item| matches!(item.payload, ModelContextPayload::ProviderOpaque(_)));
        let checkpoint = ContextCheckpoint {
            id: compacted
                .window_id
                .clone()
                .unwrap_or_else(|| metadata.event_id.clone()),
            conversation_id: metadata.conversation_id.clone(),
            through_sequence,
            lineage: provider_native.then(|| self.lineage.clone()),
            mode: if provider_native {
                CompactionMode::ProviderNative
            } else {
                CompactionMode::Semantic
            },
            replacement,
        };
        Ok(metadata.into_event(ContextEventPayload::Compaction(checkpoint)))
    }

    fn opaque_response_item(
        &self,
        item: &ResponseItem,
        raw_json: Option<&[u8]>,
        fallback_id: &str,
        kind: &'static str,
    ) -> Result<ProviderOpaqueItem, CodexAdapterError> {
        let payload = match raw_json {
            Some(bytes) => {
                let decoded: ResponseItem = from_slice(bytes, "decode raw response item")?;
                if &decoded != item {
                    return Err(CodexAdapterError::RawPayloadMismatch);
                }
                bytes.to_vec()
            }
            None if matches!(item, ResponseItem::Other) => {
                return Err(CodexAdapterError::RawPayloadRequired { kind });
            }
            None => {
                let bytes = to_vec(item, "serialize response item")?;
                let decoded: ResponseItem = from_slice(&bytes, "verify response item")?;
                if &decoded != item {
                    return Err(CodexAdapterError::RawPayloadRequired { kind });
                }
                bytes
            }
        };
        Ok(ProviderOpaqueItem {
            lineage: self.lineage.clone(),
            provider_item_id: item
                .id()
                .map_or_else(|| fallback_id.to_string(), ToString::to_string),
            kind: kind.to_string(),
            payload: OpaquePayload::new(payload),
        })
    }

    fn opaque_serialized<T: Serialize>(
        &self,
        value: &T,
        provider_item_id: &str,
        kind: &'static str,
    ) -> Result<ProviderOpaqueItem, CodexAdapterError> {
        Ok(ProviderOpaqueItem {
            lineage: self.lineage.clone(),
            provider_item_id: provider_item_id.to_string(),
            kind: kind.to_string(),
            payload: OpaquePayload::new(to_vec(value, "serialize opaque rollout item")?),
        })
    }
}
