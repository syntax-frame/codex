use codex_context_engine::AttachmentKind;
use codex_context_engine::ContentPart;
use codex_context_engine::Message;
use codex_context_engine::MessagePhase;
use codex_context_engine::MessageRole;
use codex_context_engine::ModelContextItem;
use codex_context_engine::ModelContextPayload;
use codex_context_engine::OpaquePayload;
use codex_context_engine::ProviderOpaqueItem;
use codex_context_engine::ToolPhase;
use codex_context_engine::ToolRecord;
use codex_protocol::models::AgentMessageInputContent;
use codex_protocol::models::ContentItem;
use codex_protocol::models::FunctionCallOutputBody;
use codex_protocol::models::FunctionCallOutputPayload;
use codex_protocol::models::LocalShellAction;
use codex_protocol::models::LocalShellStatus;
use codex_protocol::models::MessagePhase as CodexMessagePhase;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::InterAgentCommunication;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::CodexAdapterError;
use crate::CodexContextAdapter;
use crate::PreparedCodexInputItem;
use crate::codec::from_slice;
use crate::codec::opaque_kind;

impl CodexContextAdapter<'_> {
    pub(crate) fn prepare_model_input_item(
        &self,
        item: &ModelContextItem,
    ) -> Result<PreparedCodexInputItem, CodexAdapterError> {
        match &item.payload {
            ModelContextPayload::Message(message) => Ok(PreparedCodexInputItem::Typed {
                item: self.message_input(&item.id, message)?,
                original_json: None,
            }),
            ModelContextPayload::Tool(tool) => Ok(PreparedCodexInputItem::Typed {
                item: self.tool_input(tool)?,
                original_json: None,
            }),
            ModelContextPayload::ProviderOpaque(opaque) => self.opaque_input(opaque),
        }
    }

    fn message_input(
        &self,
        item_id: &str,
        message: &Message,
    ) -> Result<ResponseItem, CodexAdapterError> {
        if let Some(route) = &message.route {
            let recipient = route.recipients.first().cloned().ok_or_else(|| {
                CodexAdapterError::MissingRouteRecipient {
                    item_id: item_id.to_string(),
                }
            })?;
            let content = message
                .content
                .iter()
                .map(|part| match part {
                    ContentPart::Text { text } => {
                        Ok(AgentMessageInputContent::InputText { text: text.clone() })
                    }
                    ContentPart::Attachment { .. } => {
                        Err(CodexAdapterError::UnsupportedRoutedContent {
                            item_id: item_id.to_string(),
                        })
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(ResponseItem::AgentMessage {
                id: None,
                author: route.author.clone(),
                recipient,
                content,
                internal_chat_message_metadata_passthrough: None,
            });
        }

        let role = match message.role {
            MessageRole::User => "user",
            MessageRole::Assistant => "assistant",
            MessageRole::Developer => "developer",
            MessageRole::System => "system",
        };
        let content = message
            .content
            .iter()
            .map(|part| self.content_input(part, &message.role))
            .collect::<Result<Vec<_>, _>>()?;
        let phase = message.phase.as_ref().map(|phase| match phase {
            MessagePhase::Commentary => CodexMessagePhase::Commentary,
            MessagePhase::FinalAnswer => CodexMessagePhase::FinalAnswer,
        });
        Ok(ResponseItem::Message {
            id: None,
            role: role.to_string(),
            content,
            phase,
            internal_chat_message_metadata_passthrough: None,
        })
    }

    fn content_input(
        &self,
        part: &ContentPart,
        role: &MessageRole,
    ) -> Result<ContentItem, CodexAdapterError> {
        match part {
            ContentPart::Text { text } if matches!(role, MessageRole::Assistant) => {
                Ok(ContentItem::OutputText { text: text.clone() })
            }
            ContentPart::Text { text } => Ok(ContentItem::InputText { text: text.clone() }),
            ContentPart::Attachment {
                attachment_id,
                media_type,
                kind,
            } => {
                if matches!(kind, AttachmentKind::File) {
                    return Err(CodexAdapterError::UnsupportedAttachment { kind: kind.clone() });
                }
                let materializer = self.attachment_materializer.ok_or_else(|| {
                    CodexAdapterError::MissingAttachmentMaterializer { kind: kind.clone() }
                })?;
                let materialized = materializer
                    .materialize(attachment_id, media_type, kind)
                    .ok_or_else(|| CodexAdapterError::UnmaterializedAttachment {
                        attachment_id: attachment_id.clone(),
                    })?;
                if materialized.source.is_empty() {
                    return Err(CodexAdapterError::EmptyMaterializedAttachment);
                }
                match kind {
                    AttachmentKind::Image => Ok(ContentItem::InputImage {
                        image_url: materialized.source,
                        detail: None,
                    }),
                    AttachmentKind::Audio => Ok(ContentItem::InputAudio {
                        audio_url: materialized.source,
                    }),
                    AttachmentKind::File => unreachable!("file attachment rejected above"),
                }
            }
        }
    }

    fn tool_input(&self, tool: &ToolRecord) -> Result<ResponseItem, CodexAdapterError> {
        let kind = string_field(tool, "kind")?;
        match (kind, &tool.phase) {
            ("function", ToolPhase::Requested) => Ok(ResponseItem::FunctionCall {
                id: None,
                name: tool.name.clone(),
                namespace: optional_string_field(tool, "namespace")?,
                arguments: string_field(tool, "arguments")?.to_string(),
                call_id: tool.call_id.clone(),
                internal_chat_message_metadata_passthrough: None,
            }),
            ("custom", ToolPhase::Requested) => Ok(ResponseItem::CustomToolCall {
                id: None,
                status: None,
                call_id: tool.call_id.clone(),
                name: tool.name.clone(),
                namespace: optional_string_field(tool, "namespace")?,
                input: string_field(tool, "input")?.to_string(),
                internal_chat_message_metadata_passthrough: None,
            }),
            ("function", ToolPhase::Completed | ToolPhase::Failed) => {
                Ok(ResponseItem::FunctionCallOutput {
                    id: None,
                    call_id: tool.call_id.clone(),
                    output: output_payload(tool)?,
                    internal_chat_message_metadata_passthrough: None,
                })
            }
            ("custom", ToolPhase::Completed | ToolPhase::Failed) => {
                Ok(ResponseItem::CustomToolCallOutput {
                    id: None,
                    call_id: tool.call_id.clone(),
                    name: (tool.name != "custom_tool").then(|| tool.name.clone()),
                    output: output_payload(tool)?,
                    internal_chat_message_metadata_passthrough: None,
                })
            }
            ("local_shell", _) => self.local_shell_input(tool),
            _ => Err(CodexAdapterError::UnsupportedToolRecord {
                call_id: tool.call_id.clone(),
                name: tool.name.clone(),
                phase: tool.phase.clone(),
            }),
        }
    }

    fn local_shell_input(&self, tool: &ToolRecord) -> Result<ResponseItem, CodexAdapterError> {
        let action = decode_field::<LocalShellAction>(tool, "action")?;
        let status = match tool.phase {
            ToolPhase::Requested => LocalShellStatus::InProgress,
            ToolPhase::Completed => LocalShellStatus::Completed,
            ToolPhase::Failed => LocalShellStatus::Incomplete,
        };
        Ok(ResponseItem::LocalShellCall {
            id: None,
            call_id: Some(tool.call_id.clone()),
            status,
            action,
            internal_chat_message_metadata_passthrough: None,
        })
    }

    fn opaque_input(
        &self,
        opaque: &ProviderOpaqueItem,
    ) -> Result<PreparedCodexInputItem, CodexAdapterError> {
        if opaque.lineage != self.lineage {
            return Err(CodexAdapterError::IncompatibleLineage {
                item_id: opaque.provider_item_id.clone(),
                expected: self.lineage.clone(),
                actual: opaque.lineage.clone(),
            });
        }

        if opaque.kind == "codex.inter_agent_communication" {
            let communication: InterAgentCommunication = from_slice(
                opaque.payload.as_bytes(),
                "decode opaque inter-agent communication",
            )?;
            return Ok(PreparedCodexInputItem::Typed {
                item: communication.to_model_input_item(),
                original_json: Some(opaque.payload.clone()),
            });
        }

        let response_item: ResponseItem =
            from_slice(opaque.payload.as_bytes(), "decode opaque response item")?;
        if matches!(response_item, ResponseItem::Other) {
            return Ok(PreparedCodexInputItem::RawOpaque {
                item_id: opaque.provider_item_id.clone(),
                kind: opaque.kind.clone(),
                payload: opaque.payload.clone(),
            });
        }
        let actual_kind = opaque_kind(&response_item);
        if actual_kind != opaque.kind {
            return Err(CodexAdapterError::OpaqueKindMismatch {
                item_id: opaque.provider_item_id.clone(),
                declared_kind: opaque.kind.clone(),
                actual_kind: actual_kind.to_string(),
            });
        }
        Ok(PreparedCodexInputItem::Typed {
            item: response_item,
            original_json: Some(OpaquePayload::new(opaque.payload.as_bytes().to_vec())),
        })
    }
}

fn string_field<'a>(
    tool: &'a ToolRecord,
    field: &'static str,
) -> Result<&'a str, CodexAdapterError> {
    tool.data
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_tool_data(tool, field, "expected a string"))
}

fn optional_string_field(
    tool: &ToolRecord,
    field: &'static str,
) -> Result<Option<String>, CodexAdapterError> {
    match tool.data.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid_tool_data(tool, field, "expected a string or null")),
    }
}

fn decode_field<T: DeserializeOwned>(
    tool: &ToolRecord,
    field: &'static str,
) -> Result<T, CodexAdapterError> {
    let value = tool
        .data
        .get(field)
        .cloned()
        .ok_or_else(|| invalid_tool_data(tool, field, "field is missing"))?;
    serde_json::from_value(value).map_err(|error| invalid_tool_data(tool, field, error.to_string()))
}

fn output_payload(tool: &ToolRecord) -> Result<FunctionCallOutputPayload, CodexAdapterError> {
    let body = decode_field::<FunctionCallOutputBody>(tool, "output")?;
    let success = match tool.data.get("success") {
        None | Some(Value::Null) => match tool.phase {
            ToolPhase::Failed => Some(false),
            ToolPhase::Completed => None,
            ToolPhase::Requested => unreachable!("requested outputs are rejected by the caller"),
        },
        Some(Value::Bool(success)) => Some(*success),
        Some(_) => {
            return Err(invalid_tool_data(
                tool,
                "success",
                "expected a boolean or null",
            ));
        }
    };
    if matches!(tool.phase, ToolPhase::Failed) && success != Some(false) {
        return Err(invalid_tool_data(
            tool,
            "success",
            "failed output must set success to false",
        ));
    }
    Ok(FunctionCallOutputPayload { body, success })
}

fn invalid_tool_data(
    tool: &ToolRecord,
    field: &'static str,
    message: impl Into<String>,
) -> CodexAdapterError {
    CodexAdapterError::InvalidToolData {
        call_id: tool.call_id.clone(),
        field,
        message: message.into(),
    }
}
