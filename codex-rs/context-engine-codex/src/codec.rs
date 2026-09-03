use codex_context_engine::ContextEventPayload;
use codex_context_engine::MessageRole;
use codex_context_engine::ModelContextItem;
use codex_context_engine::ModelContextPayload;
use codex_context_engine::ToolPhase;
use codex_protocol::models::ReasoningItemContent;
use codex_protocol::models::ResponseItem;
use serde::Serialize;
use serde_json::Value;

use crate::CodexAdapterError;

pub(crate) fn event_payload_to_model(
    payload: ContextEventPayload,
    fallback_id: String,
) -> Result<ModelContextItem, CodexAdapterError> {
    let (id, payload) = match payload {
        ContextEventPayload::Message(message) => {
            (fallback_id, ModelContextPayload::Message(message))
        }
        ContextEventPayload::Tool(tool) => (fallback_id, ModelContextPayload::Tool(tool)),
        ContextEventPayload::ProviderOpaque(opaque) => (
            opaque.provider_item_id.clone(),
            ModelContextPayload::ProviderOpaque(opaque),
        ),
        ContextEventPayload::Compaction(_) => {
            unreachable!("response items cannot nest checkpoints")
        }
    };
    Ok(ModelContextItem {
        id,
        source_sequence: None,
        payload,
    })
}

pub(crate) fn message_role(role: &str) -> Result<MessageRole, CodexAdapterError> {
    match role {
        "user" => Ok(MessageRole::User),
        "assistant" => Ok(MessageRole::Assistant),
        "developer" => Ok(MessageRole::Developer),
        "system" => Ok(MessageRole::System),
        role => Err(CodexAdapterError::UnsupportedRole {
            role: role.to_string(),
        }),
    }
}

pub(crate) fn output_phase(success: Option<bool>) -> ToolPhase {
    if success == Some(false) {
        ToolPhase::Failed
    } else {
        ToolPhase::Completed
    }
}

pub(crate) fn opaque_kind(item: &ResponseItem) -> &'static str {
    match item {
        ResponseItem::AdditionalTools { .. } => "codex.additional_tools",
        ResponseItem::Message { .. } => "codex.message",
        ResponseItem::AgentMessage { .. } => "codex.agent_message.encrypted",
        ResponseItem::Reasoning { .. } => "codex.reasoning",
        ResponseItem::ToolSearchCall { .. } => "codex.tool_search_call",
        ResponseItem::ToolSearchOutput { .. } => "codex.tool_search_output",
        ResponseItem::WebSearchCall { .. } => "codex.web_search_call",
        ResponseItem::ImageGenerationCall { .. } => "codex.image_generation_call",
        ResponseItem::Compaction { .. } => "codex.compaction",
        ResponseItem::ContextCompaction { .. } => "codex.context_compaction",
        ResponseItem::Other => "codex.unknown_response_item",
        ResponseItem::LocalShellCall { .. }
        | ResponseItem::FunctionCall { .. }
        | ResponseItem::FunctionCallOutput { .. }
        | ResponseItem::CustomToolCall { .. }
        | ResponseItem::CustomToolCallOutput { .. }
        | ResponseItem::CompactionTrigger { .. } => {
            unreachable!("semantic and request-control items are handled before opaque mapping")
        }
    }
}

/// Returns the typed value represented by Codex's provider serializer.
///
/// Codex deliberately omits locally retained reasoning text from provider
/// input. Keep that omission explicit so a lossless provider payload does not
/// require persisting the decrypted local-only field.
pub(crate) fn provider_serialization_view(item: &ResponseItem) -> ResponseItem {
    let mut view = item.clone();
    if let ResponseItem::Reasoning { content, .. } = &mut view
        && reasoning_content_is_omitted(content)
    {
        *content = None;
    }
    view
}

/// Restores fields intentionally excluded from provider serialization.
///
/// This is a transient exact-route sidecar: the values come from the current
/// in-memory source item and never enter the neutral event or its diagnostics.
pub(crate) fn restore_local_only_fields(source: &ResponseItem, rebuilt: &mut ResponseItem) {
    if let (
        ResponseItem::Reasoning {
            content: source_content,
            ..
        },
        ResponseItem::Reasoning {
            content: rebuilt_content,
            ..
        },
    ) = (source, rebuilt)
        && reasoning_content_is_omitted(source_content)
    {
        *rebuilt_content = source_content.clone();
    }
}

fn reasoning_content_is_omitted(content: &Option<Vec<ReasoningItemContent>>) -> bool {
    content.as_ref().is_some_and(|content| {
        !content
            .iter()
            .any(|part| matches!(part, ReasoningItemContent::ReasoningText { .. }))
    })
}

pub(crate) fn to_value<T: Serialize>(
    value: &T,
    operation: &'static str,
) -> Result<Value, CodexAdapterError> {
    serde_json::to_value(value).map_err(|error| CodexAdapterError::ProviderJson {
        operation,
        message: error.to_string(),
    })
}

pub(crate) fn to_vec<T: Serialize>(
    value: &T,
    operation: &'static str,
) -> Result<Vec<u8>, CodexAdapterError> {
    serde_json::to_vec(value).map_err(|error| CodexAdapterError::ProviderJson {
        operation,
        message: error.to_string(),
    })
}

pub(crate) fn from_slice<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    operation: &'static str,
) -> Result<T, CodexAdapterError> {
    serde_json::from_slice(bytes).map_err(|error| CodexAdapterError::ProviderJson {
        operation,
        message: error.to_string(),
    })
}
