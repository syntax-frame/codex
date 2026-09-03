use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ProviderLineage {
    pub provider: String,
    pub protocol: String,
    /// Adapter-defined compatibility identity. A model change may keep or
    /// replace this value depending on provider continuation rules.
    pub lineage_id: String,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpaquePayload(Vec<u8>);

impl OpaquePayload {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the exact bytes only for serialization by the owning adapter.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OpaquePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "<redacted opaque payload: {} bytes>",
            self.0.len()
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderOpaqueItem {
    pub lineage: ProviderLineage,
    pub provider_item_id: String,
    pub kind: String,
    pub payload: OpaquePayload,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    User,
    Assistant,
    Developer,
    System,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageVisibility {
    TranscriptAndModel,
    TranscriptOnly,
    ModelOnly,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessagePhase {
    Commentary,
    FinalAnswer,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDelivery {
    QueueOnly,
    TriggerTurn,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageRoute {
    pub author: String,
    pub recipients: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<MessageDelivery>,
}

impl MessageVisibility {
    fn includes_transcript(&self) -> bool {
        matches!(self, Self::TranscriptAndModel | Self::TranscriptOnly)
    }

    fn includes_model(&self) -> bool {
        matches!(self, Self::TranscriptAndModel | Self::ModelOnly)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentKind {
    Image,
    Audio,
    File,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text {
        text: String,
    },
    Attachment {
        attachment_id: String,
        media_type: String,
        kind: AttachmentKind,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: MessageRole,
    pub visibility: MessageVisibility,
    pub content: Vec<ContentPart>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<MessagePhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<MessageRoute>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPhase {
    Requested,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolRecord {
    pub call_id: String,
    pub name: String,
    pub phase: ToolPhase,
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ModelContextPayload {
    Message(Message),
    Tool(ToolRecord),
    ProviderOpaque(ProviderOpaqueItem),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelContextItem {
    pub id: String,
    pub source_sequence: Option<u64>,
    pub payload: ModelContextPayload,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactionMode {
    Semantic,
    ProviderNative,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextCheckpoint {
    pub id: String,
    pub conversation_id: String,
    pub through_sequence: u64,
    /// None is a provider-neutral semantic checkpoint. Native checkpoints are
    /// usable only by the exact adapter-defined lineage.
    pub lineage: Option<ProviderLineage>,
    pub mode: CompactionMode,
    pub replacement: Vec<ModelContextItem>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ContextEventPayload {
    Message(Message),
    Tool(ToolRecord),
    ProviderOpaque(ProviderOpaqueItem),
    Compaction(ContextCheckpoint),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextEvent {
    pub id: String,
    pub conversation_id: String,
    pub turn_id: Option<String>,
    pub sequence: u64,
    pub payload: ContextEventPayload,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContextProjection {
    pub transcript: Vec<ContextEvent>,
    pub model_context: Vec<ModelContextItem>,
    pub excluded_opaque_event_ids: Vec<String>,
    pub checkpoint_id: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ForkRequest {
    pub source_conversation_id: String,
    pub target_conversation_id: String,
    pub through_sequence: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ForkSeed {
    pub source_conversation_id: String,
    pub target_conversation_id: String,
    pub forked_at_sequence: u64,
    pub transcript: Vec<ContextEvent>,
    pub model_context: Vec<ModelContextItem>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ContextContractError {
    #[error("{field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("event {event_id} belongs to {actual}, expected {expected}")]
    ConversationMismatch {
        event_id: String,
        expected: String,
        actual: String,
    },
    #[error("event sequence {current} must be greater than {previous}")]
    NonIncreasingSequence { previous: u64, current: u64 },
    #[error("duplicate event id {event_id}")]
    DuplicateEventId { event_id: String },
    #[error("checkpoint {checkpoint_id} is invalid: {reason}")]
    InvalidCheckpoint {
        checkpoint_id: String,
        reason: String,
    },
    #[error("fork sequence {through_sequence} exceeds available sequence {last_sequence}")]
    ForkOutOfRange {
        through_sequence: u64,
        last_sequence: u64,
    },
}

pub fn validate_events(events: &[ContextEvent]) -> Result<(), ContextContractError> {
    let Some(first) = events.first() else {
        return Ok(());
    };
    require_nonempty(&first.conversation_id, "conversation_id")?;

    let mut previous = 0;
    let mut ids = HashSet::new();
    for event in events {
        require_nonempty(&event.id, "event_id")?;
        if event.conversation_id != first.conversation_id {
            return Err(ContextContractError::ConversationMismatch {
                event_id: event.id.clone(),
                expected: first.conversation_id.clone(),
                actual: event.conversation_id.clone(),
            });
        }
        if event.sequence <= previous {
            return Err(ContextContractError::NonIncreasingSequence {
                previous,
                current: event.sequence,
            });
        }
        previous = event.sequence;
        if !ids.insert(event.id.as_str()) {
            return Err(ContextContractError::DuplicateEventId {
                event_id: event.id.clone(),
            });
        }
        validate_event(event)?;
    }
    Ok(())
}

pub fn project_context(
    events: &[ContextEvent],
    target: &ProviderLineage,
) -> Result<ContextProjection, ContextContractError> {
    validate_events(events)?;

    let transcript = events
        .iter()
        .filter(|event| {
            matches!(
                &event.payload,
                ContextEventPayload::Message(message) if message.visibility.includes_transcript()
            )
        })
        .cloned()
        .collect();

    let checkpoint = events.iter().rev().find_map(|event| {
        let ContextEventPayload::Compaction(checkpoint) = &event.payload else {
            return None;
        };
        checkpoint
            .lineage
            .as_ref()
            .is_none_or(|lineage| lineage == target)
            .then_some(checkpoint)
    });

    let mut excluded_opaque_event_ids = Vec::new();
    let mut model_context = Vec::new();
    let through_sequence = if let Some(checkpoint) = checkpoint {
        for item in &checkpoint.replacement {
            push_compatible_item(
                item.clone(),
                target,
                &mut model_context,
                &mut excluded_opaque_event_ids,
            );
        }
        checkpoint.through_sequence
    } else {
        0
    };

    for event in events
        .iter()
        .filter(|event| event.sequence > through_sequence)
    {
        let Some(item) = event_model_item(event) else {
            continue;
        };
        push_compatible_item(
            item,
            target,
            &mut model_context,
            &mut excluded_opaque_event_ids,
        );
    }

    Ok(ContextProjection {
        transcript,
        model_context,
        excluded_opaque_event_ids,
        checkpoint_id: checkpoint.map(|checkpoint| checkpoint.id.clone()),
    })
}

pub fn prepare_fork(
    events: &[ContextEvent],
    request: &ForkRequest,
    target: &ProviderLineage,
) -> Result<ForkSeed, ContextContractError> {
    validate_events(events)?;
    let last_sequence = events.last().map_or(0, |event| event.sequence);
    if request.through_sequence > last_sequence {
        return Err(ContextContractError::ForkOutOfRange {
            through_sequence: request.through_sequence,
            last_sequence,
        });
    }

    let source: Vec<_> = events
        .iter()
        .filter(|event| event.sequence <= request.through_sequence)
        .cloned()
        .collect();
    if let Some(event) = source.first()
        && event.conversation_id != request.source_conversation_id
    {
        return Err(ContextContractError::ConversationMismatch {
            event_id: event.id.clone(),
            expected: request.source_conversation_id.clone(),
            actual: event.conversation_id.clone(),
        });
    }
    let projection = project_context(&source, target)?;
    Ok(ForkSeed {
        source_conversation_id: request.source_conversation_id.clone(),
        target_conversation_id: request.target_conversation_id.clone(),
        forked_at_sequence: request.through_sequence,
        transcript: projection.transcript,
        model_context: projection.model_context,
    })
}

fn require_nonempty(value: &str, field: &'static str) -> Result<(), ContextContractError> {
    if value.is_empty() {
        return Err(ContextContractError::EmptyField { field });
    }
    Ok(())
}

fn validate_event(event: &ContextEvent) -> Result<(), ContextContractError> {
    match &event.payload {
        ContextEventPayload::Message(message) => {
            if message.content.is_empty() {
                return Err(ContextContractError::EmptyField {
                    field: "message.content",
                });
            }
        }
        ContextEventPayload::Tool(tool) => {
            require_nonempty(&tool.call_id, "tool.call_id")?;
            require_nonempty(&tool.name, "tool.name")?;
        }
        ContextEventPayload::ProviderOpaque(item) => validate_opaque(item)?,
        ContextEventPayload::Compaction(checkpoint) => {
            require_nonempty(&checkpoint.id, "checkpoint.id")?;
            if checkpoint.conversation_id != event.conversation_id {
                return Err(ContextContractError::InvalidCheckpoint {
                    checkpoint_id: checkpoint.id.clone(),
                    reason: "conversation does not match its event".to_string(),
                });
            }
            if checkpoint.through_sequence >= event.sequence {
                return Err(ContextContractError::InvalidCheckpoint {
                    checkpoint_id: checkpoint.id.clone(),
                    reason: "through_sequence must precede the checkpoint event".to_string(),
                });
            }
            if matches!(checkpoint.mode, CompactionMode::ProviderNative)
                != checkpoint.lineage.is_some()
            {
                return Err(ContextContractError::InvalidCheckpoint {
                    checkpoint_id: checkpoint.id.clone(),
                    reason: "native checkpoints require lineage; semantic checkpoints forbid it"
                        .to_string(),
                });
            }
            for item in &checkpoint.replacement {
                if let ModelContextPayload::ProviderOpaque(opaque) = &item.payload {
                    validate_opaque(opaque)?;
                    if checkpoint.lineage.as_ref() != Some(&opaque.lineage) {
                        return Err(ContextContractError::InvalidCheckpoint {
                            checkpoint_id: checkpoint.id.clone(),
                            reason: "opaque replacement does not match checkpoint lineage"
                                .to_string(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_opaque(item: &ProviderOpaqueItem) -> Result<(), ContextContractError> {
    require_nonempty(&item.provider_item_id, "provider_opaque.provider_item_id")?;
    require_nonempty(&item.kind, "provider_opaque.kind")?;
    require_nonempty(&item.lineage.provider, "provider_lineage.provider")?;
    require_nonempty(&item.lineage.protocol, "provider_lineage.protocol")?;
    require_nonempty(&item.lineage.lineage_id, "provider_lineage.lineage_id")?;
    if item.payload.as_bytes().is_empty() {
        return Err(ContextContractError::EmptyField {
            field: "provider_opaque.payload",
        });
    }
    Ok(())
}

fn event_model_item(event: &ContextEvent) -> Option<ModelContextItem> {
    let payload = match &event.payload {
        ContextEventPayload::Message(message) if message.visibility.includes_model() => {
            ModelContextPayload::Message(message.clone())
        }
        ContextEventPayload::Tool(tool) => ModelContextPayload::Tool(tool.clone()),
        ContextEventPayload::ProviderOpaque(item) => {
            ModelContextPayload::ProviderOpaque(item.clone())
        }
        ContextEventPayload::Message(_) | ContextEventPayload::Compaction(_) => return None,
    };
    Some(ModelContextItem {
        id: event.id.clone(),
        source_sequence: Some(event.sequence),
        payload,
    })
}

fn push_compatible_item(
    item: ModelContextItem,
    target: &ProviderLineage,
    output: &mut Vec<ModelContextItem>,
    excluded: &mut Vec<String>,
) {
    if matches!(
        &item.payload,
        ModelContextPayload::ProviderOpaque(opaque) if &opaque.lineage != target
    ) {
        excluded.push(item.id);
    } else {
        output.push(item);
    }
}
