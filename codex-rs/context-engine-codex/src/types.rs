use codex_context_engine::ContextEvent;
use codex_context_engine::ContextEventPayload;
use codex_context_engine::OpaquePayload;
use codex_protocol::models::ResponseItem;
use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EventMetadata {
    pub event_id: String,
    pub conversation_id: String,
    pub turn_id: Option<String>,
    pub sequence: u64,
}

impl EventMetadata {
    pub(crate) fn into_event(self, payload: ContextEventPayload) -> ContextEvent {
        ContextEvent {
            id: self.event_id,
            conversation_id: self.conversation_id,
            turn_id: self.turn_id,
            sequence: self.sequence,
            payload,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IgnoredRolloutItem {
    SessionMetadata,
    DeliveryMetadata,
    RemoteExecutionPersistence,
    TurnReferenceContext,
    WorldState,
    PresentationEvent,
    RequestControl,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AdaptedRolloutItem {
    Event(Box<ContextEvent>),
    Ignored(IgnoredRolloutItem),
}

#[derive(Clone, PartialEq)]
pub enum PreparedCodexInputItem {
    /// A current Codex item. Opaque source JSON remains available so a raw
    /// transport can preserve the provider envelope byte-for-byte.
    Typed {
        item: ResponseItem,
        original_json: Option<OpaquePayload>,
    },
    /// A future Codex record that the current protocol crate cannot decode.
    RawOpaque {
        item_id: String,
        kind: String,
        payload: OpaquePayload,
    },
}

impl PreparedCodexInputItem {
    pub fn response_item(&self) -> Option<&ResponseItem> {
        match self {
            Self::Typed { item, .. } => Some(item),
            Self::RawOpaque { .. } => None,
        }
    }

    pub fn original_json(&self) -> Option<&[u8]> {
        match self {
            Self::Typed {
                original_json: Some(payload),
                ..
            }
            | Self::RawOpaque { payload, .. } => Some(payload.as_bytes()),
            Self::Typed {
                original_json: None,
                ..
            } => None,
        }
    }

    pub fn into_response_item(self) -> Result<ResponseItem, crate::CodexAdapterError> {
        match self {
            Self::Typed { item, .. } => Ok(item),
            Self::RawOpaque { item_id, .. } => {
                Err(crate::CodexAdapterError::RawTransportRequired { item_id })
            }
        }
    }
}

impl fmt::Debug for PreparedCodexInputItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Typed {
                item,
                original_json: None,
            } => formatter.debug_tuple("Typed").field(item).finish(),
            Self::Typed {
                original_json: Some(payload),
                ..
            } => formatter
                .debug_struct("TypedOpaque")
                .field("original_json", payload)
                .finish_non_exhaustive(),
            Self::RawOpaque {
                item_id,
                kind,
                payload,
            } => formatter
                .debug_struct("RawOpaque")
                .field("item_id", item_id)
                .field("kind", kind)
                .field("payload", payload)
                .finish(),
        }
    }
}
