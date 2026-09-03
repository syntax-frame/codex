use codex_context_engine::ContextEvent;
use codex_context_engine::ContextEventPayload;

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
