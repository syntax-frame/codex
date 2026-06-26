use codex_protocol::ThreadId;
use codex_protocol::protocol::AgentCommunicationKind;
use codex_protocol::protocol::AgentCommunicationMetadata;
use codex_protocol::protocol::AgentCommunicationState;
use codex_protocol::protocol::InterAgentCommunication;
use uuid::Uuid;

const AGENT_COMMUNICATION_LOG_ENV: &str = "CODEX_AGENT_COMMUNICATION_LOG";

fn agent_communication_logging_enabled(value: Option<&std::ffi::OsStr>) -> bool {
    value == Some(std::ffi::OsStr::new("1"))
}

pub(crate) fn new_agent_communication_metadata(
    kind: AgentCommunicationKind,
    sender_thread_id: ThreadId,
    source_call_id: Option<&str>,
) -> Option<AgentCommunicationMetadata> {
    if !agent_communication_logging_enabled(
        std::env::var_os(AGENT_COMMUNICATION_LOG_ENV).as_deref(),
    ) {
        return None;
    }
    Some(build_agent_communication_metadata(
        kind,
        sender_thread_id,
        source_call_id,
    ))
}

fn build_agent_communication_metadata(
    kind: AgentCommunicationKind,
    sender_thread_id: ThreadId,
    source_call_id: Option<&str>,
) -> AgentCommunicationMetadata {
    AgentCommunicationMetadata {
        id: Uuid::new_v4().to_string(),
        kind,
        sender_thread_id,
        source_call_id: source_call_id.map(str::to_owned),
    }
}

pub(crate) fn emit_agent_communication_created(
    communication: &InterAgentCommunication,
    receiver_thread_id: ThreadId,
) {
    let Some(metadata) = communication.agent_communication_metadata.as_ref() else {
        return;
    };
    emit_agent_communication_event(
        metadata,
        AgentCommunicationState::Created,
        receiver_thread_id,
        communication_content(communication),
    );
}

fn emit_agent_communication_event(
    metadata: &AgentCommunicationMetadata,
    state: AgentCommunicationState,
    receiver_thread_id: ThreadId,
    content: &str,
) {
    tracing::event!(
        // Message content is emitted only when `CODEX_AGENT_COMMUNICATION_LOG=1`. You can opt into
        // this dedicated target with `RUST_LOG=warn,codex_agent_communication=info`.
        target: "codex_agent_communication",
        tracing::Level::INFO,
        {
            event.name = "codex.agent_communication",
            communication_id = %metadata.id,
            kind = metadata.kind.as_str(),
            state = state.as_str(),
            sender_thread_id = %metadata.sender_thread_id,
            receiver_thread_id = %receiver_thread_id,
            content,
            source_call_id = metadata.source_call_id.as_deref(),
        },
        "agent communication updated"
    );
}

pub(crate) fn emit_agent_communication_enqueued(metadata: AgentCommunicationMetadata) {
    tracing::event!(
        target: "codex_agent_communication",
        tracing::Level::INFO,
        {
            event.name = "codex.agent_communication",
            communication_id = %metadata.id,
            state = AgentCommunicationState::Enqueued.as_str(),
        },
        "agent communication updated"
    );
}

pub(crate) fn communication_content(communication: &InterAgentCommunication) -> &str {
    if communication.content.is_empty() {
        communication
            .encrypted_content
            .as_deref()
            .unwrap_or_default()
    } else {
        &communication.content
    }
}

#[cfg(test)]
#[path = "agent_communication_tests.rs"]
mod tests;
