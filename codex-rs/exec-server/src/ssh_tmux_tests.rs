use pretty_assertions::assert_eq;

use super::TmuxProcessDescriptor;
use super::stable_identifier;

#[test]
fn identifiers_are_stable_and_separate_agents() {
    assert_eq!(stable_identifier("agent-a"), "9c3f6a8a5ba885b0");
    assert_ne!(stable_identifier("agent-a"), stable_identifier("agent-b"));
}

#[test]
fn descriptor_uses_tmux_safe_names() {
    let descriptor = TmuxProcessDescriptor::new(
        "conversation:connection with spaces",
        "process/with:punctuation",
        true,
    );

    assert!(
        descriptor
            .session_name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    );
    assert!(
        descriptor
            .window_name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    );
}

#[test]
fn reconnect_monitor_starts_after_delivered_bytes() {
    let descriptor = TmuxProcessDescriptor::new("agent", "process", false);
    let command = descriptor.monitor_command(4_097);

    assert!(command.contains("offset=4097"));
    assert!(command.contains("count=$((bytes - offset + 1))"));
}
