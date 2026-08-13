use super::*;
use crate::config::test_config;
use crate::init_state_db;
use crate::installation_id::INSTALLATION_ID_FILENAME;
use crate::rollout::RolloutRecorder;
use crate::session::session::SessionSettingsUpdate;
use crate::session::tests::build_world_state_from_turn_context;
use crate::session::tests::make_session_and_context;
use crate::tasks::InterruptedTurnHistoryMarker;
use crate::tasks::interrupted_turn_history_marker;
use codex_extension_api::empty_extension_registry;
use codex_models_manager::manager::RefreshStrategy;
use codex_protocol::ResponseItemId;
use codex_protocol::capabilities::CapabilityRootLocation;
use codex_protocol::capabilities::SelectedCapabilityRoot;
use codex_protocol::models::ContentItem;
use codex_protocol::models::FunctionCallOutputBody;
use codex_protocol::models::FunctionCallOutputPayload;
use codex_protocol::models::MessagePhase;
use codex_protocol::models::ReasoningItemReasoningSummary;
use codex_protocol::models::ResponseItem;
use codex_protocol::openai_models::ModelsResponse;
use codex_protocol::plan_tool::PlanItemArg;
use codex_protocol::plan_tool::StepStatus;
use codex_protocol::plan_tool::UpdatePlanArgs;
use codex_protocol::protocol::AgentMessageEvent;
use codex_protocol::protocol::InitialHistory;
use codex_protocol::protocol::InternalSessionSource;
use codex_protocol::protocol::RemoteExecutionLaunchIntent;
use codex_protocol::protocol::RemoteExecutionProtocolMarker;
use codex_protocol::protocol::RemoteExecutionReceiptKind;
use codex_protocol::protocol::RemoteExecutionRejectionReason;
use codex_protocol::protocol::RemoteExecutionSessionCommitted;
use codex_protocol::protocol::RemoteExecutionSessionPrepared;
use codex_protocol::protocol::RemoteExecutionWriteIntent;
use codex_protocol::protocol::RemoteExecutionWriteRequest;
use codex_protocol::protocol::ResumedHistory;
use codex_protocol::protocol::SessionMeta;
use codex_protocol::protocol::SessionMetaLine;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::protocol::ThreadSource;
use codex_protocol::protocol::TruncationPolicy;
use codex_protocol::protocol::TurnCompleteEvent;
use codex_protocol::protocol::TurnStartedEvent;
use codex_protocol::protocol::UserMessageEvent;
use codex_utils_path_uri::PathUri;
use core_test_support::PathBufExt;
use core_test_support::PathExt;
use core_test_support::responses::mount_models_once;
use core_test_support::responses::strip_response_item_ids_from_json;
use pretty_assertions::assert_eq;
use sha2::Digest;
use sha2::Sha256;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tempfile::tempdir;
use wiremock::MockServer;

const TEST_INSTALLATION_ID: &str = "11111111-1111-4111-8111-111111111111";

#[test]
fn rollout_read_error_mapping_preserves_typed_loader_source() {
    let error = thread_store_rollout_read_error(ThreadStoreError::RolloutRead {
        source: std::io::Error::other(codex_rollout::RolloutReadError::MalformedJson { record: 7 }),
    });
    let CodexErr::Io(source) = error else {
        panic!("rollout read failure must remain typed I/O");
    };
    assert!(matches!(
        codex_rollout::rollout_read_error(&source),
        Some(codex_rollout::RolloutReadError::MalformedJson { record: 7 })
    ));
}

fn scanner_call(name: &str, call_id: &str, turn_id: &str, arguments: &str) -> RolloutItem {
    let mut item = ResponseItem::FunctionCall {
        id: None,
        name: name.to_string(),
        namespace: None,
        arguments: arguments.to_string(),
        call_id: call_id.to_string(),
        internal_chat_message_metadata_passthrough: None,
    };
    item.set_turn_id_if_missing(turn_id);
    RolloutItem::ResponseItem(item)
}

fn scanner_output(call_id: &str, turn_id: &str) -> RolloutItem {
    let mut item = ResponseItem::FunctionCallOutput {
        id: None,
        call_id: call_id.to_string(),
        output: FunctionCallOutputPayload::from_text("done".to_string()),
        internal_chat_message_metadata_passthrough: None,
    };
    item.set_turn_id_if_missing(turn_id);
    RolloutItem::ResponseItem(item)
}

fn scanner_marker_with_stdin_intent(
    thread_id: &str,
    turn_id: &str,
    protocol_version: u32,
    stdin_intent_before_write: bool,
) -> RolloutItem {
    RolloutItem::RemoteExecutionProtocolMarker(RemoteExecutionProtocolMarker {
        thread_id: thread_id.to_string(),
        turn_id: turn_id.to_string(),
        protocol_version,
        identity_schema: "thread-turn-call-generation".to_string(),
        descriptor_before_go: true,
        stdin_intent_before_write,
    })
}

fn scanner_marker(thread_id: &str, turn_id: &str, protocol_version: u32) -> RolloutItem {
    scanner_marker_with_stdin_intent(thread_id, turn_id, protocol_version, true)
}

fn scanner_launch_intent(
    thread_id: &str,
    turn_id: &str,
    call_id: &str,
    generation: u32,
    digest: &str,
) -> RolloutItem {
    RolloutItem::RemoteExecutionLaunchIntent(RemoteExecutionLaunchIntent {
        thread_id: thread_id.to_string(),
        turn_id: turn_id.to_string(),
        call_id: call_id.to_string(),
        attempt_generation: generation,
        command_digest: digest.to_string(),
        original_session_id: 4242,
        tty: false,
    })
}

fn scanner_committed_session(
    thread_id: &str,
    session_id: i32,
    command_digest: &str,
    cursor: u64,
) -> RolloutItem {
    RolloutItem::RemoteExecutionSessionCommitted(RemoteExecutionSessionCommitted {
        thread_id: thread_id.to_string(),
        exec_turn_id: "exec-turn".to_string(),
        exec_call_id: "exec-call".to_string(),
        receipt_turn_id: "exec-turn".to_string(),
        receipt_call_id: "exec-call".to_string(),
        receipt_kind: RemoteExecutionReceiptKind::InitialExec,
        attempt_generation: 0,
        session_id,
        command_digest: command_digest.to_string(),
        range_start: 0,
        range_end: cursor,
        receipt_output_digest: "receipt-output".to_string(),
        prepared_receipt_digest: "prepared-receipt".to_string(),
        rejection_reason: None,
        rejection_write_id: None,
        rejection_input_sha256: None,
        terminal_acknowledgement_token: None,
        terminal_output_digest: None,
        terminal_status: None,
        terminal: false,
    })
}

fn scanner_write_intent(
    thread_id: &str,
    turn_id: &str,
    call_id: &str,
    session_id: i32,
    command_digest: &str,
    cursor: u64,
    input: &str,
) -> RolloutItem {
    let input_sha256 = Sha256::digest(input.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    RolloutItem::RemoteExecutionWriteIntent(RemoteExecutionWriteIntent {
        thread_id: thread_id.to_string(),
        exec_turn_id: "exec-turn".to_string(),
        exec_call_id: "exec-call".to_string(),
        receipt_turn_id: turn_id.to_string(),
        receipt_call_id: call_id.to_string(),
        attempt_generation: 0,
        session_id,
        command_digest: command_digest.to_string(),
        committed_output_cursor: cursor,
        write_id: "a".repeat(64),
        input_sha256,
        input_len: input.len() as u64,
    })
}

fn scanner_write_request(
    thread_id: &str,
    turn_id: &str,
    call_id: &str,
    session_id: i32,
    command_digest: &str,
    cursor: u64,
    input: &str,
) -> RolloutItem {
    let input_sha256 = Sha256::digest(input.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    RolloutItem::RemoteExecutionWriteRequest(RemoteExecutionWriteRequest {
        thread_id: thread_id.to_string(),
        exec_turn_id: "exec-turn".to_string(),
        exec_call_id: "exec-call".to_string(),
        receipt_turn_id: turn_id.to_string(),
        receipt_call_id: call_id.to_string(),
        attempt_generation: 0,
        session_id,
        command_digest: command_digest.to_string(),
        committed_output_cursor: cursor,
        input_sha256,
        input_len: input.len() as u64,
        yield_time_ms: crate::unified_exec::MIN_YIELD_TIME_MS,
        max_output_tokens: None,
        truncation_policy: TruncationPolicy::Bytes(2_048),
    })
}

#[test]
fn scanner_uses_only_unique_exact_post_call_launch_intent() {
    let request = ThreadManager::scan_active_remote_calls(
        "thread".to_string(),
        &[
            scanner_marker("thread", "turn", 2),
            scanner_call("exec_command", "exec", "turn", "{}"),
            scanner_launch_intent("thread", "turn", "exec", 0, "digest-0"),
        ],
    )
    .expect("scan");
    assert_eq!(
        request.incomplete_executions[0]
            .expected_command_digest
            .as_deref(),
        Some("digest-0")
    );
    assert_eq!(
        request.incomplete_executions[1].expected_command_digest,
        None
    );
    assert_eq!(
        request.incomplete_executions[0].expected_session_id,
        Some(4242)
    );
    assert_eq!(request.incomplete_executions[0].expected_tty, Some(false));
}

#[test]
fn scanner_rejects_late_duplicate_conflicting_or_wrong_identity_intent_authority() {
    for intents in [
        vec![
            scanner_launch_intent("thread", "turn", "exec", 0, "digest-a"),
            scanner_launch_intent("thread", "turn", "exec", 0, "digest-a"),
        ],
        vec![
            scanner_launch_intent("thread", "turn", "exec", 0, "digest-a"),
            scanner_launch_intent("thread", "turn", "exec", 0, "digest-b"),
        ],
        vec![scanner_launch_intent(
            "other-thread",
            "turn",
            "exec",
            0,
            "digest-a",
        )],
    ] {
        let mut history = vec![
            scanner_marker("thread", "turn", 2),
            scanner_call("exec_command", "exec", "turn", "{}"),
        ];
        history.extend(intents);
        ThreadManager::scan_active_remote_calls("thread".to_string(), &history)
            .expect_err("invalid launch intent must fail closed");
    }

    ThreadManager::scan_active_remote_calls(
        "thread".to_string(),
        &[
            scanner_marker("thread", "turn", 2),
            scanner_launch_intent("thread", "turn", "exec", 0, "too-early"),
            scanner_call("exec_command", "exec", "turn", "{}"),
        ],
    )
    .expect_err("early launch intent must fail closed");
}

#[test]
fn active_tail_scanner_requires_valid_marker_before_each_supported_call() {
    let valid = ThreadManager::scan_active_remote_calls(
        "thread".to_string(),
        &[
            scanner_marker("thread", "turn", 2),
            scanner_call("exec_command", "exec", "turn", "{}"),
        ],
    )
    .expect("valid marker");
    assert!(valid.incomplete_executions.iter().all(|slot| {
        slot.protocol_evidence == codex_exec_server::RemoteExecutionProtocolEvidence::V2Proven
    }));

    for history in [
        vec![scanner_call("exec_command", "legacy", "turn", "{}")],
        vec![
            scanner_call("exec_command", "late", "turn", "{}"),
            scanner_marker("thread", "turn", 2),
        ],
        vec![
            scanner_marker("thread", "turn", 99),
            scanner_call("exec_command", "unknown", "turn", "{}"),
        ],
        vec![
            scanner_marker("thread", "turn", 2),
            scanner_call("exec_command", "duplicate", "turn", "{}"),
            scanner_marker("thread", "turn", 2),
        ],
        vec![
            scanner_marker("thread", "turn", 2),
            scanner_call("exec_command", "conflict", "turn", "{}"),
            scanner_marker("thread", "turn", 99),
        ],
    ] {
        let request =
            ThreadManager::scan_active_remote_calls("thread".to_string(), &history).expect("scan");
        assert!(request.incomplete_executions.iter().all(|slot| {
            slot.protocol_evidence
                == codex_exec_server::RemoteExecutionProtocolEvidence::LegacyUnknown
        }));
    }
}

#[test]
fn marker_conflict_is_turn_local_and_late_marker_never_backfills_evidence() {
    let request = ThreadManager::scan_active_remote_calls(
        "thread".to_string(),
        &[
            scanner_marker("thread", "old-turn", 2),
            scanner_marker("thread", "old-turn", 99),
            scanner_call("exec_command", "old", "old-turn", "{}"),
            scanner_output("old", "old-turn"),
            scanner_call("exec_command", "late", "new-turn", "{}"),
            scanner_marker("thread", "new-turn", 2),
        ],
    )
    .expect("turn-local marker classification");
    assert!(request.incomplete_executions.iter().all(|slot| {
        slot.call_id == "late"
            && slot.protocol_evidence
                == codex_exec_server::RemoteExecutionProtocolEvidence::LegacyUnknown
    }));

    let request = ThreadManager::scan_active_remote_calls(
        "thread".to_string(),
        &[
            scanner_marker("thread", "poisoned", 2),
            scanner_marker("thread", "poisoned", 2),
            scanner_marker("thread", "clean", 2),
            scanner_call("exec_command", "clean-call", "clean", "{}"),
        ],
    )
    .expect("old turn conflict must not poison clean turn");
    assert!(request.incomplete_executions.iter().all(|slot| {
        slot.call_id == "clean-call"
            && slot.protocol_evidence
                == codex_exec_server::RemoteExecutionProtocolEvidence::V2Proven
    }));
}

#[test]
fn clean_legacy_history_can_start_a_new_marked_turn() {
    let request = ThreadManager::scan_active_remote_calls(
        "thread".to_string(),
        &[
            scanner_call("exec_command", "old", "old-turn", "{}"),
            scanner_output("old", "old-turn"),
            scanner_marker("thread", "new-turn", 2),
            scanner_call("exec_command", "new", "new-turn", "{}"),
        ],
    )
    .expect("clean legacy history may migrate at a new turn");
    assert!(request.incomplete_executions.iter().all(|slot| {
        slot.call_id == "new"
            && slot.protocol_evidence
                == codex_exec_server::RemoteExecutionProtocolEvidence::V2Proven
    }));
}

#[test]
fn active_tail_scanner_supports_exec_and_preserves_write_interaction() {
    let history = vec![
        scanner_call("unrelated", "ignored", "turn-1", "{}"),
        scanner_call("exec_command", "exec", "turn-1", "{}"),
        scanner_call(
            "write_stdin",
            "write",
            "turn-1",
            r#"{"session_id":42,"chars":""}"#,
        ),
    ];
    let request =
        ThreadManager::scan_active_remote_calls("thread".to_string(), &history).expect("scan");

    assert_eq!(request.incomplete_executions.len(), 2);
    assert!(
        request
            .incomplete_executions
            .iter()
            .all(|slot| slot.call_id == "exec")
    );
    assert_eq!(request.pending_writes.len(), 1);
    assert_eq!(request.pending_writes[0].call_id, "write");
    assert_eq!(request.pending_writes[0].turn_id, "turn-1");
    assert_eq!(request.pending_writes[0].session_id, 42);
    assert!(request.pending_writes[0].input_is_empty);
    assert!(!request.pending_writes[0].pre_send_intent_required);
    assert!(!request.pending_writes[0].pre_send_intent_persisted);
}

#[test]
fn scanner_classifies_build121_nonempty_stdin_intent_exactly() {
    let input = "continue\n";
    let base = vec![
        scanner_committed_session("thread", 42, "command-digest", 17),
        scanner_marker("thread", "write-turn", 2),
        scanner_call(
            "write_stdin",
            "write-call",
            "write-turn",
            r#"{"session_id":42,"chars":"continue\n"}"#,
        ),
    ];

    let without_intent =
        ThreadManager::scan_active_remote_calls("thread".to_string(), &base).expect("scan");
    assert_eq!(without_intent.pending_writes.len(), 1);
    assert!(without_intent.pending_writes[0].pre_send_intent_required);
    assert!(!without_intent.pending_writes[0].pre_send_intent_persisted);

    let mut with_intent = base.clone();
    with_intent.push(scanner_write_request(
        "thread",
        "write-turn",
        "write-call",
        42,
        "command-digest",
        17,
        input,
    ));
    with_intent.push(scanner_write_intent(
        "thread",
        "write-turn",
        "write-call",
        42,
        "command-digest",
        17,
        input,
    ));
    let request =
        ThreadManager::scan_active_remote_calls("thread".to_string(), &with_intent).expect("scan");
    assert!(request.pending_writes[0].pre_send_intent_required);
    assert!(request.pending_writes[0].pre_send_intent_persisted);

    let mut conflicting = base;
    conflicting.push(scanner_write_request(
        "thread",
        "write-turn",
        "write-call",
        42,
        "command-digest",
        17,
        input,
    ));
    conflicting.push(scanner_write_intent(
        "thread",
        "write-turn",
        "write-call",
        42,
        "command-digest",
        17,
        "different\n",
    ));
    ThreadManager::scan_active_remote_calls("thread".to_string(), &conflicting)
        .expect_err("conflicting stdin intent must fail closed");
}

#[test]
fn scanner_never_classifies_a_persisted_remote_interrupt_as_proven_unsent() {
    let input = "\u{3}";
    let arguments = serde_json::json!({
        "session_id": 42,
        "chars": input,
    })
    .to_string();
    let history = vec![
        scanner_committed_session("thread", 42, "command-digest", 17),
        scanner_marker("thread", "interrupt-turn", 2),
        scanner_call(
            "write_stdin",
            "interrupt-call",
            "interrupt-turn",
            &arguments,
        ),
        scanner_write_request(
            "thread",
            "interrupt-turn",
            "interrupt-call",
            42,
            "command-digest",
            17,
            input,
        ),
        scanner_write_intent(
            "thread",
            "interrupt-turn",
            "interrupt-call",
            42,
            "command-digest",
            17,
            input,
        ),
    ];

    let request =
        ThreadManager::scan_active_remote_calls("thread".to_string(), &history).expect("scan");
    assert_eq!(request.pending_writes.len(), 1);
    assert!(!request.pending_writes[0].input_is_empty);
    assert!(request.pending_writes[0].pre_send_intent_required);
    assert!(
        request.pending_writes[0].pre_send_intent_persisted,
        "restart must take delivery-unknown recovery and never send a second interrupt"
    );
}

struct ResumeRepairBackend {
    reconcile_calls: Arc<AtomicUsize>,
    start_calls: Arc<AtomicUsize>,
    adopt_calls: Arc<AtomicUsize>,
    write_calls: Arc<AtomicUsize>,
    signal_calls: Arc<AtomicUsize>,
    terminate_calls: Arc<AtomicUsize>,
}

struct ResumeRepairProcess {
    process_id: codex_exec_server::ProcessId,
    write_calls: Arc<AtomicUsize>,
    signal_calls: Arc<AtomicUsize>,
    terminate_calls: Arc<AtomicUsize>,
    wake_tx: tokio::sync::watch::Sender<u64>,
}

impl codex_exec_server::ExecProcess for ResumeRepairProcess {
    fn process_id(&self) -> &codex_exec_server::ProcessId {
        &self.process_id
    }

    fn subscribe_wake(&self) -> tokio::sync::watch::Receiver<u64> {
        self.wake_tx.subscribe()
    }

    fn subscribe_events(&self) -> codex_exec_server::ExecProcessEventReceiver {
        codex_exec_server::ExecProcessEventReceiver::empty()
    }

    fn read(
        &self,
        _after_seq: Option<u64>,
        _max_bytes: Option<usize>,
        _wait_ms: Option<u64>,
    ) -> codex_exec_server::ExecProcessFuture<'_, codex_exec_server::ReadResponse> {
        Box::pin(async {
            Ok(codex_exec_server::ReadResponse {
                chunks: Vec::new(),
                next_seq: 1,
                exited: false,
                exit_code: None,
                closed: false,
                failure: None,
                sandbox_denied: false,
            })
        })
    }

    fn write(
        &self,
        _chunk: Vec<u8>,
    ) -> codex_exec_server::ExecProcessFuture<'_, codex_exec_server::WriteResponse> {
        self.write_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(codex_exec_server::WriteResponse {
                status: codex_exec_server::WriteStatus::Accepted,
            })
        })
    }

    fn signal(
        &self,
        _signal: codex_exec_server::ProcessSignal,
    ) -> codex_exec_server::ExecProcessFuture<'_, codex_exec_server::ProcessSignalOutcome> {
        self.signal_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(codex_exec_server::ProcessSignalOutcome::Accepted) })
    }

    fn terminate(&self) -> codex_exec_server::ExecProcessFuture<'_, ()> {
        self.terminate_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

impl codex_exec_server::ExecBackend for ResumeRepairBackend {
    fn start(
        &self,
        _params: codex_exec_server::ExecParams,
    ) -> codex_exec_server::ExecBackendFuture<'_> {
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(codex_exec_server::ExecServerError::Protocol(
                "resume repair must not launch a process".to_string(),
            ))
        })
    }

    fn adopt_execution(
        &self,
        request: codex_exec_server::AdoptionRequest,
    ) -> codex_exec_server::ExecBackendFuture<'_> {
        self.adopt_calls.fetch_add(1, Ordering::SeqCst);
        let write_calls = Arc::clone(&self.write_calls);
        let signal_calls = Arc::clone(&self.signal_calls);
        let terminate_calls = Arc::clone(&self.terminate_calls);
        Box::pin(async move {
            if request.identity.turn_id != "exec-turn"
                || request.identity.call_id != "exec-call"
                || request.identity.attempt_generation != 0
                || request.expected_command_digest != "command-digest"
                || request.original_session_id != Some(42)
                || request.committed_output_cursor != 17
                || !request.tty
            {
                return Err(codex_exec_server::ExecServerError::Protocol(
                    "resume fixture received conflicting adoption authority".to_string(),
                ));
            }
            let (wake_tx, _wake_rx) = tokio::sync::watch::channel(0);
            Ok(codex_exec_server::StartedExecProcess {
                process: Arc::new(ResumeRepairProcess {
                    process_id: "42".to_string().into(),
                    write_calls,
                    signal_calls,
                    terminate_calls,
                    wake_tx,
                }),
            })
        })
    }

    fn reconcile(
        &self,
        request: codex_exec_server::ReconciliationRequest,
    ) -> codex_exec_server::ExecBackendReconcileFuture<'_> {
        self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if request.incomplete_executions.len() != 1 || !request.pending_writes.is_empty() {
                return Err(codex_exec_server::ExecServerError::Protocol(
                    "resume fixture expected one execution and no signal replay".to_string(),
                ));
            }
            let incomplete = request
                .incomplete_executions
                .into_iter()
                .next()
                .expect("length checked");
            let output = b"process running\r\n".to_vec();
            if incomplete.turn_id != "exec-turn"
                || incomplete.call_id != "exec-call"
                || incomplete.attempt_generation != 0
                || incomplete.expected_command_digest.as_deref() != Some("command-digest")
                || incomplete.expected_session_id != Some(42)
                || incomplete.expected_tty != Some(true)
            {
                return Err(codex_exec_server::ExecServerError::Protocol(
                    "resume fixture received conflicting reconciliation authority".to_string(),
                ));
            }
            let status = codex_exec_server::RecoveredExecutionStatus::RecoveryLost;
            let output_sha256 = format!("{:x}", Sha256::digest(&output));
            Ok(vec![codex_exec_server::RecoveredExecution {
                identity: codex_exec_server::ExecutionIdentity {
                    thread_id: request.thread_id,
                    turn_id: incomplete.turn_id,
                    call_id: incomplete.call_id,
                    attempt_generation: incomplete.attempt_generation,
                },
                command_digest: incomplete.expected_command_digest,
                committed_output_cursor: output.len() as u64,
                output,
                status: status.clone(),
                terminal_verified_dead: true,
                session_id: incomplete.expected_session_id,
                delivery_unknown: false,
                acknowledgement: codex_exec_server::RecoveredExecutionAcknowledgement::new(
                    "resume-fixture-terminal-proof".to_string(),
                )
                .with_terminal_proof(
                    codex_exec_server::TerminalAcknowledgementProof {
                        range_start: 0,
                        range_end: 17,
                        output_sha256,
                        status,
                    },
                ),
            }])
        })
    }
}

fn resume_repair_commit(
    prepared: &RemoteExecutionSessionPrepared,
) -> RemoteExecutionSessionCommitted {
    RemoteExecutionSessionCommitted {
        thread_id: prepared.thread_id.clone(),
        exec_turn_id: prepared.exec_turn_id.clone(),
        exec_call_id: prepared.exec_call_id.clone(),
        receipt_turn_id: prepared.receipt_turn_id.clone(),
        receipt_call_id: prepared.receipt_call_id.clone(),
        receipt_kind: prepared.receipt_kind.clone(),
        attempt_generation: prepared.attempt_generation,
        session_id: prepared.session_id,
        command_digest: prepared.command_digest.clone(),
        range_start: prepared.range_start,
        range_end: prepared.range_end,
        receipt_output_digest: prepared.receipt_output_digest.clone(),
        prepared_receipt_digest: crate::session::prepared_remote_receipt_digest_for_tests(prepared)
            .expect("prepared receipt digest"),
        rejection_reason: prepared.rejection_reason.clone(),
        rejection_write_id: prepared.rejection_write_id.clone(),
        rejection_input_sha256: prepared.rejection_input_sha256.clone(),
        terminal_acknowledgement_token: prepared.terminal_acknowledgement_token.clone(),
        terminal_output_digest: prepared.terminal_output_digest.clone(),
        terminal_status: prepared.terminal_status.clone(),
        terminal: prepared.terminal_candidate,
    }
}

fn resume_repair_initial_receipt(
    thread_id: &str,
    environment_id: &str,
) -> (RolloutItem, RolloutItem, RemoteExecutionSessionCommitted) {
    let output_text = "process running\r\n";
    let prepared = RemoteExecutionSessionPrepared {
        thread_id: thread_id.to_string(),
        exec_turn_id: "exec-turn".to_string(),
        exec_call_id: "exec-call".to_string(),
        receipt_turn_id: "exec-turn".to_string(),
        receipt_call_id: "exec-call".to_string(),
        receipt_kind: RemoteExecutionReceiptKind::InitialExec,
        attempt_generation: 0,
        session_id: 42,
        command_digest: "command-digest".to_string(),
        tty: true,
        output_mode: "pty".to_string(),
        environment_id: environment_id.to_string(),
        cwd: "file:///workspace".to_string(),
        hook_command: "sleep 30".to_string(),
        range_start: 0,
        range_end: 17,
        receipt_output_digest: format!("{:x}", Sha256::digest(output_text.as_bytes())),
        receipt_output_text: output_text.to_string(),
        rejection_reason: None,
        rejection_write_id: None,
        rejection_input_sha256: None,
        terminal_acknowledgement_token: None,
        terminal_output_digest: None,
        terminal_status: None,
        terminal_candidate: false,
    };
    let mut output = ResponseItem::FunctionCallOutput {
        id: None,
        call_id: "exec-call".to_string(),
        output: FunctionCallOutputPayload::from_text(output_text.to_string()),
        internal_chat_message_metadata_passthrough: None,
    };
    output.set_turn_id_if_missing("exec-turn");
    let committed = resume_repair_commit(&prepared);
    (
        RolloutItem::RemoteExecutionSessionPrepared(prepared),
        RolloutItem::ResponseItem(output),
        committed,
    )
}

fn resume_repair_committed_empty_poll(
    base: &RemoteExecutionSessionPrepared,
    turn_id: &str,
    call_id: &str,
) -> Vec<RolloutItem> {
    let receipt_output_text = format!(
        "Chunk ID: {call_id}\n\
         Wall time: 5.0000 seconds\n\
         Process running with session ID 42\n\
         Original token count: 0\n\
         Output:\n"
    );
    let prepared = RemoteExecutionSessionPrepared {
        receipt_turn_id: turn_id.to_string(),
        receipt_call_id: call_id.to_string(),
        receipt_kind: RemoteExecutionReceiptKind::EmptyPoll,
        range_start: 17,
        range_end: 17,
        receipt_output_digest: format!("{:x}", Sha256::digest(receipt_output_text.as_bytes())),
        receipt_output_text: receipt_output_text.clone(),
        rejection_reason: None,
        rejection_write_id: None,
        rejection_input_sha256: None,
        terminal_acknowledgement_token: None,
        terminal_output_digest: None,
        terminal_status: None,
        terminal_candidate: false,
        ..base.clone()
    };
    let mut output = ResponseItem::FunctionCallOutput {
        id: None,
        call_id: call_id.to_string(),
        output: FunctionCallOutputPayload {
            body: FunctionCallOutputBody::Text(receipt_output_text),
            success: Some(true),
        },
        internal_chat_message_metadata_passthrough: None,
    };
    output.set_turn_id_if_missing(turn_id);
    let committed = resume_repair_commit(&prepared);
    vec![
        scanner_call(
            "write_stdin",
            call_id,
            turn_id,
            &serde_json::json!({"session_id": 42}).to_string(),
        ),
        RolloutItem::RemoteExecutionSessionPrepared(prepared),
        RolloutItem::ResponseItem(output),
        RolloutItem::RemoteExecutionSessionCommitted(committed),
    ]
}

#[tokio::test]
async fn prepared_interrupt_rejection_resumes_once_and_preserves_completed_final_response() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    config.experimental_thread_store = ThreadStoreConfig::InMemory {
        id: format!("prepared-rejection-resume-{}", uuid::Uuid::new_v4()),
    };
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let reconcile_calls = Arc::new(AtomicUsize::new(0));
    let start_calls = Arc::new(AtomicUsize::new(0));
    let adopt_calls = Arc::new(AtomicUsize::new(0));
    let write_calls = Arc::new(AtomicUsize::new(0));
    let signal_calls = Arc::new(AtomicUsize::new(0));
    let terminate_calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(ResumeRepairBackend {
        reconcile_calls: Arc::clone(&reconcile_calls),
        start_calls: Arc::clone(&start_calls),
        adopt_calls: Arc::clone(&adopt_calls),
        write_calls: Arc::clone(&write_calls),
        signal_calls: Arc::clone(&signal_calls),
        terminate_calls: Arc::clone(&terminate_calls),
    });
    let environment_id = "resume-fixture";
    let environment_manager = Arc::new(
        codex_exec_server::EnvironmentManager::with_exec_backend_for_tests(
            environment_id,
            backend,
            /*durable_remote_exec_recovery*/ true,
        ),
    );
    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let thread_store = thread_store_from_config(&config, /*state_db*/ None);
    let in_memory_store = thread_store
        .as_any()
        .downcast_ref::<InMemoryThreadStore>()
        .expect("configured in-memory store");
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        environment_manager,
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        Arc::clone(&thread_store),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .start_thread(config.clone())
        .await
        .expect("create source thread");
    source
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown source thread");
    let _ = manager.remove_thread(&source.thread_id).await;
    let calls_before_resume = in_memory_store.calls().await;
    let thread_id = source.thread_id;
    let thread_id_text = thread_id.to_string();
    let (initial_prepared, initial_output, initial_commit) =
        resume_repair_initial_receipt(&thread_id_text, environment_id);
    let RolloutItem::RemoteExecutionSessionPrepared(initial_prepared_metadata) =
        initial_prepared.clone()
    else {
        unreachable!();
    };
    let input = "\u{3}";
    let input_sha256 = format!("{:x}", Sha256::digest(input.as_bytes()));
    let write_id = "a".repeat(64);
    let failed_text =
        "write_stdin failed: remote interrupt rejected before delivery: process ownership changed";
    let write_call = scanner_call(
        "write_stdin",
        "interrupt-call",
        "final-response-turn",
        &serde_json::json!({"session_id": 42, "chars": input}).to_string(),
    );
    let request = scanner_write_request(
        &thread_id_text,
        "final-response-turn",
        "interrupt-call",
        42,
        "command-digest",
        17,
        input,
    );
    let intent = RemoteExecutionWriteIntent {
        thread_id: thread_id_text.clone(),
        exec_turn_id: "exec-turn".to_string(),
        exec_call_id: "exec-call".to_string(),
        receipt_turn_id: "final-response-turn".to_string(),
        receipt_call_id: "interrupt-call".to_string(),
        attempt_generation: 0,
        session_id: 42,
        command_digest: "command-digest".to_string(),
        committed_output_cursor: 17,
        write_id: write_id.clone(),
        input_sha256: input_sha256.clone(),
        input_len: 1,
    };
    let rejection = RemoteExecutionSessionPrepared {
        thread_id: thread_id_text.clone(),
        exec_turn_id: "exec-turn".to_string(),
        exec_call_id: "exec-call".to_string(),
        receipt_turn_id: "final-response-turn".to_string(),
        receipt_call_id: "interrupt-call".to_string(),
        receipt_kind: RemoteExecutionReceiptKind::RejectedBeforeDelivery,
        attempt_generation: 0,
        session_id: 42,
        command_digest: "command-digest".to_string(),
        tty: true,
        output_mode: "pty".to_string(),
        environment_id: environment_id.to_string(),
        cwd: "file:///workspace".to_string(),
        hook_command: "sleep 30".to_string(),
        range_start: 17,
        range_end: 17,
        receipt_output_digest: format!("{:x}", Sha256::digest(failed_text.as_bytes())),
        receipt_output_text: failed_text.to_string(),
        rejection_reason: Some(RemoteExecutionRejectionReason::InterruptOwnershipMismatch),
        rejection_write_id: Some(write_id),
        rejection_input_sha256: Some(input_sha256),
        terminal_acknowledgement_token: None,
        terminal_output_digest: None,
        terminal_status: None,
        terminal_candidate: false,
    };
    let mut failed_output = ResponseItem::FunctionCallOutput {
        id: None,
        call_id: "interrupt-call".to_string(),
        output: FunctionCallOutputPayload {
            body: FunctionCallOutputBody::Text(failed_text.to_string()),
            success: Some(false),
        },
        internal_chat_message_metadata_passthrough: None,
    };
    failed_output.set_turn_id_if_missing("final-response-turn");
    let rejection_commit = resume_repair_commit(&rejection);
    let final_turn_started = RolloutItem::EventMsg(EventMsg::TurnStarted(TurnStartedEvent {
        turn_id: "final-response-turn".to_string(),
        trace_id: None,
        started_at: None,
        model_context_window: None,
        collaboration_mode_kind: Default::default(),
    }));
    let plan_event = EventMsg::PlanUpdate(UpdatePlanArgs {
        explanation: Some("repair complete".to_string()),
        plan: vec![PlanItemArg {
            step: "preserve completed work".to_string(),
            status: StepStatus::Completed,
        }],
    });
    let plan = RolloutItem::EventMsg(plan_event.clone());
    let mut final_response_item = assistant_msg("Build 148 repaired the resume path.");
    if let ResponseItem::Message { phase, .. } = &mut final_response_item {
        *phase = Some(MessagePhase::FinalAnswer);
    }
    final_response_item.set_turn_id_if_missing("final-response-turn");
    let final_response = RolloutItem::ResponseItem(final_response_item.clone());
    let task_complete_event = EventMsg::TurnComplete(TurnCompleteEvent {
        turn_id: "final-response-turn".to_string(),
        last_agent_message: Some("Build 148 repaired the resume path.".to_string()),
        error: None,
        started_at: None,
        completed_at: None,
        duration_ms: None,
        time_to_first_token_ms: None,
    });
    let task_complete = RolloutItem::EventMsg(task_complete_event.clone());
    let rollout_path = config.codex_home.join("rollouts/rejection.jsonl");
    let mut history = vec![
        scanner_marker(&thread_id_text, "exec-turn", 2),
        scanner_call(
            "exec_command",
            "exec-call",
            "exec-turn",
            &serde_json::json!({
                "cmd": "sleep 30",
                "tty": true,
                "yield_time_ms": 1_000,
            })
            .to_string(),
        ),
        RolloutItem::RemoteExecutionLaunchIntent(RemoteExecutionLaunchIntent {
            thread_id: thread_id_text.clone(),
            turn_id: "exec-turn".to_string(),
            call_id: "exec-call".to_string(),
            attempt_generation: 0,
            command_digest: "command-digest".to_string(),
            original_session_id: 42,
            tty: true,
        }),
        initial_prepared,
        initial_output,
        RolloutItem::RemoteExecutionSessionCommitted(initial_commit),
        final_turn_started,
        scanner_marker(&thread_id_text, "final-response-turn", 2),
        write_call,
        request,
        RolloutItem::RemoteExecutionWriteIntent(intent),
        RolloutItem::RemoteExecutionSessionPrepared(rejection),
        RolloutItem::ResponseItem(failed_output),
        RolloutItem::RemoteExecutionSessionCommitted(rejection_commit),
    ];
    history.extend(resume_repair_committed_empty_poll(
        &initial_prepared_metadata,
        "final-response-turn",
        "poll-call-1",
    ));
    history.extend(resume_repair_committed_empty_poll(
        &initial_prepared_metadata,
        "final-response-turn",
        "poll-call-2",
    ));
    history.extend([plan.clone(), final_response.clone(), task_complete.clone()]);
    let pending = ThreadManager::scan_active_remote_calls(thread_id_text.clone(), &history)
        .expect("scan fully committed terminal history");
    assert!(pending.incomplete_executions.is_empty());
    assert!(pending.pending_writes.is_empty());

    let resumed = manager
        .resume_thread_with_history_and_tools(
            config,
            InitialHistory::Resumed(ResumedHistory {
                conversation_id: thread_id,
                history: Arc::new(history),
                rollout_path: Some(rollout_path.to_path_buf()),
            }),
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
            Vec::new(),
            pending.pending_writes,
        )
        .await
        .expect("fully committed terminal history should resume");

    let repaired = resumed
        .thread
        .load_history(/*include_archived*/ true)
        .await
        .expect("load repaired history");
    assert_eq!(
        repaired
            .items
            .iter()
            .filter(|item| {
                matches!(
                    item,
                    RolloutItem::ResponseItem(ResponseItem::FunctionCallOutput {
                        call_id,
                        output,
                        ..
                    }) if call_id == "interrupt-call"
                        && output.body.to_text().as_deref() == Some(failed_text)
                )
            })
            .count(),
        1
    );
    assert_eq!(
        repaired
            .items
            .iter()
            .filter(|item| {
                matches!(
                    item,
                    RolloutItem::RemoteExecutionSessionCommitted(committed)
                        if committed.receipt_call_id == "interrupt-call"
                            && committed.receipt_kind
                                == RemoteExecutionReceiptKind::RejectedBeforeDelivery
                )
            })
            .count(),
        1
    );
    for retained in [&plan, &final_response, &task_complete] {
        let retained_json = serde_json::to_value(retained).expect("serialize retained item");
        assert_eq!(
            repaired
                .items
                .iter()
                .filter(|item| {
                    serde_json::to_value(item).expect("serialize repaired item") == retained_json
                })
                .count(),
            1
        );
    }
    let rescanned = ThreadManager::scan_active_remote_calls(thread_id_text, &repaired.items)
        .expect("repaired history should scan");
    assert!(rescanned.pending_writes.is_empty());
    let model_history = resumed.thread.session.clone_history().await;
    assert_eq!(
        model_history
            .raw_items()
            .iter()
            .filter(|item| {
                matches!(
                    item,
                    ResponseItem::Message {
                        role,
                        content,
                        phase: Some(MessagePhase::FinalAnswer),
                        ..
                    } if role == "assistant"
                        && item.turn_id() == Some("final-response-turn")
                        && content
                            == &vec![ContentItem::OutputText {
                                text: "Build 148 repaired the resume path.".to_string(),
                            }]
                )
            })
            .count(),
        1
    );
    let initial_messages = resumed
        .session_configured
        .initial_messages
        .as_ref()
        .expect("resumed session should expose initial events");
    for expected in [&plan_event, &task_complete_event] {
        let expected_json = serde_json::to_value(expected).expect("serialize expected event");
        assert_eq!(
            initial_messages
                .iter()
                .filter(|event| {
                    serde_json::to_value(event).expect("serialize initial event") == expected_json
                })
                .count(),
            1
        );
    }
    assert_eq!(reconcile_calls.load(Ordering::SeqCst), 1);
    assert_eq!(start_calls.load(Ordering::SeqCst), 0);
    assert_eq!(adopt_calls.load(Ordering::SeqCst), 0);
    assert_eq!(write_calls.load(Ordering::SeqCst), 0);
    assert_eq!(signal_calls.load(Ordering::SeqCst), 0);
    let calls = in_memory_store.calls().await;
    assert_eq!(calls.resume_thread - calls_before_resume.resume_thread, 1);
    assert_eq!(
        calls.append_items - calls_before_resume.append_items,
        0,
        "fully committed history must not be rewritten"
    );

    let terminal = resumed
        .thread
        .session
        .services
        .unified_exec_manager
        .write_stdin(crate::unified_exec::WriteStdinRequest {
            process_id: 42,
            input: "",
            yield_time_ms: crate::unified_exec::MIN_EMPTY_YIELD_TIME_MS,
            max_output_tokens: None,
            truncation_policy: TruncationPolicy::Bytes(2_048),
            interaction_event: None,
        })
        .await
        .expect("retire restored recovery-lost session");
    assert!(terminal.raw_output.is_empty());
    assert_eq!(terminal.exit_code, Some(125));
    assert!(terminal.recovery_lost);
    let retired = resumed
        .thread
        .session
        .services
        .unified_exec_manager
        .write_stdin(crate::unified_exec::WriteStdinRequest {
            process_id: 42,
            input: "",
            yield_time_ms: crate::unified_exec::MIN_EMPTY_YIELD_TIME_MS,
            max_output_tokens: None,
            truncation_policy: TruncationPolicy::Bytes(2_048),
            interaction_event: None,
        })
        .await;
    assert!(matches!(
        retired,
        Err(crate::unified_exec::UnifiedExecError::UnknownProcessId { process_id: 42 })
    ));

    resumed
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown resumed thread");
    assert_eq!(terminate_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn scanner_accepts_persisted_stdin_intent_under_legacy_v2_marker_without_proven_unsent_replay() {
    let history = vec![
        scanner_committed_session("thread", 42, "command-digest", 17),
        scanner_marker_with_stdin_intent("thread", "write-turn", 2, false),
        scanner_call(
            "write_stdin",
            "write-call",
            "write-turn",
            r#"{"session_id":42,"chars":"continue\n"}"#,
        ),
        scanner_write_intent(
            "thread",
            "write-turn",
            "write-call",
            42,
            "command-digest",
            17,
            "continue\n",
        ),
    ];

    let request =
        ThreadManager::scan_active_remote_calls("thread".to_string(), &history).expect("scan");
    assert_eq!(request.pending_writes.len(), 1);
    assert!(!request.pending_writes[0].pre_send_intent_required);
    assert!(request.pending_writes[0].pre_send_intent_persisted);
}

#[test]
fn scanner_rejects_stdin_intent_bound_to_an_earlier_session_cursor() {
    let history = vec![
        scanner_committed_session("thread", 42, "command-digest", 17),
        scanner_committed_session("thread", 42, "command-digest", 29),
        scanner_marker("thread", "write-turn", 2),
        scanner_call(
            "write_stdin",
            "write-call",
            "write-turn",
            r#"{"session_id":42,"chars":"continue\n"}"#,
        ),
        scanner_write_request(
            "thread",
            "write-turn",
            "write-call",
            42,
            "command-digest",
            17,
            "continue\n",
        ),
        scanner_write_intent(
            "thread",
            "write-turn",
            "write-call",
            42,
            "command-digest",
            17,
            "continue\n",
        ),
    ];

    ThreadManager::scan_active_remote_calls("thread".to_string(), &history)
        .expect_err("an earlier matching commit must not supersede the latest exact cursor");
}

#[test]
fn scanner_accepts_same_turn_commit_between_marker_and_stdin_call() {
    let input = "continue\n";
    let history = vec![
        scanner_marker("thread", "write-turn", 2),
        scanner_committed_session("thread", 42, "command-digest", 17),
        scanner_call(
            "write_stdin",
            "write-call",
            "write-turn",
            r#"{"session_id":42,"chars":"continue\n"}"#,
        ),
        scanner_write_request(
            "thread",
            "write-turn",
            "write-call",
            42,
            "command-digest",
            17,
            input,
        ),
        scanner_write_intent(
            "thread",
            "write-turn",
            "write-call",
            42,
            "command-digest",
            17,
            input,
        ),
    ];

    let request =
        ThreadManager::scan_active_remote_calls("thread".to_string(), &history).expect("scan");
    assert_eq!(request.pending_writes.len(), 1);
    assert!(request.pending_writes[0].pre_send_intent_required);
    assert!(request.pending_writes[0].pre_send_intent_persisted);
}

#[test]
fn active_tail_scanner_rejects_duplicates_and_turn_conflicts() {
    assert!(
        ThreadManager::scan_active_remote_calls(
            "thread".to_string(),
            &[
                scanner_call("exec_command", "dup", "turn-1", "{}"),
                scanner_call("exec_command", "dup", "turn-1", "{}"),
            ],
        )
        .is_err()
    );
    assert!(
        ThreadManager::scan_active_remote_calls(
            "thread".to_string(),
            &[
                scanner_call("exec_command", "done", "turn-1", "{}"),
                scanner_output("done", "turn-1"),
                scanner_output("done", "turn-1"),
            ],
        )
        .is_err()
    );
    assert!(
        ThreadManager::scan_active_remote_calls(
            "thread".to_string(),
            &[
                scanner_call("exec_command", "first", "turn-1", "{}"),
                scanner_call("exec_command", "second", "turn-2", "{}"),
            ],
        )
        .is_err()
    );
    assert!(
        ThreadManager::scan_active_remote_calls(
            "thread".to_string(),
            &[
                scanner_call("exec_command", "earlier", "turn-1", "{}"),
                scanner_call("unrelated", "later", "turn-2", "{}"),
            ],
        )
        .is_err()
    );
}

#[test]
fn recovered_output_is_truthful_and_preserves_exact_bytes() {
    let execution = codex_exec_server::RecoveredExecution {
        identity: codex_exec_server::ExecutionIdentity {
            thread_id: ThreadId::new().to_string(),
            turn_id: String::new(),
            call_id: "call-after-crash".to_string(),
            attempt_generation: 0,
        },
        command_digest: None,
        output: b"exact output\n".to_vec(),
        status: codex_exec_server::RecoveredExecutionStatus::Exited(0),
        terminal_verified_dead: true,
        session_id: Some(42),
        committed_output_cursor: 13,
        delivery_unknown: false,
        acknowledgement: codex_exec_server::RecoveredExecutionAcknowledgement::new(
            "0123456789abcdef-token".to_string(),
        ),
    };

    let output = format_recovered_execution_output(&execution);

    assert_eq!(
        output,
        "Process exited with code 0\nOutput:\nexact output\n"
    );
    assert!(!output.contains("aborted"));
}

#[test]
fn recovered_output_names_unrecoverable_terminal_result_truthfully() {
    let execution = codex_exec_server::RecoveredExecution {
        identity: codex_exec_server::ExecutionIdentity {
            thread_id: ThreadId::new().to_string(),
            turn_id: String::new(),
            call_id: "call-recovery-lost".to_string(),
            attempt_generation: 0,
        },
        command_digest: None,
        output: b"exact output\n".to_vec(),
        status: codex_exec_server::RecoveredExecutionStatus::RecoveryLost,
        terminal_verified_dead: true,
        session_id: Some(43),
        committed_output_cursor: 13,
        delivery_unknown: false,
        acknowledgement: codex_exec_server::RecoveredExecutionAcknowledgement::new(
            "0123456789abcdef-recovery-lost".to_string(),
        ),
    };

    let output = format_recovered_execution_output(&execution);

    assert_eq!(
        output,
        "The exact remote process ended, but its exit or signal result was not recoverable\n\
         Output:\nexact output\n"
    );
    assert!(!output.contains("code 125"));
    assert!(!output.contains("terminated"));
}

#[test]
fn recovered_terminal_acknowledgement_binds_exact_output_and_status() {
    let execution = codex_exec_server::RecoveredExecution {
        identity: codex_exec_server::ExecutionIdentity {
            thread_id: ThreadId::new().to_string(),
            turn_id: "turn".to_string(),
            call_id: "call-recovery-lost".to_string(),
            attempt_generation: 0,
        },
        command_digest: Some("digest".to_string()),
        output: b"exact output\n".to_vec(),
        status: codex_exec_server::RecoveredExecutionStatus::RecoveryLost,
        terminal_verified_dead: true,
        session_id: Some(43),
        committed_output_cursor: 13,
        delivery_unknown: false,
        acknowledgement: codex_exec_server::RecoveredExecutionAcknowledgement::new(
            "0123456789abcdef-recovery-lost".to_string(),
        ),
    };

    let acknowledgement =
        terminal_acknowledgement_for_recovered_execution(&execution).expect("terminal proof");
    let proof = acknowledgement.terminal_proof().expect("bound proof");
    assert_eq!(proof.range_start, 0);
    assert_eq!(proof.range_end, 13);
    assert_eq!(
        proof.status,
        codex_exec_server::RecoveredExecutionStatus::RecoveryLost
    );
    assert_eq!(
        proof.output_sha256,
        "1de7edcfb5d1a77e878e4411456fa5ce9ea0a2b23ad095cfbb63ab10ddf0580a"
    );

    let mut uncertain = execution;
    uncertain.terminal_verified_dead = false;
    assert!(terminal_acknowledgement_for_recovered_execution(&uncertain).is_err());
}

#[test]
fn running_foreground_recovery_adopts_and_waits_before_rollout_repair() {
    let source = include_str!("thread_manager.rs");
    let repair = source
        .split("async fn append_recovered_execution_outputs_to_rollout")
        .nth(1)
        .expect("recovery repair function")
        .split("#[derive(Debug)]")
        .next()
        .expect("recovery repair body");
    let running = repair
        .find("RecoveredExecutionStatus::Running")
        .expect("running recovery branch");
    let adopt = repair[running..]
        .find("adopt_default_environment_execution")
        .expect("exact foreground adoption")
        + running;
    let event_wait = repair[adopt..]
        .find("events.recv().await")
        .expect("truthful terminal wait")
        + adopt;
    let terminal_verify = repair[event_wait..]
        .find("reconcile_default_environment")
        .expect("exact retained-descriptor verification")
        + event_wait;
    let append = repair
        .find("append_function_output_if_missing")
        .expect("durable rollout repair");
    assert!(running < adopt);
    assert!(adopt < event_wait);
    assert!(event_wait < terminal_verify);
    assert!(terminal_verify < append);
    assert!(source.contains("original_session_id: Some(original_session_id)"));
    assert!(repair.contains("!verified.terminal_verified_dead"));
    assert!(!repair.contains("if execution.session_id.is_some()"));
}

#[test]
fn running_foreground_adoption_preserves_persisted_session_id() {
    let mut execution = recovered_slot(
        "foreground",
        0,
        codex_exec_server::RecoveredExecutionStatus::Running,
        false,
    );
    execution.command_digest = Some("digest".to_string());
    execution.session_id = Some(4242);
    execution.committed_output_cursor = 17;

    let authority = IncompleteExecution {
        turn_id: execution.identity.turn_id.clone(),
        call_id: execution.identity.call_id.clone(),
        attempt_generation: execution.identity.attempt_generation,
        expected_command_digest: Some("digest".to_string()),
        expected_session_id: Some(4242),
        expected_tty: Some(false),
        protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
    };
    let request = foreground_adoption_request(&execution, Some(&authority))
        .expect("foreground adoption request");
    assert_eq!(request.original_session_id, Some(4242));
    assert_eq!(request.committed_output_cursor, 17);
    assert_eq!(request.identity, execution.identity);
}

#[test]
fn resumed_background_sessions_restore_before_thread_exposure() {
    let source = include_str!("session/session.rs");
    let session_new = source
        .split("pub(crate) async fn new(")
        .nth(1)
        .expect("session construction")
        .split("pub(crate) async fn")
        .next()
        .expect("session construction body");
    let session = session_new
        .find("let sess = Arc::new(Session")
        .expect("session value");
    let restore = session_new
        .find("repair_pending_empty_polls_before_reconstruction")
        .expect("background restoration");
    let exposure = session_new
        .find("SessionConfiguredEvent")
        .expect("first externally visible event");
    assert!(session < restore);
    assert!(restore < exposure);
}

fn recovered_slot(
    call_id: &str,
    generation: u32,
    status: codex_exec_server::RecoveredExecutionStatus,
    terminal_verified_dead: bool,
) -> codex_exec_server::RecoveredExecution {
    codex_exec_server::RecoveredExecution {
        identity: codex_exec_server::ExecutionIdentity {
            thread_id: "thread".to_string(),
            turn_id: "turn".to_string(),
            call_id: call_id.to_string(),
            attempt_generation: generation,
        },
        command_digest: None,
        output: format!("{call_id}-{generation}").into_bytes(),
        status,
        terminal_verified_dead,
        session_id: None,
        committed_output_cursor: 0,
        delivery_unknown: false,
        acknowledgement: codex_exec_server::RecoveredExecutionAcknowledgement::new(format!(
            "{call_id}-{generation}-token"
        )),
    }
}

#[test]
fn recovered_rows_are_grouped_and_selected_before_repair() {
    let selected = select_recovered_execution_rows(
        vec![
            recovered_slot(
                "second",
                1,
                codex_exec_server::RecoveredExecutionStatus::Running,
                false,
            ),
            recovered_slot(
                "first",
                0,
                codex_exec_server::RecoveredExecutionStatus::Exited(0),
                true,
            ),
            recovered_slot(
                "second",
                0,
                codex_exec_server::RecoveredExecutionStatus::Exited(1),
                true,
            ),
            recovered_slot(
                "first",
                1,
                codex_exec_server::RecoveredExecutionStatus::Missing,
                false,
            ),
        ],
        &HashSet::new(),
    )
    .expect("complete exact slot pairs should select once per call");

    assert_eq!(selected.len(), 2);
    let SelectedRecoveryAction::RepairAndAcknowledge(first) = &selected[0] else {
        panic!("terminal generation must acknowledge after repair");
    };
    assert_eq!(first.identity.call_id, "first");
    assert_eq!(first.identity.attempt_generation, 0);
    let SelectedRecoveryAction::RepairAndAcknowledge(second) = &selected[1] else {
        panic!("selected generation must use normal recovery action");
    };
    assert_eq!(second.identity.call_id, "second");
    assert_eq!(second.identity.attempt_generation, 1);
}

#[test]
fn recovered_rows_fail_closed_before_repair() {
    assert!(
        select_recovered_execution_rows(
            vec![recovered_slot(
                "missing-slot",
                0,
                codex_exec_server::RecoveredExecutionStatus::Exited(0),
                true,
            )],
            &HashSet::new()
        )
        .is_err()
    );
    assert!(
        select_recovered_execution_rows(
            vec![
                recovered_slot(
                    "not-launched",
                    0,
                    codex_exec_server::RecoveredExecutionStatus::Missing,
                    false,
                ),
                recovered_slot(
                    "not-launched",
                    1,
                    codex_exec_server::RecoveredExecutionStatus::Missing,
                    false,
                ),
            ],
            &HashSet::new()
        )
        .is_err()
    );
    assert!(
        select_recovered_execution_rows(
            vec![
                recovered_slot(
                    "unverified",
                    0,
                    codex_exec_server::RecoveredExecutionStatus::Exited(0),
                    false,
                ),
                recovered_slot(
                    "unverified",
                    1,
                    codex_exec_server::RecoveredExecutionStatus::Missing,
                    false,
                ),
            ],
            &HashSet::new()
        )
        .is_err()
    );
    assert!(
        select_recovered_execution_rows(
            vec![
                recovered_slot(
                    "duplicate",
                    0,
                    codex_exec_server::RecoveredExecutionStatus::Exited(0),
                    true,
                ),
                recovered_slot(
                    "duplicate",
                    0,
                    codex_exec_server::RecoveredExecutionStatus::Exited(0),
                    true,
                ),
                recovered_slot(
                    "duplicate",
                    1,
                    codex_exec_server::RecoveredExecutionStatus::Missing,
                    false,
                ),
            ],
            &HashSet::new()
        )
        .is_err()
    );
}

#[test]
fn not_launched_is_accepted_only_with_exact_v2_marker_evidence() {
    let rows = || {
        vec![
            recovered_slot(
                "not-launched",
                0,
                codex_exec_server::RecoveredExecutionStatus::Missing,
                false,
            ),
            recovered_slot(
                "not-launched",
                1,
                codex_exec_server::RecoveredExecutionStatus::Missing,
                false,
            ),
        ]
    };
    assert!(select_recovered_execution_rows(rows(), &HashSet::new()).is_err());
    let evidence = HashSet::from([(
        "thread".to_string(),
        "turn".to_string(),
        "not-launched".to_string(),
    )]);
    let selected = select_recovered_execution_rows(rows(), &evidence).expect("exact v2 evidence");
    assert_eq!(selected.len(), 1);
    let SelectedRecoveryAction::RepairWithoutAcknowledgement(execution) = &selected[0] else {
        panic!("absent roots must repair without descriptor acknowledgement");
    };
    assert_eq!(
        execution.status,
        codex_exec_server::RecoveredExecutionStatus::Missing
    );
    assert_eq!(
        format_recovered_execution_output(execution),
        "Process was not launched\nOutput:\nnot-launched-0"
    );
}

struct FakeAgentGraphStore {
    root_thread_id: ThreadId,
    descendant_thread_ids: Vec<ThreadId>,
}

impl codex_agent_graph_store::AgentGraphStore for FakeAgentGraphStore {
    fn upsert_thread_spawn_edge(
        &self,
        _parent_thread_id: ThreadId,
        _child_thread_id: ThreadId,
        _status: codex_agent_graph_store::ThreadSpawnEdgeStatus,
    ) -> codex_agent_graph_store::AgentGraphStoreFuture<'_, ()> {
        Box::pin(async { panic!("unexpected graph upsert") })
    }

    fn set_thread_spawn_edge_status(
        &self,
        _child_thread_id: ThreadId,
        _status: codex_agent_graph_store::ThreadSpawnEdgeStatus,
    ) -> codex_agent_graph_store::AgentGraphStoreFuture<'_, ()> {
        Box::pin(async { panic!("unexpected graph status update") })
    }

    fn list_thread_spawn_children(
        &self,
        _parent_thread_id: ThreadId,
        _status_filter: Option<codex_agent_graph_store::ThreadSpawnEdgeStatus>,
    ) -> codex_agent_graph_store::AgentGraphStoreFuture<'_, Vec<ThreadId>> {
        Box::pin(async { panic!("unexpected direct-child listing") })
    }

    fn list_thread_spawn_descendants(
        &self,
        root_thread_id: ThreadId,
        status_filter: Option<codex_agent_graph_store::ThreadSpawnEdgeStatus>,
    ) -> codex_agent_graph_store::AgentGraphStoreFuture<'_, Vec<ThreadId>> {
        assert_eq!(root_thread_id, self.root_thread_id);
        assert_eq!(status_filter, None);
        let descendant_thread_ids = self.descendant_thread_ids.clone();
        Box::pin(async move { Ok(descendant_thread_ids) })
    }
}

fn user_msg(text: &str) -> ResponseItem {
    ResponseItem::Message {
        id: None,
        role: "user".to_string(),
        content: vec![ContentItem::OutputText {
            text: text.to_string(),
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    }
}
fn assistant_msg(text: &str) -> ResponseItem {
    ResponseItem::Message {
        id: None,
        role: "assistant".to_string(),
        content: vec![ContentItem::OutputText {
            text: text.to_string(),
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    }
}

fn contextual_user_interrupted_marker() -> ResponseItem {
    interrupted_turn_history_marker(InterruptedTurnHistoryMarker::ContextualUser)
        .expect("contextual-user interrupted marker should be enabled")
}

fn developer_interrupted_marker() -> ResponseItem {
    interrupted_turn_history_marker(InterruptedTurnHistoryMarker::Developer)
        .expect("developer interrupted marker should be enabled")
}

#[test]
fn effective_originator_prefers_thread_scoped_sources_before_env_originator() {
    for (metrics_service_name, persisted_originator, inherited_originator, expected_originator) in [
        (
            Some("codex_work_desktop"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "codex_work_desktop",
        ),
        (
            Some("codex_work_web"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "codex_work_web",
        ),
        (
            Some("codex_work_mobile"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "codex_work_mobile",
        ),
        (
            Some("codex_work_cca"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "codex_work_cca",
        ),
        (
            Some("chatgpt_cca"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "chatgpt_cca",
        ),
        (
            Some("chatgpt_cca_extra"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "persisted_originator",
        ),
        (
            None,
            Some("persisted_originator"),
            Some("inherited_originator"),
            "persisted_originator",
        ),
        (
            None,
            None,
            Some("inherited_originator"),
            "inherited_originator",
        ),
    ] {
        assert_eq!(
            effective_originator_value(
                metrics_service_name,
                Some("Codex Desktop".to_string()),
                persisted_originator.map(str::to_string),
                inherited_originator.map(str::to_string),
                "codex_cli_rs".to_string(),
            ),
            expected_originator
        );
    }
}

#[tokio::test]
async fn missing_live_parent_inherits_no_dynamic_tool_authority() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let missing_parent = ThreadId::new();
    let inherited = manager
        .state
        .inherited_dynamic_tools_for_spawn(
            &SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: missing_parent,
                depth: 1,
                agent_path: None,
                agent_nickname: None,
                agent_role: None,
            }),
            Some(missing_parent),
            /*forked_from_thread_id*/ None,
        )
        .await;

    assert!(inherited.is_empty());
}

#[test]
fn truncates_before_requested_user_message() {
    let items = [
        user_msg("u1"),
        assistant_msg("a1"),
        assistant_msg("a2"),
        user_msg("u2"),
        assistant_msg("a3"),
        ResponseItem::Reasoning {
            id: Some(ResponseItemId::with_suffix("rs", "1")),
            summary: vec![ReasoningItemReasoningSummary::SummaryText {
                text: "s".to_string(),
            }],
            content: None,
            encrypted_content: None,
            internal_chat_message_metadata_passthrough: None,
        },
        ResponseItem::FunctionCall {
            id: None,
            call_id: "c1".to_string(),
            name: "tool".to_string(),
            namespace: None,
            arguments: "{}".to_string(),
            internal_chat_message_metadata_passthrough: None,
        },
        assistant_msg("a4"),
    ];

    let initial: Vec<RolloutItem> = items
        .iter()
        .cloned()
        .map(RolloutItem::ResponseItem)
        .collect();
    let truncated = truncate_before_nth_user_message(
        InitialHistory::Forked(initial),
        /*n*/ 1,
        &SnapshotTurnState {
            ends_mid_turn: false,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
    let got_items = truncated.get_rollout_items();
    let expected_items = vec![
        RolloutItem::ResponseItem(items[0].clone()),
        RolloutItem::ResponseItem(items[1].clone()),
        RolloutItem::ResponseItem(items[2].clone()),
    ];
    assert_eq!(
        serde_json::to_value(got_items).unwrap(),
        serde_json::to_value(&expected_items).unwrap()
    );

    let initial2: Vec<RolloutItem> = items
        .iter()
        .cloned()
        .map(RolloutItem::ResponseItem)
        .collect();
    let truncated2 = truncate_before_nth_user_message(
        InitialHistory::Forked(initial2.clone()),
        /*n*/ 2,
        &SnapshotTurnState {
            ends_mid_turn: false,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
    assert_eq!(
        serde_json::to_value(truncated2.get_rollout_items()).unwrap(),
        serde_json::to_value(initial2).unwrap()
    );
}

#[test]
fn out_of_range_truncation_drops_only_unfinished_suffix_mid_turn() {
    let items = vec![
        RolloutItem::ResponseItem(user_msg("u1")),
        RolloutItem::ResponseItem(assistant_msg("a1")),
        RolloutItem::ResponseItem(user_msg("u2")),
        RolloutItem::ResponseItem(assistant_msg("partial")),
    ];

    let truncated = truncate_before_nth_user_message(
        InitialHistory::Forked(items.clone()),
        usize::MAX,
        &SnapshotTurnState {
            ends_mid_turn: true,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );

    assert_eq!(
        serde_json::to_value(truncated.get_rollout_items()).unwrap(),
        serde_json::to_value(items[..2].to_vec()).unwrap()
    );
}

#[test]
fn fork_thread_accepts_legacy_usize_snapshot_argument() {
    fn assert_legacy_snapshot_callsite(
        manager: &ThreadManager,
        config: Config,
        path: std::path::PathBuf,
    ) {
        let _future = manager.fork_thread(
            usize::MAX,
            config,
            path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        );
    }

    let _: fn(&ThreadManager, Config, std::path::PathBuf) = assert_legacy_snapshot_callsite;
}

#[test]
fn out_of_range_truncation_drops_pre_user_active_turn_prefix() {
    let items = vec![
        RolloutItem::ResponseItem(user_msg("u1")),
        RolloutItem::ResponseItem(assistant_msg("a1")),
        RolloutItem::EventMsg(EventMsg::TurnStarted(TurnStartedEvent {
            turn_id: "turn-2".to_string(),
            trace_id: None,
            started_at: None,
            model_context_window: None,
            collaboration_mode_kind: Default::default(),
        })),
        RolloutItem::ResponseItem(user_msg("u2")),
        RolloutItem::ResponseItem(assistant_msg("partial")),
    ];

    let snapshot_state = snapshot_turn_state(&InitialHistory::Forked(items.clone()));
    assert_eq!(
        snapshot_state,
        SnapshotTurnState {
            ends_mid_turn: true,
            active_turn_id: Some("turn-2".to_string()),
            active_turn_started_at: None,
            active_turn_start_index: Some(2),
        },
    );

    let truncated = truncate_before_nth_user_message(
        InitialHistory::Forked(items.clone()),
        usize::MAX,
        &snapshot_state,
    );

    assert_eq!(
        serde_json::to_value(truncated.get_rollout_items()).unwrap(),
        serde_json::to_value(items[..2].to_vec()).unwrap()
    );
}

#[tokio::test]
async fn ignores_session_prefix_messages_when_truncating() {
    let (session, turn_context) = make_session_and_context().await;
    let turn_context = Arc::new(turn_context);
    let world_state = build_world_state_from_turn_context(&session, &turn_context).await;
    let mut items = session
        .build_initial_context_with_world_state(&turn_context, &world_state)
        .await;
    items.push(user_msg("feature request"));
    items.push(assistant_msg("ack"));
    items.push(user_msg("second question"));
    items.push(assistant_msg("answer"));

    let rollout_items: Vec<RolloutItem> = items
        .iter()
        .cloned()
        .map(RolloutItem::ResponseItem)
        .collect();

    let truncated = truncate_before_nth_user_message(
        InitialHistory::Forked(rollout_items),
        /*n*/ 1,
        &SnapshotTurnState {
            ends_mid_turn: false,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
    let got_items = truncated.get_rollout_items();

    let expected: Vec<RolloutItem> = vec![
        RolloutItem::ResponseItem(items[0].clone()),
        RolloutItem::ResponseItem(items[1].clone()),
        RolloutItem::ResponseItem(items[2].clone()),
        RolloutItem::ResponseItem(items[3].clone()),
    ];

    assert_eq!(
        serde_json::to_value(got_items).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
}

#[tokio::test]
async fn shutdown_all_threads_bounded_submits_shutdown_to_every_thread() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let thread_1 = manager
        .start_thread(config.clone())
        .await
        .expect("start first thread")
        .thread_id;
    let thread_2 = manager
        .start_thread(config.clone())
        .await
        .expect("start second thread")
        .thread_id;

    let report = manager
        .shutdown_all_threads_bounded(Duration::from_secs(10))
        .await;

    let mut expected_completed = vec![thread_1, thread_2];
    expected_completed.sort_by_key(std::string::ToString::to_string);
    assert_eq!(report.completed, expected_completed);
    assert!(report.submit_failed.is_empty());
    assert!(report.timed_out.is_empty());
    assert!(manager.list_thread_ids().await.is_empty());
}

#[tokio::test]
async fn code_mode_session_provider_is_shared_across_threads() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let first = manager
        .start_thread(config.clone())
        .await
        .expect("start first thread");
    let second = manager
        .start_thread(config)
        .await
        .expect("start second thread");

    let first_provider = first
        .thread
        .session
        .services
        .code_mode_service
        .session_provider();
    let second_provider = second
        .thread
        .session
        .services
        .code_mode_service
        .session_provider();
    assert!(Arc::ptr_eq(&first_provider, &second_provider));
    assert!(Arc::ptr_eq(
        &first_provider,
        &manager.state.code_mode_session_provider
    ));

    let mut completed = vec![first.thread_id, second.thread_id];
    completed.sort_by_key(std::string::ToString::to_string);
    let report = manager
        .shutdown_all_threads_bounded(Duration::from_secs(10))
        .await;
    assert_eq!(
        report,
        ThreadShutdownReport {
            completed,
            submit_failed: Vec::new(),
            timed_out: Vec::new(),
        }
    );
}

#[tokio::test]
async fn start_thread_keeps_internal_threads_hidden_from_normal_lookups() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let thread = manager
        .start_thread_with_options(StartThreadOptions {
            config,
            allow_provider_model_fallback: false,
            initial_history: InitialHistory::New,
            history_mode: None,
            session_source: Some(SessionSource::Internal(
                InternalSessionSource::MemoryConsolidation,
            )),
            thread_source: None,
            dynamic_tools: Vec::new(),
            metrics_service_name: None,
            parent_trace: None,
            environments: Vec::new(),
            thread_extension_init: Default::default(),
            supports_openai_form_elicitation: false,
        })
        .await
        .expect("internal thread should start");

    assert_eq!(manager.list_thread_ids().await, Vec::new());
    assert!(manager.get_thread(thread.thread_id).await.is_err());

    let report = manager
        .shutdown_all_threads_bounded(Duration::from_secs(10))
        .await;
    assert_eq!(report.completed, vec![thread.thread_id]);
    assert!(report.submit_failed.is_empty());
    assert!(report.timed_out.is_empty());
    assert!(manager.list_thread_ids().await.is_empty());
}

#[tokio::test]
async fn start_thread_seeds_extension_data_for_mcp_and_lifecycle_contributors() {
    struct InitialDataRecorder {
        lifecycle_observed: Arc<std::sync::Mutex<Vec<(String, String)>>>,
        mcp_observed: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl codex_extension_api::ThreadLifecycleContributor<Config> for InitialDataRecorder {
        fn on_thread_start<'a>(
            &'a self,
            input: codex_extension_api::ThreadStartInput<'a, Config>,
        ) -> codex_extension_api::ExtensionFuture<'a, ()> {
            Box::pin(async move {
                let selected_root = input
                    .thread_store
                    .get::<Vec<SelectedCapabilityRoot>>()
                    .and_then(|roots| roots.first().cloned())
                    .expect("selected root should be available");
                self.lifecycle_observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((input.thread_store.level_id().to_string(), selected_root.id));
                input
                    .thread_store
                    .insert(Vec::<SelectedCapabilityRoot>::new());
            })
        }
    }

    impl codex_extension_api::McpServerContributor<Config> for InitialDataRecorder {
        fn id(&self) -> &'static str {
            "selected_root_test"
        }

        fn contribute<'a>(
            &'a self,
            context: codex_extension_api::McpServerContributionContext<'a, Config>,
        ) -> codex_extension_api::ExtensionFuture<'a, Vec<codex_extension_api::McpServerContribution>>
        {
            Box::pin(async move {
                let thread_init = context
                    .thread_init()
                    .expect("initial MCP resolution should be thread-scoped");
                let selected_root = thread_init
                    .get::<Vec<SelectedCapabilityRoot>>()
                    .and_then(|roots| roots.first().cloned())
                    .expect("selected root should be available");
                self.mcp_observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(selected_root.id.clone());
                let mut server = codex_mcp::codex_apps_mcp_server_config(
                    "https://selected.invalid",
                    /*apps_mcp_product_sku*/ None,
                    /*originator*/ None,
                );
                let CapabilityRootLocation::Environment { environment_id, .. } =
                    &selected_root.location;
                server.environment_id = environment_id.clone();
                server.enabled = false;
                let plugin_id = selected_root.id;
                vec![codex_extension_api::McpServerContribution::SelectedPlugin {
                    name: plugin_id.clone(),
                    plugin_display_name: plugin_id.clone(),
                    plugin_id,
                    selection_order: 0,
                    config: Box::new(server),
                }]
            })
        }
    }

    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    config
        .features
        .enable(Feature::Apps)
        .expect("test config should allow apps");
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let lifecycle_observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mcp_observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = Arc::new(InitialDataRecorder {
        lifecycle_observed: Arc::clone(&lifecycle_observed),
        mcp_observed: Arc::clone(&mcp_observed),
    });
    let mut extensions = codex_extension_api::ExtensionRegistryBuilder::new();
    extensions.thread_lifecycle_contributor(recorder.clone());
    extensions.mcp_server_contributor(recorder);
    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        Arc::new(extensions.build()),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );
    let selected_root_init = |id: &str, environment_id: &str| {
        let mut init = codex_extension_api::ExtensionDataInit::new();
        init.insert(vec![SelectedCapabilityRoot {
            id: id.to_string(),
            location: CapabilityRootLocation::Environment {
                environment_id: environment_id.to_string(),
                path: PathUri::parse(&format!("file:///plugins/{id}")).expect("plugin root URI"),
            },
        }]);
        init
    };

    let first_thread = manager
        .start_thread_with_options(StartThreadOptions {
            config: config.clone(),
            allow_provider_model_fallback: false,
            initial_history: InitialHistory::New,
            history_mode: None,
            session_source: None,
            thread_source: None,
            dynamic_tools: Vec::new(),
            metrics_service_name: Some("codex_work_desktop".to_string()),
            parent_trace: None,
            environments: Vec::new(),
            thread_extension_init: selected_root_init("selected-a", "env-a"),
            supports_openai_form_elicitation: false,
        })
        .await
        .expect("start first thread");
    let second_thread = manager
        .start_thread_with_options(StartThreadOptions {
            config: config.clone(),
            allow_provider_model_fallback: false,
            initial_history: InitialHistory::New,
            history_mode: None,
            session_source: None,
            thread_source: None,
            dynamic_tools: Vec::new(),
            metrics_service_name: None,
            parent_trace: None,
            environments: Vec::new(),
            thread_extension_init: selected_root_init("selected-b", "env-b"),
            supports_openai_form_elicitation: false,
        })
        .await
        .expect("start second thread");
    let first_session = &first_thread.thread.session;
    let first_originator = first_session.originator().await;
    let first_resolved = first_session
        .services
        .mcp_manager
        .runtime_config_for_step(
            &config,
            &first_session.services.mcp_thread_init,
            &first_session.services.thread_extension_data,
            &first_originator,
            /*ready_selected_capability_roots*/ &[],
            /*executor_capability_discovery*/ None,
        )
        .await;
    let second_session = &second_thread.thread.session;
    let second_originator = second_session.originator().await;
    let second_resolved = second_session
        .services
        .mcp_manager
        .runtime_config_for_step(
            &config,
            &second_session.services.mcp_thread_init,
            &second_session.services.thread_extension_data,
            &second_originator,
            /*ready_selected_capability_roots*/ &[],
            /*executor_capability_discovery*/ None,
        )
        .await;

    assert_eq!(
        *lifecycle_observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![
            (first_thread.thread_id.to_string(), "selected-a".to_string()),
            (
                second_thread.thread_id.to_string(),
                "selected-b".to_string()
            ),
        ]
    );
    assert_eq!(
        *mcp_observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![
            "selected-a".to_string(),
            "selected-b".to_string(),
            "selected-a".to_string(),
            "selected-b".to_string(),
        ]
    );
    let selected_servers = |config: &codex_mcp::McpConfig| {
        codex_mcp::configured_mcp_servers(config)
            .into_iter()
            .filter(|(name, _)| name.starts_with("selected-"))
            .map(|(name, server)| (name, server.environment_id))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    assert_eq!(
        selected_servers(&first_resolved.config),
        std::collections::BTreeMap::from([("selected-a".to_string(), "env-a".to_string())])
    );
    assert_eq!(
        selected_servers(&second_resolved.config),
        std::collections::BTreeMap::from([("selected-b".to_string(), "env-b".to_string())])
    );
    let codex_apps_server = codex_mcp::configured_mcp_servers(&first_resolved.config)
        .remove(codex_mcp::CODEX_APPS_MCP_SERVER_NAME)
        .expect("Codex Apps server should be configured");
    let codex_apps_headers = match codex_apps_server.transport {
        codex_config::McpServerTransportConfig::StreamableHttp { http_headers, .. } => http_headers,
        codex_config::McpServerTransportConfig::Stdio { .. } => {
            panic!("Codex Apps server should use streamable HTTP")
        }
    };
    assert_eq!(
        codex_apps_headers
            .expect("Codex Apps headers should be configured")
            .get("originator"),
        Some(&"codex_work_desktop".to_string())
    );
}

#[tokio::test]
async fn selected_capability_roots_round_trip_through_fork() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let selected_roots = vec![SelectedCapabilityRoot {
        id: "demo@1".to_string(),
        location: CapabilityRootLocation::Environment {
            environment_id: "build".to_string(),
            path: PathUri::parse("file:///plugins/demo").expect("plugin root URI"),
        },
    }];
    let inherited = manager
        .start_thread_with_options(StartThreadOptions {
            config,
            allow_provider_model_fallback: false,
            initial_history: InitialHistory::Forked(vec![RolloutItem::SessionMeta(
                SessionMetaLine {
                    meta: SessionMeta {
                        selected_capability_roots: selected_roots.clone(),
                        ..SessionMeta::default()
                    },
                    git: None,
                },
            )]),
            history_mode: None,
            session_source: None,
            thread_source: None,
            dynamic_tools: Vec::new(),
            metrics_service_name: None,
            parent_trace: None,
            environments: Vec::new(),
            thread_extension_init: Default::default(),
            supports_openai_form_elicitation: false,
        })
        .await
        .expect("start inherited fork");
    inherited.thread.ensure_rollout_materialized().await;
    inherited
        .thread
        .flush_rollout()
        .await
        .expect("flush inherited fork");
    let inherited_history = RolloutRecorder::get_rollout_history(
        &inherited
            .thread
            .rollout_path()
            .expect("inherited fork rollout path"),
    )
    .await
    .expect("read inherited fork rollout");

    assert_eq!(
        inherited_history.get_selected_capability_roots(),
        selected_roots
    );
}

#[tokio::test]
async fn resume_and_fork_do_not_restore_thread_environments_from_rollout() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );
    let selected_cwd =
        AbsolutePathBuf::try_from(config.cwd.as_path().join("selected")).expect("absolute path");
    std::fs::create_dir_all(&selected_cwd).expect("create selected cwd");
    let environments = vec![TurnEnvironmentSelection {
        environment_id: "local".to_string(),
        cwd: PathUri::from_abs_path(&selected_cwd),
        workspace_roots: Vec::new(),
    }];
    let default_cwd = config.cwd.clone();
    let mut source_config = config.clone();
    source_config.cwd = selected_cwd.clone();
    let source = manager
        .start_thread_with_options(StartThreadOptions {
            config: source_config,
            allow_provider_model_fallback: false,
            initial_history: InitialHistory::New,
            history_mode: None,
            session_source: None,
            thread_source: None,
            dynamic_tools: Vec::new(),
            metrics_service_name: None,
            parent_trace: None,
            environments: environments.clone(),
            thread_extension_init: Default::default(),
            supports_openai_form_elicitation: false,
        })
        .await
        .expect("start source thread");
    source.thread.ensure_rollout_materialized().await;
    source
        .thread
        .flush_rollout()
        .await
        .expect("flush source rollout");
    let rollout_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    source
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown source thread before resume");
    let _ = manager.remove_thread(&source.thread_id).await;

    let resumed = manager
        .resume_thread_from_rollout(
            config.clone(),
            rollout_path.clone(),
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume source thread");
    let resumed_turn = resumed
        .thread
        .session
        .new_turn_with_sub_id("resume-turn".to_string(), SessionSettingsUpdate::default())
        .await
        .expect("build resumed turn context");
    assert_eq!(resumed_turn.environments.turn_environments().count(), 1);
    assert_eq!(
        resumed_turn
            .environments
            .primary()
            .expect("primary environment")
            .cwd(),
        &PathUri::from_abs_path(&default_cwd)
    );
    assert_ne!(
        resumed_turn
            .environments
            .primary()
            .expect("primary environment")
            .cwd(),
        &PathUri::from_abs_path(&selected_cwd)
    );

    let forked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config,
            rollout_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("fork source thread");
    let forked_turn = forked
        .thread
        .session
        .new_turn_with_sub_id("fork-turn".to_string(), SessionSettingsUpdate::default())
        .await
        .expect("build forked turn context");
    assert_eq!(forked_turn.environments.turn_environments().count(), 1);
    assert_eq!(
        forked_turn
            .environments
            .primary()
            .expect("primary environment")
            .cwd(),
        &PathUri::from_abs_path(&default_cwd)
    );
    assert_ne!(
        forked_turn
            .environments
            .primary()
            .expect("primary environment")
            .cwd(),
        &PathUri::from_abs_path(&selected_cwd)
    );
}

#[tokio::test]
async fn explicit_installation_id_skips_codex_home_file() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let installation_id = uuid::Uuid::new_v4().to_string();
    let state_db = init_state_db(&config).await;
    let thread_store = thread_store_from_config(&config, state_db.clone());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store,
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        installation_id.clone(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let thread = manager
        .start_thread(config.clone())
        .await
        .expect("start thread with explicit installation id");

    assert!(!config.codex_home.join(INSTALLATION_ID_FILENAME).exists());
    assert_eq!(thread.thread.session.installation_id, installation_id);

    thread
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown thread");
    let _ = manager.remove_thread(&thread.thread_id).await;
}

#[tokio::test]
async fn resume_active_thread_from_rollout_returns_running_thread() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .start_thread(config.clone())
        .await
        .expect("start source thread");
    source.thread.ensure_rollout_materialized().await;
    source
        .thread
        .flush_rollout()
        .await
        .expect("flush source rollout");
    let rollout_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");

    let resumed = manager
        .resume_thread_from_rollout(
            config,
            rollout_path,
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume active source thread");
    assert_eq!(resumed.thread_id, source.thread_id);
    assert!(Arc::ptr_eq(&resumed.thread, &source.thread));

    source
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown source thread");
}

#[tokio::test]
async fn resume_stopped_thread_from_rollout_spawns_new_thread() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .start_thread(config.clone())
        .await
        .expect("start source thread");
    source.thread.ensure_rollout_materialized().await;
    source
        .thread
        .flush_rollout()
        .await
        .expect("flush source rollout");
    let rollout_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    source
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown source thread");

    let resumed = manager
        .resume_thread_from_rollout(
            config,
            rollout_path,
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume stopped source thread");
    assert_eq!(resumed.thread_id, source.thread_id);
    assert!(!Arc::ptr_eq(&resumed.thread, &source.thread));

    resumed
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown resumed thread");
}

#[tokio::test]
async fn resume_stopped_thread_from_rollout_preserves_thread_source() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let state_db = init_state_db(&config).await;
    let thread_store = thread_store_from_config(&config, state_db.clone());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store,
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .start_thread_with_options(StartThreadOptions {
            config: config.clone(),
            allow_provider_model_fallback: false,
            initial_history: InitialHistory::New,
            history_mode: None,
            session_source: None,
            thread_source: Some(ThreadSource::User),
            dynamic_tools: Vec::new(),
            metrics_service_name: None,
            parent_trace: None,
            environments: Vec::new(),
            thread_extension_init: Default::default(),
            supports_openai_form_elicitation: false,
        })
        .await
        .expect("start source thread");
    source.thread.ensure_rollout_materialized().await;
    source
        .thread
        .flush_rollout()
        .await
        .expect("flush source rollout");
    let rollout_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    source
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown source thread before resume");
    let _ = manager.remove_thread(&source.thread_id).await;

    let resumed = manager
        .resume_thread_from_rollout(
            config,
            rollout_path,
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume source thread");

    assert_eq!(
        resumed
            .thread
            .config_snapshot()
            .await
            .thread_source
            .as_ref(),
        Some(&ThreadSource::User)
    );

    resumed
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown resumed thread");
}

#[tokio::test]
async fn subtree_listing_uses_injected_graph_store_without_state_db() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let root_thread_id = ThreadId::new();
    let descendant_thread_ids = vec![ThreadId::new(), ThreadId::new()];
    let agent_graph_store = Arc::new(FakeAgentGraphStore {
        root_thread_id,
        descendant_thread_ids: descendant_thread_ids.clone(),
    });
    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        Some(agent_graph_store),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let mut expected_thread_ids = vec![root_thread_id];
    expected_thread_ids.extend(descendant_thread_ids);
    assert_eq!(
        manager
            .list_agent_subtree_thread_ids(root_thread_id)
            .await
            .expect("subtree should load from injected graph store"),
        expected_thread_ids
    );
}

#[tokio::test]
async fn rollout_path_resume_and_fork_read_history_through_thread_store() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    config.experimental_thread_store = ThreadStoreConfig::InMemory {
        id: format!("thread-manager-{}", uuid::Uuid::new_v4()),
    };
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let state_db = init_state_db(&config).await;
    let thread_store = thread_store_from_config(&config, state_db.clone());
    let in_memory_store = thread_store
        .as_any()
        .downcast_ref::<InMemoryThreadStore>()
        .expect("configured in-memory store");
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store.clone(),
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .start_thread(config.clone())
        .await
        .expect("start source thread");
    source
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown source thread");
    let _ = manager.remove_thread(&source.thread_id).await;

    let rollout_path = config
        .codex_home
        .join("rollouts/source.jsonl")
        .to_path_buf();
    let resumed = manager
        .resume_thread_with_history(
            config.clone(),
            InitialHistory::Resumed(ResumedHistory {
                conversation_id: source.thread_id,
                history: Arc::new(vec![RolloutItem::ResponseItem(user_msg("hello"))]),
                rollout_path: Some(rollout_path.clone()),
            }),
            auth_manager.clone(),
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("seed rollout path in store");
    resumed
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown seeded resumed thread");
    let _ = manager.remove_thread(&resumed.thread_id).await;

    let resumed_from_path = manager
        .resume_thread_from_rollout(
            config.clone(),
            rollout_path.clone(),
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume from rollout path");
    assert_eq!(resumed_from_path.thread_id, resumed.thread_id);

    let forked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config,
            rollout_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("fork from rollout path");
    assert_ne!(forked.thread_id, resumed.thread_id);

    let calls = in_memory_store.calls().await;
    assert_eq!(calls.read_thread_by_rollout_path, 2);

    resumed_from_path
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown path-resumed thread");
    forked
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown forked thread");
}

#[tokio::test]
async fn new_uses_active_provider_for_model_refresh() {
    let server = MockServer::start().await;
    let models_mock = mount_models_once(&server, ModelsResponse { models: vec![] }).await;

    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    config.model_catalog = None;
    config.model_provider.base_url = Some(server.uri());

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let _ = manager
        .list_models(
            RefreshStrategy::Online,
            crate::test_support::default_http_client_factory(),
        )
        .await;
    assert_eq!(models_mock.requests().len(), 1);
}

#[tokio::test]
async fn injected_models_manager_controls_refresh_policy() {
    let server = MockServer::start().await;
    let _ = mount_models_once(&server, ModelsResponse { models: vec![] }).await;
    let _ = mount_models_once(&server, ModelsResponse { models: vec![] }).await;

    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    config.model_catalog = None;
    config.model_provider.base_url = Some(server.uri());

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let provider = create_model_provider(
        config.model_provider.clone(),
        Some(Arc::clone(&auth_manager)),
    );
    let models_manager = provider.models_manager_without_cache(config.model_catalog.clone());
    let manager = ThreadManager::new(
        &config,
        auth_manager,
        models_manager,
        crate::CodexAppsToolsCache::default(),
        SessionSource::Custom("test-embedder".to_string()),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let http_client_factory = crate::test_support::default_http_client_factory();
    let _ = manager
        .list_models(
            RefreshStrategy::OnlineIfUncached,
            http_client_factory.clone(),
        )
        .await;
    let _ = manager
        .list_models(RefreshStrategy::OnlineIfUncached, http_client_factory)
        .await;

    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        2
    );
    assert!(!config.codex_home.join("models_cache.json").exists());
}

#[test]
fn interrupted_fork_snapshot_appends_interrupt_boundary() {
    let committed_history =
        InitialHistory::Forked(vec![RolloutItem::ResponseItem(user_msg("hello"))]);

    assert_eq!(
        serde_json::to_value(
            append_interrupted_boundary(
                committed_history,
                /*turn_id*/ None,
                /*started_at*/ None,
                InterruptedTurnHistoryMarker::ContextualUser,
            )
            .get_rollout_items()
        )
        .expect("serialize interrupted fork history"),
        serde_json::to_value(vec![
            RolloutItem::ResponseItem(user_msg("hello")),
            RolloutItem::ResponseItem(contextual_user_interrupted_marker()),
            RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
                turn_id: None,
                started_at: None,
                reason: TurnAbortReason::Interrupted,
                completed_at: None,
                duration_ms: None,
            })),
        ])
        .expect("serialize expected interrupted fork history"),
    );
    assert_eq!(
        serde_json::to_value(
            append_interrupted_boundary(
                InitialHistory::New,
                /*turn_id*/ None,
                /*started_at*/ None,
                InterruptedTurnHistoryMarker::ContextualUser,
            )
            .get_rollout_items()
        )
        .expect("serialize interrupted empty fork history"),
        serde_json::to_value(vec![
            RolloutItem::ResponseItem(contextual_user_interrupted_marker()),
            RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
                turn_id: None,
                started_at: None,
                reason: TurnAbortReason::Interrupted,
                completed_at: None,
                duration_ms: None,
            })),
        ])
        .expect("serialize expected interrupted empty history"),
    );
}

#[test]
fn disabled_interrupted_fork_snapshot_appends_only_interrupt_event() {
    let committed_history =
        InitialHistory::Forked(vec![RolloutItem::ResponseItem(user_msg("hello"))]);

    assert_eq!(
        serde_json::to_value(
            append_interrupted_boundary(
                committed_history,
                /*turn_id*/ None,
                /*started_at*/ None,
                InterruptedTurnHistoryMarker::Disabled,
            )
            .get_rollout_items()
        )
        .expect("serialize disabled interrupted fork history"),
        serde_json::to_value(vec![
            RolloutItem::ResponseItem(user_msg("hello")),
            RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
                turn_id: None,
                started_at: None,
                reason: TurnAbortReason::Interrupted,
                completed_at: None,
                duration_ms: None,
            })),
        ])
        .expect("serialize expected disabled interrupted fork history"),
    );
    assert_eq!(
        serde_json::to_value(
            append_interrupted_boundary(
                InitialHistory::New,
                /*turn_id*/ None,
                /*started_at*/ None,
                InterruptedTurnHistoryMarker::Disabled,
            )
            .get_rollout_items()
        )
        .expect("serialize disabled interrupted empty fork history"),
        serde_json::to_value(vec![RolloutItem::EventMsg(EventMsg::TurnAborted(
            TurnAbortedEvent {
                turn_id: None,
                started_at: None,
                reason: TurnAbortReason::Interrupted,
                completed_at: None,
                duration_ms: None,
            },
        ))])
        .expect("serialize expected disabled interrupted empty fork history"),
    );
}

#[test]
fn interrupted_snapshot_is_not_mid_turn() {
    let interrupted_history = InitialHistory::Forked(vec![
        RolloutItem::ResponseItem(user_msg("hello")),
        RolloutItem::ResponseItem(assistant_msg("partial")),
        RolloutItem::ResponseItem(contextual_user_interrupted_marker()),
        RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
            turn_id: Some("turn-1".to_string()),
            started_at: None,
            reason: TurnAbortReason::Interrupted,
            completed_at: None,
            duration_ms: None,
        })),
    ]);

    assert_eq!(
        snapshot_turn_state(&interrupted_history),
        SnapshotTurnState {
            ends_mid_turn: false,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
}

#[test]
fn multi_agent_v2_interrupted_marker_uses_developer_input_message() {
    let marker = developer_interrupted_marker();

    let ResponseItem::Message { role, content, .. } = marker else {
        panic!("expected interrupted marker to be a message");
    };
    assert_eq!(role, "developer");
    assert!(
        matches!(
            content.as_slice(),
            [ContentItem::InputText { text }]
                if text.contains(crate::context::TurnAborted::INTERRUPTED_DEVELOPER_GUIDANCE)
        ),
        "expected interrupted marker to use developer InputText content"
    );
}

#[test]
fn completed_legacy_event_history_is_not_mid_turn() {
    let completed_history = InitialHistory::Forked(vec![
        RolloutItem::EventMsg(EventMsg::UserMessage(UserMessageEvent {
            client_id: None,
            message: "hello".to_string(),
            images: None,
            text_elements: Vec::new(),
            local_images: Vec::new(),
            ..Default::default()
        })),
        RolloutItem::EventMsg(EventMsg::AgentMessage(AgentMessageEvent {
            message: "done".to_string(),
            phase: None,
            memory_citation: None,
        })),
    ]);

    assert_eq!(
        snapshot_turn_state(&completed_history),
        SnapshotTurnState {
            ends_mid_turn: false,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
}

#[test]
fn mixed_response_and_legacy_user_event_history_is_mid_turn() {
    let mixed_history = InitialHistory::Forked(vec![
        RolloutItem::ResponseItem(user_msg("hello")),
        RolloutItem::EventMsg(EventMsg::UserMessage(UserMessageEvent {
            client_id: None,
            message: "hello".to_string(),
            images: None,
            text_elements: Vec::new(),
            local_images: Vec::new(),
            ..Default::default()
        })),
    ]);

    assert_eq!(
        snapshot_turn_state(&mixed_history),
        SnapshotTurnState {
            ends_mid_turn: true,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
}

#[tokio::test]
async fn interrupted_fork_snapshot_does_not_synthesize_turn_id_for_legacy_history() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let state_db = init_state_db(&config).await;
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, state_db.clone()),
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .resume_thread_with_history(
            config.clone(),
            InitialHistory::Forked(vec![
                RolloutItem::ResponseItem(user_msg("hello")),
                RolloutItem::ResponseItem(assistant_msg("partial")),
            ]),
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("create source thread from completed history");
    let source_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    let source_history = RolloutRecorder::get_rollout_history(&source_path)
        .await
        .expect("read source rollout history");
    let source_snapshot_state = snapshot_turn_state(&source_history);
    assert!(source_snapshot_state.ends_mid_turn);
    let expected_turn_id = source_snapshot_state.active_turn_id.clone();
    assert_eq!(expected_turn_id, None);

    let forked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config.clone(),
            source_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("fork interrupted snapshot");
    let forked_path = forked
        .thread
        .rollout_path()
        .expect("forked rollout path should exist");
    let history = RolloutRecorder::get_rollout_history(&forked_path)
        .await
        .expect("read forked rollout history");
    assert!(!snapshot_turn_state(&history).ends_mid_turn);
    let rollout_items: Vec<_> = history
        .get_rollout_items()
        .iter()
        .filter(|item| !matches!(item, RolloutItem::SessionMeta(_)))
        .collect();
    let interrupted_marker_json = serde_json::to_value(RolloutItem::ResponseItem(
        contextual_user_interrupted_marker(),
    ))
    .expect("serialize interrupted marker");
    let interrupted_abort_json = serde_json::to_value(RolloutItem::EventMsg(
        EventMsg::TurnAborted(TurnAbortedEvent {
            turn_id: expected_turn_id,
            started_at: None,
            reason: TurnAbortReason::Interrupted,
            completed_at: None,
            duration_ms: None,
        }),
    ))
    .expect("serialize interrupted abort event");
    assert_eq!(
        rollout_items
            .iter()
            .filter(|item| {
                strip_response_item_ids_from_json(
                    serde_json::to_value(item).expect("serialize rollout item"),
                ) == interrupted_marker_json
            })
            .count(),
        1,
    );
    assert_eq!(
        rollout_items
            .iter()
            .filter(|item| {
                serde_json::to_value(item).expect("serialize rollout item")
                    == interrupted_abort_json
            })
            .count(),
        1,
    );
}

#[tokio::test]
async fn interrupted_fork_snapshot_preserves_explicit_turn_id() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let state_db = init_state_db(&config).await;
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, state_db.clone()),
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .resume_thread_with_history(
            config.clone(),
            InitialHistory::Forked(vec![
                RolloutItem::EventMsg(EventMsg::TurnStarted(TurnStartedEvent {
                    turn_id: "turn-explicit".to_string(),
                    trace_id: None,
                    started_at: None,
                    model_context_window: None,
                    collaboration_mode_kind: Default::default(),
                })),
                RolloutItem::ResponseItem(user_msg("hello")),
                RolloutItem::ResponseItem(assistant_msg("partial")),
            ]),
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("create source thread from explicit partial history");
    let source_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    let source_history = RolloutRecorder::get_rollout_history(&source_path)
        .await
        .expect("read source rollout history");
    let source_snapshot_state = snapshot_turn_state(&source_history);
    assert_eq!(
        source_snapshot_state,
        SnapshotTurnState {
            ends_mid_turn: true,
            active_turn_id: Some("turn-explicit".to_string()),
            active_turn_started_at: None,
            active_turn_start_index: Some(1),
        },
    );

    let forked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config.clone(),
            source_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("fork interrupted snapshot");
    let forked_path = forked
        .thread
        .rollout_path()
        .expect("forked rollout path should exist");
    let history = RolloutRecorder::get_rollout_history(&forked_path)
        .await
        .expect("read forked rollout history");
    let rollout_items: Vec<_> = history
        .get_rollout_items()
        .iter()
        .filter(|item| !matches!(item, RolloutItem::SessionMeta(_)))
        .collect();

    assert!(rollout_items.iter().any(|item| {
        matches!(
            item,
            RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
                turn_id: Some(turn_id),
                started_at: None,
                reason: TurnAbortReason::Interrupted,
            completed_at: None,
            duration_ms: None,
            })) if turn_id == "turn-explicit"
        )
    }));
}

#[tokio::test]
async fn interrupted_fork_snapshot_uses_persisted_mid_turn_history_without_live_source() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let state_db = init_state_db(&config).await;
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, state_db.clone()),
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .resume_thread_with_history(
            config.clone(),
            InitialHistory::Forked(vec![
                RolloutItem::ResponseItem(user_msg("hello")),
                RolloutItem::ResponseItem(assistant_msg("partial")),
            ]),
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("create source thread from partial history");
    let source_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    let source_history = RolloutRecorder::get_rollout_history(&source_path)
        .await
        .expect("read source rollout history");
    assert!(snapshot_turn_state(&source_history).ends_mid_turn);
    manager.remove_thread(&source.thread_id).await;

    let forked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config.clone(),
            source_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("fork interrupted snapshot");
    let forked_path = forked
        .thread
        .rollout_path()
        .expect("forked rollout path should exist");
    let history = RolloutRecorder::get_rollout_history(&forked_path)
        .await
        .expect("read forked rollout history");
    assert!(!snapshot_turn_state(&history).ends_mid_turn);

    let forked_rollout_items: Vec<_> = history
        .get_rollout_items()
        .iter()
        .filter(|item| !matches!(item, RolloutItem::SessionMeta(_)))
        .collect();
    let interrupted_marker_json = serde_json::to_value(RolloutItem::ResponseItem(
        contextual_user_interrupted_marker(),
    ))
    .expect("serialize interrupted marker");
    assert_eq!(
        forked_rollout_items
            .iter()
            .filter(|item| {
                strip_response_item_ids_from_json(
                    serde_json::to_value(item).expect("serialize forked rollout item"),
                ) == interrupted_marker_json
            })
            .count(),
        1,
    );

    manager.remove_thread(&forked.thread_id).await;
    let reforked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config.clone(),
            forked_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("re-fork interrupted snapshot");
    let reforked_path = reforked
        .thread
        .rollout_path()
        .expect("re-forked rollout path should exist");
    let reforked_history = RolloutRecorder::get_rollout_history(&reforked_path)
        .await
        .expect("read re-forked rollout history");
    let reforked_rollout_items: Vec<_> = reforked_history
        .get_rollout_items()
        .iter()
        .filter(|item| !matches!(item, RolloutItem::SessionMeta(_)))
        .collect();

    assert_eq!(
        reforked_rollout_items
            .iter()
            .filter(|item| {
                strip_response_item_ids_from_json(
                    serde_json::to_value(item).expect("serialize re-forked rollout item"),
                ) == interrupted_marker_json
            })
            .count(),
        1,
    );
    assert_eq!(
        reforked_rollout_items
            .iter()
            .filter(|item| {
                matches!(
                    item,
                    RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
                        reason: TurnAbortReason::Interrupted,
                        ..
                    }))
                )
            })
            .count(),
        1,
    );
}
