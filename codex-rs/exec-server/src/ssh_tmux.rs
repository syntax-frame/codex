//! tmux-backed process continuity for SSH server-mode agents.
//!
//! Every agent owns one tmux session and every running tool process owns a
//! window in that session. Live output is mirrored to a remote log. If the SSH
//! transport drops, the monitor reconnects at the last delivered byte while
//! the command continues inside tmux.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use russh::ChannelMsg;
use sha2::Digest;
use sha2::Sha256;
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::sync::watch;

use crate::AdoptionRequest;
use crate::ExecServerError;
use crate::PreparedExecution;
use crate::ProcessSignalOutcome;
use crate::ProcessSignalRejectionReason;
use crate::ReconciliationRequest;
use crate::RecoveredExecution;
use crate::RecoveredExecutionAcknowledgement;
use crate::RecoveredExecutionStatus;
use crate::StartedExecProcess;
use crate::process::ExecProcessEventLog;
use crate::protocol::ExecOutputStream;
use crate::protocol::ExecParams;
use crate::protocol::ExecutionIdentity;

use super::ChannelCommand;
use super::PROCESS_EVENT_CHANNEL_CAPACITY;
use super::RETAINED_OUTPUT_BYTES_PER_PROCESS;
use super::SharedState;
use super::SshProcess;
use super::SshProcessBackend;
use super::build_remote_command_body;
use super::publish_closed;
use super::publish_exit;
use super::publish_output_with_absolute_range;
use super::shell_quote;
use super::with_remote_path;

const MONITOR_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);
const TMUX_BOOTSTRAP_ATTEMPTS: usize = 4;
const TMUX_TERMINATE_ATTEMPTS: usize = 3;
const COMPLETED_WINDOW_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
const AGENT_SESSION_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
// A controller normally refreshes the remote lease every five seconds. Fifteen
// minutes exceeds the bounded reconnect schedule and gives transient mobile
// suspension ample recovery time, while still bounding crash-orphan lifetime.
const CONTROLLER_LEASE_SECONDS: u64 = 15 * 60;
const CONTROLLER_HEARTBEAT_SECONDS: u64 = 5;
const OWNERSHIP_MARKER: &str = "agentapp-tmux-v2";

pub(super) async fn reconcile(
    backend: &SshProcessBackend,
    request: &ReconciliationRequest,
) -> Result<Vec<RecoveredExecution>, ExecServerError> {
    validate_reconciliation_request(request)?;
    let command = exact_reconciliation_command(backend.session_key(), request);
    let result = backend
        .transport()
        .exec_control(&with_remote_path(&command), None)
        .await?;
    if result.exit_code != 0 {
        return Err(ExecServerError::Protocol(format!(
            "ssh tmux exact reconciliation failed with exit {}: {}",
            result.exit_code,
            String::from_utf8_lossy(&result.output).trim()
        )));
    }
    parse_recovered_executions(&result.output)
}

fn validate_reconciliation_request(request: &ReconciliationRequest) -> Result<(), ExecServerError> {
    if request.incomplete_executions.iter().any(|execution| {
        execution.protocol_evidence != crate::RemoteExecutionProtocolEvidence::V2Proven
    }) {
        return Err(ExecServerError::Protocol(
            "remote execution recovery lacks preceding durable-v2 protocol evidence".to_string(),
        ));
    }
    Ok(())
}

pub(super) async fn acknowledge_consumed(
    backend: &SshProcessBackend,
    acknowledgement: &RecoveredExecutionAcknowledgement,
) -> Result<(), ExecServerError> {
    let command = acknowledgement_command(backend.session_key(), acknowledgement);
    let result = backend
        .transport()
        .exec_control(&with_remote_path(&command), None)
        .await?;
    if result.exit_code == 0 {
        Ok(())
    } else {
        Err(ExecServerError::Protocol(format!(
            "ssh tmux recovery acknowledgement failed with exit {}: {}",
            result.exit_code,
            String::from_utf8_lossy(&result.output).trim()
        )))
    }
}

pub(super) async fn release_acknowledged(
    backend: &SshProcessBackend,
    acknowledgement: &RecoveredExecutionAcknowledgement,
) -> Result<(), ExecServerError> {
    if acknowledgement.terminal_proof().is_none() {
        return Err(ExecServerError::Protocol(
            "ssh tmux acknowledgement release requires terminal proof".to_string(),
        ));
    }
    let command = acknowledgement_release_command(backend.session_key(), acknowledgement);
    let result = backend
        .transport()
        .exec_control(&with_remote_path(&command), None)
        .await?;
    if result.exit_code == 0 {
        Ok(())
    } else {
        Err(ExecServerError::Protocol(format!(
            "ssh tmux acknowledgement release failed with exit {}: {}",
            result.exit_code,
            String::from_utf8_lossy(&result.output).trim()
        )))
    }
}

pub(super) async fn start(
    backend: SshProcessBackend,
    params: ExecParams,
) -> Result<StartedExecProcess, ExecServerError> {
    start_prepared(backend, PreparedExecution::new(params)).await
}

pub(super) async fn start_prepared(
    backend: SshProcessBackend,
    prepared: PreparedExecution,
) -> Result<StartedExecProcess, ExecServerError> {
    let (params, prepared_digest) = prepared.into_parts();
    params.execution_identity.as_ref().ok_or_else(|| {
        ExecServerError::Protocol(
            "ssh tmux lifecycle requires structured execution_identity".to_string(),
        )
    })?;
    if crate::canonical_command_digest(&params) != prepared_digest {
        return Err(ExecServerError::Protocol(
            "prepared execution digest no longer matches its immutable parameters".to_string(),
        ));
    }
    let mut descriptor = TmuxProcessDescriptor::new_with_digest(
        backend.session_key(),
        backend.controller_id(),
        &params,
        prepared_digest,
    );
    let bootstrap = with_remote_path(&descriptor.bootstrap_command(&params));
    for attempt in 0..TMUX_BOOTSTRAP_ATTEMPTS {
        let error = match backend.transport().exec_control(&bootstrap, None).await {
            Ok(result) if result.exit_code == 0 => {
                let output = String::from_utf8_lossy(&result.output);
                let controller = output.lines().find_map(|line| {
                    line.strip_prefix("AGENTAPP_TMUX_READY ")
                        .and_then(|payload| payload.split_whitespace().nth(1))
                });
                let Some(controller) = controller else {
                    return Err(ExecServerError::Protocol(
                        "ssh tmux bootstrap omitted fenced controller identity".to_string(),
                    ));
                };
                descriptor.controller_id = controller.to_string();
                break;
            }
            Ok(result) => {
                let output = String::from_utf8_lossy(&result.output);
                if result.exit_code == 127 || output.contains("AGENTAPP_TMUX_MISSING") {
                    return Err(ExecServerError::Protocol(format!(
                        "ssh tmux_required: unavailable: {}",
                        output.trim()
                    )));
                }
                ExecServerError::Protocol(format!(
                    "ssh tmux bootstrap failed with exit {}: {}",
                    result.exit_code,
                    output.trim()
                ))
            }
            Err(error) => error,
        };

        if attempt + 1 == TMUX_BOOTSTRAP_ATTEMPTS {
            return Err(error);
        }
        let jitter = descriptor
            .agent_id
            .get(..2)
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .unwrap_or(0);
        let delay = 150 * (1u64 << attempt) + jitter;
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }

    let process_id = params.process_id.clone();
    let events = ExecProcessEventLog::new(
        PROCESS_EVENT_CHANNEL_CAPACITY,
        RETAINED_OUTPUT_BYTES_PER_PROCESS,
    );
    let (wake_tx, _wake_rx) = watch::channel(0);
    let output_notify = Arc::new(Notify::new());
    let state = Arc::new(StdMutex::new(SharedState::default()));
    let (cmd_tx, cmd_rx) = mpsc::channel::<ChannelCommand>(64);
    let stream = if params.tty {
        ExecOutputStream::Pty
    } else {
        ExecOutputStream::Stdout
    };

    tokio::spawn(monitor_pump(
        backend,
        descriptor,
        stream,
        events.clone(),
        wake_tx.clone(),
        Arc::clone(&output_notify),
        Arc::clone(&state),
        cmd_rx,
        0,
    ));

    Ok(StartedExecProcess {
        process: Arc::new(SshProcess {
            process_id,
            events,
            wake_tx,
            output_notify,
            state,
            cmd_tx,
        }),
    })
}

pub(super) async fn adopt_execution(
    backend: SshProcessBackend,
    request: AdoptionRequest,
) -> Result<StartedExecProcess, ExecServerError> {
    let mut descriptor = TmuxProcessDescriptor::from_adoption(
        backend.session_key(),
        backend.controller_id(),
        &request,
    );
    let result = backend
        .transport()
        .exec_control(&with_remote_path(&descriptor.adoption_command()), None)
        .await?;
    if result.exit_code != 0 {
        return Err(ExecServerError::Protocol(format!(
            "ssh tmux adoption failed with exit {}: {}",
            result.exit_code,
            String::from_utf8_lossy(&result.output).trim()
        )));
    }
    let output = String::from_utf8_lossy(&result.output);
    let controller = output
        .lines()
        .find_map(|line| line.strip_prefix("AGENTAPP_TMUX_ADOPTED "))
        .ok_or_else(|| {
            ExecServerError::Protocol(
                "ssh tmux adoption omitted fenced controller identity".to_string(),
            )
        })?;
    descriptor.controller_id = controller.to_string();

    let events = ExecProcessEventLog::new(
        PROCESS_EVENT_CHANNEL_CAPACITY,
        RETAINED_OUTPUT_BYTES_PER_PROCESS,
    );
    let (wake_tx, _wake_rx) = watch::channel(0);
    let output_notify = Arc::new(Notify::new());
    let state = Arc::new(StdMutex::new(SharedState::default()));
    let (cmd_tx, cmd_rx) = mpsc::channel::<ChannelCommand>(64);
    let stream = if request.tty {
        ExecOutputStream::Pty
    } else {
        ExecOutputStream::Stdout
    };
    tokio::spawn(monitor_pump(
        backend,
        descriptor.clone(),
        stream,
        events.clone(),
        wake_tx.clone(),
        Arc::clone(&output_notify),
        Arc::clone(&state),
        cmd_rx,
        request.committed_output_cursor,
    ));
    let process_id = request
        .original_session_id
        .map(|value| value.to_string())
        .unwrap_or(descriptor.process_id);
    Ok(StartedExecProcess {
        process: Arc::new(SshProcess {
            process_id: crate::ProcessId::new(process_id),
            events,
            wake_tx,
            output_notify,
            state,
            cmd_tx,
        }),
    })
}

pub(super) fn is_unavailable(error: &ExecServerError) -> bool {
    error.to_string().contains("tmux_required: unavailable")
}

#[allow(clippy::too_many_arguments)]
async fn monitor_pump(
    backend: SshProcessBackend,
    descriptor: TmuxProcessDescriptor,
    stream: ExecOutputStream,
    events: ExecProcessEventLog,
    wake_tx: watch::Sender<u64>,
    output_notify: Arc<Notify>,
    state: Arc<StdMutex<SharedState>>,
    mut cmd_rx: mpsc::Receiver<ChannelCommand>,
    initial_delivered_bytes: u64,
) {
    let mut delivered_bytes = initial_delivered_bytes;
    let mut reconnect_attempts = 0usize;
    let mut commands_open = true;
    let exit_code = 'monitor: loop {
        let mut channel = match backend.transport().open_work_channel().await {
            Ok(channel) => channel,
            Err(error) => {
                if reconnect_attempts == usize::MAX {
                    publish_monitor_failure(&error);
                }
                reconnect_attempts = reconnect_attempts.saturating_add(1);
                monitor_retry_delay(reconnect_attempts).await;
                continue;
            }
        };
        let monitor_command = descriptor.monitor_command(delivered_bytes + 1);
        if let Err(error) = channel.channel().exec(true, monitor_command).await {
            if reconnect_attempts == usize::MAX {
                publish_monitor_failure(&error);
            }
            reconnect_attempts = reconnect_attempts.saturating_add(1);
            monitor_retry_delay(reconnect_attempts).await;
            continue;
        }
        let monitor_attached_at = Instant::now();

        let mut channel_exit = None;
        loop {
            tokio::select! {
                message = channel.channel_mut().wait() => {
                    let Some(message) = message else {
                        break;
                    };
                    match message {
                        ChannelMsg::Data { data } => {
                            let absolute_start = delivered_bytes;
                            delivered_bytes = delivered_bytes.saturating_add(data.len() as u64);
                            reconnect_attempts = 0;
                            publish_output_with_absolute_range(
                                &state,
                                &events,
                                &wake_tx,
                                &output_notify,
                                stream,
                                data.to_vec(),
                                absolute_start,
                                delivered_bytes,
                            );
                        }
                        ChannelMsg::ExtendedData { data, .. } => {
                            // The persisted process log is emitted on stdout. Monitor
                            // diagnostics on stderr are transport diagnostics, not
                            // command output. Publishing them would make the model
                            // output diverge from the authoritative remote cursor.
                            tracing::debug!(
                                diagnostic = %String::from_utf8_lossy(&data),
                                "ignored tmux monitor diagnostic"
                            );
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            channel_exit = Some(exit_status as i32);
                        }
                        ChannelMsg::ExitSignal { .. } if channel_exit.is_none() => {
                            channel_exit = Some(-1);
                        }
                        ChannelMsg::Eof | ChannelMsg::Close => {}
                        _ => {}
                    }
                }
                command = cmd_rx.recv(), if commands_open => {
                    match command {
                        Some(ChannelCommand::Write {
                            data,
                            write_id,
                            ack,
                        }) => {
                            let result = descriptor
                                .write(backend.transport(), &data, write_id.as_deref())
                                .await
                                .map_err(|error| error.to_string());
                            let _ = ack.send(result);
                        }
                        Some(ChannelCommand::Signal { ack, .. }) => {
                            let result = descriptor.interrupt(backend.transport()).await;
                            if let Err(error) = &result {
                                tracing::debug!(
                                    session_key = %backend.session_key(),
                                    error = %error,
                                    "failed to interrupt tmux process"
                                );
                            }
                            let _ = ack.send(
                                result.map_err(|error| error.to_string())
                            );
                        }
                        Some(ChannelCommand::Terminate { ack }) => {
                            let result =
                                terminate_with_retry(&descriptor, backend.transport()).await;
                            if let Err(error) = &result {
                                tracing::debug!(
                                    session_key = %backend.session_key(),
                                    error = %error,
                                    "failed to terminate tmux process"
                                );
                            }
                            let _ = ack.send(result.map_err(|error| error.to_string()));
                        }
                        None => commands_open = false,
                    }
                }
            }

            if channel_exit.is_some() {
                match descriptor.classify_monitor_exit(backend.transport()).await {
                    Ok(MonitorExitClassification::Terminal(exit_code)) => {
                        break 'monitor exit_code;
                    }
                    Ok(MonitorExitClassification::OwnershipLost) => {
                        tracing::debug!(
                            session_key = %backend.session_key(),
                            "obsolete tmux monitor stopped after controller ownership changed"
                        );
                        return;
                    }
                    Ok(MonitorExitClassification::ChannelLost) | Err(_) => {
                        break;
                    }
                }
            }
        }

        if monitor_attached_at.elapsed() >= Duration::from_secs(CONTROLLER_HEARTBEAT_SECONDS) {
            reconnect_attempts = 0;
        }
        reconnect_attempts = reconnect_attempts.saturating_add(1);
        monitor_retry_delay(reconnect_attempts).await;
    };

    let mut confirmed_exit = exit_code;
    if exit_code != -1
        && let Err(error) = descriptor.cleanup(backend.transport()).await
    {
        tracing::debug!(
            session_key = %backend.session_key(),
            error = %error,
            "failed to confirm completed tmux process termination"
        );
        publish_monitor_failure(&error);
        confirmed_exit = -1;
    }
    publish_exit(&state, &events, &wake_tx, &output_notify, confirmed_exit);
    publish_closed(&state, &events, &wake_tx, &output_notify);
}

fn publish_monitor_failure(error: &dyn std::fmt::Display) {
    tracing::warn!(
        error = %error,
        "AgentApp SSH monitor lost; the remote command remains owned by its persisted descriptor"
    );
}

async fn terminate_with_retry(
    descriptor: &TmuxProcessDescriptor,
    transport: &crate::ssh_transport::SshTransport,
) -> Result<(), ExecServerError> {
    let mut last_error = None;
    for attempt in 0..TMUX_TERMINATE_ATTEMPTS {
        match descriptor.terminate(transport).await {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        if attempt + 1 < TMUX_TERMINATE_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(150 * (1u64 << attempt))).await;
        }
    }
    Err(last_error.unwrap_or_else(|| {
        ExecServerError::Protocol("ssh tmux terminate exhausted retries".to_string())
    }))
}

async fn monitor_retry_delay(attempt: usize) {
    let exponent = attempt.saturating_sub(1).min(4) as u32;
    let delay = Duration::from_millis(250 * (1u64 << exponent));
    tokio::time::sleep(delay.min(MONITOR_RETRY_MAX_DELAY)).await;
}

#[derive(Clone, Debug)]
struct TmuxProcessDescriptor {
    agent_id: String,
    process_id: String,
    controller_id: String,
    command_digest: String,
    session_name: String,
    window_name: String,
    watchdog_window_name: String,
    tty: bool,
    thread_id_base64: String,
    turn_id_base64: String,
    call_id_base64: String,
    attempt_generation: u32,
    session_id: Option<i32>,
    acknowledgement_token: String,
}

enum MonitorExitClassification {
    Terminal(i32),
    OwnershipLost,
    ChannelLost,
}

fn parse_monitor_exit_classification(
    output: &[u8],
) -> Result<MonitorExitClassification, ExecServerError> {
    let line = String::from_utf8_lossy(output);
    let line = line.trim();
    if line == "ownership-lost" {
        Ok(MonitorExitClassification::OwnershipLost)
    } else if line == "channel-lost" {
        Ok(MonitorExitClassification::ChannelLost)
    } else if let Some(code) = line.strip_prefix("terminal ") {
        Ok(MonitorExitClassification::Terminal(code.parse().map_err(
            |_| ExecServerError::Protocol("invalid durable tmux status".to_string()),
        )?))
    } else {
        Err(ExecServerError::Protocol(
            "invalid tmux monitor exit classification".to_string(),
        ))
    }
}

impl TmuxProcessDescriptor {
    #[cfg(test)]
    fn new(agent_key: &str, controller_id: &str, params: &ExecParams) -> Self {
        Self::new_with_digest(
            agent_key,
            controller_id,
            params,
            crate::canonical_command_digest(params),
        )
    }

    fn new_with_digest(
        agent_key: &str,
        controller_id: &str,
        params: &ExecParams,
        command_digest: String,
    ) -> Self {
        let identity = params
            .execution_identity
            .as_ref()
            .expect("tmux start validates execution identity");
        let agent_id = stable_identifier(agent_key);
        let identity_key = format!(
            "{}\0{}\0{}\0{}",
            identity.thread_id, identity.turn_id, identity.call_id, identity.attempt_generation
        );
        let process_id = stable_identifier(&identity_key);
        let acknowledgement_token = format!(
            "{process_id}-{:x}",
            Sha256::digest(
                format!("{agent_id}:{process_id}:{command_digest}:{identity_key}").as_bytes()
            )
        );
        Self {
            session_name: format!("agentapp_{agent_id}"),
            window_name: format!("p_{process_id}"),
            watchdog_window_name: format!("w_{process_id}"),
            agent_id,
            process_id,
            controller_id: controller_id.to_string(),
            command_digest,
            tty: params.tty,
            thread_id_base64: STANDARD.encode(identity.thread_id.as_bytes()),
            turn_id_base64: STANDARD.encode(identity.turn_id.as_bytes()),
            call_id_base64: STANDARD.encode(identity.call_id.as_bytes()),
            attempt_generation: identity.attempt_generation,
            session_id: params.process_id.as_str().parse().ok(),
            acknowledgement_token,
        }
    }

    fn from_adoption(agent_key: &str, controller_id: &str, request: &AdoptionRequest) -> Self {
        let identity = &request.identity;
        let agent_id = stable_identifier(agent_key);
        let identity_key = format!(
            "{}\0{}\0{}\0{}",
            identity.thread_id, identity.turn_id, identity.call_id, identity.attempt_generation
        );
        let process_id = stable_identifier(&identity_key);
        let acknowledgement_token = format!(
            "{process_id}-{:x}",
            Sha256::digest(
                format!(
                    "{agent_id}:{process_id}:{}:{identity_key}",
                    request.expected_command_digest
                )
                .as_bytes()
            )
        );
        Self {
            session_name: format!("agentapp_{agent_id}"),
            window_name: format!("p_{process_id}"),
            watchdog_window_name: format!("w_{process_id}"),
            agent_id,
            process_id,
            controller_id: controller_id.to_string(),
            command_digest: request.expected_command_digest.clone(),
            tty: request.tty,
            thread_id_base64: STANDARD.encode(identity.thread_id.as_bytes()),
            turn_id_base64: STANDARD.encode(identity.turn_id.as_bytes()),
            call_id_base64: STANDARD.encode(identity.call_id.as_bytes()),
            attempt_generation: identity.attempt_generation,
            session_id: request.original_session_id,
            acknowledgement_token,
        }
    }

    fn adoption_command(&self) -> String {
        let root = self.remote_directory();
        let adoption_key = stable_identifier(&format!(
            "{}:{}:adoption",
            self.process_id, self.controller_id
        ));
        format!(
            concat!(
                "set -eu\n",
                "root=\"{root}\"\n",
                "expected_session={session}\n",
                "expected_window={window}\n",
                "candidate_controller={candidate}\n",
                "agentapp_adopt_probe_process_group() {{\n",
                "  probe_state=unknown\n",
                "  [ -x /bin/kill ] || return\n",
                "  if /bin/kill -0 -- \"-$1\" 2>/dev/null; then probe_state=alive; return; fi\n",
                "  if kill_error=$(LC_ALL=C /bin/kill -0 -- \"-$1\" 2>&1); then probe_state=alive; return; fi\n",
                "  case \"$kill_error\" in *\"No such process\"*) probe_state=dead ;; esac\n",
                "}}\n",
                "agentapp_adopt_authority() {{\n",
                "  [ -d \"$root\" ] || {{ echo AGENTAPP_TMUX_ADOPT_MISSING >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/owner\" 2>/dev/null || true)\" = {owner} ] || {{ echo AGENTAPP_TMUX_ADOPT_AUTHORITY_MISMATCH >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/identity\" 2>/dev/null || true)\" = {identity} ] || {{ echo AGENTAPP_TMUX_ADOPT_AUTHORITY_MISMATCH >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/thread-id\" 2>/dev/null || true)\" = {thread_id} ] || {{ echo AGENTAPP_TMUX_ADOPT_AUTHORITY_MISMATCH >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/turn-id\" 2>/dev/null || true)\" = {turn_id} ] || {{ echo AGENTAPP_TMUX_ADOPT_AUTHORITY_MISMATCH >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/call-id\" 2>/dev/null || true)\" = {call_id} ] || {{ echo AGENTAPP_TMUX_ADOPT_AUTHORITY_MISMATCH >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/attempt-generation\" 2>/dev/null || true)\" = {generation} ] || {{ echo AGENTAPP_TMUX_ADOPT_AUTHORITY_MISMATCH >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/session-id\" 2>/dev/null || true)\" = {session_id} ] || {{ echo AGENTAPP_TMUX_ADOPT_AUTHORITY_MISMATCH >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/tty\" 2>/dev/null || true)\" = {tty} ] || {{ echo AGENTAPP_TMUX_ADOPT_AUTHORITY_MISMATCH >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/digest\" 2>/dev/null || true)\" = {digest} ] || {{ echo AGENTAPP_TMUX_ADOPT_AUTHORITY_MISMATCH >&2; exit 77; }}\n",
                "}}\n",
                "agentapp_adopt_live_pane() {{\n",
                "  adopt_state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "  case \"$adopt_state\" in running) ;; prepared) [ -e \"$root/go\" ] || {{ echo AGENTAPP_TMUX_ADOPT_NOT_RUNNING >&2; exit 78; }} ;; *) echo AGENTAPP_TMUX_ADOPT_NOT_RUNNING >&2; exit 78 ;; esac\n",
                "  [ ! -f \"$root/status\" ] || {{ echo AGENTAPP_TMUX_ADOPT_TERMINAL >&2; exit 78; }}\n",
                "  process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
                "  pane_pid=${{process_identity%%:*}}\n",
                "  pgid=${{process_identity#*:}}\n",
                "  case \"$pane_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_ADOPT_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  case \"$pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_ADOPT_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  if window_listing=$(LC_ALL=C tmux list-windows -t \"$expected_session:\" -F '#{{window_name}}' 2>&1); then\n",
                "    printf '%s\\n' \"$window_listing\" | grep -Fqx \"$expected_window\" || {{ echo AGENTAPP_TMUX_ADOPT_WINDOW_MISSING >&2; exit 80; }}\n",
                "  else\n",
                "    case \"$window_listing\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) echo AGENTAPP_TMUX_ADOPT_WINDOW_MISSING >&2; exit 80 ;; *) echo AGENTAPP_TMUX_ADOPT_WINDOW_QUERY_FAILED >&2; exit 77 ;; esac\n",
                "  fi\n",
                "  current_pane=$(tmux display-message -p -t \"$expected_session:$expected_window.0\" '#{{pane_pid}}' 2>/dev/null || true)\n",
                "  current_pgid=$(ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' ')\n",
                "  [ \"$current_pane\" = \"$pane_pid\" ] && [ \"$current_pgid\" = \"$pgid\" ] && kill -0 \"-$pgid\" 2>/dev/null || {{ echo AGENTAPP_TMUX_ADOPT_OWNERSHIP_MISMATCH >&2; exit 80; }}\n",
                "}}\n",
                "agentapp_adopt_authority\n",
                "agentapp_adopt_live_pane\n",
                "if [ -e \"$root/transition-claim\" ]; then\n",
                "  claim_line=$(cat \"$root/transition-claim\" 2>/dev/null || true)\n",
                "  old_ifs=$IFS\n",
                "  IFS='|'\n",
                "  read claim_kind claim_nonce claim_controller claim_operation_pid claim_operation_pgid claim_window claim_pane claim_pgid <<AGENTAPP_TRANSITION_EOF\n",
                "$claim_line\n",
                "AGENTAPP_TRANSITION_EOF\n",
                "  IFS=$old_ifs\n",
                "  case \"$claim_kind\" in adoption|bootstrap) ;; recovery) echo AGENTAPP_TMUX_ADOPT_RECOVERY_CONFLICT >&2; exit 79 ;; *) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
                "  case \"$claim_nonce\" in ''|*[!0-9a-zA-Z_.-]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
                "  case \"$claim_operation_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
                "  case \"$claim_operation_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
                "  claim_generation=${{claim_controller%%:*}}\n",
                "  claim_controller_id=${{claim_controller#*:}}\n",
                "  case \"$claim_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
                "  [ -n \"$claim_controller_id\" ] && [ \"$claim_controller_id\" != \"$claim_controller\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "  [ \"$claim_window\" = \"$expected_window\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "  live_operation_pgid=$(ps -o pgid= -p \"$claim_operation_pid\" 2>/dev/null | tr -d ' ')\n",
                "  [ \"$live_operation_pgid\" != \"$claim_operation_pgid\" ] || {{ echo AGENTAPP_TMUX_ADOPT_BUSY >&2; exit 79; }}\n",
                "  agentapp_adopt_probe_process_group \"$claim_operation_pgid\"\n",
                "  case \"$probe_state\" in dead) ;; alive) echo AGENTAPP_TMUX_ADOPT_BUSY >&2; exit 79 ;; *) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  agentapp_adopt_authority\n",
                "  agentapp_adopt_live_pane\n",
                "  [ \"$claim_operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "  case \"$claim_kind\" in\n",
                "    adoption)\n",
                "      [ \"$claim_pane\" = \"$pane_pid\" ] && [ \"$claim_pgid\" = \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "      current_controller=$(cat \"$root/controller\" 2>/dev/null || true)\n",
                "      current_generation=${{current_controller%%:*}}\n",
                "      case \"$current_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_CONTROLLER_GENERATION_UNKNOWN >&2; exit 80 ;; esac\n",
                "      if [ \"$claim_controller\" != \"$current_controller\" ]; then [ \"$claim_generation\" -eq $((current_generation + 1)) ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}; fi\n",
                "      ;;\n",
                "    bootstrap)\n",
                "      [ -e \"$root/go\" ] || {{ echo AGENTAPP_TMUX_ADOPT_BOOTSTRAP_CONFLICT >&2; exit 79; }}\n",
                "      {{ [ \"$claim_pane:$claim_pgid\" = -:- ] || {{ [ \"$claim_pane\" = \"$pane_pid\" ] && [ \"$claim_pgid\" = \"$pgid\" ]; }}; }} || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "      [ \"$claim_controller\" = \"$(cat \"$root/controller\" 2>/dev/null || true)\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "      ;;\n",
                "  esac\n",
                "  [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$claim_line\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  quarantine=\"$root/transition-claim.quarantine.$claim_nonce\"\n",
                "  [ ! -e \"$quarantine\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_QUARANTINE_CONFLICT >&2; exit 79; }}\n",
                "  mv \"$root/transition-claim\" \"$quarantine\"\n",
                "fi\n",
                "agentapp_adopt_authority\n",
                "agentapp_adopt_live_pane\n",
                "observed=$(cat \"$root/controller\" 2>/dev/null || true)\n",
                "observed_generation=${{observed%%:*}}\n",
                "case \"$observed_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_CONTROLLER_GENERATION_UNKNOWN >&2; exit 80 ;; esac\n",
                "next_generation=$((observed_generation + 1))\n",
                "next=\"$next_generation:$candidate_controller\"\n",
                "operation_pid=$$\n",
                "operation_pgid=$(ps -o pgid= -p \"$operation_pid\" 2>/dev/null | tr -d ' ')\n",
                "case \"$operation_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "case \"$operation_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "[ \"$operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80; }}\n",
                "transition_candidate=\"$root/.transition-candidate.a_{adoption_key}.$$\"\n",
                "[ ! -e \"$transition_candidate\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CANDIDATE_CONFLICT >&2; exit 79; }}\n",
                "( umask 077; set -C; printf 'adoption|a_{adoption_key}|%s|%s|%s|%s|%s|%s\\n' \"$next\" \"$operation_pid\" \"$operation_pgid\" \"$expected_window\" \"$pane_pid\" \"$pgid\" > \"$transition_candidate\" ) || {{ echo AGENTAPP_TMUX_TRANSITION_CANDIDATE_CONFLICT >&2; exit 79; }}\n",
                "ln \"$transition_candidate\" \"$root/transition-claim\" 2>/dev/null || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_ADOPT_BUSY >&2; exit 79; }}\n",
                "release_transition_claim() {{ if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; }}\n",
                "trap 'release_transition_claim' EXIT\n",
                "agentapp_adopt_authority\n",
                "agentapp_adopt_live_pane\n",
                "[ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$observed\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "[ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"adoption|a_{adoption_key}|$next|$operation_pid|$operation_pgid|$expected_window|$pane_pid|$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "printf '%s\\n' \"$next_generation\" > \"$root/lease-generation.tmp\"\n",
                "mv \"$root/lease-generation.tmp\" \"$root/lease-generation\"\n",
                "printf '%s\\n' \"$next\" > \"$root/controller.tmp\"\n",
                "mv \"$root/controller.tmp\" \"$root/controller\"\n",
                "if [ -f \"$root/recovery-required\" ] && [ \"$(cat \"$root/recovery-required\")\" = \"$observed\" ]; then rm -f \"$root/recovery-required\"; fi\n",
                "date +%s > \"$root/lease.tmp\"\n",
                "mv \"$root/lease.tmp\" \"$root/lease\"\n",
                "printf 'AGENTAPP_TMUX_ADOPTED %s\\n' \"$next\"\n"
            ),
            root = root,
            session = shell_quote(&self.session_name),
            window = shell_quote(&self.window_name),
            owner = shell_quote(OWNERSHIP_MARKER),
            identity = shell_quote(&self.process_id),
            thread_id = shell_quote(&self.thread_id_base64),
            turn_id = shell_quote(&self.turn_id_base64),
            call_id = shell_quote(&self.call_id_base64),
            generation = shell_quote(&self.attempt_generation.to_string()),
            session_id = shell_quote(
                &self
                    .session_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string())
            ),
            tty = shell_quote(if self.tty { "1" } else { "0" }),
            digest = shell_quote(&self.command_digest),
            candidate = shell_quote(&self.controller_id),
            adoption_key = adoption_key,
        )
    }

    fn agent_directory(&self) -> String {
        format!("$HOME/.agentapp/tmux/{}", self.agent_id)
    }

    fn remote_directory(&self) -> String {
        format!("$HOME/.agentapp/tmux/{}/{}", self.agent_id, self.process_id)
    }

    fn target(&self) -> String {
        format!("{}:{}.0", self.session_name, self.window_name)
    }

    fn watchdog_target(&self) -> String {
        format!("{}:{}.0", self.session_name, self.watchdog_window_name)
    }

    fn process_script(&self, params: &ExecParams) -> String {
        let root = self.remote_directory();
        let command = build_remote_command_body(params);
        let invocation = if self.tty {
            format!("( {command} )")
        } else {
            format!(
                "mkfifo \"$root/stdin\" 2>/dev/null || true\nexec 3<>\"$root/stdin\"\n( {command} ) <&3 >>\"$root/output\" 2>&1"
            )
        };
        format!(
            "#!/bin/sh\nroot=\"{root}\"\ntarget={target}\npgid=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')\ncase \"$pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac\nprintf '%s:%s\\n' \"$$\" \"$pgid\" > \"$root/process-identity.tmp\"\nmv \"$root/process-identity.tmp\" \"$root/process-identity\"\nrm -f \"$root/status.tmp\"\n{invocation}\ncode=$?\nif mkdir \"$root/terminal-claim\" 2>/dev/null; then\n  printf 'completed\\n' > \"$root/terminal-claim/kind.tmp\"\n  mv \"$root/terminal-claim/kind.tmp\" \"$root/terminal-claim/kind\"\n  printf '%s\\n' \"$code\" > \"$root/status.tmp\"\n  mv \"$root/status.tmp\" \"$root/status\"\n  printf 'completed\\n' > \"$root/state.tmp\"\n  mv \"$root/state.tmp\" \"$root/state\"\nelse\n  while [ ! -f \"$root/status\" ]; do sleep 1; done\n  code=$(cat \"$root/status\" 2>/dev/null || printf '125')\nfi\ni=0\nwhile [ \"$i\" -lt {COMPLETED_WINDOW_RETENTION_SECONDS} ] && [ ! -f \"$root/release\" ]; do\n  sleep 1\n  i=$((i + 1))\ndone\nexit \"$code\"\n",
            target = shell_quote(&self.target()),
        )
    }

    fn watchdog_script(&self) -> String {
        let root = self.remote_directory();
        format!(
            "#!/bin/sh\nroot=\"{root}\"\nwhile [ ! -f \"$root/status\" ]; do\n  now=$(date +%s)\n  lease=$(cat \"$root/lease\" 2>/dev/null || printf '0')\n  case \"$lease\" in ''|*[!0-9]*) lease=0 ;; esac\n  if [ $((now - lease)) -ge {CONTROLLER_LEASE_SECONDS} ] && [ ! -f \"$root/recovery-required\" ]; then\n    observed=$(cat \"$root/controller\" 2>/dev/null || true)\n    observed_generation=${{observed%%:*}}\n    observed_controller=${{observed#*:}}\n    case \"$observed_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_CONTROLLER_GENERATION_UNKNOWN >&2; exit 80 ;; esac\n    if [ -z \"$observed_controller\" ] || [ \"$observed_controller\" = \"$observed\" ]; then echo AGENTAPP_TMUX_CONTROLLER_UNKNOWN >&2; exit 80; fi\n    printf '%s:%s\\n' \"$observed_generation\" \"$observed_controller\" > \"$root/recovery-required.tmp\"\n    mv \"$root/recovery-required.tmp\" \"$root/recovery-required\"\n  fi\n  sleep {CONTROLLER_HEARTBEAT_SECONDS}\ndone\n",
        )
    }

    fn bootstrap_command(&self, params: &ExecParams) -> String {
        let agent_root = self.agent_directory();
        let root = self.remote_directory();
        let script = self.process_script(params);
        let watchdog_script = self.watchdog_script();
        let start_command = format!(
            "while [ ! -f \"{root}/go\" ]; do sleep 1; done; exec /bin/sh \"{root}/command.sh\""
        );
        let watchdog_command = format!("exec /bin/sh \"{root}/watchdog.sh\"");
        let pipe_command = format!("cat >> \"{root}/output\"");
        let pipe_setup = if self.tty {
            format!(
                "tmux pipe-pane -O -t \"$target\" {}",
                shell_quote(&pipe_command)
            )
        } else {
            ":".to_string()
        };

        format!(
            concat!(
                "set -eu\n",
                "if ! command -v tmux >/dev/null 2>&1; then echo AGENTAPP_TMUX_MISSING >&2; exit 127; fi\n",
                "agent_root=\"{agent_root}\"\n",
                "root=\"{root}\"\n",
                "session={session}\n",
                "window={window}\n",
                "watchdog_window={watchdog_window}\n",
                "controller={controller}\n",
                "digest={digest}\n",
                "staging_name=.descriptor-stage-{identity}-{controller_key}-$$\n",
                "staging=\"$agent_root/$staging_name\"\n",
                "mkdir -p \"$agent_root\"\n",
                "candidate_controller=\"$controller\"\n",
                "if ! tmux has-session -t \"$session\" 2>/dev/null; then\n",
                "  tmux new-session -d -s \"$session\" -n __agentapp_keeper {keeper} || tmux has-session -t \"$session\"\n",
                "fi\n",
                "tmux respawn-pane -k -t \"$session:__agentapp_keeper.0\" {keeper} >/dev/null 2>&1 || true\n",
                "window_exists=0\n",
                "if tmux list-windows -t \"$session\" -F '#{{window_name}}' | grep -Fqx \"$window\"; then window_exists=1; fi\n",
                "watchdog_exists=0\n",
                "if tmux list-windows -t \"$session\" -F '#{{window_name}}' | grep -Fqx \"$watchdog_window\"; then watchdog_exists=1; fi\n",
                "create_window=0\n",
                "create_watchdog=0\n",
                "release_start=0\n",
                "if [ -d \"$root\" ] && [ \"$(cat \"$root/owner\" 2>/dev/null || true)\" != {owner_check} ]; then\n",
                "  if [ \"$window_exists\" -eq 1 ]; then echo AGENTAPP_TMUX_LEGACY_WINDOW_CONFLICT >&2; exit 76; fi\n",
                "  legacy=\"$root.legacy.$controller.$$\"\n",
                "  mv \"$root\" \"$legacy\" || {{ echo AGENTAPP_TMUX_LEGACY_QUARANTINE_FAILED >&2; exit 76; }}\n",
                "fi\n",
                "if [ -d \"$root\" ]; then\n",
                "  if [ \"$(cat \"$root/owner\" 2>/dev/null || true)\" != {owner_check} ] || [ \"$(cat \"$root/identity\" 2>/dev/null || true)\" != {identity} ] || [ \"$(cat \"$root/thread-id\" 2>/dev/null || true)\" != {thread_id} ] || [ \"$(cat \"$root/turn-id\" 2>/dev/null || true)\" != {turn_id} ] || [ \"$(cat \"$root/call-id\" 2>/dev/null || true)\" != {call_id} ] || [ \"$(cat \"$root/attempt-generation\" 2>/dev/null || true)\" != {attempt_generation} ] || [ \"$(cat \"$root/session-id\" 2>/dev/null || true)\" != {session_id} ] || [ \"$(cat \"$root/tty\" 2>/dev/null || true)\" != {tty} ] || [ \"$(cat \"$root/digest\" 2>/dev/null || true)\" != \"$digest\" ]; then echo AGENTAPP_TMUX_IDENTITY_MISMATCH >&2; exit 76; fi\n",
                "  existing_state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "  case \"$existing_state\" in prepared|running) ;; completed|terminated|launch-interrupted) echo AGENTAPP_TMUX_EXECUTION_TERMINAL >&2; exit 79 ;; *) echo AGENTAPP_TMUX_EXECUTION_STATE_UNKNOWN >&2; exit 79 ;; esac\n",
                "  if [ \"$window_exists\" -eq 1 ]; then current_pane=$(tmux display-message -p -t \"$session:$window.0\" '#{{pane_pid}}' 2>/dev/null || true); current_pgid=$(ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' '); process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true); if [ -z \"$process_identity\" ] && [ ! -f \"$root/go\" ] && [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = prepared ]; then case \"$current_pane:$current_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80 ;; esac; printf '%s:%s\\n' \"$current_pane\" \"$current_pgid\" > \"$root/process-identity.tmp\"; mv \"$root/process-identity.tmp\" \"$root/process-identity\"; process_identity=\"$current_pane:$current_pgid\"; fi; stored_pane=${{process_identity%%:*}}; stored_pgid=${{process_identity#*:}}; if [ -z \"$current_pane\" ] || [ \"$stored_pane\" != \"$current_pane\" ] || [ \"$stored_pgid\" != \"$current_pgid\" ]; then echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80; fi; if [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = prepared ]; then release_start=1; fi; fi\n",
                "  if [ \"$window_exists\" -eq 0 ] && [ ! -f \"$root/status\" ]; then if [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = prepared ] && [ ! -f \"$root/process-identity\" ]; then create_window=1; release_start=1; else echo AGENTAPP_TMUX_EXECUTION_STATE_UNKNOWN >&2; exit 79; fi; fi\n",
                "elif [ \"$window_exists\" -eq 1 ]; then\n",
                "  echo AGENTAPP_TMUX_LEGACY_WINDOW_CONFLICT >&2\n",
                "  exit 76\n",
                "else\n",
                "  owns_staging=0\n",
                "  cleanup_descriptor_staging_path() {{\n",
                "    descriptor_staging_path=$1\n",
                "    [ \"$owns_staging\" -eq 1 ] && [ -d \"$descriptor_staging_path\" ] || return 0\n",
                "    rm -f \"$descriptor_staging_path/output\" \"$descriptor_staging_path/owner\" \"$descriptor_staging_path/identity\" \"$descriptor_staging_path/thread-id\" \"$descriptor_staging_path/turn-id\" \"$descriptor_staging_path/call-id\" \"$descriptor_staging_path/attempt-generation\" \"$descriptor_staging_path/session-id\" \"$descriptor_staging_path/tty\" \"$descriptor_staging_path/acknowledgement-token\" \"$descriptor_staging_path/digest\" \"$descriptor_staging_path/window\" \"$descriptor_staging_path/state\"\n",
                "    rmdir \"$descriptor_staging_path\" 2>/dev/null || true\n",
                "    return 0\n",
                "  }}\n",
                "  cleanup_descriptor_staging() {{\n",
                "    cleanup_descriptor_staging_path \"$staging\"\n",
                "    cleanup_descriptor_staging_path \"$root/$staging_name\"\n",
                "    return 0\n",
                "  }}\n",
                "  descriptor_publish_failed() {{ echo AGENTAPP_TMUX_DESCRIPTOR_PUBLISH_FAILED >&2; exit 74; }}\n",
                "  trap 'cleanup_descriptor_staging' EXIT\n",
                "  trap 'exit 129' HUP\n",
                "  trap 'exit 130' INT\n",
                "  trap 'exit 143' TERM\n",
                "  if ! (umask 077; mkdir \"$staging\") 2>/dev/null; then if [ -e \"$staging\" ] || [ -L \"$staging\" ]; then echo AGENTAPP_TMUX_DESCRIPTOR_STAGE_CONFLICT >&2; exit 75; else descriptor_publish_failed; fi; fi\n",
                "  owns_staging=1\n",
                "  : > \"$staging/output\" || descriptor_publish_failed\n",
                "  printf '%s\\n' {owner} > \"$staging/owner\" || descriptor_publish_failed\n",
                "  printf '%s\\n' {identity} > \"$staging/identity\" || descriptor_publish_failed\n",
                "  printf '%s\\n' {thread_id} > \"$staging/thread-id\" || descriptor_publish_failed\n",
                "  printf '%s\\n' {turn_id} > \"$staging/turn-id\" || descriptor_publish_failed\n",
                "  printf '%s\\n' {call_id} > \"$staging/call-id\" || descriptor_publish_failed\n",
                "  printf '%s\\n' {attempt_generation} > \"$staging/attempt-generation\" || descriptor_publish_failed\n",
                "  printf '%s\\n' {session_id} > \"$staging/session-id\" || descriptor_publish_failed\n",
                "  printf '%s\\n' {tty} > \"$staging/tty\" || descriptor_publish_failed\n",
                "  printf '%s\\n' {acknowledgement_token} > \"$staging/acknowledgement-token\" || descriptor_publish_failed\n",
                "  printf '%s\\n' \"$digest\" > \"$staging/digest\" || descriptor_publish_failed\n",
                "  printf '%s\\n' \"$window\" > \"$staging/window\" || descriptor_publish_failed\n",
                "  printf 'prepared\\n' > \"$staging/state\" || descriptor_publish_failed\n",
                "  if [ -e \"$root\" ] || [ -L \"$root\" ]; then echo AGENTAPP_TMUX_DESCRIPTOR_CAS_CONFLICT >&2; exit 75; fi\n",
                "  if ! mv -n \"$staging\" \"$root\" 2>/dev/null; then if [ -e \"$root\" ] || [ -L \"$root\" ]; then echo AGENTAPP_TMUX_DESCRIPTOR_CAS_CONFLICT >&2; exit 75; else descriptor_publish_failed; fi; fi\n",
                "  if [ -d \"$staging\" ] || [ -d \"$root/$staging_name\" ]; then echo AGENTAPP_TMUX_DESCRIPTOR_CAS_CONFLICT >&2; exit 75; fi\n",
                "  owns_staging=0\n",
                "  trap - EXIT HUP INT TERM\n",
                "  create_window=1\n",
                "  release_start=1\n",
                "fi\n",
                "if [ ! -f \"$root/status\" ] && [ \"$watchdog_exists\" -eq 0 ]; then create_watchdog=1; fi\n",
                "current=$(cat \"$root/lease-generation\" 2>/dev/null || printf '0')\n",
                "case \"$current\" in ''|*[!0-9]*) current=0 ;; esac\n",
                "assignment=\"$agent_root/controller-$candidate_controller\"\n",
                "assigned=$(cat \"$assignment\" 2>/dev/null || true)\n",
                "case \"$assigned\" in ''|*[!0-9]*) assigned=$((current + 1)); printf '%s\\n' \"$assigned\" > \"$assignment.tmp\"; mv \"$assignment.tmp\" \"$assignment\" ;; esac\n",
                "if [ \"$assigned\" -lt \"$current\" ]; then echo AGENTAPP_TMUX_STALE_CONTROLLER >&2; exit 75; fi\n",
                "active=\"$assigned:$candidate_controller\"\n",
                "if [ \"$release_start\" -eq 1 ]; then\n",
                "  operation_pid=$$\n",
                "  operation_pgid=$(ps -o pgid= -p \"$operation_pid\" 2>/dev/null | tr -d ' ')\n",
                "  case \"$operation_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  case \"$operation_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  claim_pane=-\n",
                "  claim_pgid=-\n",
                "  if [ \"$window_exists\" -eq 1 ]; then\n",
                "    claim_pane=$(tmux display-message -p -t \"$session:$window.0\" '#{{pane_pid}}' 2>/dev/null || true)\n",
                "    claim_pgid=$(ps -o pgid= -p \"$claim_pane\" 2>/dev/null | tr -d ' ')\n",
                "    case \"$claim_pane\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "    case \"$claim_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  fi\n",
                "  transition_candidate=\"$root/.transition-candidate.b_{controller_key}.$$\"\n",
                "  printf 'bootstrap|b_{controller_key}|%s|%s|%s|%s|%s|%s\\n' \"$active\" \"$operation_pid\" \"$operation_pgid\" \"$window\" \"$claim_pane\" \"$claim_pgid\" > \"$transition_candidate\"\n",
                "  ln \"$transition_candidate\" \"$root/transition-claim\" 2>/dev/null || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  release_transition_claim() {{ if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; }}\n",
                "  trap 'release_transition_claim' EXIT\n",
                "  [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = prepared ] && [ ! -e \"$root/go\" ] && [ ! -e \"$root/status\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
                "fi\n",
                "printf '%s\\n' \"$assigned\" > \"$root/lease-generation.tmp\"\n",
                "mv \"$root/lease-generation.tmp\" \"$root/lease-generation\"\n",
                "printf '%s\\n' \"$active\" > \"$root/controller.tmp\"\n",
                "mv \"$root/controller.tmp\" \"$root/controller\"\n",
                "date +%s > \"$root/lease\"\n",
                "rm -f \"$root/recovery-required\"\n",
                "if [ \"$create_watchdog\" -eq 1 ]; then\n",
                "  printf '%s' {watchdog_script} > \"$root/watchdog.sh\"\n",
                "  chmod 700 \"$root/watchdog.sh\"\n",
                "  tmux new-window -d -t \"$session:\" -n \"$watchdog_window\" {watchdog_start}\n",
                "fi\n",
                "if [ \"$create_window\" -eq 1 ]; then\n",
                "  date +%s > \"$root/lease\"\n",
                "  printf '%s' {script} > \"$root/command.sh\"\n",
                "  chmod 700 \"$root/command.sh\"\n",
                "  tmux new-window -d -t \"$session:\" -n \"$window\" {start}\n",
                "  pane_pid=$(tmux display-message -p -t \"$session:$window.0\" '#{{pane_pid}}')\n",
                "  case \"$pane_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80 ;; esac\n",
                "  pane_pgid=$(ps -o pgid= -p \"$pane_pid\" 2>/dev/null | tr -d ' ')\n",
                "  case \"$pane_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac\n",
                "  printf '%s:%s\\n' \"$pane_pid\" \"$pane_pgid\" > \"$root/process-identity.tmp\"\n",
                "  mv \"$root/process-identity.tmp\" \"$root/process-identity\"\n",
                "fi\n",
                "target=\"$session:$window.0\"\n",
                "if [ \"$release_start\" -eq 1 ]; then\n",
                "  current_pane=$(tmux display-message -p -t \"$target\" '#{{pane_pid}}' 2>/dev/null || true)\n",
                "  current_pgid=$(ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' ')\n",
                "  case \"$current_pane\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  case \"$current_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$active\" ] || {{ echo AGENTAPP_TMUX_STALE_CONTROLLER >&2; exit 75; }}\n",
                "  [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = prepared ] && [ ! -e \"$root/go\" ] && [ ! -e \"$root/status\" ] && [ ! -e \"$root/recovery-required\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
                "  stored_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
                "  [ \"$stored_identity\" = \"$current_pane:$current_pgid\" ] && kill -0 \"-$current_pgid\" 2>/dev/null || {{ echo AGENTAPP_TMUX_TRANSITION_OWNERSHIP_MISMATCH >&2; exit 80; }}\n",
                "  {pipe_setup}\n",
                "  printf 'running\\n' > \"$root/state.tmp\"\n",
                "  mv \"$root/state.tmp\" \"$root/state\"\n",
                "  : > \"$root/go.tmp\"\n",
                "  mv \"$root/go.tmp\" \"$root/go\"\n",
                "  release_transition_claim\n",
                "  trap - EXIT\n",
                "fi\n",
                "printf 'AGENTAPP_TMUX_READY %s %s\\n' \"$target\" \"$active\"\n",
            ),
            agent_root = agent_root,
            root = root,
            session = shell_quote(&self.session_name),
            window = shell_quote(&self.window_name),
            watchdog_window = shell_quote(&self.watchdog_window_name),
            controller = shell_quote(&self.controller_id),
            controller_key = stable_identifier(&self.controller_id),
            digest = shell_quote(&self.command_digest),
            owner = shell_quote(OWNERSHIP_MARKER),
            owner_check = shell_quote(OWNERSHIP_MARKER),
            identity = shell_quote(&self.process_id),
            thread_id = shell_quote(&self.thread_id_base64),
            turn_id = shell_quote(&self.turn_id_base64),
            call_id = shell_quote(&self.call_id_base64),
            attempt_generation = shell_quote(&self.attempt_generation.to_string()),
            session_id = shell_quote(
                &self
                    .session_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string())
            ),
            tty = shell_quote(if self.tty { "1" } else { "0" }),
            acknowledgement_token = shell_quote(&self.acknowledgement_token),
            keeper = shell_quote(&format!("sleep {AGENT_SESSION_RETENTION_SECONDS}")),
            script = shell_quote(&script),
            watchdog_script = shell_quote(&watchdog_script),
            start = shell_quote(&start_command),
            watchdog_start = shell_quote(&watchdog_command),
            pipe_setup = pipe_setup,
        )
    }

    fn monitor_command(&self, first_byte: u64) -> String {
        let root = self.remote_directory();
        format!(
            "root=\"{root}\"\ncontroller={}\ndigest={}\noffset={first_byte}\nstable=0\nwhile :; do\n  if [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" != \"$controller\" ] || [ \"$(cat \"$root/digest\" 2>/dev/null || true)\" != \"$digest\" ]; then exit 125; fi\n  date +%s > \"$root/lease.tmp\" && mv \"$root/lease.tmp\" \"$root/lease\"\n  bytes=0\n  if [ -f \"$root/output\" ]; then bytes=$(wc -c < \"$root/output\"); fi\n  if [ \"$bytes\" -ge \"$offset\" ]; then\n    count=$((bytes - offset + 1))\n    tail -c +\"$offset\" \"$root/output\" | head -c \"$count\"\n    offset=$((offset + count))\n    stable=0\n  elif [ -f \"$root/status\" ]; then\n    stable=$((stable + 1))\n    if [ \"$stable\" -ge 3 ]; then\n      code=$(cat \"$root/status\" 2>/dev/null || printf '125')\n      case \"$code\" in ''|*[!0-9]*) code=125 ;; esac\n      exit \"$code\"\n    fi\n  else\n    stable=0\n  fi\n  sleep 1\ndone\n",
            shell_quote(&self.controller_id),
            shell_quote(&self.command_digest),
        )
    }

    async fn classify_monitor_exit(
        &self,
        transport: &crate::ssh_transport::SshTransport,
    ) -> Result<MonitorExitClassification, ExecServerError> {
        let root = self.remote_directory();
        let command = format!(
            concat!(
                "root=\"{root}\"\n",
                "if [ \"$(cat \"$root/owner\" 2>/dev/null || true)\" != {owner} ] || [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" != {controller} ] || [ \"$(cat \"$root/digest\" 2>/dev/null || true)\" != {digest} ]; then printf 'ownership-lost\\n'; exit 0; fi\n",
                "if [ ! -f \"$root/status\" ] || [ ! -d \"$root/terminal-claim\" ]; then printf 'channel-lost\\n'; exit 0; fi\n",
                "code=$(cat \"$root/status\" 2>/dev/null || true); case \"$code\" in ''|*[!0-9]*) printf 'channel-lost\\n' ;; *) printf 'terminal %s\\n' \"$code\" ;; esac\n"
            ),
            root = root,
            owner = shell_quote(OWNERSHIP_MARKER),
            controller = shell_quote(&self.controller_id),
            digest = shell_quote(&self.command_digest),
        );
        let result = transport
            .exec_control(&with_remote_path(&command), None)
            .await?;
        if result.exit_code != 0 {
            return Err(ExecServerError::Protocol(format!(
                "tmux monitor exit classification failed with {}",
                result.exit_code
            )));
        }
        parse_monitor_exit_classification(&result.output)
    }

    async fn write(
        &self,
        transport: &crate::ssh_transport::SshTransport,
        data: &[u8],
        write_id: Option<&str>,
    ) -> Result<(), ExecServerError> {
        let command = if let Some(write_id) = write_id {
            self.durable_write_command(data, write_id)
        } else if self.tty {
            let buffer = format!("agentapp_{}", self.process_id);
            format!(
                "{}; tmux load-buffer -b {} - && tmux paste-buffer -d -b {} -t {}",
                self.ownership_guard(),
                shell_quote(&buffer),
                shell_quote(&buffer),
                shell_quote(&self.target())
            )
        } else {
            let root = self.remote_directory();
            format!(
                "root=\"{root}\"; {}; [ ! -f \"$root/status\" ] || exit 3; cat > \"$root/stdin\"",
                self.ownership_guard()
            )
        };
        let result = transport
            .exec_control(&with_remote_path(&command), Some(data))
            .await?;
        if result.exit_code == 0 {
            Ok(())
        } else {
            Err(ExecServerError::Protocol(format!(
                "ssh tmux stdin failed with exit {}: {}",
                result.exit_code,
                String::from_utf8_lossy(&result.output).trim()
            )))
        }
    }

    fn durable_write_command(&self, data: &[u8], write_id: &str) -> String {
        let root = self.remote_directory();
        let write_key = format!(
            "{:x}",
            Sha256::digest(format!("agentapp-tmux-stdin-v2\0{write_id}").as_bytes())
        );
        let input_sha256 = format!("{:x}", Sha256::digest(data));
        let input_len = data.len();
        let delivery = if self.tty {
            let buffer = format!("agentapp_{}_{}", self.process_id, write_key);
            format!(
                "tmux load-buffer -b {buffer} \"$data_candidate\" && tmux paste-buffer -d -b {buffer} -t {target}",
                buffer = shell_quote(&buffer),
                target = shell_quote(&self.target()),
            )
        } else {
            "cat \"$data_candidate\" > \"$root/stdin\"".to_string()
        };
        format!(
            concat!(
                "set -eu\n",
                "root=\"{root}\"\n",
                "{ownership_guard}\n",
                "write_key={write_key}\n",
                "expected_input_sha256={input_sha256}\n",
                "expected_input_len={input_len}\n",
                "claim=\"$root/stdin-write-$write_key.claim\"\n",
                "result=\"$root/stdin-write-$write_key.result\"\n",
                "data_candidate=\"$root/.stdin-write-data.$write_key.$$\"\n",
                "claim_candidate=\"$root/.stdin-write-claim.$write_key.$$\"\n",
                "result_candidate=\"$root/.stdin-write-result.$write_key.$$\"\n",
                "cleanup_write_candidates() {{ rm -f \"$data_candidate\" \"$claim_candidate\" \"$result_candidate\"; }}\n",
                "interrupt_write() {{ signal_status=$1; trap - EXIT HUP INT TERM; cleanup_write_candidates; exit \"$signal_status\"; }}\n",
                "trap 'cleanup_write_candidates' EXIT\n",
                "trap 'interrupt_write 129' HUP\n",
                "trap 'interrupt_write 130' INT\n",
                "trap 'interrupt_write 143' TERM\n",
                "( umask 077; set -C; cat > \"$data_candidate\" ) || {{ echo AGENTAPP_TMUX_STDIN_DATA_CONFLICT >&2; exit 78; }}\n",
                "observed_input_len=$(wc -c < \"$data_candidate\" 2>/dev/null || printf '0'); observed_input_len=$(printf '%s' \"$observed_input_len\" | tr -d ' ')\n",
                "[ \"$observed_input_len\" -eq \"$expected_input_len\" ] || {{ echo AGENTAPP_TMUX_STDIN_LENGTH_CONFLICT >&2; exit 78; }}\n",
                "if command -v shasum >/dev/null 2>&1; then observed_input_sha256=$(shasum -a 256 \"$data_candidate\" | awk '{{print $1}}'); elif command -v sha256sum >/dev/null 2>&1; then observed_input_sha256=$(sha256sum \"$data_candidate\" | awk '{{print $1}}'); else echo AGENTAPP_TMUX_STDIN_SHA256_UNAVAILABLE >&2; exit 77; fi\n",
                "[ \"$observed_input_sha256\" = \"$expected_input_sha256\" ] || {{ echo AGENTAPP_TMUX_STDIN_DIGEST_CONFLICT >&2; exit 78; }}\n",
                "expected_claim=\"pending $expected_input_sha256 $expected_input_len\"\n",
                "expected_result=\"accepted $expected_input_sha256 $expected_input_len\"\n",
                "if [ -e \"$result\" ]; then\n",
                "  [ -f \"$result\" ] && [ ! -L \"$result\" ] && [ \"$(cat \"$result\" 2>/dev/null || true)\" = \"$expected_result\" ] || {{ echo AGENTAPP_TMUX_STDIN_RESULT_CONFLICT >&2; exit 78; }}\n",
                "  [ -f \"$claim\" ] && [ ! -L \"$claim\" ] && [ \"$(cat \"$claim\" 2>/dev/null || true)\" = \"$expected_claim\" ] || {{ echo AGENTAPP_TMUX_STDIN_CLAIM_CONFLICT >&2; exit 78; }}\n",
                "  exit 0\n",
                "fi\n",
                "if [ -e \"$claim\" ]; then\n",
                "  [ -f \"$claim\" ] && [ ! -L \"$claim\" ] && [ \"$(cat \"$claim\" 2>/dev/null || true)\" = \"$expected_claim\" ] || {{ echo AGENTAPP_TMUX_STDIN_CLAIM_CONFLICT >&2; exit 78; }}\n",
                "  echo AGENTAPP_TMUX_STDIN_DELIVERY_UNKNOWN >&2\n",
                "  exit 75\n",
                "fi\n",
                "[ ! -f \"$root/status\" ] || {{ echo AGENTAPP_TMUX_STDIN_CLOSED >&2; exit 3; }}\n",
                "( umask 077; set -C; printf '%s\\n' \"$expected_claim\" > \"$claim_candidate\" ) || {{ echo AGENTAPP_TMUX_STDIN_CLAIM_CONFLICT >&2; exit 78; }}\n",
                "if ! ln \"$claim_candidate\" \"$claim\" 2>/dev/null; then\n",
                "  if [ -e \"$result\" ] && [ \"$(cat \"$result\" 2>/dev/null || true)\" = \"$expected_result\" ]; then exit 0; fi\n",
                "  if [ -e \"$claim\" ] && [ \"$(cat \"$claim\" 2>/dev/null || true)\" = \"$expected_claim\" ]; then echo AGENTAPP_TMUX_STDIN_DELIVERY_UNKNOWN >&2; exit 75; fi\n",
                "  echo AGENTAPP_TMUX_STDIN_CLAIM_CONFLICT >&2\n",
                "  exit 78\n",
                "fi\n",
                "rm -f \"$claim_candidate\"\n",
                // The durable claim is never removed here. If this process is
                // lost before its result rename, retries fail closed instead
                // of delivering the same bytes a second time.
                "{delivery}\n",
                "( umask 077; set -C; printf '%s\\n' \"$expected_result\" > \"$result_candidate\" ) || {{ echo AGENTAPP_TMUX_STDIN_RESULT_CONFLICT >&2; exit 78; }}\n",
                "[ ! -e \"$result\" ] || {{ echo AGENTAPP_TMUX_STDIN_RESULT_CONFLICT >&2; exit 78; }}\n",
                "mv \"$result_candidate\" \"$result\"\n",
                "trap - EXIT HUP INT TERM\n",
                "cleanup_write_candidates\n",
                "exit 0\n"
            ),
            root = root,
            ownership_guard = self.ownership_guard(),
            write_key = shell_quote(&write_key),
            input_sha256 = shell_quote(&input_sha256),
            input_len = shell_quote(&input_len.to_string()),
            delivery = delivery,
        )
    }

    async fn interrupt(
        &self,
        transport: &crate::ssh_transport::SshTransport,
    ) -> Result<ProcessSignalOutcome, ExecServerError> {
        let result = transport
            .exec_control(&with_remote_path(&self.interrupt_command()), None)
            .await?;
        interrupt_outcome_from_control_result(result.exit_code, &result.output)
    }

    fn interrupt_command(&self) -> String {
        let root = self.remote_directory();
        format!(
            concat!(
                "set -eu; root=\"{root}\"; {ownership}; ",
                "stored_identity=$(cat \"$root/process-identity\" 2>/dev/null || true); ",
                "pane_pid=${{stored_identity%%:*}}; pgid=${{stored_identity#*:}}; ",
                "case \"$stored_identity\" in *:*:*) echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80 ;; esac; ",
                "case \"$pane_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80 ;; esac; ",
                "case \"$pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80 ;; esac; ",
                "[ \"$pane_pid:$pgid\" = \"$stored_identity\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80; }}; ",
                "current_identity=$(tmux display-message -p -t {target} '#{{pane_id}}:#{{pane_pid}}' 2>/dev/null || true); ",
                "pane_id=${{current_identity%%:*}}; current_pane=${{current_identity#*:}}; ",
                "case \"$pane_id\" in %*) ;; *) echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80 ;; esac; ",
                "case \"$current_pane\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80 ;; esac; ",
                "current_pgid=$(command -p ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' '); ",
                "[ \"$current_pane:$current_pgid\" = \"$stored_identity\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; ",
                "current_controller=$(cat \"$root/controller\" 2>/dev/null || true); ",
                "case \"$current_controller\" in *:*) ;; *) echo AGENTAPP_TMUX_INTERRUPT_CONTROLLER_UNKNOWN >&2; exit 80 ;; esac; ",
                "operation_pid=$$; operation_pgid=$(command -p ps -o pgid= -p \"$operation_pid\" 2>/dev/null | tr -d ' '); ",
                "case \"$operation_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80 ;; esac; ",
                "[ \"$operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80; }}; ",
                "interrupt_nonce=i_${{operation_pid}}_${{operation_pgid}}; ",
                "transition_candidate=\"$root/.transition-candidate.$interrupt_nonce.$operation_pid\"; ",
                "expected_claim=\"interrupt|$interrupt_nonce|$current_controller|$operation_pid|$operation_pgid|$(cat \"$root/window\" 2>/dev/null || true)|$pane_pid|$pgid\"; ",
                "( umask 077; set -C; printf '%s\\n' \"$expected_claim\" > \"$transition_candidate\" ) || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}; ",
                "ln \"$transition_candidate\" \"$root/transition-claim\" 2>/dev/null || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}; ",
                "release_interrupt_claim() {{ if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; }}; ",
                "trap 'release_interrupt_claim' EXIT HUP INT TERM; ",
                "require_interrupt_claim() {{ [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}; }}; ",
                "require_interrupt_claim; ",
                "[ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$current_controller\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}; ",
                "[ ! -f \"$root/status\" ] && [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = running ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}; ",
                "{ownership}; ",
                "rechecked_identity=$(tmux display-message -p -t \"$pane_id\" '#{{pane_id}}:#{{pane_pid}}' 2>/dev/null || true); ",
                "[ \"$rechecked_identity\" = \"$current_identity\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; ",
                "rechecked_pgid=$(command -p ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' '); ",
                "[ \"$current_pane:$rechecked_pgid\" = \"$stored_identity\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; ",
                "require_interrupt_claim; ",
                "tmux send-keys -t \"$pane_id\" C-c; ",
                "release_interrupt_claim; trap - EXIT HUP INT TERM",
            ),
            root = root,
            ownership = self.ownership_guard(),
            target = shell_quote(&self.target()),
        )
    }

    async fn terminate(
        &self,
        transport: &crate::ssh_transport::SshTransport,
    ) -> Result<(), ExecServerError> {
        let root = self.remote_directory();
        let command = format!(
            "root=\"{root}\"; {}; claimed=0; if mkdir \"$root/terminal-claim\" 2>/dev/null; then claimed=1; printf 'terminated\\n' > \"$root/terminal-claim/kind.tmp\"; mv \"$root/terminal-claim/kind.tmp\" \"$root/terminal-claim/kind\"; fi; {}; if [ \"$claimed\" -eq 1 ]; then printf '143\\n' > \"$root/status.tmp\"; mv \"$root/status.tmp\" \"$root/status\"; printf 'terminated\\n' > \"$root/state.tmp\"; mv \"$root/state.tmp\" \"$root/state\"; else i=0; while [ ! -f \"$root/status\" ] && [ \"$i\" -lt 30 ]; do sleep 1; i=$((i + 1)); done; [ -f \"$root/status\" ] || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}; fi",
            self.ownership_guard(),
            self.confirmed_process_group_termination()
        );
        self.run_control(transport, &command, "terminate").await
    }

    async fn cleanup(
        &self,
        transport: &crate::ssh_transport::SshTransport,
    ) -> Result<(), ExecServerError> {
        let root = self.remote_directory();
        let command = format!(
            "root=\"{root}\"; if {}; then {}; fi",
            self.ownership_check(),
            self.confirmed_process_group_termination()
        );
        self.run_control(transport, &command, "cleanup").await
    }

    fn confirmed_process_group_termination(&self) -> String {
        format!(
            "process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true); pane_pid=${{process_identity%%:*}}; pgid=${{process_identity#*:}}; case \"$pane_pid:$pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac; agentapp_termination_probe_group() {{ agentapp_termination_group_state=unknown; [ -x /bin/kill ] || return; if /bin/kill -0 -- \"-$pgid\" 2>/dev/null; then agentapp_termination_group_state=alive; return; fi; if agentapp_kill_error=$(LC_ALL=C /bin/kill -0 -- \"-$pgid\" 2>&1); then agentapp_termination_group_state=alive; return; fi; case \"$agentapp_kill_error\" in *\"No such process\"*) agentapp_termination_group_state=dead ;; esac; }}; window_exists=0; if tmux list-windows -t {} -F '#{{window_name}}' 2>/dev/null | grep -Fqx {}; then window_exists=1; fi; if [ \"$window_exists\" -eq 1 ]; then current_pane=$(tmux display-message -p -t {} '#{{pane_pid}}' 2>/dev/null || true); current_pgid=$(command -p ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' '); if [ -z \"$current_pane\" ] || [ \"$pane_pid\" != \"$current_pane\" ] || [ \"$current_pgid\" != \"$pgid\" ]; then echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80; fi; if kill -0 \"-$pgid\" 2>/dev/null; then kill -TERM \"-$pgid\" 2>/dev/null || true; i=0; while kill -0 \"-$pgid\" 2>/dev/null && [ \"$i\" -lt 10 ]; do sleep 1; i=$((i + 1)); done; fi; if kill -0 \"-$pgid\" 2>/dev/null; then kill -KILL \"-$pgid\" 2>/dev/null || true; i=0; while kill -0 \"-$pgid\" 2>/dev/null && [ \"$i\" -lt 5 ]; do sleep 1; i=$((i + 1)); done; fi; elif kill -0 \"-$pgid\" 2>/dev/null; then echo AGENTAPP_TMUX_PROCESS_IDENTITY_UNKNOWN >&2; exit 80; fi; agentapp_termination_probe_group; case \"$agentapp_termination_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_PROCESS_GROUP_ALIVE >&2; exit 81 ;; *) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac; tmux kill-window -t {} 2>/dev/null || true; if tmux list-windows -t {} -F '#{{window_name}}' 2>/dev/null | grep -Fqx {}; then echo AGENTAPP_TMUX_TERMINATION_UNCONFIRMED >&2; exit 78; fi; tmux kill-window -t {} 2>/dev/null || true",
            shell_quote(&self.session_name),
            shell_quote(&self.window_name),
            shell_quote(&self.target()),
            shell_quote(&self.target()),
            shell_quote(&self.session_name),
            shell_quote(&self.window_name),
            shell_quote(&self.watchdog_target())
        )
    }

    fn ownership_check(&self) -> String {
        let root = self.remote_directory();
        format!(
            "[ \"$(cat \"{root}/owner\" 2>/dev/null || true)\" = {} ] && [ \"$(cat \"{root}/controller\" 2>/dev/null || true)\" = {} ] && [ \"$(cat \"{root}/digest\" 2>/dev/null || true)\" = {} ]",
            shell_quote(OWNERSHIP_MARKER),
            shell_quote(&self.controller_id),
            shell_quote(&self.command_digest)
        )
    }

    fn ownership_guard(&self) -> String {
        format!(
            "{} || {{ echo AGENTAPP_TMUX_OWNERSHIP_MISMATCH >&2; exit 77; }}",
            self.ownership_check()
        )
    }

    async fn run_control(
        &self,
        transport: &crate::ssh_transport::SshTransport,
        command: &str,
        operation: &str,
    ) -> Result<(), ExecServerError> {
        let result = transport
            .exec_control(&with_remote_path(command), None)
            .await?;
        if result.exit_code == 0 {
            Ok(())
        } else {
            Err(ExecServerError::Protocol(format!(
                "ssh tmux {operation} failed with exit {}: {}",
                result.exit_code,
                String::from_utf8_lossy(&result.output).trim()
            )))
        }
    }
}

// AgentApp's context lock admits exactly one local resume reconciler for a
// rollout. The remote transition claim serializes that reconciler with a
// bootstrap shell that may have survived the app process. A claim is never
// stolen by age: its operation process must be gone and its exact command
// window/process group must be verified dead before the claim is quarantined.
fn prepared_rollback_fragment(agent_id: &str, process_id: &str) -> String {
    let recovery_key = stable_identifier(&format!("{agent_id}:{process_id}:prepared-recovery"));
    format!(
        concat!(
            "  prepared_terminal_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
            "  prepared_terminal_status=$(cat \"$root/status\" 2>/dev/null || true)\n",
            "  if {{ [ \"$state\" = prepared ] || [ \"$state\" = running ]; }} && [ ! -e \"$root/go\" ] && [ \"$prepared_terminal_kind:$prepared_terminal_status\" = launch-interrupted:125 ]; then\n",
            "    printf 'launch-interrupted\\n' > \"$root/state.tmp\"\n",
            "    mv \"$root/state.tmp\" \"$root/state\"\n",
            "    state=launch-interrupted\n",
            "  fi\n",
            "  if {{ [ \"$state\" = prepared ] || [ \"$state\" = running ]; }} && [ ! -e \"$root/go\" ]; then\n",
            "    expected_session=agentapp_{agent_id}\n",
            "    expected_window=p_{process_id}\n",
            "    watchdog_window=w_{process_id}\n",
            "    agentapp_window_exists() {{\n",
            "      window_to_check=$1\n",
            "      exact_window_exists=0\n",
            "      if window_listing=$(LC_ALL=C tmux list-windows -t \"$expected_session:\" -F '#{{window_name}}' 2>&1); then\n",
            "        if printf '%s\\n' \"$window_listing\" | grep -Fqx \"$window_to_check\"; then exact_window_exists=1; fi\n",
            "      else\n",
            "        case \"$window_listing\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) ;; *) echo AGENTAPP_TMUX_RECONCILE_WINDOW_QUERY_FAILED >&2; exit 77 ;; esac\n",
            "      fi\n",
            "    }}\n",
            "    agentapp_terminate_pre_go_window() {{\n",
            "      owned_pane=$1\n",
            "      owned_pgid=$2\n",
            "      agentapp_window_exists \"$expected_window\"\n",
            "      if [ \"$exact_window_exists\" -eq 1 ]; then\n",
            "        current_pane=$(tmux display-message -p -t \"$expected_session:$expected_window.0\" '#{{pane_pid}}' 2>/dev/null || true)\n",
            "        current_pgid=$(ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' ')\n",
            "        case \"$current_pane\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "        case \"$current_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "        if [ \"$owned_pane\" = - ] || [ \"$owned_pgid\" = - ]; then\n",
            "          stored_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
            "          if [ -n \"$stored_identity\" ]; then\n",
            "            owned_pane=${{stored_identity%%:*}}\n",
            "            owned_pgid=${{stored_identity#*:}}\n",
            "          else\n",
            "            owned_pane=$current_pane\n",
            "            owned_pgid=$current_pgid\n",
            "            printf '%s:%s\\n' \"$owned_pane\" \"$owned_pgid\" > \"$root/process-identity.tmp\"\n",
            "            mv \"$root/process-identity.tmp\" \"$root/process-identity\"\n",
            "          fi\n",
            "        fi\n",
            "        case \"$owned_pane\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "        case \"$owned_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "        [ \"$current_pane\" = \"$owned_pane\" ] && [ \"$current_pgid\" = \"$owned_pgid\" ] || {{ echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_MISMATCH >&2; exit 80; }}\n",
            "        agentapp_probe_process_group \"$owned_pgid\"\n",
            "        case \"$agentapp_process_group_state\" in alive) ;; dead) ;; *) echo AGENTAPP_TMUX_RECONCILE_PROCESS_QUERY_UNCERTAIN >&2; exit 80 ;; esac\n",
            "        if [ \"$agentapp_process_group_state\" = alive ]; then\n",
            "          kill -TERM \"-$owned_pgid\" 2>/dev/null || true\n",
            "          i=0\n",
            "          while [ \"$i\" -lt 10 ]; do agentapp_probe_process_group \"$owned_pgid\"; [ \"$agentapp_process_group_state\" = alive ] || break; sleep 1; i=$((i + 1)); done\n",
            "        fi\n",
            "        agentapp_probe_process_group \"$owned_pgid\"\n",
            "        case \"$agentapp_process_group_state\" in alive) ;; dead) ;; *) echo AGENTAPP_TMUX_RECONCILE_PROCESS_QUERY_UNCERTAIN >&2; exit 80 ;; esac\n",
            "        if [ \"$agentapp_process_group_state\" = alive ]; then\n",
            "          kill -KILL \"-$owned_pgid\" 2>/dev/null || true\n",
            "          i=0\n",
            "          while [ \"$i\" -lt 5 ]; do agentapp_probe_process_group \"$owned_pgid\"; [ \"$agentapp_process_group_state\" = alive ] || break; sleep 1; i=$((i + 1)); done\n",
            "        fi\n",
            "        agentapp_probe_process_group \"$owned_pgid\"\n",
            "        case \"$agentapp_process_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_RECONCILE_PROCESS_GROUP_ALIVE >&2; exit 81 ;; *) echo AGENTAPP_TMUX_RECONCILE_PROCESS_QUERY_UNCERTAIN >&2; exit 80 ;; esac\n",
            "        tmux kill-window -t \"$expected_session:$expected_window\" 2>/dev/null || true\n",
            "        agentapp_window_exists \"$expected_window\"\n",
            "        [ \"$exact_window_exists\" -eq 0 ] || {{ echo AGENTAPP_TMUX_RECONCILE_TERMINATION_UNCONFIRMED >&2; exit 78; }}\n",
            "      elif [ \"$owned_pgid\" != - ]; then\n",
            "        case \"$owned_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "        agentapp_probe_process_group \"$owned_pgid\"\n",
            "        case \"$agentapp_process_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_RECONCILE_PROCESS_WITHOUT_WINDOW >&2; exit 80 ;; *) echo AGENTAPP_TMUX_RECONCILE_PROCESS_QUERY_UNCERTAIN >&2; exit 80 ;; esac\n",
            "      fi\n",
            "    }}\n",
            "    reuse_existing_claim=0\n",
            "    if [ -e \"$root/transition-claim\" ]; then\n",
            "      existing_claim=$(cat \"$root/transition-claim\" 2>/dev/null || true)\n",
            "      old_ifs=$IFS; IFS='|'\n",
            "      read claim_kind claim_nonce claim_controller claim_operation_pid claim_operation_pgid claim_window claim_pane claim_pgid <<AGENTAPP_PREPARED_CLAIM_EOF\n",
            "$existing_claim\n",
            "AGENTAPP_PREPARED_CLAIM_EOF\n",
            "      IFS=$old_ifs\n",
            "      case \"$claim_kind\" in bootstrap|recovery) ;; *) echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79 ;; esac\n",
            "      case \"$claim_nonce\" in ''|*[!0-9a-zA-Z_.-]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "      case \"$claim_operation_pid:$claim_operation_pgid\" in *[!0-9:]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "      claim_generation=${{claim_controller%%:*}}; claim_controller_id=${{claim_controller#*:}}\n",
            "      case \"$claim_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "      [ -n \"$claim_controller_id\" ] && [ \"$claim_controller_id\" != \"$claim_controller\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
            "      claim_candidate=\"$root/.transition-candidate.$claim_nonce.$claim_operation_pid\"\n",
            "      [ -f \"$claim_candidate\" ] && [ ! -L \"$claim_candidate\" ] && [ \"$claim_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$claim_candidate\" 2>/dev/null || true)\" = \"$existing_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "      live_operation_pgid=$(command -p ps -o pgid= -p \"$claim_operation_pid\" 2>/dev/null | tr -d ' ')\n",
            "      [ \"$live_operation_pgid\" != \"$claim_operation_pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
            "      agentapp_probe_process_group \"$claim_operation_pgid\"\n",
            "      case \"$agentapp_process_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79 ;; *) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "      [ \"$claim_window\" = \"$expected_window\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
            "      reuse_existing_claim=1\n",
            "    fi\n",
            "    observed=$(cat \"$root/controller\" 2>/dev/null || true)\n",
            "    observed_generation=${{observed%%:*}}\n",
            "    case \"$observed_generation\" in ''|*[!0-9]*) observed_generation=0 ;; esac\n",
            "    if [ \"$reuse_existing_claim\" -eq 1 ]; then\n",
            "      next_generation=$claim_generation\n",
            "      next=$claim_controller\n",
            "      if [ \"$next\" != \"$observed\" ]; then [ \"$next_generation\" -eq $((observed_generation + 1)) ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}; fi\n",
            "      transition_candidate=$claim_candidate\n",
            "      expected_recovery_claim=$existing_claim\n",
            "    else\n",
            "      next_generation=$((observed_generation + 1))\n",
            "      next=\"$next_generation:r_{recovery_key}\"\n",
            "      agentapp_window_exists \"$expected_window\"\n",
            "      claim_pane=-\n",
            "      claim_pgid=-\n",
            "      if [ \"$exact_window_exists\" -eq 1 ]; then\n",
            "        claim_pane=$(tmux display-message -p -t \"$expected_session:$expected_window.0\" '#{{pane_pid}}' 2>/dev/null || true)\n",
            "        claim_pgid=$(ps -o pgid= -p \"$claim_pane\" 2>/dev/null | tr -d ' ')\n",
            "        case \"$claim_pane\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "        case \"$claim_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "      fi\n",
            "      operation_pid=$$\n",
            "      operation_pgid=$(ps -o pgid= -p \"$operation_pid\" 2>/dev/null | tr -d ' ')\n",
            "      case \"$operation_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "      case \"$operation_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "      transition_candidate=\"$root/.transition-candidate.r_{recovery_key}.$$\"\n",
            "      expected_recovery_claim=\"recovery|r_{recovery_key}|$next|$operation_pid|$operation_pgid|$expected_window|$claim_pane|$claim_pgid\"\n",
            "      printf '%s\\n' \"$expected_recovery_claim\" > \"$transition_candidate\"\n",
            "      ln \"$transition_candidate\" \"$root/transition-claim\" 2>/dev/null || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
            "    fi\n",
            "    cleanup_new_transition_claim() {{ if [ \"$reuse_existing_claim\" -eq 0 ]; then if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; fi; }}\n",
            "    release_transition_claim() {{ if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_recovery_claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; }}\n",
            "    require_recovery_claim() {{ [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_recovery_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}; }}\n",
            "    trap 'cleanup_new_transition_claim' EXIT\n",
            "    [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$observed\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "    require_recovery_claim\n",
            "    if [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" != \"$next\" ]; then\n",
            "      printf '%s\\n' \"$next_generation\" > \"$root/lease-generation.tmp\"\n",
            "      mv \"$root/lease-generation.tmp\" \"$root/lease-generation\"\n",
            "      require_recovery_claim\n",
            "      printf '%s\\n' \"$next\" > \"$root/controller.tmp\"\n",
            "      mv \"$root/controller.tmp\" \"$root/controller\"\n",
            "      require_recovery_claim\n",
            "    fi\n",
            "    state=$(cat \"$root/state\" 2>/dev/null || true)\n",
            "    {{ [ \"$state\" = prepared ] || [ \"$state\" = running ]; }} && [ ! -e \"$root/go\" ] && [ ! -e \"$root/status\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
            "    agentapp_terminate_pre_go_window \"$claim_pane\" \"$claim_pgid\"\n",
            "    agentapp_window_exists \"$watchdog_window\"\n",
            "    if [ \"$exact_window_exists\" -eq 1 ]; then tmux kill-window -t \"$expected_session:$watchdog_window\" 2>/dev/null || true; fi\n",
            "    agentapp_window_exists \"$watchdog_window\"\n",
            "    [ \"$exact_window_exists\" -eq 0 ] || {{ echo AGENTAPP_TMUX_RECONCILE_WATCHDOG_PRESENT >&2; exit 78; }}\n",
            "    state=$(cat \"$root/state\" 2>/dev/null || true)\n",
            "    [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$next\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "    {{ [ \"$state\" = prepared ] || [ \"$state\" = running ]; }} && [ ! -e \"$root/go\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
            "    agentapp_window_exists \"$expected_window\"\n",
            "    [ \"$exact_window_exists\" -eq 0 ] || {{ echo AGENTAPP_TMUX_RECONCILE_TERMINATION_UNCONFIRMED >&2; exit 78; }}\n",
            "    prepared_terminal_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
            "    if [ ! -e \"$root/terminal-claim\" ]; then mkdir \"$root/terminal-claim\" 2>/dev/null || true; fi\n",
            "    [ -d \"$root/terminal-claim\" ] && [ ! -L \"$root/terminal-claim\" ] || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}\n",
            "    [ -z \"$prepared_terminal_kind\" ] || [ \"$prepared_terminal_kind\" = launch-interrupted ] || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}\n",
            "    printf 'launch-interrupted\\n' > \"$root/terminal-claim/kind.tmp\"\n",
            "    mv \"$root/terminal-claim/kind.tmp\" \"$root/terminal-claim/kind\"\n",
            "    [ -e \"$root/output\" ] || : > \"$root/output\"\n",
            "    printf '125\\n' > \"$root/status.tmp\"\n",
            "    mv \"$root/status.tmp\" \"$root/status\"\n",
            "    printf 'launch-interrupted\\n' > \"$root/state.tmp\"\n",
            "    mv \"$root/state.tmp\" \"$root/state\"\n",
            "    rm -f \"$root/recovery-required\"\n",
            "    release_transition_claim\n",
            "    trap - EXIT\n",
            "    state=launch-interrupted\n",
            "  fi\n"
        ),
        agent_id = agent_id,
        process_id = process_id,
        recovery_key = recovery_key,
    )
}

// A remote command can disappear before command.sh writes terminal descriptor
// fields. Reconciliation may retire that exact stale-running state only after
// proving that the descriptor is locally authoritative, its recorded process
// group is gone, and its exact command window is absent. This deliberately
// records recovery loss rather than inventing a natural exit or claiming that
// a previously requested signal was delivered. Any live process, live
// transition, malformed identity, or failed tmux query remains ambiguous and
// fails closed.
fn stale_running_recovery_loss_fragment(agent_id: &str, process_id: &str) -> String {
    let recovery_key = stable_identifier(&format!("{agent_id}:{process_id}:stale-running"));
    format!(
        concat!(
            "  stale_terminal_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
            "  if [ \"$state\" = running ] && [ -e \"$root/go\" ]; then\n",
            "    expected_session=agentapp_{agent_id}\n",
            "    expected_window=p_{process_id}\n",
            "    watchdog_window=w_{process_id}\n",
            "    stored_window=$(cat \"$root/window\" 2>/dev/null || true)\n",
            "    [ \"$stored_window\" = \"$expected_window\" ] || {{ echo AGENTAPP_TMUX_RECONCILE_WINDOW_IDENTITY_MISMATCH >&2; exit 80; }}\n",
            "    process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
            "    pane_pid=${{process_identity%%:*}}\n",
            "    pgid=${{process_identity#*:}}\n",
            "    case \"$process_identity\" in *:*:*) echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "    case \"$pane_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "    case \"$pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "    [ \"$pane_pid:$pgid\" = \"$process_identity\" ] || {{ echo AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN >&2; exit 80; }}\n",
            "    agentapp_stale_window_exists() {{\n",
            "      stale_window_to_check=$1\n",
            "      stale_window_exists=0\n",
            "      if stale_window_listing=$(LC_ALL=C tmux list-windows -t \"$expected_session:\" -F '#{{window_name}}' 2>&1); then\n",
            "        if printf '%s\\n' \"$stale_window_listing\" | grep -Fqx \"$stale_window_to_check\"; then stale_window_exists=1; fi\n",
            "      else\n",
            "        case \"$stale_window_listing\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) ;; *) echo AGENTAPP_TMUX_RECONCILE_WINDOW_QUERY_FAILED >&2; exit 77 ;; esac\n",
            "      fi\n",
            "    }}\n",
            "    agentapp_stale_window_exists \"$expected_window\"\n",
            "    if [ \"$stale_window_exists\" -eq 0 ]; then\n",
            "      agentapp_probe_process_group \"$pgid\"\n",
            "      case \"$agentapp_process_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_RECONCILE_PROCESS_WITHOUT_WINDOW >&2; exit 80 ;; *) echo AGENTAPP_TMUX_RECONCILE_PROCESS_QUERY_UNCERTAIN >&2; exit 80 ;; esac\n",
            "      operation_pid=$$\n",
            "      operation_pgid=$(command -p ps -o pgid= -p \"$operation_pid\" 2>/dev/null | tr -d ' ')\n",
            "      case \"$operation_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "      case \"$operation_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "      [ \"$operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80; }}\n",
            "      observed=$(cat \"$root/controller\" 2>/dev/null || true)\n",
            "      observed_generation=${{observed%%:*}}\n",
            "      case \"$observed_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_CONTROLLER_GENERATION_UNKNOWN >&2; exit 80 ;; esac\n",
            "      reuse_existing_claim=0\n",
            "      if [ -e \"$root/transition-claim\" ]; then\n",
            "        expected_stale_claim=$(cat \"$root/transition-claim\" 2>/dev/null || true)\n",
            "        old_ifs=$IFS; IFS='|'\n",
            "        read claim_kind claim_nonce claim_controller claim_operation_pid claim_operation_pgid claim_window claim_pane claim_pgid <<AGENTAPP_STALE_CLAIM_EOF\n",
            "$expected_stale_claim\n",
            "AGENTAPP_STALE_CLAIM_EOF\n",
            "        IFS=$old_ifs\n",
            "        case \"$claim_kind\" in recovery|bootstrap|interrupt) ;; *) echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79 ;; esac\n",
            "        case \"$claim_nonce\" in ''|*[!0-9a-zA-Z_.-]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "        case \"$claim_operation_pid:$claim_operation_pgid\" in *[!0-9:]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "        claim_generation=${{claim_controller%%:*}}; claim_controller_id=${{claim_controller#*:}}\n",
            "        case \"$claim_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "        [ -n \"$claim_controller_id\" ] && [ \"$claim_controller_id\" != \"$claim_controller\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
            "        [ \"$claim_window\" = \"$expected_window\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
            "        case \"$claim_kind\" in bootstrap) [ \"$claim_pane:$claim_pgid\" = -:- ] || [ \"$claim_pane:$claim_pgid\" = \"$pane_pid:$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }} ;; *) [ \"$claim_pane:$claim_pgid\" = \"$pane_pid:$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }} ;; esac\n",
            "        [ \"$claim_operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
            "        transition_candidate=\"$root/.transition-candidate.$claim_nonce.$claim_operation_pid\"\n",
            "        [ -f \"$transition_candidate\" ] && [ ! -L \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$transition_candidate\" 2>/dev/null || true)\" = \"$expected_stale_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "        live_operation_pgid=$(command -p ps -o pgid= -p \"$claim_operation_pid\" 2>/dev/null | tr -d ' ')\n",
            "        [ \"$live_operation_pgid\" != \"$claim_operation_pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
            "        agentapp_probe_process_group \"$claim_operation_pgid\"\n",
            "        case \"$agentapp_process_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79 ;; *) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "        next_generation=$claim_generation\n",
            "        next=$claim_controller\n",
            "        case \"$claim_kind\" in recovery) if [ \"$next\" != \"$observed\" ]; then [ \"$next_generation\" -eq $((observed_generation + 1)) ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}; fi ;; *) [ \"$next\" = \"$observed\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }} ;; esac\n",
            "        reuse_existing_claim=1\n",
            "      else\n",
            "        next_generation=$((observed_generation + 1))\n",
            "        next=\"$next_generation:s_{recovery_key}\"\n",
            "        transition_candidate=\"$root/.transition-candidate.s_{recovery_key}.$$\"\n",
            "        expected_stale_claim=\"recovery|s_{recovery_key}|$next|$operation_pid|$operation_pgid|$expected_window|$pane_pid|$pgid\"\n",
            "        printf '%s\\n' \"$expected_stale_claim\" > \"$transition_candidate\"\n",
            "        ln \"$transition_candidate\" \"$root/transition-claim\" 2>/dev/null || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
            "      fi\n",
            "      cleanup_new_stale_claim() {{ if [ \"$reuse_existing_claim\" -eq 0 ]; then if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; fi; }}\n",
            "      release_stale_transition_claim() {{ if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_stale_claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; }}\n",
            "      agentapp_require_stale_claim_inode() {{\n",
            "        [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "        [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_stale_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "      }}\n",
            "      agentapp_require_stale_claim() {{\n",
            "        agentapp_require_stale_claim_inode\n",
            "        [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$next\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "      }}\n",
            "      trap 'cleanup_new_stale_claim' EXIT\n",
            "      [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = running ] && [ -e \"$root/go\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
            "      [ \"$(cat \"$root/process-identity\" 2>/dev/null || true)\" = \"$process_identity\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_OWNERSHIP_MISMATCH >&2; exit 80; }}\n",
            "      [ \"$(cat \"$root/window\" 2>/dev/null || true)\" = \"$expected_window\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_OWNERSHIP_MISMATCH >&2; exit 80; }}\n",
            "      [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$observed\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "      agentapp_require_stale_claim_inode\n",
            "      if [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" != \"$next\" ]; then\n",
            "        printf '%s\\n' \"$next_generation\" > \"$root/lease-generation.tmp\"\n",
            "        mv \"$root/lease-generation.tmp\" \"$root/lease-generation\"\n",
            "        printf '%s\\n' \"$next\" > \"$root/controller.tmp\"\n",
            "        mv \"$root/controller.tmp\" \"$root/controller\"\n",
            "      fi\n",
            "      agentapp_require_stale_claim\n",
            "      agentapp_stale_window_exists \"$expected_window\"\n",
            "      [ \"$stale_window_exists\" -eq 0 ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
            "      agentapp_probe_process_group \"$pgid\"\n",
            "      case \"$agentapp_process_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_RECONCILE_PROCESS_WITHOUT_WINDOW >&2; exit 80 ;; *) echo AGENTAPP_TMUX_RECONCILE_PROCESS_QUERY_UNCERTAIN >&2; exit 80 ;; esac\n",
            "      agentapp_require_stale_claim\n",
            "      agentapp_stale_window_exists \"$watchdog_window\"\n",
            "      if [ \"$stale_window_exists\" -eq 1 ]; then tmux kill-window -t \"$expected_session:$watchdog_window\" 2>/dev/null || true; fi\n",
            "      agentapp_stale_window_exists \"$watchdog_window\"\n",
            "      [ \"$stale_window_exists\" -eq 0 ] || {{ echo AGENTAPP_TMUX_RECONCILE_WATCHDOG_PRESENT >&2; exit 78; }}\n",
            "      agentapp_require_stale_claim\n",
            "      stale_terminal_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
            "      stale_terminal_status=$(cat \"$root/status\" 2>/dev/null || true)\n",
            "      terminal_state=\n",
            "      terminal_status=\n",
            "      case \"$stale_terminal_kind:$stale_terminal_status\" in\n",
            "        completed:*[!0-9]*|completed:) terminal_state=recovery-lost; terminal_status=125 ;;\n",
            "        completed:*) terminal_state=completed; terminal_status=$stale_terminal_status ;;\n",
            "        terminated:143) terminal_state=terminated; terminal_status=143 ;;\n",
            "        recovery-lost:|recovery-lost:125) terminal_state=recovery-lost; terminal_status=125 ;;\n",
            "        launch-interrupted:125) terminal_state=launch-interrupted; terminal_status=125 ;;\n",
            "        :|terminated:) terminal_state=recovery-lost; terminal_status=125 ;;\n",
            "        *) echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82 ;;\n",
            "      esac\n",
            "      if [ \"$terminal_state\" = recovery-lost ]; then\n",
            "        if [ ! -e \"$root/terminal-claim\" ]; then mkdir \"$root/terminal-claim\" 2>/dev/null || true; fi\n",
            "        [ -d \"$root/terminal-claim\" ] && [ ! -L \"$root/terminal-claim\" ] || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}\n",
            "        for terminal_entry in \"$root/terminal-claim\"/* \"$root/terminal-claim\"/.[!.]* \"$root/terminal-claim\"/..?*; do [ ! -e \"$terminal_entry\" ] || {{ [ \"${{terminal_entry##*/}}\" = kind ] || [ \"${{terminal_entry##*/}}\" = kind.tmp ]; }} || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}; done\n",
            "        agentapp_require_stale_claim\n",
            "        printf 'recovery-lost\\n' > \"$root/terminal-claim/kind.tmp\"\n",
            "        mv \"$root/terminal-claim/kind.tmp\" \"$root/terminal-claim/kind\"\n",
            "      fi\n",
            "      agentapp_require_stale_claim\n",
            "      [ -e \"$root/output\" ] || : > \"$root/output\"\n",
            "      if [ -e \"$root/status\" ]; then\n",
            "        [ \"$(cat \"$root/status\" 2>/dev/null || true)\" = \"$terminal_status\" ] || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}\n",
            "      else\n",
            "        printf '%s\\n' \"$terminal_status\" > \"$root/status.tmp\"\n",
            "        mv \"$root/status.tmp\" \"$root/status\"\n",
            "      fi\n",
            "      agentapp_require_stale_claim\n",
            "      rm -f \"$root/recovery-required\"\n",
            "      printf '%s\\n' \"$terminal_state\" > \"$root/state.tmp\"\n",
            "      mv \"$root/state.tmp\" \"$root/state\"\n",
            "      release_stale_transition_claim\n",
            "      trap - EXIT\n",
            "      state=$terminal_state\n",
            "    fi\n",
            "  fi\n"
        ),
        agent_id = agent_id,
        process_id = process_id,
        recovery_key = recovery_key,
    )
}

fn exact_reconciliation_command(agent_key: &str, request: &ReconciliationRequest) -> String {
    let agent_id = stable_identifier(agent_key);
    let mut command = format!(
        concat!(
            "set -eu\n",
            "base=\"$HOME/.agentapp/tmux/{agent_id}\"\n",
            // A failed signal-zero probe is not itself death proof: EPERM and
            // ESRCH both use a nonzero status. Accept only the kernel utility's
            // locale-stabilized ESRCH diagnostic, and retain an explicit
            // unknown outcome for every other failure.
            "agentapp_probe_process_group() {{\n",
            "  agentapp_probe_pgid=$1\n",
            "  agentapp_process_group_state=unknown\n",
            "  [ -x /bin/kill ] || return\n",
            "  if /bin/kill -0 -- \"-$agentapp_probe_pgid\" 2>/dev/null; then agentapp_process_group_state=alive; return; fi\n",
            "  if agentapp_kill_error=$(LC_ALL=C /bin/kill -0 -- \"-$agentapp_probe_pgid\" 2>&1); then agentapp_process_group_state=alive; return; fi\n",
            "  case \"$agentapp_kill_error\" in *\"No such process\"*) agentapp_process_group_state=dead ;; esac\n",
            "}}\n",
        ),
        agent_id = agent_id,
    );
    for execution in &request.incomplete_executions {
        let expected_command_digest = execution.expected_command_digest.as_deref().unwrap_or("-");
        let expected_session_id = execution
            .expected_session_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let expected_tty = execution
            .expected_tty
            .map(|value| if value { "1" } else { "0" })
            .unwrap_or("-");
        let identity = ExecutionIdentity {
            thread_id: request.thread_id.clone(),
            turn_id: execution.turn_id.clone(),
            call_id: execution.call_id.clone(),
            attempt_generation: execution.attempt_generation,
        };
        let identity_key = format!(
            "{}\0{}\0{}\0{}",
            identity.thread_id, identity.turn_id, identity.call_id, identity.attempt_generation
        );
        let process_id = stable_identifier(&identity_key);
        let root = format!("$base/{process_id}");
        let expected_thread = STANDARD.encode(identity.thread_id.as_bytes());
        let expected_turn = STANDARD.encode(identity.turn_id.as_bytes());
        let expected_call = STANDARD.encode(identity.call_id.as_bytes());
        let prepared_rollback = prepared_rollback_fragment(&agent_id, &process_id);
        let stale_running_recovery_loss =
            stale_running_recovery_loss_fragment(&agent_id, &process_id);
        command.push_str(&format!(
            concat!(
                "root=\"{root}\"\n",
                "if [ ! -e \"$root\" ]; then\n",
                "  expected_window=p_{process_id}\n",
                "  expected_session=agentapp_{agent_id}\n",
                "  if session_probe=$(LC_ALL=C tmux has-session -t \"$expected_session\" 2>&1 >/dev/null); then\n",
                "    windows=$(LC_ALL=C tmux list-windows -t \"$expected_session:\" -F '#{{window_name}}' 2>&1) || {{ echo AGENTAPP_TMUX_RECONCILE_WINDOW_QUERY_FAILED >&2; exit 77; }}\n",
                "    if printf '%s\\n' \"$windows\" | grep -Fqx \"$expected_window\"; then echo AGENTAPP_TMUX_RECONCILE_ORPHAN_WINDOW >&2; exit 77; fi\n",
                "  else\n",
                "    session_status=$?\n",
                "    [ \"$session_status\" -eq 1 ] || {{ echo AGENTAPP_TMUX_RECONCILE_SESSION_QUERY_FAILED >&2; exit 77; }}\n",
                "    case \"$session_probe\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) ;; *) echo AGENTAPP_TMUX_RECONCILE_SESSION_QUERY_FAILED >&2; exit 77 ;; esac\n",
                "  fi\n",
                "  printf 'AGENTAPP_RECOVERED %s %s %s %s missing - - 0 0 1 - - -\\n' {thread} {turn} {call} {attempt}\n",
                "else\n",
                "  [ -d \"$root\" ] || {{ echo AGENTAPP_TMUX_RECONCILE_UNKNOWN >&2; exit 77; }}\n",
                "  [ {expected_digest} != - ] || {{ echo AGENTAPP_TMUX_RECONCILE_LOCAL_DIGEST_MISSING >&2; exit 77; }}\n",
                "  [ {expected_session_id} != - ] || {{ echo AGENTAPP_TMUX_RECONCILE_LOCAL_SESSION_MISSING >&2; exit 77; }}\n",
                "  [ {expected_tty} != - ] || {{ echo AGENTAPP_TMUX_RECONCILE_LOCAL_STREAM_MODE_MISSING >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/owner\" 2>/dev/null || true)\" = {owner} ] || {{ echo AGENTAPP_TMUX_RECONCILE_UNOWNED >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/identity\" 2>/dev/null || true)\" = {process_id} ] || {{ echo AGENTAPP_TMUX_RECONCILE_IDENTITY_CONFLICT >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/thread-id\" 2>/dev/null || true)\" = {thread} ] || {{ echo AGENTAPP_TMUX_RECONCILE_THREAD_CONFLICT >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/turn-id\" 2>/dev/null || true)\" = {turn} ] || {{ echo AGENTAPP_TMUX_RECONCILE_TURN_CONFLICT >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/call-id\" 2>/dev/null || true)\" = {call} ] || {{ echo AGENTAPP_TMUX_RECONCILE_CALL_CONFLICT >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/attempt-generation\" 2>/dev/null || true)\" = {attempt} ] || {{ echo AGENTAPP_TMUX_RECONCILE_ATTEMPT_CONFLICT >&2; exit 77; }}\n",
                "  token=$(cat \"$root/acknowledgement-token\" 2>/dev/null || true)\n",
                "  digest=$(cat \"$root/digest\" 2>/dev/null || true); [ -n \"$digest\" ] || {{ echo AGENTAPP_TMUX_RECONCILE_DIGEST_MISSING >&2; exit 77; }}\n",
                "  [ \"$digest\" = {expected_digest} ] || {{ echo AGENTAPP_TMUX_RECONCILE_DIGEST_CONFLICT >&2; exit 77; }}\n",
                "  session_id=$(cat \"$root/session-id\" 2>/dev/null || printf '-')\n",
                "  [ \"$session_id\" = {expected_session_id} ] || {{ echo AGENTAPP_TMUX_RECONCILE_SESSION_CONFLICT >&2; exit 77; }}\n",
                "  [ \"$(cat \"$root/tty\" 2>/dev/null || true)\" = {expected_tty} ] || {{ echo AGENTAPP_TMUX_RECONCILE_STREAM_MODE_CONFLICT >&2; exit 77; }}\n",
                "  state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "{prepared_rollback}",
                "{stale_running_recovery_loss}",
                "  cursor=$(wc -c < \"$root/output\" 2>/dev/null || printf '0'); cursor=$(printf '%s' \"$cursor\" | tr -d ' ')\n",
                "  state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "  delivery_unknown=0\n",
                "  terminal_verified_dead=0\n",
                "  code=$(cat \"$root/status\" 2>/dev/null || printf '-')\n",
                "  case \"$state\" in completed) recovered=completed ;; terminated) recovered=terminated ;; recovery-lost) recovered=recovery-lost ;; launch-interrupted) recovered=launch-interrupted ;; running) if [ -e \"$root/go\" ]; then recovered=running; else recovered=unknown; fi ;; prepared) if [ -e \"$root/go\" ]; then recovered=running; else recovered=prepared; fi ;; *) recovered=unknown ;; esac\n",
                "  if [ \"$recovered\" = completed ] || [ \"$recovered\" = terminated ] || [ \"$recovered\" = recovery-lost ] || [ \"$recovered\" = launch-interrupted ]; then\n",
                "    process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
                "    pane_pid=${{process_identity%%:*}}; pgid=${{process_identity#*:}}\n",
                "    window=$(cat \"$root/window\" 2>/dev/null || true); expected_window=p_{process_id}\n",
                "    claim_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
                "    identity_valid=1\n",
                "    [ \"$window\" = \"$expected_window\" ] || identity_valid=0\n",
                "    case \"$recovered:$claim_kind\" in completed:completed|terminated:terminated|recovery-lost:recovery-lost|launch-interrupted:launch-interrupted) ;; *) identity_valid=0 ;; esac\n",
                "    if [ \"$recovered\" = completed ]; then case \"$code\" in ''|*[!0-9-]*) identity_valid=0 ;; esac; fi\n",
                "    if [ \"$recovered\" = launch-interrupted ] && [ ! -e \"$root/go\" ]; then\n",
                "      if [ -z \"$process_identity\" ]; then pane_pid=-; pgid=-; else case \"$process_identity\" in *:*:*) identity_valid=0 ;; esac; case \"$pane_pid\" in ''|*[!0-9]*) identity_valid=0 ;; esac; case \"$pgid\" in ''|*[!0-9]*) identity_valid=0 ;; esac; [ \"$pane_pid:$pgid\" = \"$process_identity\" ] || identity_valid=0; fi\n",
                "    else\n",
                "      case \"$process_identity\" in *:*:*) identity_valid=0 ;; esac\n",
                "      case \"$pane_pid\" in ''|*[!0-9]*) identity_valid=0 ;; esac\n",
                "      case \"$pgid\" in ''|*[!0-9]*) identity_valid=0 ;; esac\n",
                "      [ \"$pane_pid:$pgid\" = \"$process_identity\" ] || identity_valid=0\n",
                "    fi\n",
                "    process_dead=0\n",
                "    if [ \"$pgid\" = - ]; then\n",
                "      process_dead=1\n",
                "    else\n",
                "      agentapp_probe_process_group \"$pgid\"\n",
                "      case \"$agentapp_process_group_state\" in dead) process_dead=1 ;; alive) ;; *) identity_valid=0 ;; esac\n",
                "    fi\n",
                "    window_absent=0\n",
                "    if terminal_windows=$(LC_ALL=C tmux list-windows -t agentapp_{agent_id}: -F '#{{window_name}}' 2>&1); then\n",
                "      if ! printf '%s\\n' \"$terminal_windows\" | grep -Fqx \"$expected_window\"; then window_absent=1; fi\n",
                "    else\n",
                "      case \"$terminal_windows\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) window_absent=1 ;; *) identity_valid=0 ;; esac\n",
                "    fi\n",
                "    if [ \"$identity_valid\" -eq 1 ] && [ \"$process_dead\" -eq 1 ] && [ \"$window_absent\" -eq 1 ]; then terminal_verified_dead=1; fi\n",
                "  fi\n",
                "  [ -f \"$root/recovery-required\" ] && recovered=unknown\n",
                "  [ -r \"$root/output\" ] || {{ echo AGENTAPP_TMUX_RECONCILE_OUTPUT_UNREADABLE >&2; exit 77; }}\n",
                "  snapshot_size=$(wc -c < \"$root/output\" 2>/dev/null || printf '0'); snapshot_size=$(printf '%s' \"$snapshot_size\" | tr -d ' ')\n",
                "  [ \"$snapshot_size\" -ge \"$cursor\" ] || {{ echo AGENTAPP_TMUX_RECONCILE_OUTPUT_SHRANK >&2; exit 77; }}\n",
                "  if [ \"$cursor\" -eq 0 ]; then output=-; else output=$(head -c \"$cursor\" \"$root/output\" | base64 | tr -d '\\n'); fi\n",
                "  printf 'AGENTAPP_RECOVERED %s %s %s %s %s %s %s %s %s %s %s %s %s\\n' {thread} {turn} {call} {attempt} \"$recovered\" \"$code\" \"$session_id\" \"$cursor\" \"$delivery_unknown\" \"$terminal_verified_dead\" \"$token\" \"$digest\" \"$output\"\n",
                "fi\n"
            ),
            root = root,
            owner = shell_quote(OWNERSHIP_MARKER),
            thread = shell_quote(&expected_thread),
            turn = shell_quote(&expected_turn),
            call = shell_quote(&expected_call),
            attempt = shell_quote(&identity.attempt_generation.to_string()),
            expected_digest = shell_quote(expected_command_digest),
            expected_session_id = shell_quote(&expected_session_id),
            expected_tty = shell_quote(expected_tty),
            prepared_rollback = prepared_rollback,
            stale_running_recovery_loss = stale_running_recovery_loss,
            process_id = process_id,
            agent_id = agent_id,
        ));
    }
    command
}

fn acknowledgement_keys(acknowledgement: &RecoveredExecutionAcknowledgement) -> (String, String) {
    let legacy_acknowledgement_key =
        format!("{:x}", Sha256::digest(acknowledgement.as_str().as_bytes()));
    let (range_start, range_end, output_sha256, state, exit_code) =
        match acknowledgement.terminal_proof() {
            Some(proof) => {
                let (state, exit_code) = match proof.status {
                    RecoveredExecutionStatus::Exited(exit_code) => {
                        ("completed".to_string(), exit_code.to_string())
                    }
                    RecoveredExecutionStatus::Terminated => {
                        ("terminated".to_string(), "143".to_string())
                    }
                    RecoveredExecutionStatus::RecoveryLost => {
                        ("recovery-lost".to_string(), "125".to_string())
                    }
                    RecoveredExecutionStatus::LaunchInterrupted => {
                        ("launch-interrupted".to_string(), "125".to_string())
                    }
                    _ => ("-".to_string(), "-".to_string()),
                };
                (
                    proof.range_start.to_string(),
                    proof.range_end.to_string(),
                    proof.output_sha256.clone(),
                    state,
                    exit_code,
                )
            }
            None => (
                "-".to_string(),
                "-".to_string(),
                "-".to_string(),
                "-".to_string(),
                "-".to_string(),
            ),
        };
    let acknowledgement_key_material = format!(
        "agentapp-tmux-ack-v2\0{}\0{}\0{}\0{}\0{}\0{}",
        acknowledgement.as_str(),
        range_start,
        range_end,
        output_sha256,
        state,
        exit_code
    );
    let acknowledgement_key = format!(
        "{:x}",
        Sha256::digest(acknowledgement_key_material.as_bytes())
    );
    (acknowledgement_key, legacy_acknowledgement_key)
}

fn acknowledgement_command(
    agent_key: &str,
    acknowledgement: &RecoveredExecutionAcknowledgement,
) -> String {
    let agent_id = stable_identifier(agent_key);
    // Build 119 tombstones were keyed only by the backend token and were left
    // empty. The generated command accepts that legacy path once, relying on
    // Core's exact durable Prepared/output/Commit chain, and atomically binds
    // it to the first full proof via `proof-key`. New tombstones are keyed by
    // the full domain-separated proof from their creation.
    let (
        expected_range_start,
        expected_range_end,
        expected_output_sha256,
        expected_state,
        expected_exit_code,
    ) = match acknowledgement.terminal_proof() {
        Some(proof) => {
            let (state, exit_code) = match proof.status {
                RecoveredExecutionStatus::Exited(exit_code) => {
                    ("completed".to_string(), exit_code.to_string())
                }
                RecoveredExecutionStatus::Terminated => {
                    ("terminated".to_string(), "143".to_string())
                }
                RecoveredExecutionStatus::RecoveryLost => {
                    ("recovery-lost".to_string(), "125".to_string())
                }
                RecoveredExecutionStatus::LaunchInterrupted => {
                    ("launch-interrupted".to_string(), "125".to_string())
                }
                _ => ("-".to_string(), "-".to_string()),
            };
            (
                proof.range_start.to_string(),
                proof.range_end.to_string(),
                proof.output_sha256.clone(),
                state,
                exit_code,
            )
        }
        None => (
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
        ),
    };
    let (acknowledgement_key, legacy_acknowledgement_key) = acknowledgement_keys(acknowledgement);
    format!(
        concat!(
            "set -eu\n",
            "setopt nonomatch 2>/dev/null || true\n",
            "base=\"$HOME/.agentapp/tmux/{agent_id}\"\n",
            "token={token}\n",
            "expected_range_start={expected_range_start}\n",
            "expected_range_end={expected_range_end}\n",
            "expected_output_sha256={expected_output_sha256}\n",
            "expected_terminal_state={expected_state}\n",
            "expected_exit_code={expected_exit_code}\n",
            "case \"$expected_range_start\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_ACK_PROOF_MISSING >&2; exit 78 ;; esac\n",
            "case \"$expected_range_end\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_ACK_PROOF_MISSING >&2; exit 78 ;; esac\n",
            "[ \"$expected_range_end\" -ge \"$expected_range_start\" ] || {{ echo AGENTAPP_TMUX_ACK_RANGE_CONFLICT >&2; exit 78; }}\n",
            "[ \"$expected_output_sha256\" != - ] || {{ echo AGENTAPP_TMUX_ACK_PROOF_MISSING >&2; exit 78; }}\n",
            "[ \"${{#expected_output_sha256}}\" -eq 64 ] || {{ echo AGENTAPP_TMUX_ACK_PROOF_MALFORMED >&2; exit 78; }}\n",
            "case \"$expected_output_sha256\" in *[!0-9a-f]*) echo AGENTAPP_TMUX_ACK_PROOF_MALFORMED >&2; exit 78 ;; esac\n",
            "case \"$expected_terminal_state\" in completed|terminated|recovery-lost|launch-interrupted) ;; *) echo AGENTAPP_TMUX_ACK_PROOF_MISSING >&2; exit 78 ;; esac\n",
            "case \"$expected_exit_code\" in ''|*[!0-9-]*) echo AGENTAPP_TMUX_ACK_PROOF_MISSING >&2; exit 78 ;; *) ;; esac\n",
            "process_id=${{token%%-*}}\n",
            "case \"$process_id\" in ''|*[!0-9a-f]*) echo AGENTAPP_TMUX_ACK_BAD_TOKEN >&2; exit 78 ;; esac\n",
            "[ \"${{#process_id}}\" -eq 16 ] || {{ echo AGENTAPP_TMUX_ACK_BAD_TOKEN >&2; exit 78; }}\n",
            "token_proof=${{token#*-}}\n",
            "[ \"$token\" = \"$process_id-$token_proof\" ] && [ \"${{#token_proof}}\" -eq 64 ] || {{ echo AGENTAPP_TMUX_ACK_BAD_TOKEN >&2; exit 78; }}\n",
            "case \"$token_proof\" in *[!0-9a-f]*) echo AGENTAPP_TMUX_ACK_BAD_TOKEN >&2; exit 78 ;; esac\n",
            "root=\"$base/$process_id\"\n",
            "session=agentapp_{agent_id}\n",
            "expected_window=\"p_$process_id\"\n",
            "watchdog_window=\"w_$process_id\"\n",
            "tombstone=\"$base/.acknowledged-$process_id-{acknowledgement_key}\"\n",
            "legacy_tombstone=\"$base/.acknowledged-$process_id-{legacy_acknowledgement_key}\"\n",
            "agentapp_ack_probe_process_group() {{\n",
            "  probe_state=unknown\n",
            "  [ -x /bin/kill ] || return\n",
            "  if /bin/kill -0 -- \"-$1\" 2>/dev/null; then probe_state=alive; return; fi\n",
            "  if kill_error=$(LC_ALL=C /bin/kill -0 -- \"-$1\" 2>&1); then probe_state=alive; return; fi\n",
            "  case \"$kill_error\" in *\"No such process\"*) probe_state=dead ;; esac\n",
            "}}\n",
            "agentapp_ack_preflight_root() {{\n",
            "  for entry in \"$root\"/* \"$root\"/.[!.]* \"$root\"/..?*; do\n",
            "    [ -e \"$entry\" ] || continue\n",
            "    name=${{entry##*/}}\n",
            "    case \"$name\" in command.sh|watchdog.sh|output|stdin|go|go.tmp|release|status|status.tmp|state|state.tmp|owner|identity|thread-id|turn-id|call-id|attempt-generation|session-id|tty|acknowledgement-token|digest|window|process-identity|process-identity.tmp|controller|controller.tmp|lease|lease.tmp|lease-generation|lease-generation.tmp|recovery-required|recovery-required.tmp|transition-claim|terminal-claim|.transition-candidate.*|transition-claim.quarantine.*) ;; stdin-write-*.claim|stdin-write-*.result|.stdin-write-*) [ -f \"$entry\" ] && [ ! -L \"$entry\" ] || {{ echo AGENTAPP_TMUX_ACK_UNEXPECTED_STDIN_ENTRY >&2; exit 78; }} ;; proof-key|.proof-candidate.*) [ \"$root\" = \"$legacy_tombstone\" ] || {{ echo AGENTAPP_TMUX_ACK_UNEXPECTED_ENTRY >&2; exit 78; }} ;; *) echo AGENTAPP_TMUX_ACK_UNEXPECTED_ENTRY >&2; exit 78 ;; esac\n",
            "  done\n",
            "  if [ -d \"$root/terminal-claim\" ]; then\n",
            "    for terminal_entry in \"$root/terminal-claim\"/* \"$root/terminal-claim\"/.[!.]* \"$root/terminal-claim\"/..?*; do\n",
            "      [ -e \"$terminal_entry\" ] || continue\n",
            "      [ \"${{terminal_entry##*/}}\" = kind ] || {{ echo AGENTAPP_TMUX_ACK_UNEXPECTED_TERMINAL_ENTRY >&2; exit 78; }}\n",
            "    done\n",
            "  fi\n",
            "}}\n",
            "agentapp_sha256_stdin() {{\n",
            "  if command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{{print $1}}'; return; fi\n",
            "  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{{print $1}}'; return; fi\n",
            "  echo AGENTAPP_TMUX_ACK_SHA256_UNAVAILABLE >&2; exit 77\n",
            "}}\n",
            "agentapp_cleanup_ack_tombstone() {{\n",
            "  agentapp_ack_preflight_root\n",
            "  rm -f \"$root/command.sh\" \"$root/watchdog.sh\" \"$root/output\" \"$root/stdin\" \"$root/go\" \"$root/go.tmp\" \"$root/release\" \"$root/status\" \"$root/status.tmp\" \"$root/state\" \"$root/state.tmp\" \"$root/owner\" \"$root/identity\" \"$root/thread-id\" \"$root/turn-id\" \"$root/call-id\" \"$root/attempt-generation\" \"$root/session-id\" \"$root/tty\" \"$root/acknowledgement-token\" \"$root/digest\" \"$root/window\" \"$root/process-identity\" \"$root/process-identity.tmp\" \"$root/controller\" \"$root/controller.tmp\" \"$root/lease\" \"$root/lease.tmp\" \"$root/lease-generation\" \"$root/lease-generation.tmp\" \"$root/recovery-required\" \"$root/recovery-required.tmp\" \"$root/terminal-claim/kind\"\n",
            "  rmdir \"$root/terminal-claim\" 2>/dev/null || true\n",
            "  rm -f \"$root\"/transition-claim.quarantine.*\n",
            "  rm -f \"$root/transition-claim\" \"$root\"/.transition-candidate.*\n",
            "  rm -f \"$root\"/.proof-candidate.*\n",
            "  rm -f \"$root\"/stdin-write-*.claim \"$root\"/stdin-write-*.result \"$root\"/.stdin-write-*\n",
            "}}\n",
            "if [ -e \"$tombstone\" ]; then\n",
            "  [ -d \"$tombstone\" ] && [ ! -e \"$root\" ] || {{ echo AGENTAPP_TMUX_ACK_TOMBSTONE_CONFLICT >&2; exit 78; }}\n",
            "  root=\"$tombstone\"\n",
            "  agentapp_cleanup_ack_tombstone\n",
            "  exit 0\n",
            "fi\n",
            "if [ -e \"$legacy_tombstone\" ]; then\n",
            "  [ -d \"$legacy_tombstone\" ] && [ ! -e \"$root\" ] || {{ echo AGENTAPP_TMUX_ACK_TOMBSTONE_CONFLICT >&2; exit 78; }}\n",
            "  root=\"$legacy_tombstone\"\n",
            "  agentapp_ack_preflight_root\n",
            "  legacy_proof_candidate=\"$root/.proof-candidate.{acknowledgement_key}.$$\"\n",
            "  if [ ! -e \"$root/proof-key\" ]; then\n",
            "    rm -f \"$legacy_proof_candidate\"\n",
            "    ( umask 077; set -C; printf '%s\\n' {acknowledgement_key} > \"$legacy_proof_candidate\" ) || {{ echo AGENTAPP_TMUX_ACK_TOMBSTONE_PROOF_CONFLICT >&2; exit 78; }}\n",
            "    ln \"$legacy_proof_candidate\" \"$root/proof-key\" 2>/dev/null || true\n",
            "    rm -f \"$legacy_proof_candidate\"\n",
            "  fi\n",
            "  [ \"$(cat \"$root/proof-key\" 2>/dev/null || true)\" = {acknowledgement_key} ] || {{ echo AGENTAPP_TMUX_ACK_TOMBSTONE_PROOF_CONFLICT >&2; exit 78; }}\n",
            "  agentapp_cleanup_ack_tombstone\n",
            "  exit 0\n",
            "fi\n",
            "agentapp_ack_windows() {{\n",
            "  command_window_present=0\n",
            "  watchdog_window_present=0\n",
            "  if window_listing=$(LC_ALL=C tmux list-windows -t \"$session:\" -F '#{{window_name}}' 2>&1); then\n",
            "    if printf '%s\\n' \"$window_listing\" | grep -Fqx \"$expected_window\"; then command_window_present=1; fi\n",
            "    if printf '%s\\n' \"$window_listing\" | grep -Fqx \"$watchdog_window\"; then watchdog_window_present=1; fi\n",
            "  else\n",
            "    case \"$window_listing\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) ;; *) echo AGENTAPP_TMUX_ACK_WINDOW_QUERY_FAILED >&2; exit 77 ;; esac\n",
            "  fi\n",
            "}}\n",
            "agentapp_ack_terminal_proof() {{\n",
            "  [ -d \"$root\" ] || {{ echo AGENTAPP_TMUX_ACK_UNKNOWN >&2; exit 78; }}\n",
            "  [ \"$(cat \"$root/acknowledgement-token\" 2>/dev/null || true)\" = \"$token\" ] || {{ echo AGENTAPP_TMUX_ACK_CHANGED >&2; exit 78; }}\n",
            "  [ \"$(cat \"$root/owner\" 2>/dev/null || true)\" = {owner} ] || {{ echo AGENTAPP_TMUX_ACK_UNOWNED >&2; exit 78; }}\n",
            "  state=$(cat \"$root/state\" 2>/dev/null || true)\n",
            "  case \"$state\" in completed|terminated|recovery-lost|launch-interrupted) ;; *) echo AGENTAPP_TMUX_ACK_NONTERMINAL >&2; exit 78 ;; esac\n",
            "  [ \"$state\" = \"$expected_terminal_state\" ] || {{ echo AGENTAPP_TMUX_ACK_TERMINAL_STATUS_CHANGED >&2; exit 78; }}\n",
            "  code=$(cat \"$root/status\" 2>/dev/null || printf '-')\n",
            "  [ \"$code\" = \"$expected_exit_code\" ] || {{ echo AGENTAPP_TMUX_ACK_EXIT_STATUS_CHANGED >&2; exit 78; }}\n",
            "  [ -r \"$root/output\" ] || {{ echo AGENTAPP_TMUX_ACK_OUTPUT_UNREADABLE >&2; exit 78; }}\n",
            "  output_size=$(wc -c < \"$root/output\" 2>/dev/null || printf '0'); output_size=$(printf '%s' \"$output_size\" | tr -d ' ')\n",
            "  [ \"$output_size\" -eq \"$expected_range_end\" ] || {{ echo AGENTAPP_TMUX_ACK_OUTPUT_LENGTH_CHANGED >&2; exit 78; }}\n",
            "  range_len=$((expected_range_end - expected_range_start))\n",
            "  if [ \"$range_len\" -eq 0 ]; then observed_output_sha256=$(printf '' | agentapp_sha256_stdin); else observed_output_sha256=$(tail -c +$((expected_range_start + 1)) \"$root/output\" | head -c \"$range_len\" | agentapp_sha256_stdin); fi\n",
            "  [ \"$observed_output_sha256\" = \"$expected_output_sha256\" ] || {{ echo AGENTAPP_TMUX_ACK_OUTPUT_DIGEST_CHANGED >&2; exit 78; }}\n",
            "  terminal_claim_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
            "  [ \"$terminal_claim_kind\" = \"$state\" ] || {{ echo AGENTAPP_TMUX_ACK_TERMINAL_CLAIM_MISMATCH >&2; exit 78; }}\n",
            "  target=$(cat \"$root/window\" 2>/dev/null || true)\n",
            "  [ \"$target\" = \"$expected_window\" ] || {{ echo AGENTAPP_TMUX_ACK_TARGET_MISMATCH >&2; exit 78; }}\n",
            "  pane_pid=-\n",
            "  pgid=-\n",
            "  process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
            "  if [ -n \"$process_identity\" ]; then\n",
            "    pane_pid=${{process_identity%%:*}}\n",
            "    pgid=${{process_identity#*:}}\n",
            "    case \"$pane_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_ACK_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "    case \"$pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_ACK_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "    agentapp_ack_probe_process_group \"$pgid\"\n",
            "    case \"$probe_state\" in dead) ;; alive) echo AGENTAPP_TMUX_ACK_PROCESS_GROUP_ALIVE >&2; exit 81 ;; *) echo AGENTAPP_TMUX_ACK_PROCESS_QUERY_UNCERTAIN >&2; exit 80 ;; esac\n",
            "  fi\n",
            "  agentapp_ack_windows\n",
            "  [ \"$command_window_present\" -eq 0 ] || {{ echo AGENTAPP_TMUX_ACK_TARGET_PRESENT >&2; exit 78; }}\n",
            "}}\n",
            "agentapp_ack_terminal_proof\n",
            "if [ -e \"$root/transition-claim\" ]; then\n",
            "  existing_claim=$(cat \"$root/transition-claim\" 2>/dev/null || true)\n",
            "  old_ifs=$IFS\n",
            "  IFS='|'\n",
            "  read claim_kind claim_nonce claim_controller claim_operation_pid claim_operation_pgid claim_window claim_pane claim_pgid <<AGENTAPP_TRANSITION_EOF\n",
            "$existing_claim\n",
            "AGENTAPP_TRANSITION_EOF\n",
            "  IFS=$old_ifs\n",
            "  case \"$claim_kind\" in bootstrap|recovery|adoption|acknowledgement) ;; *) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "  case \"$claim_nonce\" in ''|*[!0-9a-zA-Z_.-]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "  claim_generation=${{claim_controller%%:*}}\n",
            "  claim_controller_id=${{claim_controller#*:}}\n",
            "  case \"$claim_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "  [ -n \"$claim_controller_id\" ] && [ \"$claim_controller_id\" != \"$claim_controller\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
            "  current_controller=$(cat \"$root/controller\" 2>/dev/null || true)\n",
            "  current_generation=${{current_controller%%:*}}\n",
            "  case \"$current_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_CONTROLLER_GENERATION_UNKNOWN >&2; exit 80 ;; esac\n",
            "  case \"$claim_kind\" in adoption) if [ \"$claim_controller\" != \"$current_controller\" ]; then [ \"$claim_generation\" -eq $((current_generation + 1)) ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}; fi ;; *) [ \"$claim_controller\" = \"$current_controller\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }} ;; esac\n",
            "  case \"$claim_operation_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "  case \"$claim_operation_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "  [ \"$claim_window\" = \"$expected_window\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
            "  live_operation_pgid=$(ps -o pgid= -p \"$claim_operation_pid\" 2>/dev/null | tr -d ' ')\n",
            "  [ \"$live_operation_pgid\" != \"$claim_operation_pgid\" ] || {{ echo AGENTAPP_TMUX_ACK_BUSY >&2; exit 79; }}\n",
            "  agentapp_ack_probe_process_group \"$claim_operation_pgid\"\n",
            "  case \"$probe_state\" in dead) ;; alive) echo AGENTAPP_TMUX_ACK_BUSY >&2; exit 79 ;; *) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "  if [ \"$claim_pane:$claim_pgid\" != -:- ]; then\n",
            "    case \"$claim_pane\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "    case \"$claim_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
            "    [ \"$claim_pane\" = \"$pane_pid\" ] && [ \"$claim_pgid\" = \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
            "  fi\n",
            "  [ \"$claim_operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
            "  agentapp_ack_terminal_proof\n",
            "  [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$existing_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "  quarantine=\"$root/transition-claim.quarantine.$claim_nonce\"\n",
            "  [ ! -e \"$quarantine\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_QUARANTINE_CONFLICT >&2; exit 79; }}\n",
            "  mv \"$root/transition-claim\" \"$quarantine\"\n",
            "fi\n",
            "agentapp_ack_terminal_proof\n",
            "if [ \"$watchdog_window_present\" -eq 1 ]; then tmux kill-window -t \"$session:$watchdog_window\" 2>/dev/null || true; fi\n",
            "for stdin_claim in \"$root\"/stdin-write-*.claim; do\n",
            "  [ -e \"$stdin_claim\" ] || continue\n",
            "  stdin_name=${{stdin_claim##*/}}\n",
            "  stdin_key=${{stdin_name#stdin-write-}}; stdin_key=${{stdin_key%.claim}}\n",
            "  [ \"${{#stdin_key}}\" -eq 64 ] || {{ echo AGENTAPP_TMUX_ACK_STDIN_KEY_MALFORMED >&2; exit 78; }}\n",
            "  case \"$stdin_key\" in *[!0-9a-f]*) echo AGENTAPP_TMUX_ACK_STDIN_KEY_MALFORMED >&2; exit 78 ;; esac\n",
            "  tmux delete-buffer -b \"agentapp_${{process_id}}_$stdin_key\" 2>/dev/null || true\n",
            "done\n",
            "agentapp_ack_windows\n",
            "[ \"$command_window_present\" -eq 0 ] && [ \"$watchdog_window_present\" -eq 0 ] || {{ echo AGENTAPP_TMUX_ACK_WINDOW_PRESENT >&2; exit 78; }}\n",
            "agentapp_ack_preflight_root\n",
            "[ \"$(cat \"$root/acknowledgement-token\" 2>/dev/null || true)\" = \"$token\" ] || {{ echo AGENTAPP_TMUX_ACK_CHANGED >&2; exit 78; }}\n",
            "[ ! -e \"$tombstone\" ] || {{ echo AGENTAPP_TMUX_ACK_TOMBSTONE_CONFLICT >&2; exit 78; }}\n",
            "observed=$(cat \"$root/controller\" 2>/dev/null || true)\n",
            "observed_generation=${{observed%%:*}}\n",
            "observed_controller_id=${{observed#*:}}\n",
            "case \"$observed_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_CONTROLLER_GENERATION_UNKNOWN >&2; exit 80 ;; esac\n",
            "[ -n \"$observed_controller_id\" ] && [ \"$observed_controller_id\" != \"$observed\" ] || {{ echo AGENTAPP_TMUX_CONTROLLER_UNKNOWN >&2; exit 80; }}\n",
            "operation_pid=$$\n",
            "operation_pgid=$(ps -o pgid= -p \"$operation_pid\" 2>/dev/null | tr -d ' ')\n",
            "case \"$operation_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "case \"$operation_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "[ \"$operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80; }}\n",
            "transition_candidate=\"$root/.transition-candidate.k_{acknowledgement_key}.$$\"\n",
            "[ ! -e \"$transition_candidate\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CANDIDATE_CONFLICT >&2; exit 79; }}\n",
            "( umask 077; set -C; printf 'acknowledgement|k_{acknowledgement_key}|%s|%s|%s|%s|%s|%s\\n' \"$observed\" \"$operation_pid\" \"$operation_pgid\" \"$expected_window\" \"$pane_pid\" \"$pgid\" > \"$transition_candidate\" ) || {{ echo AGENTAPP_TMUX_TRANSITION_CANDIDATE_CONFLICT >&2; exit 79; }}\n",
            "ln \"$transition_candidate\" \"$root/transition-claim\" 2>/dev/null || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_ACK_BUSY >&2; exit 79; }}\n",
            "release_ack_claim() {{ if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; }}\n",
            "interrupt_ack_claim() {{ signal_status=$1; trap - EXIT HUP INT TERM; release_ack_claim; exit \"$signal_status\"; }}\n",
            "trap 'release_ack_claim' EXIT\n",
            "trap 'interrupt_ack_claim 129' HUP\n",
            "trap 'interrupt_ack_claim 130' INT\n",
            "trap 'interrupt_ack_claim 143' TERM\n",
            // All filesystem-, process-, output-, and tmux-bound proof is
            // complete before the claim. Once claimed, keep the atomic commit
            // window to local scalar checks plus one rename so loss of the SSH
            // control channel cannot repeatedly strand the turn at this point.
            "[ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$observed\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "[ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"acknowledgement|k_{acknowledgement_key}|$observed|$operation_pid|$operation_pgid|$expected_window|$pane_pid|$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "[ \"$(cat \"$root/acknowledgement-token\" 2>/dev/null || true)\" = \"$token\" ] || {{ echo AGENTAPP_TMUX_ACK_CHANGED >&2; exit 78; }}\n",
            "[ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
            "candidate_name=${{transition_candidate##*/}}\n",
            "mv \"$root\" \"$tombstone\"\n",
            "root=\"$tombstone\"\n",
            "transition_candidate=\"$root/$candidate_name\"\n",
            "agentapp_cleanup_ack_tombstone\n",
            "trap - EXIT HUP INT TERM\n",
            "exit 0\n"
        ),
        agent_id = agent_id,
        token = shell_quote(acknowledgement.as_str()),
        owner = shell_quote(OWNERSHIP_MARKER),
        acknowledgement_key = acknowledgement_key,
        legacy_acknowledgement_key = legacy_acknowledgement_key,
        expected_range_start = shell_quote(&expected_range_start),
        expected_range_end = shell_quote(&expected_range_end),
        expected_output_sha256 = shell_quote(&expected_output_sha256),
        expected_state = shell_quote(&expected_state),
        expected_exit_code = shell_quote(&expected_exit_code),
    )
}

fn acknowledgement_release_command(
    agent_key: &str,
    acknowledgement: &RecoveredExecutionAcknowledgement,
) -> String {
    let agent_id = stable_identifier(agent_key);
    let (acknowledgement_key, legacy_acknowledgement_key) = acknowledgement_keys(acknowledgement);
    format!(
        concat!(
            "set -eu\n",
            "setopt nonomatch 2>/dev/null || true\n",
            "base=\"$HOME/.agentapp/tmux/{agent_id}\"\n",
            "token={token}\n",
            "process_id=${{token%%-*}}\n",
            "case \"$process_id\" in ''|*[!0-9a-f]*) echo AGENTAPP_TMUX_RELEASE_BAD_TOKEN >&2; exit 78 ;; esac\n",
            "[ \"${{#process_id}}\" -eq 16 ] || {{ echo AGENTAPP_TMUX_RELEASE_BAD_TOKEN >&2; exit 78; }}\n",
            "token_proof=${{token#*-}}\n",
            "[ \"$token\" = \"$process_id-$token_proof\" ] && [ \"${{#token_proof}}\" -eq 64 ] || {{ echo AGENTAPP_TMUX_RELEASE_BAD_TOKEN >&2; exit 78; }}\n",
            "case \"$token_proof\" in *[!0-9a-f]*) echo AGENTAPP_TMUX_RELEASE_BAD_TOKEN >&2; exit 78 ;; esac\n",
            "root=\"$base/$process_id\"\n",
            "tombstone=\"$base/.acknowledged-$process_id-{acknowledgement_key}\"\n",
            "legacy_tombstone=\"$base/.acknowledged-$process_id-{legacy_acknowledgement_key}\"\n",
            "[ ! -e \"$root\" ] || {{ echo AGENTAPP_TMUX_RELEASE_LIVE_ROOT_PRESENT >&2; exit 78; }}\n",
            "if [ -e \"$tombstone\" ] && [ -e \"$legacy_tombstone\" ]; then echo AGENTAPP_TMUX_RELEASE_TOMBSTONE_CONFLICT >&2; exit 78; fi\n",
            "if [ -e \"$tombstone\" ]; then\n",
            "  [ -d \"$tombstone\" ] && [ ! -L \"$tombstone\" ] || {{ echo AGENTAPP_TMUX_RELEASE_TOMBSTONE_CONFLICT >&2; exit 78; }}\n",
            "  for entry in \"$tombstone\"/* \"$tombstone\"/.[!.]* \"$tombstone\"/..?*; do [ ! -e \"$entry\" ] || {{ echo AGENTAPP_TMUX_RELEASE_UNEXPECTED_ENTRY >&2; exit 78; }}; done\n",
            "  rmdir \"$tombstone\"\n",
            "  exit 0\n",
            "fi\n",
            "if [ -e \"$legacy_tombstone\" ]; then\n",
            "  [ -d \"$legacy_tombstone\" ] && [ ! -L \"$legacy_tombstone\" ] || {{ echo AGENTAPP_TMUX_RELEASE_TOMBSTONE_CONFLICT >&2; exit 78; }}\n",
            "  [ -f \"$legacy_tombstone/proof-key\" ] && [ ! -L \"$legacy_tombstone/proof-key\" ] || {{ echo AGENTAPP_TMUX_RELEASE_PROOF_MISSING >&2; exit 78; }}\n",
            "  [ \"$(cat \"$legacy_tombstone/proof-key\" 2>/dev/null || true)\" = {acknowledgement_key} ] || {{ echo AGENTAPP_TMUX_RELEASE_PROOF_CONFLICT >&2; exit 78; }}\n",
            "  for entry in \"$legacy_tombstone\"/* \"$legacy_tombstone\"/.[!.]* \"$legacy_tombstone\"/..?*; do\n",
            "    [ -e \"$entry\" ] || continue\n",
            "    [ \"${{entry##*/}}\" = proof-key ] || {{ echo AGENTAPP_TMUX_RELEASE_UNEXPECTED_ENTRY >&2; exit 78; }}\n",
            "  done\n",
            "  rm -f \"$legacy_tombstone/proof-key\"\n",
            "  rmdir \"$legacy_tombstone\"\n",
            "fi\n",
            "exit 0\n"
        ),
        agent_id = agent_id,
        token = shell_quote(acknowledgement.as_str()),
        acknowledgement_key = acknowledgement_key,
        legacy_acknowledgement_key = legacy_acknowledgement_key,
    )
}

fn parse_recovered_executions(output: &[u8]) -> Result<Vec<RecoveredExecution>, ExecServerError> {
    let recovered = String::from_utf8_lossy(output)
        .lines()
        .filter(|line| !line.is_empty())
        .enumerate()
        .map(|(line_index, line)| {
            let fields = line.splitn(14, ' ').collect::<Vec<_>>();
            if fields.len() != 14 || fields[0] != "AGENTAPP_RECOVERED" {
                return Err(ExecServerError::Protocol(format!(
                    "ssh tmux reconciliation returned malformed data at line {} \
                     (field count {}, marker {})",
                    line_index + 1,
                    fields.len(),
                    fields.first().copied() == Some("AGENTAPP_RECOVERED"),
                )));
            }
            let decode_text = |value: &str| {
                STANDARD
                    .decode(value)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
            };
            let identity = ExecutionIdentity {
                thread_id: decode_text(fields[1]).ok_or_else(|| {
                    ExecServerError::Protocol("invalid recovered thread identity".to_string())
                })?,
                turn_id: decode_text(fields[2]).ok_or_else(|| {
                    ExecServerError::Protocol("invalid recovered turn identity".to_string())
                })?,
                call_id: decode_text(fields[3]).ok_or_else(|| {
                    ExecServerError::Protocol("invalid recovered call identity".to_string())
                })?,
                attempt_generation: fields[4].parse().map_err(|_| {
                    ExecServerError::Protocol("invalid recovered attempt generation".to_string())
                })?,
            };
            let status = match fields[5] {
                "missing" => RecoveredExecutionStatus::Missing,
                "prepared" => RecoveredExecutionStatus::Prepared,
                "launch-interrupted" => RecoveredExecutionStatus::LaunchInterrupted,
                "running" => RecoveredExecutionStatus::Running,
                "completed" => {
                    RecoveredExecutionStatus::Exited(fields[6].parse().map_err(|_| {
                        ExecServerError::Protocol("invalid recovered exit code".to_string())
                    })?)
                }
                "terminated" => RecoveredExecutionStatus::Terminated,
                "recovery-lost" => RecoveredExecutionStatus::RecoveryLost,
                "unknown" => RecoveredExecutionStatus::Unknown,
                _ => {
                    return Err(ExecServerError::Protocol(
                        "invalid recovered execution state".to_string(),
                    ));
                }
            };
            let session_id = match fields[7] {
                "-" => None,
                value => Some(value.parse().map_err(|_| {
                    ExecServerError::Protocol("invalid recovered session id".to_string())
                })?),
            };
            let delivery_unknown = match fields[9] {
                "0" => false,
                "1" => true,
                _ => {
                    return Err(ExecServerError::Protocol(
                        "invalid recovered stdin delivery state".to_string(),
                    ));
                }
            };
            let terminal_verified_dead = match fields[10] {
                "0" => false,
                "1" => true,
                _ => {
                    return Err(ExecServerError::Protocol(
                        "invalid terminal verification state".to_string(),
                    ));
                }
            };
            let command_digest = match fields[12] {
                "-" => None,
                value => Some(value.to_string()),
            };
            let output = if fields[13] == "-" {
                Vec::new()
            } else {
                STANDARD.decode(fields[13]).map_err(|_| {
                    ExecServerError::Protocol("invalid recovered output bytes".to_string())
                })?
            };
            let committed_output_cursor = fields[8].parse().map_err(|_| {
                ExecServerError::Protocol("invalid recovered output cursor".to_string())
            })?;
            if output.len() as u64 != committed_output_cursor {
                return Err(ExecServerError::Protocol(
                    "recovered output length does not match committed cursor".to_string(),
                ));
            }
            Ok(RecoveredExecution {
                identity,
                command_digest,
                output,
                status,
                terminal_verified_dead,
                session_id,
                committed_output_cursor,
                delivery_unknown,
                acknowledgement: RecoveredExecutionAcknowledgement::new(fields[11].to_string()),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut slots = std::collections::HashSet::new();
    for execution in &recovered {
        let slot = (
            execution.identity.thread_id.clone(),
            execution.identity.turn_id.clone(),
            execution.identity.call_id.clone(),
            execution.identity.attempt_generation,
        );
        if !slots.insert(slot) {
            return Err(ExecServerError::Protocol(
                "ssh tmux reconciliation returned duplicate descriptor slot".to_string(),
            ));
        }
    }
    Ok(recovered)
}

fn interrupt_outcome_from_control_result(
    exit_code: i32,
    output: &[u8],
) -> Result<ProcessSignalOutcome, ExecServerError> {
    if exit_code == 0 {
        return Ok(ProcessSignalOutcome::Accepted);
    }
    let diagnostic = String::from_utf8_lossy(output);
    if exit_code == 80 && diagnostic.trim() == "AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH" {
        return Ok(ProcessSignalOutcome::RejectedBeforeDelivery(
            ProcessSignalRejectionReason::OwnershipMismatch,
        ));
    }
    Err(ExecServerError::Protocol(format!(
        "ssh tmux interrupt failed with exit {exit_code}: {}",
        diagnostic.trim()
    )))
}

fn stable_identifier(value: &str) -> String {
    // FNV-1a is deterministic across launches and sufficient for short remote
    // resource names. This is an identifier, not a security boundary.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
#[path = "ssh_tmux_tests.rs"]
mod tests;
