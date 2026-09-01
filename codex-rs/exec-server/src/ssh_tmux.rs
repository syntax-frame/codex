//! tmux-backed process continuity for SSH server-mode agents.
//!
//! Every running tool process owns one tmux session. Durable execution state
//! lives outside tmux, so a terminal process can release all runtime resources
//! while its output and acknowledgement proof remain recoverable. Live output
//! is mirrored to a remote log. If the SSH transport drops, the monitor
//! reconnects at the last delivered byte while the command continues in tmux.

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
use super::build_remote_command;
use super::publish_closed;
use super::publish_exit;
use super::publish_output_with_absolute_range;
use super::shell_quote;
use super::with_remote_path;

const MONITOR_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);
const TMUX_BOOTSTRAP_ATTEMPTS: usize = 4;
const TMUX_TERMINATE_ATTEMPTS: usize = 3;
const BOOTSTRAP_KEEPER_MAX_SECONDS: u64 = 2 * 60;
// A controller normally refreshes the remote lease every five seconds. Fifteen
// minutes exceeds the bounded reconnect schedule and gives transient mobile
// suspension ample recovery time, while still bounding crash-orphan lifetime.
const CONTROLLER_LEASE_SECONDS: u64 = 15 * 60;
const CONTROLLER_HEARTBEAT_SECONDS: u64 = 5;
const EXECUTION_MAX_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
// A remote monitor is only a transport attachment; the tmux execution owns
// continuity. Periodic reattachment bounds orphaned SSH exec processes when a
// client disappears without closing its channel cleanly.
const MONITOR_ATTACHMENT_SECONDS: u64 = 5 * 60;
const OWNERSHIP_MARKER: &str = "agentapp-tmux-v2";

fn tty_pipe_setup_command(target: &str) -> String {
    format!(
        concat!(
            "pipe_generation=$(cat \"$root/output-pipe-generation\" 2>/dev/null || printf '0')\n",
            "case \"$pipe_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_OUTPUT_PIPE_GENERATION_UNKNOWN >&2; exit 83 ;; esac\n",
            "pipe_generation=$((pipe_generation + 1))\n",
            "printf '%s\\n' \"$pipe_generation\" > \"$root/output-pipe-generation.tmp\"\n",
            "mv \"$root/output-pipe-generation.tmp\" \"$root/output-pipe-generation\"\n",
            "tmux pipe-pane -O -t {target} \"if cat >> \\\"$root/output\\\"; then : > \\\"$root/output-closed.$pipe_generation.tmp\\\" && mv \\\"$root/output-closed.$pipe_generation.tmp\\\" \\\"$root/output-closed.$pipe_generation\\\"; fi\""
        ),
        target = target,
    )
}

fn output_drain_function_fragment() -> &'static str {
    concat!(
        "agentapp_wait_for_output_drain() {\n",
        "  [ \"$(cat \"$root/tty\" 2>/dev/null || true)\" = 1 ] || return 0\n",
        "  [ ! -e \"$root/go\" ] && return 0\n",
        "  output_pipe_generation=$(cat \"$root/output-pipe-generation\" 2>/dev/null || true)\n",
        "  if [ -z \"$output_pipe_generation\" ]; then\n",
        "    [ -f \"$root/output-closed\" ] && return 0\n",
        "    echo AGENTAPP_TMUX_OUTPUT_PIPE_GENERATION_UNKNOWN >&2\n",
        "    return 83\n",
        "  fi\n",
        "  case \"$output_pipe_generation\" in *[!0-9]*) echo AGENTAPP_TMUX_OUTPUT_PIPE_GENERATION_UNKNOWN >&2; return 83 ;; esac\n",
        "  output_wait=0\n",
        "  while [ ! -f \"$root/output-closed.$output_pipe_generation\" ] && [ \"$output_wait\" -lt 30 ]; do sleep 1; output_wait=$((output_wait + 1)); done\n",
        "  [ -f \"$root/output-closed.$output_pipe_generation\" ] || { echo AGENTAPP_TMUX_OUTPUT_PIPE_DRAIN_TIMEOUT >&2; return 83; }\n",
        "  return 0\n",
        "}\n"
    )
}

fn orphaned_execution_session_reaper_command() -> String {
    let identifier_pattern = "[0-9a-f]".repeat(16);
    let session_pattern = format!("agentapp_{identifier_pattern}_{identifier_pattern}");
    format!(
        concat!(
            "agentapp_reap_acknowledged_sessions() (\n",
            "  base=\"$HOME/.agentapp/tmux\"\n",
            "  lock=\"$base/.orphan-session-reaper\"\n",
            "  mkdir -p \"$base\"\n",
            "  if [ -d \"$lock\" ] && [ -n \"$(find \"$lock\" -prune -type d -mmin +30 -print 2>/dev/null)\" ]; then rmdir \"$lock\" 2>/dev/null || true; fi\n",
            "  mkdir \"$lock\" 2>/dev/null || exit 0\n",
            "  trap 'rmdir \"$lock\" 2>/dev/null || true' EXIT HUP INT TERM\n",
            "  now=$(date +%s)\n",
            "  case \"$now\" in ''|*[!0-9]*) exit 0 ;; esac\n",
            "  listing=$(tmux list-sessions -F '#{{session_name}}|#{{session_created}}' 2>/dev/null) || exit 0\n",
            "  reaped=0\n",
            "  while IFS='|' read -r candidate created_at; do\n",
            "    [ \"$reaped\" -lt {batch} ] || break\n",
            "    case \"$candidate\" in {session_pattern}) ;; *) continue ;; esac\n",
            "    case \"$created_at\" in ''|*[!0-9]*) continue ;; esac\n",
            "    [ \"$now\" -ge \"$created_at\" ] || continue\n",
            "    [ $((now - created_at)) -ge {max_lifetime} ] || continue\n",
            "    suffix=${{candidate#agentapp_}}\n",
            "    orphan_agent=${{suffix%%_*}}\n",
            "    orphan_process=${{suffix#*_}}\n",
            "    root=\"$base/$orphan_agent/$orphan_process\"\n",
            "    {{ [ ! -e \"$root\" ] && [ ! -L \"$root\" ]; }} || continue\n",
            "    panes=$(tmux list-panes -s -t \"$candidate\" -F '#{{window_name}}|#{{window_id}}|#{{pane_id}}|#{{pane_dead}}' 2>/dev/null) || continue\n",
            "    valid=1\n",
            "    pane_count=0\n",
            "    window_ids=\n",
            "    while IFS='|' read -r orphan_window orphan_window_id orphan_pane_id orphan_dead; do\n",
            "      pane_count=$((pane_count + 1))\n",
            "      case \"$orphan_window\" in \"p_$orphan_process\"|\"w_$orphan_process\"|__agentapp_keeper) ;; *) valid=0 ;; esac\n",
            "      case \"$orphan_window_id\" in @*[!0-9]*|@) valid=0 ;; @*) ;; *) valid=0 ;; esac\n",
            "      case \"$orphan_pane_id\" in %*[!0-9]*|%) valid=0 ;; %*) ;; *) valid=0 ;; esac\n",
            "      [ \"$orphan_dead\" = 1 ] || valid=0\n",
            "      window_ids=\"$window_ids $orphan_window_id\"\n",
            "    done <<AGENTAPP_ORPHAN_PANES_EOF\n",
            "$panes\n",
            "AGENTAPP_ORPHAN_PANES_EOF\n",
            "    [ \"$valid\" -eq 1 ] && [ \"$pane_count\" -gt 0 ] || continue\n",
            "    for orphan_window_id in $window_ids; do tmux kill-window -t \"$orphan_window_id\" 2>/dev/null || true; done\n",
            "    tmux has-session -t \"$candidate\" 2>/dev/null && continue\n",
            "    reaped=$((reaped + 1))\n",
            "  done <<AGENTAPP_ORPHAN_SESSIONS_EOF\n",
            "$listing\n",
            "AGENTAPP_ORPHAN_SESSIONS_EOF\n",
            "  exit 0\n",
            ")\n",
            "agentapp_reap_acknowledged_sessions || true\n"
        ),
        batch = ORPHANED_SESSION_REAPER_BATCH,
        max_lifetime = EXECUTION_MAX_LIFETIME_SECONDS,
        session_pattern = session_pattern,
    )
}

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
                let ready = output.lines().find_map(|line| {
                    let mut fields = line
                        .strip_prefix("AGENTAPP_TMUX_READY ")?
                        .split_whitespace();
                    let target = fields.next()?;
                    let controller = fields.next()?;
                    fields.next().is_none().then_some((target, controller))
                });
                let Some((target, controller)) = ready else {
                    return Err(ExecServerError::Protocol(
                        "ssh tmux bootstrap omitted fenced controller identity".to_string(),
                    ));
                };
                let target_suffix = format!(":{}.0", descriptor.window_name);
                let session = target.strip_suffix(&target_suffix).ok_or_else(|| {
                    ExecServerError::Protocol(
                        "ssh tmux bootstrap reported an incompatible target".to_string(),
                    )
                })?;
                descriptor.apply_reported_session(session)?;
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
    let adopted = output
        .lines()
        .find_map(|line| {
            let mut fields = line
                .strip_prefix("AGENTAPP_TMUX_ADOPTED ")?
                .split_whitespace();
            let controller = fields.next()?;
            let session = fields.next()?;
            fields.next().is_none().then_some((controller, session))
        })
        .ok_or_else(|| {
            ExecServerError::Protocol(
                "ssh tmux adoption omitted fenced controller identity".to_string(),
            )
        })?;
    descriptor.apply_reported_session(adopted.1)?;
    descriptor.controller_id = adopted.0.to_string();

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
                        publish_closed(&state, &events, &wake_tx, &output_notify);
                        return;
                    }
                    Ok(MonitorExitClassification::ChannelLost) | Err(_) => {
                        match descriptor.recover_dead_execution(backend.transport()).await {
                            Ok(Some(exit_code)) => break 'monitor exit_code,
                            Ok(None) => break,
                            Err(error) => {
                                tracing::debug!(
                                    session_key = %backend.session_key(),
                                    error = %error,
                                    "tmux monitor could not reconcile a possible dead command pane"
                                );
                                break;
                            }
                        }
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
            session_name: execution_session_name(&agent_id, &process_id),
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
            session_name: execution_session_name(&agent_id, &process_id),
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

    fn apply_reported_session(&mut self, reported_session: &str) -> Result<(), ExecServerError> {
        let legacy_session = legacy_session_name(&self.agent_id);
        if reported_session != self.session_name && reported_session != legacy_session {
            return Err(ExecServerError::Protocol(
                "ssh tmux reported an incompatible execution session".to_string(),
            ));
        }
        self.session_name = reported_session.to_string();
        Ok(())
    }

    fn adoption_command(&self) -> String {
        let root = self.remote_directory();
        let adoption_key = stable_identifier(&format!(
            "{}:{}:adoption",
            self.process_id, self.controller_id
        ));
        let pipe_setup = if self.tty {
            tty_pipe_setup_command("\"$expected_session:$expected_window.0\"")
        } else {
            ":".to_string()
        };
        format!(
            concat!(
                "set -eu\n",
                "root=\"{root}\"\n",
                "default_session={session}\n",
                "legacy_session={legacy_session}\n",
                "stored_session=$(cat \"$root/session\" 2>/dev/null || true)\n",
                "if [ -z \"$stored_session\" ]; then expected_session=$legacy_session; elif [ \"$stored_session\" = \"$default_session\" ] || [ \"$stored_session\" = \"$legacy_session\" ]; then expected_session=$stored_session; else echo AGENTAPP_TMUX_ADOPT_SESSION_MISMATCH >&2; exit 77; fi\n",
                "expected_window={window}\n",
                "session=$expected_session\n",
                "window=$expected_window\n",
                "watchdog_window={watchdog_window}\n",
                "candidate_controller={candidate}\n",
                "{output_drain_function}",
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
                "  case \"$adopt_state\" in prepared|running) ;; *) echo AGENTAPP_TMUX_ADOPT_NOT_RUNNING >&2; exit 78 ;; esac\n",
                "  [ ! -f \"$root/status\" ] || {{ echo AGENTAPP_TMUX_ADOPT_TERMINAL >&2; exit 78; }}\n",
                "  process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
                "  pane_pid=${{process_identity%%:*}}\n",
                "  pgid=${{process_identity#*:}}\n",
                "  case \"$pane_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_ADOPT_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  case \"$pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_ADOPT_PROCESS_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  stored_window_id=$(cat \"$root/window-id\" 2>/dev/null || true)\n",
                "  stored_pane_id=$(cat \"$root/pane-id\" 2>/dev/null || true)\n",
                "  {{ [ -n \"$stored_window_id\" ] && [ -n \"$stored_pane_id\" ]; }} || {{ [ -z \"$stored_window_id\" ] && [ -z \"$stored_pane_id\" ]; }} || {{ echo AGENTAPP_TMUX_ADOPT_PROCESS_IDENTITY_UNKNOWN >&2; exit 80; }}\n",
                "  if window_listing=$(LC_ALL=C tmux list-windows -t \"$expected_session:\" -F '#{{window_name}}' 2>&1); then\n",
                "    printf '%s\\n' \"$window_listing\" | grep -Fqx \"$expected_window\" || {{ echo AGENTAPP_TMUX_ADOPT_WINDOW_MISSING >&2; exit 80; }}\n",
                "  else\n",
                "    case \"$window_listing\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) echo AGENTAPP_TMUX_ADOPT_WINDOW_MISSING >&2; exit 80 ;; *) echo AGENTAPP_TMUX_ADOPT_WINDOW_QUERY_FAILED >&2; exit 77 ;; esac\n",
                "  fi\n",
                "  [ \"$(tmux list-panes -t \"$expected_session:$expected_window\" -F '#{{pane_id}}' 2>/dev/null | wc -l | tr -d ' ')\" = 1 ] || {{ echo AGENTAPP_TMUX_ADOPT_OWNERSHIP_MISMATCH >&2; exit 80; }}\n",
                "  current_identity=$(tmux display-message -p -t \"$expected_session:$expected_window.0\" '#{{window_id}}:#{{pane_id}}:#{{pane_pid}}:#{{pane_dead}}' 2>/dev/null || true)\n",
                "  old_ifs=$IFS; IFS=:; set -- $current_identity; IFS=$old_ifs\n",
                "  [ \"$#\" -eq 4 ] || {{ echo AGENTAPP_TMUX_ADOPT_PROCESS_IDENTITY_UNKNOWN >&2; exit 80; }}\n",
                "  current_window_id=$1; current_pane_id=$2; current_pane=$3; current_pane_dead=$4\n",
                "  if [ -n \"$stored_window_id\" ]; then [ \"$stored_window_id:$stored_pane_id\" = \"$current_window_id:$current_pane_id\" ] || {{ echo AGENTAPP_TMUX_ADOPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; fi\n",
                "  current_pgid=$(ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' ')\n",
                "  [ \"$current_pane_dead\" = 0 ] && [ \"$current_pane\" = \"$pane_pid\" ] && [ \"$current_pgid\" = \"$pgid\" ] && kill -0 \"-$pgid\" 2>/dev/null || {{ echo AGENTAPP_TMUX_ADOPT_OWNERSHIP_MISMATCH >&2; exit 80; }}\n",
                "}}\n",
                "agentapp_adopt_authority\n",
                "agentapp_adopt_live_pane\n",
                "roll_forward_launch=0\n",
                "resume_stale_termination=0\n",
                "if [ -e \"$root/transition-claim\" ]; then\n",
                "  claim_line=$(cat \"$root/transition-claim\" 2>/dev/null || true)\n",
                "  old_ifs=$IFS\n",
                "  IFS='|'\n",
                "  read claim_kind claim_nonce claim_controller claim_operation_pid claim_operation_pgid claim_window claim_pane claim_pgid <<AGENTAPP_TRANSITION_EOF\n",
                "$claim_line\n",
                "AGENTAPP_TRANSITION_EOF\n",
                "  IFS=$old_ifs\n",
                "  case \"$claim_kind\" in adoption|bootstrap|termination) ;; recovery) echo AGENTAPP_TMUX_ADOPT_RECOVERY_CONFLICT >&2; exit 79 ;; *) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
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
                "      if [ \"$(cat \"$root/state\" 2>/dev/null || true)\" != running ] || [ ! -e \"$root/go\" ] || [ ! -e \"$root/payload-go\" ]; then roll_forward_launch=1; fi\n",
                "      ;;\n",
                "    bootstrap)\n",
                "      {{ [ \"$claim_pane:$claim_pgid\" = -:- ] || {{ [ \"$claim_pane\" = \"$pane_pid\" ] && [ \"$claim_pgid\" = \"$pgid\" ]; }}; }} || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "      current_controller=$(cat \"$root/controller\" 2>/dev/null || true)\n",
                "      current_generation=${{current_controller%%:*}}\n",
                "      case \"$current_generation\" in ''|*[!0-9]*) current_generation=0 ;; esac\n",
                "      {{ [ \"$claim_controller\" = \"$current_controller\" ] || [ \"$claim_generation\" -eq $((current_generation + 1)) ]; }} || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "      if [ \"$claim_controller\" != \"$current_controller\" ]; then\n",
                "        printf '%s\\n' \"$claim_generation\" > \"$root/lease-generation.tmp\"\n",
                "        mv \"$root/lease-generation.tmp\" \"$root/lease-generation\"\n",
                "        printf '%s\\n' \"$claim_controller\" > \"$root/controller.tmp\"\n",
                "        mv \"$root/controller.tmp\" \"$root/controller\"\n",
                "      fi\n",
                "      roll_forward_launch=1\n",
                "      ;;\n",
                "    termination)\n",
                "      [ \"$claim_pane:$claim_pgid\" = \"$pane_pid:$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "      [ \"$claim_controller\" = \"$(cat \"$root/controller\" 2>/dev/null || true)\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "      if [ ! -e \"$root/terminal-claim\" ]; then mkdir \"$root/terminal-claim\" 2>/dev/null || true; fi\n",
                "      [ -d \"$root/terminal-claim\" ] && [ ! -L \"$root/terminal-claim\" ] || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}\n",
                "      terminal_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
                "      [ -z \"$terminal_kind\" ] || [ \"$terminal_kind\" = terminated ] || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}\n",
                "      if [ -z \"$terminal_kind\" ]; then printf 'terminated\\n' > \"$root/terminal-claim/kind.tmp\"; mv \"$root/terminal-claim/kind.tmp\" \"$root/terminal-claim/kind\"; fi\n",
                "      resume_stale_termination=1\n",
                "      ;;\n",
                "  esac\n",
                "  [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$claim_line\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  if [ \"$resume_stale_termination\" -eq 0 ]; then\n",
                "    quarantine=\"$root/transition-claim.quarantine.$claim_nonce\"\n",
                "    [ ! -e \"$quarantine\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_QUARANTINE_CONFLICT >&2; exit 79; }}\n",
                "    mv \"$root/transition-claim\" \"$quarantine\"\n",
                "  fi\n",
                "fi\n",
                "if [ \"$resume_stale_termination\" -eq 1 ]; then\n",
                "  current_controller=$(cat \"$root/controller\" 2>/dev/null || true)\n",
                "  operation_pid=$$\n",
                "  operation_pgid=$(command -p ps -o pgid= -p \"$operation_pid\" 2>/dev/null | tr -d ' ')\n",
                "  case \"$operation_pid:$operation_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  [ \"$operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80; }}\n",
                "  stale_transition_candidate=\"$root/.transition-candidate.$claim_nonce.$claim_operation_pid\"\n",
                "  transition_candidate=\"$root/.transition-candidate.ta_{adoption_key}.$operation_pid\"\n",
                "  expected_termination_claim=\"termination|ta_{adoption_key}|$current_controller|$operation_pid|$operation_pgid|$expected_window|$pane_pid|$pgid\"\n",
                "  ( umask 077; set -C; printf '%s\\n' \"$expected_termination_claim\" > \"$transition_candidate\" ) || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  takeover_arbiter=\"$root/.transition-candidate.takeover.$claim_nonce.$claim_operation_pid\"\n",
                "  takeover_depth=0\n",
                "  while {{ [ -e \"$takeover_arbiter\" ] || [ -L \"$takeover_arbiter\" ]; }}; do\n",
                "    [ -f \"$takeover_arbiter\" ] && [ ! -L \"$takeover_arbiter\" ] || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "    takeover_line=$(cat \"$takeover_arbiter\" 2>/dev/null || true)\n",
                "    old_ifs=$IFS; IFS='|'\n",
                "    read takeover_kind takeover_nonce takeover_controller takeover_operation_pid takeover_operation_pgid takeover_window takeover_pane takeover_pgid <<AGENTAPP_TAKEOVER_EOF\n",
                "$takeover_line\n",
                "AGENTAPP_TAKEOVER_EOF\n",
                "    IFS=$old_ifs\n",
                "    [ \"$takeover_kind\" = termination ] && [ \"$takeover_controller:$takeover_window:$takeover_pane:$takeover_pgid\" = \"$current_controller:$expected_window:$pane_pid:$pgid\" ] || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "    case \"$takeover_nonce\" in ''|*[!0-9a-zA-Z_.-]*) rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79 ;; esac\n",
                "    case \"$takeover_operation_pid:$takeover_operation_pgid\" in :|:*|*:|*[!0-9:]*) rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79 ;; esac\n",
                "    takeover_candidate=\"$root/.transition-candidate.$takeover_nonce.$takeover_operation_pid\"\n",
                "    [ -f \"$takeover_candidate\" ] && [ ! -L \"$takeover_candidate\" ] && [ \"$takeover_candidate\" -ef \"$takeover_arbiter\" ] && [ \"$(cat \"$takeover_candidate\" 2>/dev/null || true)\" = \"$takeover_line\" ] || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "    takeover_live_operation_pgid=$(command -p ps -o pgid= -p \"$takeover_operation_pid\" 2>/dev/null | tr -d ' ')\n",
                "    [ \"$takeover_live_operation_pgid\" != \"$takeover_operation_pgid\" ] || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "    agentapp_adopt_probe_process_group \"$takeover_operation_pgid\"\n",
                "    case \"$probe_state\" in dead) ;; alive) rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79 ;; *) rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "    next_takeover_arbiter=\"$root/.transition-candidate.takeover.$takeover_nonce.$takeover_operation_pid\"\n",
                "    [ \"$next_takeover_arbiter\" != \"$takeover_arbiter\" ] || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "    takeover_depth=$((takeover_depth + 1))\n",
                "    [ \"$takeover_depth\" -le 32 ] || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "    takeover_arbiter=$next_takeover_arbiter\n",
                "  done\n",
                "  ln \"$transition_candidate\" \"$takeover_arbiter\" 2>/dev/null || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  transition_publish=\"$transition_candidate.publish\"\n",
                "  release_termination_claim() {{ if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_termination_claim\" ]; then rm -f \"$root/transition-claim\"; fi; if [ -f \"$transition_candidate\" ] && [ -f \"$takeover_arbiter\" ] && [ \"$transition_candidate\" -ef \"$takeover_arbiter\" ]; then rm -f \"$takeover_arbiter\"; fi; rm -f \"$transition_publish\" \"$transition_candidate\"; }}\n",
                "  trap ':' HUP INT TERM\n",
                "  [ -f \"$stale_transition_candidate\" ] && [ ! -L \"$stale_transition_candidate\" ] && [ \"$stale_transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$claim_line\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  [ -f \"$takeover_arbiter\" ] && [ ! -L \"$takeover_arbiter\" ] && [ \"$transition_candidate\" -ef \"$takeover_arbiter\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  ln \"$transition_candidate\" \"$transition_publish\" 2>/dev/null || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  quarantine=\"$root/transition-claim.quarantine.$claim_nonce.$claim_operation_pid\"\n",
                "  if [ ! -e \"$quarantine\" ]; then\n",
                "    ln \"$root/transition-claim\" \"$quarantine\" 2>/dev/null || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  fi\n",
                "  [ -f \"$quarantine\" ] && [ ! -L \"$quarantine\" ] && [ \"$quarantine\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$quarantine\" 2>/dev/null || true)\" = \"$claim_line\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  mv \"$transition_publish\" \"$root/transition-claim\"\n",
                "  require_termination_claim() {{ [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_termination_claim\" ] && [ -f \"$takeover_arbiter\" ] && [ ! -L \"$takeover_arbiter\" ] && [ \"$transition_candidate\" -ef \"$takeover_arbiter\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}; }}\n",
                "  require_termination_claim\n",
                "  [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$current_controller\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  agentapp_adopt_authority\n",
                "  agentapp_adopt_live_pane\n",
                "  require_termination_claim\n",
                "  [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$current_controller\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  {termination}\n",
                "  require_termination_claim\n",
                "  agentapp_wait_for_output_drain\n",
                "  require_termination_claim\n",
                "  [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$current_controller\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  printf '143\\n' > \"$root/status.tmp\"\n",
                "  mv \"$root/status.tmp\" \"$root/status\"\n",
                "  printf 'terminated\\n' > \"$root/state.tmp\"\n",
                "  mv \"$root/state.tmp\" \"$root/state\"\n",
                "  rm -f \"$root/recovery-required\"\n",
                "  printf 'AGENTAPP_TMUX_ADOPTED %s %s\\n' \"$current_controller\" \"$expected_session\"\n",
                "  release_termination_claim\n",
                "  trap - HUP INT TERM\n",
                "  exit 0\n",
                "fi\n",
                "terminal_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
                "[ -z \"$terminal_kind\" ] || {{ echo AGENTAPP_TMUX_ADOPT_TERMINAL >&2; exit 78; }}\n",
                "if [ \"$roll_forward_launch\" -eq 0 ]; then\n",
                "  [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = running ] && [ -e \"$root/go\" ] && [ -e \"$root/payload-go\" ] || {{ echo AGENTAPP_TMUX_ADOPT_NOT_RUNNING >&2; exit 78; }}\n",
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
                "if [ \"$roll_forward_launch\" -eq 1 ]; then\n",
                "  [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"adoption|a_{adoption_key}|$next|$operation_pid|$operation_pgid|$expected_window|$pane_pid|$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  launch_state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "  {{ [ \"$launch_state\" = prepared ] || [ \"$launch_state\" = running ]; }} && [ ! -f \"$root/status\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
                "  supervisor_wait=0\n",
                "  while [ ! -f \"$root/supervisor-ready\" ] && [ \"$supervisor_wait\" -lt 30 ]; do sleep 1; supervisor_wait=$((supervisor_wait + 1)); done\n",
                "  [ -f \"$root/supervisor-ready\" ] || {{ echo AGENTAPP_TMUX_SUPERVISOR_START_TIMEOUT >&2; exit 80; }}\n",
                "  if [ ! -f \"$root/go\" ]; then {pipe_setup}; fi\n",
                "  if [ ! -f \"$root/payload-go\" ]; then : > \"$root/payload-go.tmp\"; mv \"$root/payload-go.tmp\" \"$root/payload-go\"; fi\n",
                "  if [ \"$launch_state\" != running ]; then printf 'running\\n' > \"$root/state.tmp\"; mv \"$root/state.tmp\" \"$root/state\"; fi\n",
                "  if [ ! -f \"$root/go\" ]; then : > \"$root/go.tmp\"; mv \"$root/go.tmp\" \"$root/go\"; fi\n",
                "  payload_wait=0\n",
                "  while [ ! -f \"$root/payload-ready\" ] && [ ! -f \"$root/status\" ] && [ \"$payload_wait\" -lt 30 ]; do sleep 1; payload_wait=$((payload_wait + 1)); done\n",
                "  [ -f \"$root/payload-ready\" ] || [ -f \"$root/status\" ] || {{ echo AGENTAPP_TMUX_PAYLOAD_START_TIMEOUT >&2; exit 80; }}\n",
                "fi\n",
                "date +%s > \"$root/lease.tmp\"\n",
                "mv \"$root/lease.tmp\" \"$root/lease\"\n",
                "printf 'AGENTAPP_TMUX_ADOPTED %s %s\\n' \"$next\" \"$expected_session\"\n"
            ),
            root = root,
            session = shell_quote(&self.session_name),
            legacy_session = shell_quote(&legacy_session_name(&self.agent_id)),
            window = shell_quote(&self.window_name),
            watchdog_window = shell_quote(&self.watchdog_window_name),
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
            pipe_setup = pipe_setup,
            termination = self.confirmed_process_group_termination(),
            output_drain_function = output_drain_function_fragment(),
        )
    }

    fn agent_directory(&self) -> String {
        format!("$HOME/.agentapp/tmux/{}", self.agent_id)
    }

    fn remote_directory(&self) -> String {
        format!("$HOME/.agentapp/tmux/{}/{}", self.agent_id, self.process_id)
    }

    fn bootstrap_keeper_command(&self, max_seconds: u64) -> String {
        let root = self.remote_directory();
        format!(
            "root=\"{root}\"\ndeadline=$(( $(date +%s) + {max_seconds} ))\nwhile [ ! -f \"$root/keeper-release\" ]; do\n  now=$(date +%s)\n  [ \"$now\" -lt \"$deadline\" ] || exit 0\n  sleep 1\ndone\n"
        )
    }

    fn target(&self) -> String {
        format!("{}:{}.0", self.session_name, self.window_name)
    }

    fn process_script(&self, params: &ExecParams) -> String {
        let root = self.remote_directory();
        let payload_script = self.payload_script(params);
        let sentinel_script = self.group_sentinel_script();
        let invocation = if self.tty {
            "/bin/sh \"$root/payload.sh\" < /dev/tty".to_string()
        } else {
            "mkfifo \"$root/stdin\" 2>/dev/null || true\nexec 3<>\"$root/stdin\"\n/bin/sh \"$root/payload.sh\" <&3 >>\"$root/output\" 2>&1"
                .to_string()
        };
        let output_close = if self.tty {
            format!(
                "if ! tmux pipe-pane -t {target}; then\n  echo AGENTAPP_TMUX_OUTPUT_PIPE_CLOSE_FAILED >&2\n  while :; do sleep 60; done\nfi\n{output_drain_function}if ! agentapp_wait_for_output_drain; then while :; do sleep 60; done; fi",
                target = shell_quote(&self.target()),
                output_drain_function = output_drain_function_fragment(),
            )
        } else {
            ": > \"$root/output-closed.tmp\"\nmv \"$root/output-closed.tmp\" \"$root/output-closed\""
                .to_string()
        };
        format!(
            concat!(
                "#!/bin/sh\n",
                "root=\"{root}\"\n",
                "pgid=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')\n",
                "case \"$pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac\n",
                "printf '%s:%s\\n' \"$$\" \"$pgid\" > \"$root/process-identity.tmp\"\n",
                "mv \"$root/process-identity.tmp\" \"$root/process-identity\"\n",
                "rm -f \"$root/status.tmp\" \"$root/sentinel-release\" \"$root/sentinel-release.tmp\" \"$root/sentinel-ready\" \"$root/sentinel-ready.tmp\" \"$root/sentinel-identity\" \"$root/sentinel-identity.tmp\" \"$root/output-closed\" \"$root/output-closed.tmp\"\n",
                "printf '%s' {payload_script} > \"$root/payload.sh\"\n",
                "chmod 700 \"$root/payload.sh\"\n",
                "printf '%s' {sentinel_script} > \"$root/sentinel.sh\"\n",
                "chmod 700 \"$root/sentinel.sh\"\n",
                "agentapp_supervisor_refresh_residual_group() {{\n",
                "  agentapp_residual=\n",
                "  group_snapshot=$(command -p ps -axo pid=,ppid=,pgid= 2>/dev/null || true)\n",
                "  while read member_pid member_ppid member_pgid; do\n",
                "    case \"$member_pid:$member_ppid:$member_pgid\" in :*|*::*|*:*:|*[!0-9:]*) continue ;; esac\n",
                "    [ \"$member_pid\" != \"$$\" ] && [ \"$member_pid\" != \"$sentinel_pid\" ] && [ \"$member_ppid\" != \"$sentinel_pid\" ] && [ \"$member_pgid\" = \"$pgid\" ] || continue\n",
                "    current_member_pgid=$(command -p ps -o pgid= -p \"$member_pid\" 2>/dev/null | tr -d ' ')\n",
                "    [ \"$current_member_pgid\" = \"$pgid\" ] && agentapp_residual=\"$agentapp_residual $member_pid\"\n",
                "  done <<AGENTAPP_GROUP_SNAPSHOT_EOF\n",
                "$group_snapshot\n",
                "AGENTAPP_GROUP_SNAPSHOT_EOF\n",
                "}}\n",
                "agentapp_supervisor_stop_residual_group() {{\n",
                "  agentapp_supervisor_refresh_residual_group\n",
                "  [ -n \"$agentapp_residual\" ] || return 0\n",
                "  sleep 1\n",
                "  agentapp_supervisor_refresh_residual_group\n",
                "  [ -n \"$agentapp_residual\" ] || return 0\n",
                "  /bin/kill -TERM -- \"-$pgid\" 2>/dev/null || true\n",
                "  i=0\n",
                "  while [ \"$i\" -lt 10 ]; do agentapp_supervisor_refresh_residual_group; [ -n \"$agentapp_residual\" ] || return 0; sleep 1; i=$((i + 1)); done\n",
                "  agentapp_supervisor_refresh_residual_group\n",
                "  for residual_pid in $agentapp_residual; do\n",
                "    residual_pgid=$(command -p ps -o pgid= -p \"$residual_pid\" 2>/dev/null | tr -d ' ')\n",
                "    [ \"$residual_pgid\" = \"$pgid\" ] && /bin/kill -KILL \"$residual_pid\" 2>/dev/null || true\n",
                "  done\n",
                "  i=0\n",
                "  while [ \"$i\" -lt 5 ]; do agentapp_supervisor_refresh_residual_group; [ -n \"$agentapp_residual\" ] || return 0; sleep 1; i=$((i + 1)); done\n",
                "  return 81\n",
                "}}\n",
                "/bin/sh \"$root/sentinel.sh\" \"$$\" \"$pgid\" &\n",
                "sentinel_pid=$!\n",
                "sentinel_wait=0\n",
                "while [ ! -f \"$root/sentinel-ready\" ] && [ \"$sentinel_wait\" -lt 10 ]; do sleep 1; sentinel_wait=$((sentinel_wait + 1)); done\n",
                "sentinel_identity=$(cat \"$root/sentinel-identity\" 2>/dev/null || true)\n",
                "[ -f \"$root/sentinel-ready\" ] && [ \"$sentinel_identity\" = \"$sentinel_pid:$pgid\" ] || {{ echo AGENTAPP_TMUX_SENTINEL_START_FAILED >&2; /bin/kill -KILL \"$sentinel_pid\" 2>/dev/null || true; exit 80; }}\n",
                "{invocation}\n",
                "code=$?\n",
                "if ! agentapp_supervisor_stop_residual_group; then\n",
                "  echo AGENTAPP_TMUX_RESIDUAL_PROCESS_GROUP_ALIVE >&2\n",
                "  while :; do sleep 60; done\n",
                "fi\n",
                "{output_close}\n",
                "if mkdir \"$root/terminal-claim\" 2>/dev/null; then\n",
                "  printf 'completed\\n' > \"$root/terminal-claim/kind.tmp\"\n",
                "  mv \"$root/terminal-claim/kind.tmp\" \"$root/terminal-claim/kind\"\n",
                "  printf '%s\\n' \"$code\" > \"$root/status.tmp\"\n",
                "  mv \"$root/status.tmp\" \"$root/status\"\n",
                "  printf 'completed\\n' > \"$root/state.tmp\"\n",
                "  mv \"$root/state.tmp\" \"$root/state\"\n",
                "else\n",
                "  while [ ! -f \"$root/terminal-claim/kind\" ] && [ ! -f \"$root/status\" ]; do sleep 1; done\n",
                "  if [ -f \"$root/status\" ]; then\n",
                "    code=$(cat \"$root/status\" 2>/dev/null || printf '125')\n",
                "  else\n",
                "    claim_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
                "    case \"$claim_kind\" in terminated) code=143 ;; expired) code=124 ;; recovery-lost|launch-interrupted) code=125 ;; completed) while [ ! -f \"$root/status\" ]; do sleep 1; done; code=$(cat \"$root/status\" 2>/dev/null || printf '125') ;; *) code=125 ;; esac\n",
                "  fi\n",
                "fi\n",
                ": > \"$root/sentinel-release.tmp\"\n",
                "mv \"$root/sentinel-release.tmp\" \"$root/sentinel-release\"\n",
                "exit \"$code\"\n"
            ),
            root = root,
            invocation = invocation,
            output_close = output_close,
            payload_script = shell_quote(&payload_script),
            sentinel_script = shell_quote(&sentinel_script),
        )
    }

    fn group_sentinel_script(&self) -> String {
        let root = self.remote_directory();
        format!(
            "#!/bin/sh\nroot=\"{root}\"\nsupervisor_pid=$1\nexpected_pgid=$2\nsentinel_pid=$$\nsentinel_pgid=$(command -p ps -o pgid= -p \"$sentinel_pid\" 2>/dev/null | tr -d ' ')\ncase \"$supervisor_pid:$expected_pgid:$sentinel_pid:$sentinel_pgid\" in *[!0-9:]*) exit 80 ;; esac\n[ \"$sentinel_pid\" != \"$supervisor_pid\" ] && [ \"$sentinel_pgid\" = \"$expected_pgid\" ] || exit 80\nsentinel_signal_seen=0\ntrap 'sentinel_signal_seen=1' HUP INT TERM\nprintf '%s:%s\\n' \"$sentinel_pid\" \"$sentinel_pgid\" > \"$root/sentinel-identity.tmp\"\nmv \"$root/sentinel-identity.tmp\" \"$root/sentinel-identity\"\n: > \"$root/sentinel-ready.tmp\"\nmv \"$root/sentinel-ready.tmp\" \"$root/sentinel-ready\"\nwhile [ ! -f \"$root/sentinel-release\" ]; do\n  live_supervisor_pgid=$(command -p ps -o pgid= -p \"$supervisor_pid\" 2>/dev/null | tr -d ' ')\n  if [ \"$live_supervisor_pgid\" = \"$expected_pgid\" ]; then sleep 1; continue; fi\n  if [ -n \"$live_supervisor_pgid\" ]; then break; fi\n  if supervisor_error=$(LC_ALL=C /bin/kill -0 \"$supervisor_pid\" 2>&1); then sleep 1; continue; fi\n  case \"$supervisor_error\" in *\"No such process\"*) break ;; *) sleep 1 ;; esac\ndone\n[ -f \"$root/sentinel-release\" ] && exit 0\n/bin/kill -TERM -- \"-$expected_pgid\" 2>/dev/null || true\nsleep 2\n/bin/kill -KILL -- \"-$expected_pgid\" 2>/dev/null || true\nexit 125\n"
        )
    }

    fn payload_script(&self, params: &ExecParams) -> String {
        let root = self.remote_directory();
        let command = build_remote_command(params);
        format!(
            "#!/bin/sh\nroot=\"{root}\"\npayload_pid=$$\npayload_pgid=$(ps -o pgid= -p \"$payload_pid\" 2>/dev/null | tr -d ' ')\ncase \"$payload_pid:$payload_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_PAYLOAD_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\nsupervisor_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\nsupervisor_pid=${{supervisor_identity%%:*}}\nsupervisor_pgid=${{supervisor_identity#*:}}\ncase \"$supervisor_pid:$supervisor_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac\n[ \"$payload_pid\" != \"$supervisor_pid\" ] && [ \"$payload_pgid\" = \"$supervisor_pgid\" ] || {{ echo AGENTAPP_TMUX_PAYLOAD_GROUP_MISMATCH >&2; exit 80; }}\nprintf '%s:%s\\n' \"$payload_pid\" \"$payload_pgid\" > \"$root/payload-identity.tmp\"\nmv \"$root/payload-identity.tmp\" \"$root/payload-identity\"\n: > \"$root/payload-ready.tmp\"\nmv \"$root/payload-ready.tmp\" \"$root/payload-ready\"\nwhile [ ! -f \"$root/payload-go\" ]; do sleep 1; done\n{command}\n",
        )
    }

    fn supervisor_start_command(&self) -> String {
        let root = self.remote_directory();
        let supervisor_command = format!(
            "hangup_seen=0\ninterrupt_seen=0\ntermination_seen=0\ntrap 'hangup_seen=1' HUP\ntrap 'interrupt_seen=1' INT\ntrap 'termination_seen=1' TERM\nrm -f \"{root}/payload-go\" \"{root}/payload-go.tmp\" \"{root}/payload-ready\" \"{root}/payload-ready.tmp\" \"{root}/payload-identity\" \"{root}/payload-identity.tmp\" \"{root}/supervisor-ready\" \"{root}/supervisor-ready.tmp\"\n: > \"{root}/supervisor-ready.tmp\"\nmv \"{root}/supervisor-ready.tmp\" \"{root}/supervisor-ready\"\nwhile [ ! -f \"{root}/go\" ]; do sleep 1; done\n. \"{root}/command.sh\""
        );
        format!("exec /bin/sh -c {}", shell_quote(&supervisor_command))
    }

    fn expiry_script(&self) -> String {
        let root = self.remote_directory();
        let expiry_key =
            stable_identifier(&format!("{}:{}:expiry", self.agent_id, self.process_id));
        format!(
            concat!(
                "#!/bin/sh\n",
                "set -eu\n",
                "root=\"{root}\"\n",
                "default_session={default_session}\n",
                "window={window}\n",
                "watchdog_window={watchdog_window}\n",
                "max_lifetime={max_lifetime}\n",
                "{output_drain_function}",
                "[ -d \"$root\" ] || exit 0\n",
                "[ \"$(cat \"$root/owner\" 2>/dev/null || true)\" = {owner} ] || exit 0\n",
                "[ \"$(cat \"$root/identity\" 2>/dev/null || true)\" = {identity} ] || exit 0\n",
                "[ \"$(cat \"$root/thread-id\" 2>/dev/null || true)\" = {thread_id} ] || exit 0\n",
                "[ \"$(cat \"$root/turn-id\" 2>/dev/null || true)\" = {turn_id} ] || exit 0\n",
                "[ \"$(cat \"$root/call-id\" 2>/dev/null || true)\" = {call_id} ] || exit 0\n",
                "[ \"$(cat \"$root/attempt-generation\" 2>/dev/null || true)\" = {attempt_generation} ] || exit 0\n",
                "[ \"$(cat \"$root/session-id\" 2>/dev/null || true)\" = {session_id} ] || exit 0\n",
                "[ \"$(cat \"$root/tty\" 2>/dev/null || true)\" = {tty} ] || exit 0\n",
                "[ \"$(cat \"$root/digest\" 2>/dev/null || true)\" = {digest} ] || exit 0\n",
                "[ \"$(cat \"$root/window\" 2>/dev/null || true)\" = \"$window\" ] || exit 0\n",
                "session=$(cat \"$root/session\" 2>/dev/null || true)\n",
                "[ \"$session\" = \"$default_session\" ] || exit 0\n",
                "created_at=$(cat \"$root/created-at\" 2>/dev/null || true)\n",
                "case \"$created_at\" in ''|*[!0-9]*) exit 0 ;; esac\n",
                "now=$(date +%s)\n",
                "case \"$now\" in ''|*[!0-9]*) exit 0 ;; esac\n",
                "[ \"$now\" -ge \"$created_at\" ] || exit 0\n",
                "[ $((now - created_at)) -ge \"$max_lifetime\" ] || exit 0\n",
                "[ ! -f \"$root/status\" ] && [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = running ] && [ -e \"$root/go\" ] || exit 0\n",
                "process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
                "pane_pid=${{process_identity%%:*}}\n",
                "pgid=${{process_identity#*:}}\n",
                "case \"$process_identity\" in *:*:*) exit 0 ;; esac\n",
                "case \"$pane_pid:$pgid\" in :|:*|*:|*[!0-9:]*) exit 0 ;; esac\n",
                "stored_window_id=$(cat \"$root/window-id\" 2>/dev/null || true)\n",
                "stored_pane_id=$(cat \"$root/pane-id\" 2>/dev/null || true)\n",
                "[ -n \"$stored_window_id\" ] && [ -n \"$stored_pane_id\" ] || exit 0\n",
                "[ \"$(tmux list-panes -t \"$session:$window\" -F '#{{pane_id}}' 2>/dev/null | wc -l | tr -d ' ')\" = 1 ] || exit 0\n",
                "pane_observation=$(tmux display-message -p -t \"$session:$window.0\" '#{{window_id}}:#{{pane_id}}:#{{pane_pid}}:#{{pane_dead}}' 2>/dev/null || true)\n",
                "old_ifs=$IFS; IFS=:; set -- $pane_observation; IFS=$old_ifs\n",
                "[ \"$#\" -eq 4 ] || exit 0\n",
                "current_window_id=$1; current_pane_id=$2; current_pane=$3; current_pane_dead=$4\n",
                "[ \"$current_window_id:$current_pane_id:$current_pane:$current_pane_dead\" = \"$stored_window_id:$stored_pane_id:$pane_pid:0\" ] || exit 0\n",
                "current_pgid=$(command -p ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' ')\n",
                "[ \"$current_pgid\" = \"$pgid\" ] || exit 0\n",
                "current_controller=$(cat \"$root/controller\" 2>/dev/null || true)\n",
                "controller_generation=${{current_controller%%:*}}\n",
                "controller_value=${{current_controller#*:}}\n",
                "case \"$controller_generation\" in ''|*[!0-9]*) exit 0 ;; esac\n",
                "[ -n \"$controller_value\" ] && [ \"$controller_value\" != \"$current_controller\" ] || exit 0\n",
                "operation_pid=$$\n",
                "operation_pgid=$(command -p ps -o pgid= -p \"$operation_pid\" 2>/dev/null | tr -d ' ')\n",
                "case \"$operation_pid:$operation_pgid\" in :|:*|*:|*[!0-9:]*) exit 0 ;; esac\n",
                "[ \"$operation_pgid\" != \"$pgid\" ] || exit 0\n",
                "expiry_nonce=e_{expiry_key}_$operation_pid\n",
                "transition_candidate=\"$root/.transition-candidate.$expiry_nonce.$operation_pid\"\n",
                "expected_claim=\"expiry|$expiry_nonce|$current_controller|$operation_pid|$operation_pgid|$window|$pane_pid|$pgid\"\n",
                "( umask 077; set -C; printf '%s\\n' \"$expected_claim\" > \"$transition_candidate\" ) || exit 0\n",
                "if ! ln \"$transition_candidate\" \"$root/transition-claim\" 2>/dev/null; then rm -f \"$transition_candidate\"; exit 0; fi\n",
                "release_expiry_claim() {{ if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; }}\n",
                "trap 'release_expiry_claim' EXIT HUP INT TERM\n",
                "require_expiry_claim() {{ [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_claim\" ] || {{ exit 79; }}; }}\n",
                "require_expiry_claim\n",
                "now=$(date +%s)\n",
                "case \"$now\" in ''|*[!0-9]*) exit 0 ;; esac\n",
                "[ \"$now\" -ge \"$created_at\" ] && [ $((now - created_at)) -ge \"$max_lifetime\" ] || exit 0\n",
                "[ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$current_controller\" ] || exit 0\n",
                "[ ! -f \"$root/status\" ] && [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = running ] || exit 0\n",
                "[ \"$(cat \"$root/process-identity\" 2>/dev/null || true)\" = \"$process_identity\" ] || exit 0\n",
                "rechecked_pane=$(tmux display-message -p -t \"$current_pane_id\" '#{{window_id}}:#{{pane_id}}:#{{pane_pid}}:#{{pane_dead}}' 2>/dev/null || true)\n",
                "[ \"$rechecked_pane\" = \"$pane_observation\" ] || exit 0\n",
                "rechecked_pgid=$(command -p ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' ')\n",
                "[ \"$rechecked_pgid\" = \"$pgid\" ] || exit 0\n",
                "if ! mkdir \"$root/terminal-claim\" 2>/dev/null; then exit 0; fi\n",
                "printf 'expired\\n' > \"$root/terminal-claim/kind.tmp\"\n",
                "mv \"$root/terminal-claim/kind.tmp\" \"$root/terminal-claim/kind\"\n",
                "require_expiry_claim\n",
                "[ \"$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\" = expired ] || exit 0\n",
                "{stop_process_group}\n",
                "require_expiry_claim\n",
                "if [ \"$(cat \"$root/tty\" 2>/dev/null || true)\" = 1 ]; then\n",
                "  tmux pipe-pane -t \"$current_pane_id\"\n",
                "  require_expiry_claim\n",
                "fi\n",
                "[ -e \"$root/output\" ] || : > \"$root/output\"\n",
                "if [ \"$(cat \"$root/tty\" 2>/dev/null || true)\" = 1 ]; then\n",
                "  agentapp_wait_for_output_drain\n",
                "else\n",
                "  if [ ! -f \"$root/output-closed\" ]; then : > \"$root/output-closed.tmp\"; mv \"$root/output-closed.tmp\" \"$root/output-closed\"; fi\n",
                "fi\n",
                "require_expiry_claim\n",
                "printf '\\n%s\\n' {expiry_notice} >> \"$root/output\"\n",
                "require_expiry_claim\n",
                "[ ! -f \"$root/status\" ] || exit 0\n",
                "printf '124\\n' > \"$root/status.tmp\"\n",
                "mv \"$root/status.tmp\" \"$root/status\"\n",
                "printf 'expired\\n' > \"$root/state.tmp\"\n",
                "mv \"$root/state.tmp\" \"$root/state\"\n",
                "rm -f \"$root/recovery-required\"\n",
                "require_expiry_claim\n",
                "{retire_windows}\n",
                "release_expiry_claim\n",
                "trap - EXIT HUP INT TERM\n",
                "exit 0\n"
            ),
            root = root,
            default_session = shell_quote(&self.session_name),
            window = shell_quote(&self.window_name),
            watchdog_window = shell_quote(&self.watchdog_window_name),
            max_lifetime = EXECUTION_MAX_LIFETIME_SECONDS,
            owner = shell_quote(OWNERSHIP_MARKER),
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
            digest = shell_quote(&self.command_digest),
            expiry_notice = shell_quote(crate::EXECUTION_EXPIRY_SYSTEM_NOTICE),
            expiry_key = expiry_key,
            output_drain_function = output_drain_function_fragment(),
            stop_process_group = self.confirmed_process_group_stop(),
            retire_windows = self.retire_confirmed_process_windows(false),
        )
    }

    fn terminal_cleanup_script(&self) -> String {
        let root = self.remote_directory();
        format!(
            concat!(
                "#!/bin/sh\n",
                "set -eu\n",
                "root=\"{root}\"\n",
                "default_session={default_session}\n",
                "window={window}\n",
                "watchdog_window={watchdog_window}\n",
                "{output_drain_function}",
                "[ -d \"$root\" ] || exit 1\n",
                "[ \"$(cat \"$root/owner\" 2>/dev/null || true)\" = {owner} ] || exit 1\n",
                "[ \"$(cat \"$root/identity\" 2>/dev/null || true)\" = {identity} ] || exit 1\n",
                "[ \"$(cat \"$root/thread-id\" 2>/dev/null || true)\" = {thread_id} ] || exit 1\n",
                "[ \"$(cat \"$root/turn-id\" 2>/dev/null || true)\" = {turn_id} ] || exit 1\n",
                "[ \"$(cat \"$root/call-id\" 2>/dev/null || true)\" = {call_id} ] || exit 1\n",
                "[ \"$(cat \"$root/attempt-generation\" 2>/dev/null || true)\" = {attempt_generation} ] || exit 1\n",
                "[ \"$(cat \"$root/session-id\" 2>/dev/null || true)\" = {session_id} ] || exit 1\n",
                "[ \"$(cat \"$root/tty\" 2>/dev/null || true)\" = {tty} ] || exit 1\n",
                "[ \"$(cat \"$root/digest\" 2>/dev/null || true)\" = {digest} ] || exit 1\n",
                "[ \"$(cat \"$root/window\" 2>/dev/null || true)\" = \"$window\" ] || exit 1\n",
                "session=$(cat \"$root/session\" 2>/dev/null || true)\n",
                "[ \"$session\" = \"$default_session\" ] || exit 1\n",
                "state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "claim_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
                "code=$(cat \"$root/status\" 2>/dev/null || true)\n",
                "case \"$state:$claim_kind\" in completed:completed|terminated:terminated|expired:expired|recovery-lost:recovery-lost) ;; *) exit 1 ;; esac\n",
                "case \"$state\" in\n",
                "  completed) case \"$code\" in -*) numeric_code=${{code#-}} ;; *) numeric_code=$code ;; esac; case \"$numeric_code\" in ''|*[!0-9]*) exit 1 ;; esac ;;\n",
                "  terminated) [ \"$code\" = 143 ] || exit 1 ;;\n",
                "  expired) [ \"$code\" = 124 ] || exit 1 ;;\n",
                "  recovery-lost) [ \"$code\" = 125 ] || exit 1 ;;\n",
                "esac\n",
                "{stop_process_group}\n",
                "if [ \"$(cat \"$root/tty\" 2>/dev/null || true)\" = 1 ]; then tmux pipe-pane -t \"$current_pane_id\"; fi\n",
                "agentapp_wait_for_output_drain\n",
                "{retire_windows}\n",
                "exit 0\n"
            ),
            root = root,
            default_session = shell_quote(&self.session_name),
            window = shell_quote(&self.window_name),
            watchdog_window = shell_quote(&self.watchdog_window_name),
            owner = shell_quote(OWNERSHIP_MARKER),
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
            digest = shell_quote(&self.command_digest),
            output_drain_function = output_drain_function_fragment(),
            stop_process_group = self.confirmed_process_group_stop(),
            retire_windows = self.retire_confirmed_process_windows(false),
        )
    }

    fn watchdog_script(&self) -> String {
        let root = self.remote_directory();
        format!(
            "#!/bin/sh\nroot=\"{root}\"\nwhile :; do\n  if [ -f \"$root/status\" ]; then\n    if [ -x \"$root/terminal-cleanup.sh\" ] && /bin/sh \"$root/terminal-cleanup.sh\"; then exit 0; fi\n    sleep {CONTROLLER_HEARTBEAT_SECONDS}\n    continue\n  fi\n  if [ -x \"$root/expiry.sh\" ]; then /bin/sh \"$root/expiry.sh\" || true; fi\n  [ -f \"$root/status\" ] && continue\n  now=$(date +%s)\n  lease=$(cat \"$root/lease\" 2>/dev/null || printf '0')\n  case \"$lease\" in ''|*[!0-9]*) lease=0 ;; esac\n  if [ $((now - lease)) -ge {CONTROLLER_LEASE_SECONDS} ] && [ ! -f \"$root/recovery-required\" ]; then\n    observed=$(cat \"$root/controller\" 2>/dev/null || true)\n    observed_generation=${{observed%%:*}}\n    observed_controller=${{observed#*:}}\n    case \"$observed_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_CONTROLLER_GENERATION_UNKNOWN >&2; exit 80 ;; esac\n    if [ -z \"$observed_controller\" ] || [ \"$observed_controller\" = \"$observed\" ]; then echo AGENTAPP_TMUX_CONTROLLER_UNKNOWN >&2; exit 80; fi\n    printf '%s:%s\\n' \"$observed_generation\" \"$observed_controller\" > \"$root/recovery-required.tmp\"\n    mv \"$root/recovery-required.tmp\" \"$root/recovery-required\"\n  fi\n  sleep {CONTROLLER_HEARTBEAT_SECONDS}\ndone\n",
        )
    }

    fn bootstrap_command(&self, params: &ExecParams) -> String {
        let agent_root = self.agent_directory();
        let root = self.remote_directory();
        let script = self.process_script(params);
        let watchdog_script = self.watchdog_script();
        let expiry_script = self.expiry_script();
        let terminal_cleanup_script = self.terminal_cleanup_script();
        let start_command = self.supervisor_start_command();
        let watchdog_command = format!("exec /bin/sh \"{root}/watchdog.sh\"");
        let pipe_setup = if self.tty {
            tty_pipe_setup_command("\"$target\"")
        } else {
            ":".to_string()
        };

        format!(
            concat!(
                "set -eu\n",
                "if ! command -v tmux >/dev/null 2>&1; then echo AGENTAPP_TMUX_MISSING >&2; exit 127; fi\n",
                "agentapp_raise_nofile_limit() {{\n",
                "  hard=$(ulimit -H -n 2>/dev/null || true)\n",
                "  soft=$(ulimit -S -n 2>/dev/null || true)\n",
                "  case \"$hard\" in unlimited) desired=4096 ;; ''|*[!0-9]*) return 0 ;; *) desired=$hard; [ \"$desired\" -le 4096 ] || desired=4096 ;; esac\n",
                "  case \"$soft\" in ''|*[!0-9]*) return 0 ;; esac\n",
                "  [ \"$soft\" -ge \"$desired\" ] || ulimit -S -n \"$desired\" 2>/dev/null || true\n",
                "}}\n",
                "agentapp_tmux_create() {{\n",
                "  if tmux_error=$(\"$@\" 2>&1); then return 0; fi\n",
                "  case \"$tmux_error\" in *\"Too many open files\"*|*\"fork failed: Device not configured\"*) echo AGENTAPP_TMUX_RESOURCE_EXHAUSTED >&2; printf '%s\\n' \"$tmux_error\" >&2; return 73 ;; esac\n",
                "  printf '%s\\n' \"$tmux_error\" >&2\n",
                "  return 80\n",
                "}}\n",
                "agent_root=\"{agent_root}\"\n",
                "root=\"{root}\"\n",
                "default_session={session}\n",
                "legacy_session={legacy_session}\n",
                "session=$default_session\n",
                "if [ -d \"$root\" ]; then stored_session=$(cat \"$root/session\" 2>/dev/null || true); if [ -z \"$stored_session\" ]; then session=$legacy_session; elif [ \"$stored_session\" = \"$default_session\" ] || [ \"$stored_session\" = \"$legacy_session\" ]; then session=$stored_session; else echo AGENTAPP_TMUX_SESSION_MISMATCH >&2; exit 76; fi; fi\n",
                "window={window}\n",
                "watchdog_window={watchdog_window}\n",
                "controller={controller}\n",
                "digest={digest}\n",
                "staging_name=.descriptor-stage-{identity}-{controller_key}-$$\n",
                "staging=\"$agent_root/$staging_name\"\n",
                "mkdir -p \"$agent_root\"\n",
                "candidate_controller=\"$controller\"\n",
                "if ! tmux has-session -t \"$session\" 2>/dev/null; then\n",
                "  agentapp_raise_nofile_limit\n",
                "  rm -f \"$root/keeper-release\" \"$root/keeper-release.tmp\"\n",
                "  if agentapp_tmux_create tmux new-session -d -s \"$session\" -n __agentapp_keeper {keeper}; then :; else create_status=$?; tmux has-session -t \"$session\" 2>/dev/null || exit \"$create_status\"; fi\n",
                "fi\n",
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
                "  case \"$existing_state\" in prepared|running) ;; completed|terminated|expired|launch-interrupted) echo AGENTAPP_TMUX_EXECUTION_TERMINAL >&2; exit 79 ;; *) echo AGENTAPP_TMUX_EXECUTION_STATE_UNKNOWN >&2; exit 79 ;; esac\n",
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
                "    rm -f \"$descriptor_staging_path/output\" \"$descriptor_staging_path/owner\" \"$descriptor_staging_path/identity\" \"$descriptor_staging_path/thread-id\" \"$descriptor_staging_path/turn-id\" \"$descriptor_staging_path/call-id\" \"$descriptor_staging_path/attempt-generation\" \"$descriptor_staging_path/session-id\" \"$descriptor_staging_path/session\" \"$descriptor_staging_path/tty\" \"$descriptor_staging_path/acknowledgement-token\" \"$descriptor_staging_path/digest\" \"$descriptor_staging_path/window\" \"$descriptor_staging_path/created-at\" \"$descriptor_staging_path/state\"\n",
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
                "  printf '%s\\n' \"$session\" > \"$staging/session\" || descriptor_publish_failed\n",
                "  printf '%s\\n' {tty} > \"$staging/tty\" || descriptor_publish_failed\n",
                "  printf '%s\\n' {acknowledgement_token} > \"$staging/acknowledgement-token\" || descriptor_publish_failed\n",
                "  printf '%s\\n' \"$digest\" > \"$staging/digest\" || descriptor_publish_failed\n",
                "  printf '%s\\n' \"$window\" > \"$staging/window\" || descriptor_publish_failed\n",
                "  created_at=$(date +%s)\n",
                "  case \"$created_at\" in ''|*[!0-9]*) descriptor_publish_failed ;; esac\n",
                "  printf '%s\\n' \"$created_at\" > \"$staging/created-at\" || descriptor_publish_failed\n",
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
                "agentapp_bootstrap_probe_operation_group() {{\n",
                "  bootstrap_operation_group_state=unknown\n",
                "  if /bin/kill -0 -- \"-$1\" 2>/dev/null; then bootstrap_operation_group_state=alive; return; fi\n",
                "  if bootstrap_operation_error=$(LC_ALL=C /bin/kill -0 -- \"-$1\" 2>&1); then bootstrap_operation_group_state=alive; return; fi\n",
                "  case \"$bootstrap_operation_error\" in *\"No such process\"*) bootstrap_operation_group_state=dead ;; esac\n",
                "}}\n",
                "if [ -e \"$root/transition-claim\" ]; then\n",
                "  stale_bootstrap_claim=$(cat \"$root/transition-claim\" 2>/dev/null || true)\n",
                "  old_ifs=$IFS; IFS='|'\n",
                "  read claim_kind claim_nonce claim_controller claim_operation_pid claim_operation_pgid claim_window claim_pane claim_pgid <<AGENTAPP_BOOTSTRAP_CLAIM_EOF\n",
                "$stale_bootstrap_claim\n",
                "AGENTAPP_BOOTSTRAP_CLAIM_EOF\n",
                "  IFS=$old_ifs\n",
                "  [ \"$claim_kind:$claim_nonce:$claim_controller:$claim_window\" = \"bootstrap:b_{controller_key}:$active:$window\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  case \"$claim_operation_pid:$claim_operation_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
                "  [ \"$claim_operation_pgid\" != \"$claim_pgid\" ] || [ \"$claim_pgid\" = - ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "  stale_candidate=\"$root/.transition-candidate.$claim_nonce.$claim_operation_pid\"\n",
                "  [ -f \"$stale_candidate\" ] && [ ! -L \"$stale_candidate\" ] && [ \"$stale_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$stale_candidate\" 2>/dev/null || true)\" = \"$stale_bootstrap_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  live_operation_pgid=$(command -p ps -o pgid= -p \"$claim_operation_pid\" 2>/dev/null | tr -d ' ')\n",
                "  [ \"$live_operation_pgid\" != \"$claim_operation_pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  agentapp_bootstrap_probe_operation_group \"$claim_operation_pgid\"\n",
                "  case \"$bootstrap_operation_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79 ;; *) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  if [ \"$window_exists\" -eq 1 ]; then\n",
                "    current_pane=$(tmux display-message -p -t \"$session:$window.0\" '#{{pane_pid}}' 2>/dev/null || true)\n",
                "    current_pgid=$(ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' ')\n",
                "    {{ [ \"$claim_pane:$claim_pgid\" = -:- ] || [ \"$claim_pane:$claim_pgid\" = \"$current_pane:$current_pgid\" ]; }} || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "  else\n",
                "    [ \"$claim_pane:$claim_pgid\" = -:- ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "  fi\n",
                "  [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$stale_bootstrap_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  bootstrap_quarantine=\"$root/transition-claim.quarantine.$claim_nonce.$claim_operation_pid\"\n",
                "  [ ! -e \"$bootstrap_quarantine\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_QUARANTINE_CONFLICT >&2; exit 79; }}\n",
                "  mv \"$root/transition-claim\" \"$bootstrap_quarantine\"\n",
                "  release_start=1\n",
                "fi\n",
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
                "  ( umask 077; set -C; printf 'bootstrap|b_{controller_key}|%s|%s|%s|%s|%s|%s\\n' \"$active\" \"$operation_pid\" \"$operation_pgid\" \"$window\" \"$claim_pane\" \"$claim_pgid\" > \"$transition_candidate\" ) || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  ln \"$transition_candidate\" \"$root/transition-claim\" 2>/dev/null || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  release_transition_claim() {{ if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; }}\n",
                "  trap 'release_transition_claim' EXIT\n",
                "  bootstrap_state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "  {{ [ \"$bootstrap_state\" = prepared ] || [ \"$bootstrap_state\" = running ]; }} && [ ! -e \"$root/status\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
                "fi\n",
                "printf '%s\\n' \"$assigned\" > \"$root/lease-generation.tmp\"\n",
                "mv \"$root/lease-generation.tmp\" \"$root/lease-generation\"\n",
                "printf '%s\\n' \"$active\" > \"$root/controller.tmp\"\n",
                "mv \"$root/controller.tmp\" \"$root/controller\"\n",
                "date +%s > \"$root/lease\"\n",
                "rm -f \"$root/recovery-required\"\n",
                "if [ \"$create_watchdog\" -eq 1 ]; then\n",
                "  printf '%s' {expiry_script} > \"$root/expiry.sh\"\n",
                "  chmod 700 \"$root/expiry.sh\"\n",
                "  printf '%s' {terminal_cleanup_script} > \"$root/terminal-cleanup.sh\"\n",
                "  chmod 700 \"$root/terminal-cleanup.sh\"\n",
                "  printf '%s' {watchdog_script} > \"$root/watchdog.sh\"\n",
                "  chmod 700 \"$root/watchdog.sh\"\n",
                "  agentapp_tmux_create tmux new-window -d -t \"$session:\" -n \"$watchdog_window\" {watchdog_start}\n",
                "fi\n",
                "if [ \"$create_window\" -eq 1 ]; then\n",
                "  date +%s > \"$root/lease\"\n",
                "  printf '%s' {script} > \"$root/command.sh\"\n",
                "  chmod 700 \"$root/command.sh\"\n",
                "  if agentapp_tmux_create tmux new-window -d -t \"$session:\" -n \"$window\" {start}; then :; else create_status=$?; if [ \"$create_watchdog\" -eq 1 ]; then tmux kill-window -t \"$session:$watchdog_window\" 2>/dev/null || true; fi; exit \"$create_status\"; fi\n",
                "  pane_pid=$(tmux display-message -p -t \"$session:$window.0\" '#{{pane_pid}}')\n",
                "  case \"$pane_pid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80 ;; esac\n",
                "  pane_pgid=$(ps -o pgid= -p \"$pane_pid\" 2>/dev/null | tr -d ' ')\n",
                "  case \"$pane_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac\n",
                "  printf '%s:%s\\n' \"$pane_pid\" \"$pane_pgid\" > \"$root/process-identity.tmp\"\n",
                "  mv \"$root/process-identity.tmp\" \"$root/process-identity\"\n",
                "fi\n",
                "target=\"$session:$window.0\"\n",
                "tmux set-option -w -t \"$target\" remain-on-exit on\n",
                "[ \"$(tmux show-options -w -v -t \"$target\" remain-on-exit 2>/dev/null || true)\" = on ] || {{ echo AGENTAPP_TMUX_REMAIN_ON_EXIT_UNAVAILABLE >&2; exit 80; }}\n",
                "pane_count=$(tmux list-panes -t \"$session:$window\" -F '#{{pane_id}}' 2>/dev/null | wc -l | tr -d ' ')\n",
                "[ \"$pane_count\" = 1 ] || {{ echo AGENTAPP_TMUX_PANE_COUNT_MISMATCH >&2; exit 80; }}\n",
                "window_id=$(tmux display-message -p -t \"$target\" '#{{window_id}}' 2>/dev/null || true)\n",
                "pane_id=$(tmux display-message -p -t \"$target\" '#{{pane_id}}' 2>/dev/null || true)\n",
                "case \"$window_id\" in @*[!0-9]*|@) echo AGENTAPP_TMUX_WINDOW_ID_UNKNOWN >&2; exit 80 ;; @*) ;; *) echo AGENTAPP_TMUX_WINDOW_ID_UNKNOWN >&2; exit 80 ;; esac\n",
                "case \"$pane_id\" in %*[!0-9]*|%) echo AGENTAPP_TMUX_PANE_ID_UNKNOWN >&2; exit 80 ;; %*) ;; *) echo AGENTAPP_TMUX_PANE_ID_UNKNOWN >&2; exit 80 ;; esac\n",
                "stored_window_id=$(cat \"$root/window-id\" 2>/dev/null || true)\n",
                "stored_pane_id=$(cat \"$root/pane-id\" 2>/dev/null || true)\n",
                "if [ -z \"$stored_window_id\" ] && [ -z \"$stored_pane_id\" ]; then\n",
                "  printf '%s\\n' \"$window_id\" > \"$root/window-id.tmp\"\n",
                "  mv \"$root/window-id.tmp\" \"$root/window-id\"\n",
                "  printf '%s\\n' \"$pane_id\" > \"$root/pane-id.tmp\"\n",
                "  mv \"$root/pane-id.tmp\" \"$root/pane-id\"\n",
                "else\n",
                "  [ \"$stored_window_id:$stored_pane_id\" = \"$window_id:$pane_id\" ] || {{ echo AGENTAPP_TMUX_NATIVE_IDENTITY_MISMATCH >&2; exit 80; }}\n",
                "fi\n",
                "if [ \"$release_start\" -eq 1 ]; then\n",
                "  current_pane=$(tmux display-message -p -t \"$target\" '#{{pane_pid}}' 2>/dev/null || true)\n",
                "  current_pgid=$(ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' ')\n",
                "  case \"$current_pane\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  case \"$current_pgid\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "  [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$active\" ] || {{ echo AGENTAPP_TMUX_STALE_CONTROLLER >&2; exit 75; }}\n",
                "  bootstrap_state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "  {{ [ \"$bootstrap_state\" = prepared ] || [ \"$bootstrap_state\" = running ]; }} && [ ! -e \"$root/status\" ] && [ ! -e \"$root/recovery-required\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
                "  stored_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
                "  [ \"$stored_identity\" = \"$current_pane:$current_pgid\" ] && kill -0 \"-$current_pgid\" 2>/dev/null || {{ echo AGENTAPP_TMUX_TRANSITION_OWNERSHIP_MISMATCH >&2; exit 80; }}\n",
                "  supervisor_wait=0\n",
                "  while [ ! -f \"$root/supervisor-ready\" ] && [ \"$supervisor_wait\" -lt 30 ]; do sleep 1; supervisor_wait=$((supervisor_wait + 1)); done\n",
                "  [ -f \"$root/supervisor-ready\" ] || {{ echo AGENTAPP_TMUX_SUPERVISOR_START_TIMEOUT >&2; exit 80; }}\n",
                "  if [ ! -f \"$root/go\" ]; then {pipe_setup}; fi\n",
                "  if [ ! -f \"$root/payload-go\" ]; then : > \"$root/payload-go.tmp\"; mv \"$root/payload-go.tmp\" \"$root/payload-go\"; fi\n",
                "  if [ \"$bootstrap_state\" != running ]; then printf 'running\\n' > \"$root/state.tmp\"; mv \"$root/state.tmp\" \"$root/state\"; fi\n",
                "  if [ ! -f \"$root/go\" ]; then : > \"$root/go.tmp\"; mv \"$root/go.tmp\" \"$root/go\"; fi\n",
                "fi\n",
                "if [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = running ] && [ ! -f \"$root/status\" ]; then\n",
                "  [ -f \"$root/go\" ] && [ -f \"$root/payload-go\" ] || {{ echo AGENTAPP_TMUX_PAYLOAD_RELEASE_MISSING >&2; exit 80; }}\n",
                "  stored_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
                "  case \"$stored_identity\" in *:*:*) echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80 ;; esac\n",
                "  case \"$stored_identity\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80 ;; esac\n",
                "  payload_wait=0\n",
                "  while [ ! -f \"$root/payload-ready\" ] && [ ! -f \"$root/status\" ] && [ \"$payload_wait\" -lt 30 ]; do sleep 1; payload_wait=$((payload_wait + 1)); done\n",
                "  [ -f \"$root/payload-ready\" ] || [ -f \"$root/status\" ] || {{ echo AGENTAPP_TMUX_PAYLOAD_START_TIMEOUT >&2; exit 80; }}\n",
                "  if [ -f \"$root/payload-ready\" ]; then\n",
                "    payload_identity=$(cat \"$root/payload-identity\" 2>/dev/null || true)\n",
                "    payload_pid=${{payload_identity%%:*}}\n",
                "    payload_pgid=${{payload_identity#*:}}\n",
                "    case \"$payload_pid:$payload_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_PAYLOAD_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "    [ \"$payload_pid\" != \"${{stored_identity%%:*}}\" ] && [ \"$payload_pgid\" = \"${{stored_identity#*:}}\" ] || {{ echo AGENTAPP_TMUX_PAYLOAD_GROUP_MISMATCH >&2; exit 80; }}\n",
                "  fi\n",
                "fi\n",
                "[ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$active\" ] || {{ echo AGENTAPP_TMUX_STALE_CONTROLLER >&2; exit 75; }}\n",
                ": > \"$root/keeper-release.tmp\"\n",
                "mv \"$root/keeper-release.tmp\" \"$root/keeper-release\"\n",
                "tmux kill-window -t \"$session:__agentapp_keeper\" 2>/dev/null || true\n",
                "printf 'AGENTAPP_TMUX_READY %s %s\\n' \"$target\" \"$active\"\n",
                "if [ \"$release_start\" -eq 1 ]; then release_transition_claim; trap - EXIT; fi\n",
            ),
            agent_root = agent_root,
            root = root,
            session = shell_quote(&self.session_name),
            legacy_session = shell_quote(&legacy_session_name(&self.agent_id)),
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
            keeper = shell_quote(&self.bootstrap_keeper_command(BOOTSTRAP_KEEPER_MAX_SECONDS)),
            script = shell_quote(&script),
            expiry_script = shell_quote(&expiry_script),
            terminal_cleanup_script = shell_quote(&terminal_cleanup_script),
            watchdog_script = shell_quote(&watchdog_script),
            start = shell_quote(&start_command),
            watchdog_start = shell_quote(&watchdog_command),
            pipe_setup = pipe_setup,
        )
    }

    fn monitor_command(&self, first_byte: u64) -> String {
        let root = self.remote_directory();
        format!(
            concat!(
                "root=\"{root}\"\n",
                "controller={controller}\n",
                "digest={digest}\n",
                "session={session}\n",
                "window={window}\n",
                "tty={tty}\n",
                "offset={first_byte}\n",
                "stable=0\n",
                "attached_at=$(date +%s)\n",
                "attachment_seconds={attachment_seconds}\n",
                "agentapp_monitor_group_dead() {{\n",
                "  monitor_group_state=unknown\n",
                "  [ -x /bin/kill ] || return\n",
                "  if /bin/kill -0 -- \"-$1\" 2>/dev/null; then monitor_group_state=alive; return; fi\n",
                "  if monitor_kill_error=$(LC_ALL=C /bin/kill -0 -- \"-$1\" 2>&1); then monitor_group_state=alive; return; fi\n",
                "  case \"$monitor_kill_error\" in *\"No such process\"*) monitor_group_state=dead ;; esac\n",
                "}}\n",
                "agentapp_monitor_detect_dead_execution() {{\n",
                "  monitor_execution_dead=0\n",
                "  [ ! -f \"$root/status\" ] || return\n",
                "  process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
                "  pane_pid=${{process_identity%%:*}}\n",
                "  pgid=${{process_identity#*:}}\n",
                "  case \"$process_identity\" in *:*:*) return ;; esac\n",
                "  case \"$pane_pid:$pgid\" in :|:*|*:|*[!0-9:]*) return ;; esac\n",
                "  agentapp_monitor_group_dead \"$pgid\"\n",
                "  [ \"$monitor_group_state\" = dead ] || return\n",
                "  command_window_present=0\n",
                "  if monitor_windows=$(LC_ALL=C tmux list-windows -t \"$session:\" -F '#{{window_name}}' 2>&1); then\n",
                "    if printf '%s\\n' \"$monitor_windows\" | grep -Fqx \"$window\"; then command_window_present=1; fi\n",
                "  else\n",
                "    case \"$monitor_windows\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) ;; *) return ;; esac\n",
                "  fi\n",
                "  if [ \"$command_window_present\" -eq 1 ]; then\n",
                "    stored_window_id=$(cat \"$root/window-id\" 2>/dev/null || true)\n",
                "    stored_pane_id=$(cat \"$root/pane-id\" 2>/dev/null || true)\n",
                "    [ -n \"$stored_window_id\" ] && [ -n \"$stored_pane_id\" ] || return\n",
                "    [ \"$(tmux list-panes -t \"$session:$window\" -F '#{{pane_id}}' 2>/dev/null | wc -l | tr -d ' ')\" = 1 ] || return\n",
                "    pane_observation=$(tmux display-message -p -t \"$session:$window.0\" '#{{window_id}}:#{{pane_id}}:#{{pane_pid}}:#{{pane_dead}}' 2>/dev/null || true)\n",
                "    [ \"$pane_observation\" = \"$stored_window_id:$stored_pane_id:$pane_pid:1\" ] || return\n",
                "  fi\n",
                "  monitor_execution_dead=1\n",
                "}}\n",
                "agentapp_monitor_output_closed() {{\n",
                "  monitor_output_closed=0\n",
                "  if [ \"$tty\" = 0 ]; then monitor_output_closed=1; return; fi\n",
                "  output_pipe_generation=$(cat \"$root/output-pipe-generation\" 2>/dev/null || true)\n",
                "  if [ -z \"$output_pipe_generation\" ]; then [ -f \"$root/output-closed\" ] && monitor_output_closed=1; return; fi\n",
                "  case \"$output_pipe_generation\" in *[!0-9]*) return ;; esac\n",
                "  [ -f \"$root/output-closed.$output_pipe_generation\" ] && monitor_output_closed=1\n",
                "}}\n",
                "while :; do\n",
                "  if [ \"$(cat \"$root/controller\" 2>/dev/null || true)\" != \"$controller\" ] || [ \"$(cat \"$root/digest\" 2>/dev/null || true)\" != \"$digest\" ]; then exit 125; fi\n",
                "  now=$(date +%s)\n",
                "  if [ $((now - attached_at)) -ge \"$attachment_seconds\" ]; then exit 124; fi\n",
                "  agentapp_monitor_detect_dead_execution\n",
                "  agentapp_monitor_output_closed\n",
                "  date +%s > \"$root/lease.tmp\" && mv \"$root/lease.tmp\" \"$root/lease\"\n",
                "  bytes=0\n",
                "  if [ -f \"$root/output\" ]; then bytes=$(wc -c < \"$root/output\"); fi\n",
                "  if [ \"$bytes\" -ge \"$offset\" ]; then\n",
                "    count=$((bytes - offset + 1))\n",
                "    tail -c +\"$offset\" \"$root/output\" | head -c \"$count\"\n",
                "    offset=$((offset + count))\n",
                "    stable=0\n",
                "  elif [ -f \"$root/status\" ] && [ \"$monitor_output_closed\" -eq 1 ]; then\n",
                "    stable=$((stable + 1))\n",
                "    if [ \"$stable\" -ge 3 ]; then\n",
                "      code=$(cat \"$root/status\" 2>/dev/null || printf '125')\n",
                "      case \"$code\" in ''|*[!0-9]*) code=125 ;; esac\n",
                "      exit \"$code\"\n",
                "    fi\n",
                "  elif [ \"$monitor_execution_dead\" -eq 1 ] && [ \"$monitor_output_closed\" -eq 1 ]; then\n",
                "    stable=$((stable + 1))\n",
                "    if [ \"$stable\" -ge 3 ]; then exit 125; fi\n",
                "  else\n",
                "    stable=0\n",
                "  fi\n",
                "  sleep 1\n",
                "done\n"
            ),
            controller = shell_quote(&self.controller_id),
            digest = shell_quote(&self.command_digest),
            session = shell_quote(&self.session_name),
            window = shell_quote(&self.window_name),
            tty = if self.tty { "1" } else { "0" },
            attachment_seconds = MONITOR_ATTACHMENT_SECONDS,
            root = root,
            first_byte = first_byte,
        )
    }

    fn recover_dead_execution_command(&self) -> String {
        let root = self.remote_directory();
        let recovery_key = stable_identifier(&format!(
            "{}:{}:live-dead-pane",
            self.agent_id, self.process_id
        ));
        format!(
            concat!(
                "set -eu\n",
                "root=\"{root}\"\n",
                "session={session}\n",
                "window={window}\n",
                "watchdog_window={watchdog_window}\n",
                "{output_drain_function}",
                "{ownership}\n",
                "if [ -f \"$root/status\" ]; then\n",
                "  agentapp_wait_for_output_drain\n",
                "  code=$(cat \"$root/status\" 2>/dev/null || true)\n",
                "  case \"$code\" in ''|*[!0-9-]*) echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82 ;; esac\n",
                "  printf 'terminal %s\\n' \"$code\"\n",
                "  exit 0\n",
                "fi\n",
                "process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
                "pane_pid=${{process_identity%%:*}}\n",
                "pgid=${{process_identity#*:}}\n",
                "case \"$process_identity\" in *:*:*) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac\n",
                "case \"$pane_pid:$pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac\n",
                "group_state=unknown\n",
                "if /bin/kill -0 -- \"-$pgid\" 2>/dev/null; then group_state=alive; elif kill_error=$(LC_ALL=C /bin/kill -0 -- \"-$pgid\" 2>&1); then group_state=alive; else case \"$kill_error\" in *\"No such process\"*) group_state=dead ;; esac; fi\n",
                "if [ \"$group_state\" != dead ]; then printf 'not-dead\\n'; exit 0; fi\n",
                "pane_dead_status=-\n",
                "command_window_present=0\n",
                "if window_listing=$(LC_ALL=C tmux list-windows -t \"$session:\" -F '#{{window_name}}' 2>&1); then\n",
                "  if printf '%s\\n' \"$window_listing\" | grep -Fqx \"$window\"; then command_window_present=1; fi\n",
                "else\n",
                "  case \"$window_listing\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) ;; *) echo AGENTAPP_TMUX_RECONCILE_WINDOW_QUERY_FAILED >&2; exit 77 ;; esac\n",
                "fi\n",
                "if [ \"$command_window_present\" -eq 1 ]; then\n",
                "  stored_window_id=$(cat \"$root/window-id\" 2>/dev/null || true)\n",
                "  stored_pane_id=$(cat \"$root/pane-id\" 2>/dev/null || true)\n",
                "  [ -n \"$stored_window_id\" ] && [ -n \"$stored_pane_id\" ] || {{ echo AGENTAPP_TMUX_NATIVE_IDENTITY_MISSING >&2; exit 80; }}\n",
                "  [ \"$(tmux list-panes -t \"$session:$window\" -F '#{{pane_id}}' 2>/dev/null | wc -l | tr -d ' ')\" = 1 ] || {{ echo AGENTAPP_TMUX_PANE_COUNT_MISMATCH >&2; exit 80; }}\n",
                "  pane_observation=$(tmux display-message -p -t \"$session:$window.0\" '#{{window_id}}|#{{pane_id}}|#{{pane_pid}}|#{{pane_dead}}|#{{pane_dead_status}}|#{{pane_dead_signal}}|end' 2>/dev/null || true)\n",
                "  old_ifs=$IFS; IFS='|'; set -- $pane_observation; IFS=$old_ifs\n",
                "  [ \"$#\" -eq 7 ] && [ \"$7\" = end ] || {{ echo AGENTAPP_TMUX_DEAD_PANE_IDENTITY_UNKNOWN >&2; exit 80; }}\n",
                "  [ \"$1:$2:$3:$4\" = \"$stored_window_id:$stored_pane_id:$pane_pid:1\" ] || {{ echo AGENTAPP_TMUX_DEAD_PANE_IDENTITY_MISMATCH >&2; exit 80; }}\n",
                "  if [ -n \"$5\" ] && [ -z \"$6\" ]; then case \"$5\" in *[!0-9-]*) echo AGENTAPP_TMUX_DEAD_PANE_STATUS_UNKNOWN >&2; exit 80 ;; esac; pane_dead_status=exit:$5; elif [ -z \"$5\" ] && [ -n \"$6\" ]; then case \"$6\" in *[!0-9A-Za-z_-]*) echo AGENTAPP_TMUX_DEAD_PANE_STATUS_UNKNOWN >&2; exit 80 ;; esac; pane_dead_status=signal:$6; elif [ -z \"$5\" ] && [ -z \"$6\" ]; then pane_dead_status=unknown; else echo AGENTAPP_TMUX_DEAD_PANE_STATUS_UNKNOWN >&2; exit 80; fi\n",
                "fi\n",
                "{ownership}\n",
                "[ ! -f \"$root/status\" ] || {{ code=$(cat \"$root/status\" 2>/dev/null || true); printf 'terminal %s\\n' \"$code\"; exit 0; }}\n",
                "operation_pid=$$\n",
                "operation_pgid=$(command -p ps -o pgid= -p \"$operation_pid\" 2>/dev/null | tr -d ' ')\n",
                "case \"$operation_pid:$operation_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "[ \"$operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80; }}\n",
                "current_controller=$(cat \"$root/controller\" 2>/dev/null || true)\n",
                "case \"$current_controller\" in *:*) ;; *) echo AGENTAPP_TMUX_CONTROLLER_UNKNOWN >&2; exit 80 ;; esac\n",
                "agentapp_recovery_probe_operation_group() {{\n",
                "  recovery_operation_group_state=unknown\n",
                "  if /bin/kill -0 -- \"-$1\" 2>/dev/null; then recovery_operation_group_state=alive; return; fi\n",
                "  if recovery_operation_error=$(LC_ALL=C /bin/kill -0 -- \"-$1\" 2>&1); then recovery_operation_group_state=alive; return; fi\n",
                "  case \"$recovery_operation_error\" in *\"No such process\"*) recovery_operation_group_state=dead ;; esac\n",
                "}}\n",
                "if [ -e \"$root/transition-claim\" ]; then\n",
                "  expected_recovery_claim=$(cat \"$root/transition-claim\" 2>/dev/null || true)\n",
                "  old_ifs=$IFS; IFS='|'\n",
                "  read claim_kind claim_nonce claim_controller claim_operation_pid claim_operation_pgid claim_window claim_pane claim_pgid <<AGENTAPP_RECOVERY_CLAIM_EOF\n",
                "$expected_recovery_claim\n",
                "AGENTAPP_RECOVERY_CLAIM_EOF\n",
                "  IFS=$old_ifs\n",
                "  [ \"$claim_kind\" = recovery ] || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  case \"$claim_nonce\" in r_*[!0-9a-zA-Z_.-]*|r_) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; r_*) ;; *) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
                "  case \"$claim_operation_pid:$claim_operation_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
                "  [ \"$claim_controller\" = \"$current_controller\" ] && [ \"$claim_window:$claim_pane:$claim_pgid\" = \"$window:$pane_pid:$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "  [ \"$claim_operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "  transition_candidate=\"$root/.transition-candidate.$claim_nonce.$claim_operation_pid\"\n",
                "  [ -f \"$transition_candidate\" ] && [ ! -L \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$transition_candidate\" 2>/dev/null || true)\" = \"$expected_recovery_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  live_operation_pgid=$(command -p ps -o pgid= -p \"$claim_operation_pid\" 2>/dev/null | tr -d ' ')\n",
                "  [ \"$live_operation_pgid\" != \"$claim_operation_pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  agentapp_recovery_probe_operation_group \"$claim_operation_pgid\"\n",
                "  case \"$recovery_operation_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79 ;; *) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "else\n",
                "  transition_candidate=\"$root/.transition-candidate.r_{recovery_key}.$operation_pid\"\n",
                "  expected_recovery_claim=\"recovery|r_{recovery_key}|$current_controller|$operation_pid|$operation_pgid|$window|$pane_pid|$pgid\"\n",
                "  ( umask 077; set -C; printf '%s\\n' \"$expected_recovery_claim\" > \"$transition_candidate\" ) || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  ln \"$transition_candidate\" \"$root/transition-claim\" 2>/dev/null || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "fi\n",
                "release_recovery_claim() {{ if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_recovery_claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; }}\n",
                "require_recovery_claim() {{ [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_recovery_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}; }}\n",
                "trap 'release_recovery_claim' EXIT HUP INT TERM\n",
                "require_recovery_claim\n",
                "[ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$current_controller\" ] && [ \"$(cat \"$root/state\" 2>/dev/null || true)\" = running ] && [ ! -f \"$root/status\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
                "state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "if [ ! -e \"$root/terminal-claim\" ]; then mkdir \"$root/terminal-claim\" 2>/dev/null || true; fi\n",
                "[ -d \"$root/terminal-claim\" ] && [ ! -L \"$root/terminal-claim\" ] || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}\n",
                "for terminal_entry in \"$root/terminal-claim\"/* \"$root/terminal-claim\"/.[!.]* \"$root/terminal-claim\"/..?*; do [ ! -e \"$terminal_entry\" ] || {{ [ \"${{terminal_entry##*/}}\" = kind ] || [ \"${{terminal_entry##*/}}\" = kind.tmp ]; }} || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}; done\n",
                "terminal_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
                "case \"$state:$terminal_kind\" in\n",
                "  running:|running:completed|running:recovery-lost|completed:completed|recovery-lost:recovery-lost) terminal_state=recovery-lost; terminal_status=125 ;;\n",
                "  running:terminated|terminated:terminated) terminal_state=terminated; terminal_status=143 ;;\n",
                "  running:launch-interrupted|launch-interrupted:launch-interrupted) terminal_state=launch-interrupted; terminal_status=125 ;;\n",
                "  *) echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82 ;;\n",
                "esac\n",
                "if [ \"$terminal_state\" = recovery-lost ]; then\n",
                "  printf 'recovery-lost\\n' > \"$root/terminal-claim/kind.tmp\"\n",
                "  mv \"$root/terminal-claim/kind.tmp\" \"$root/terminal-claim/kind\"\n",
                "fi\n",
                "require_recovery_claim\n",
                "if [ \"$pane_dead_status\" != - ]; then\n",
                "  printf '%s\\n' \"$pane_dead_status\" > \"$root/pane-death-status.tmp\"\n",
                "  mv \"$root/pane-death-status.tmp\" \"$root/pane-death-status\"\n",
                "fi\n",
                "require_recovery_claim\n",
                "{termination}\n",
                "require_recovery_claim\n",
                "agentapp_wait_for_output_drain\n",
                "require_recovery_claim\n",
                "[ -e \"$root/output\" ] || : > \"$root/output\"\n",
                "{ownership}\n",
                "require_recovery_claim\n",
                "printf '%s\\n' \"$terminal_status\" > \"$root/status.tmp\"\n",
                "mv \"$root/status.tmp\" \"$root/status\"\n",
                "printf '%s\\n' \"$terminal_state\" > \"$root/state.tmp\"\n",
                "mv \"$root/state.tmp\" \"$root/state\"\n",
                "rm -f \"$root/recovery-required\"\n",
                "release_recovery_claim\n",
                "trap - EXIT HUP INT TERM\n",
                "printf 'terminal %s\\n' \"$terminal_status\"\n"
            ),
            root = root,
            session = shell_quote(&self.session_name),
            window = shell_quote(&self.window_name),
            watchdog_window = shell_quote(&self.watchdog_window_name),
            ownership = self.ownership_guard(),
            recovery_key = recovery_key,
            termination = self.confirmed_process_group_termination(),
            output_drain_function = output_drain_function_fragment(),
        )
    }

    async fn recover_dead_execution(
        &self,
        transport: &crate::ssh_transport::SshTransport,
    ) -> Result<Option<i32>, ExecServerError> {
        let command = self.recover_dead_execution_command();
        let result = transport
            .exec_control(&with_remote_path(&command), None)
            .await?;
        if result.exit_code != 0 {
            return Err(ExecServerError::Protocol(format!(
                "ssh tmux dead execution recovery failed with exit {}: {}",
                result.exit_code,
                String::from_utf8_lossy(&result.output).trim()
            )));
        }
        let line = String::from_utf8_lossy(&result.output);
        let line = line.trim();
        if line == "not-dead" {
            Ok(None)
        } else if let Some(code) = line.strip_prefix("terminal ") {
            Ok(Some(code.parse().map_err(|_| {
                ExecServerError::Protocol(
                    "ssh tmux dead execution recovery returned invalid status".to_string(),
                )
            })?))
        } else {
            Err(ExecServerError::Protocol(
                "ssh tmux dead execution recovery returned invalid result".to_string(),
            ))
        }
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
                "stored_window_id=$(cat \"$root/window-id\" 2>/dev/null || true); stored_pane_id=$(cat \"$root/pane-id\" 2>/dev/null || true); ",
                "{{ [ -n \"$stored_window_id\" ] && [ -n \"$stored_pane_id\" ]; }} || {{ [ -z \"$stored_window_id\" ] && [ -z \"$stored_pane_id\" ]; }} || {{ echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80; }}; ",
                "current_identity=$(tmux display-message -p -t {target} '#{{window_id}}:#{{pane_id}}:#{{pane_pid}}:#{{pane_dead}}' 2>/dev/null || true); ",
                "old_ifs=$IFS; IFS=:; set -- $current_identity; IFS=$old_ifs; [ \"$#\" -eq 4 ] || {{ echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80; }}; ",
                "window_id=$1; pane_id=$2; current_pane=$3; pane_dead=$4; ",
                "if [ -n \"$stored_window_id\" ]; then [ \"$stored_window_id:$stored_pane_id\" = \"$window_id:$pane_id\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; fi; ",
                "[ \"$pane_dead\" = 0 ] || {{ echo AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; ",
                "case \"$window_id\" in @*) ;; *) echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80 ;; esac; ",
                "case \"$pane_id\" in %*) ;; *) echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80 ;; esac; ",
                "case \"$current_pane\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80 ;; esac; ",
                "current_pgid=$(command -p ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' '); ",
                "[ \"$current_pane:$current_pgid\" = \"$stored_identity\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; ",
                "[ -f \"$root/payload-ready\" ] && [ -f \"$root/payload-identity\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; ",
                "payload_identity=$(cat \"$root/payload-identity\" 2>/dev/null || true); payload_pid=${{payload_identity%%:*}}; payload_pgid=${{payload_identity#*:}}; ",
                "case \"$payload_pid:$payload_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80 ;; esac; ",
                "[ \"$payload_pid\" != \"$pane_pid\" ] && [ \"$payload_pgid\" = \"$pgid\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_IDENTITY_UNKNOWN >&2; exit 80; }}; ",
                "live_payload_pgid=$(command -p ps -o pgid= -p \"$payload_pid\" 2>/dev/null | tr -d ' '); ",
                "[ \"$live_payload_pgid\" = \"$payload_pgid\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; ",
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
                "rechecked_identity=$(tmux display-message -p -t \"$pane_id\" '#{{window_id}}:#{{pane_id}}:#{{pane_pid}}:#{{pane_dead}}' 2>/dev/null || true); ",
                "[ \"$rechecked_identity\" = \"$current_identity\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; ",
                "rechecked_pgid=$(command -p ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' '); ",
                "[ \"$current_pane:$rechecked_pgid\" = \"$stored_identity\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; ",
                "rechecked_payload_pgid=$(command -p ps -o pgid= -p \"$payload_pid\" 2>/dev/null | tr -d ' '); [ \"$rechecked_payload_pgid\" = \"$payload_pgid\" ] || {{ echo AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH >&2; exit 80; }}; ",
                "require_interrupt_claim; ",
                "/bin/kill -INT -- \"-$payload_pgid\"; ",
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
        let command = self.termination_command();
        self.run_control(transport, &command, "terminate").await
    }

    fn termination_command(&self) -> String {
        let root = self.remote_directory();
        let termination_key = stable_identifier(&format!(
            "{}:{}:termination",
            self.agent_id, self.process_id
        ));
        format!(
            concat!(
                "set -eu\n",
                "root=\"{root}\"\n",
                "session={session}\n",
                "window={window}\n",
                "watchdog_window={watchdog_window}\n",
                "{output_drain_function}",
                "{ownership}\n",
                "process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
                "pane_pid=${{process_identity%%:*}}\n",
                "pgid=${{process_identity#*:}}\n",
                "case \"$process_identity\" in *:*:*) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac\n",
                "case \"$pane_pid:$pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac\n",
                "current_controller=$(cat \"$root/controller\" 2>/dev/null || true)\n",
                "case \"$current_controller\" in *:*) ;; *) echo AGENTAPP_TMUX_CONTROLLER_UNKNOWN >&2; exit 80 ;; esac\n",
                "operation_pid=$$\n",
                "operation_pgid=$(command -p ps -o pgid= -p \"$operation_pid\" 2>/dev/null | tr -d ' ')\n",
                "case \"$operation_pid:$operation_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "[ \"$operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80; }}\n",
                "agentapp_termination_probe_operation_group() {{\n",
                "  termination_operation_group_state=unknown\n",
                "  if /bin/kill -0 -- \"-$1\" 2>/dev/null; then termination_operation_group_state=alive; return; fi\n",
                "  if termination_operation_error=$(LC_ALL=C /bin/kill -0 -- \"-$1\" 2>&1); then termination_operation_group_state=alive; return; fi\n",
                "  case \"$termination_operation_error\" in *\"No such process\"*) termination_operation_group_state=dead ;; esac\n",
                "}}\n",
                "if [ -e \"$root/transition-claim\" ]; then\n",
                "  expected_termination_claim=$(cat \"$root/transition-claim\" 2>/dev/null || true)\n",
                "  old_ifs=$IFS; IFS='|'\n",
                "  read claim_kind claim_nonce claim_controller claim_operation_pid claim_operation_pgid claim_window claim_pane claim_pgid <<AGENTAPP_TERMINATION_CLAIM_EOF\n",
                "$expected_termination_claim\n",
                "AGENTAPP_TERMINATION_CLAIM_EOF\n",
                "  IFS=$old_ifs\n",
                "  [ \"$claim_kind\" = termination ] || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  case \"$claim_nonce\" in t_*[!0-9a-zA-Z_.-]*|t_) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; t_*) ;; *) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
                "  case \"$claim_operation_pid:$claim_operation_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
                "  [ \"$claim_controller\" = \"$current_controller\" ] && [ \"$claim_window:$claim_pane:$claim_pgid\" = \"$window:$pane_pid:$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "  [ \"$claim_operation_pgid\" != \"$pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80; }}\n",
                "  transition_candidate=\"$root/.transition-candidate.$claim_nonce.$claim_operation_pid\"\n",
                "  [ -f \"$transition_candidate\" ] && [ ! -L \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$transition_candidate\" 2>/dev/null || true)\" = \"$expected_termination_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "  live_operation_pgid=$(command -p ps -o pgid= -p \"$claim_operation_pid\" 2>/dev/null | tr -d ' ')\n",
                "  [ \"$live_operation_pgid\" != \"$claim_operation_pgid\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  agentapp_termination_probe_operation_group \"$claim_operation_pgid\"\n",
                "  case \"$termination_operation_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79 ;; *) echo AGENTAPP_TMUX_TRANSITION_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
                "else\n",
                "  transition_candidate=\"$root/.transition-candidate.t_{termination_key}.$operation_pid\"\n",
                "  expected_termination_claim=\"termination|t_{termination_key}|$current_controller|$operation_pid|$operation_pgid|$window|$pane_pid|$pgid\"\n",
                "  ( umask 077; set -C; printf '%s\\n' \"$expected_termination_claim\" > \"$transition_candidate\" ) || {{ echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "  ln \"$transition_candidate\" \"$root/transition-claim\" 2>/dev/null || {{ rm -f \"$transition_candidate\"; echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79; }}\n",
                "fi\n",
                "release_termination_claim() {{ if [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_termination_claim\" ]; then rm -f \"$root/transition-claim\"; fi; rm -f \"$transition_candidate\"; }}\n",
                "trap ':' HUP INT TERM\n",
                "require_termination_claim() {{ [ -f \"$transition_candidate\" ] && [ \"$transition_candidate\" -ef \"$root/transition-claim\" ] && [ \"$(cat \"$root/transition-claim\" 2>/dev/null || true)\" = \"$expected_termination_claim\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}; }}\n",
                "require_termination_claim\n",
                "[ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$current_controller\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "{ownership}\n",
                "current_state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "if [ -f \"$root/status\" ]; then\n",
                "  [ \"$(cat \"$root/status\" 2>/dev/null || true)\" = 143 ] && [ \"$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\" = terminated ] || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}\n",
                "  case \"$current_state\" in running|terminated) ;; *) echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82 ;; esac\n",
                "  printf 'terminated\\n' > \"$root/state.tmp\"\n",
                "  mv \"$root/state.tmp\" \"$root/state\"\n",
                "  release_termination_claim\n",
                "  trap - HUP INT TERM\n",
                "  exit 0\n",
                "fi\n",
                "[ \"$current_state\" = running ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
                "claimed=0\n",
                "if mkdir \"$root/terminal-claim\" 2>/dev/null; then\n",
                "  claimed=1\n",
                "  printf 'terminated\\n' > \"$root/terminal-claim/kind.tmp\"\n",
                "  mv \"$root/terminal-claim/kind.tmp\" \"$root/terminal-claim/kind\"\n",
                "fi\n",
                "require_termination_claim\n",
                "[ \"$(cat \"$root/controller\" 2>/dev/null || true)\" = \"$current_controller\" ] || {{ echo AGENTAPP_TMUX_TRANSITION_CHANGED >&2; exit 79; }}\n",
                "{ownership}\n",
                "{termination}\n",
                "require_termination_claim\n",
                "agentapp_wait_for_output_drain\n",
                "require_termination_claim\n",
                "{ownership}\n",
                "terminal_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
                "if [ \"$claimed\" -eq 1 ] || {{ [ \"$terminal_kind\" = terminated ] && [ ! -f \"$root/status\" ]; }}; then\n",
                "  [ \"$terminal_kind\" = terminated ] || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}\n",
                "  printf '143\\n' > \"$root/status.tmp\"\n",
                "  mv \"$root/status.tmp\" \"$root/status\"\n",
                "  printf 'terminated\\n' > \"$root/state.tmp\"\n",
                "  mv \"$root/state.tmp\" \"$root/state\"\n",
                "else\n",
                "  i=0\n",
                "  while [ ! -f \"$root/status\" ] && [ \"$i\" -lt 30 ]; do sleep 1; i=$((i + 1)); done\n",
                "  [ -f \"$root/status\" ] || {{ echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82; }}\n",
                "fi\n",
                "release_termination_claim\n",
                "trap - HUP INT TERM\n"
            ),
            root = root,
            session = shell_quote(&self.session_name),
            ownership = self.ownership_guard(),
            termination_key = termination_key,
            window = shell_quote(&self.window_name),
            watchdog_window = shell_quote(&self.watchdog_window_name),
            termination = self.confirmed_process_group_termination(),
            output_drain_function = output_drain_function_fragment(),
        )
    }

    async fn cleanup(
        &self,
        transport: &crate::ssh_transport::SshTransport,
    ) -> Result<(), ExecServerError> {
        self.run_control(transport, &self.cleanup_command(), "cleanup")
            .await
    }

    fn cleanup_command(&self) -> String {
        let root = self.remote_directory();
        format!(
            "root=\"{root}\"; session={session}; window={window}; watchdog_window={watchdog_window}; if {}; then {}; fi",
            self.ownership_check(),
            self.confirmed_process_group_termination(),
            session = shell_quote(&self.session_name),
            window = shell_quote(&self.window_name),
            watchdog_window = shell_quote(&self.watchdog_window_name),
        )
    }

    fn confirmed_process_group_termination(&self) -> String {
        format!(
            "{}\n{}",
            self.confirmed_process_group_stop(),
            self.retire_confirmed_process_windows(true)
        )
    }

    fn confirmed_process_group_stop(&self) -> String {
        concat!(
            "process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
            "pane_pid=${process_identity%%:*}\n",
            "pgid=${process_identity#*:}\n",
            "case \"$pane_pid:$pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac\n",
            "stored_window_id=$(cat \"$root/window-id\" 2>/dev/null || true)\n",
            "stored_pane_id=$(cat \"$root/pane-id\" 2>/dev/null || true)\n",
            "{ [ -n \"$stored_window_id\" ] && [ -n \"$stored_pane_id\" ]; } || { [ -z \"$stored_window_id\" ] && [ -z \"$stored_pane_id\" ]; } || { echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80; }\n",
            "payload_identity=$(cat \"$root/payload-identity\" 2>/dev/null || true)\n",
            "has_payload=0\n",
            "payload_pid=\n",
            "payload_pgid=\n",
            "if [ -n \"$payload_identity\" ] || [ -f \"$root/payload-ready\" ]; then\n",
            "  payload_pid=${payload_identity%%:*}\n",
            "  payload_pgid=${payload_identity#*:}\n",
            "  case \"$payload_pid:$payload_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_PAYLOAD_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "  [ \"$payload_pid\" != \"$pane_pid\" ] && [ \"$payload_pgid\" = \"$pgid\" ] || { echo AGENTAPP_TMUX_PAYLOAD_GROUP_MISMATCH >&2; exit 80; }\n",
            "  has_payload=1\n",
            "fi\n",
            "agentapp_termination_probe_group() {\n",
            "  agentapp_termination_group_state=unknown\n",
            "  termination_group=$1\n",
            "  [ -x /bin/kill ] || return\n",
            "  if /bin/kill -0 -- \"-$termination_group\" 2>/dev/null; then agentapp_termination_group_state=alive; return; fi\n",
            "  if agentapp_kill_error=$(LC_ALL=C /bin/kill -0 -- \"-$termination_group\" 2>&1); then agentapp_termination_group_state=alive; return; fi\n",
            "  case \"$agentapp_kill_error\" in *\"No such process\"*) agentapp_termination_group_state=dead ;; esac\n",
            "}\n",
            "agentapp_termination_stop_payload() {\n",
            "  [ \"$has_payload\" -eq 1 ] || return 0\n",
            "  live_payload_pgid=$(command -p ps -o pgid= -p \"$payload_pid\" 2>/dev/null | tr -d ' ')\n",
            "  if [ \"$live_payload_pgid\" = \"$payload_pgid\" ]; then\n",
            "    /bin/kill -TERM -- \"-$payload_pgid\" 2>/dev/null || true\n",
            "    i=0\n",
            "    while [ \"$i\" -lt 10 ]; do current_payload_pgid=$(command -p ps -o pgid= -p \"$payload_pid\" 2>/dev/null | tr -d ' '); [ \"$current_payload_pgid\" = \"$payload_pgid\" ] || break; sleep 1; i=$((i + 1)); done\n",
            "    current_payload_pgid=$(command -p ps -o pgid= -p \"$payload_pid\" 2>/dev/null | tr -d ' ')\n",
            "    if [ \"$current_payload_pgid\" = \"$payload_pgid\" ]; then /bin/kill -KILL -- \"-$payload_pgid\" 2>/dev/null || true; i=0; while [ \"$i\" -lt 5 ]; do current_payload_pgid=$(command -p ps -o pgid= -p \"$payload_pid\" 2>/dev/null | tr -d ' '); [ \"$current_payload_pgid\" = \"$payload_pgid\" ] || break; sleep 1; i=$((i + 1)); done; fi\n",
            "  elif [ -n \"$live_payload_pgid\" ]; then\n",
            "    echo AGENTAPP_TMUX_PAYLOAD_IDENTITY_MISMATCH >&2\n",
            "    exit 80\n",
            "  fi\n",
            "}\n",
            "window_exists=0\n",
            "current_window_id=\n",
            "if tmux list-windows -t \"$session\" -F '#{window_name}' 2>/dev/null | grep -Fqx \"$window\"; then window_exists=1; fi\n",
            "if [ \"$window_exists\" -eq 1 ]; then\n",
            "  [ \"$(tmux list-panes -t \"$session:$window\" -F '#{pane_id}' 2>/dev/null | wc -l | tr -d ' ')\" = 1 ] || { echo AGENTAPP_TMUX_PANE_COUNT_MISMATCH >&2; exit 80; }\n",
            "  pane_observation=$(tmux display-message -p -t \"$session:$window.0\" '#{window_id}:#{pane_id}:#{pane_pid}:#{pane_dead}' 2>/dev/null || true)\n",
            "  old_ifs=$IFS; IFS=:; set -- $pane_observation; IFS=$old_ifs\n",
            "  [ \"$#\" -eq 4 ] || { echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80; }\n",
            "  current_window_id=$1; current_pane_id=$2; current_pane=$3; current_pane_dead=$4\n",
            "  [ \"$current_pane\" = \"$pane_pid\" ] || { echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80; }\n",
            "  if [ -n \"$stored_window_id\" ]; then [ \"$stored_window_id:$stored_pane_id\" = \"$current_window_id:$current_pane_id\" ] || { echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80; }; fi\n",
            "  case \"$current_pane_dead\" in\n",
            "    0)\n",
            "      current_pgid=$(command -p ps -o pgid= -p \"$current_pane\" 2>/dev/null | tr -d ' ')\n",
            "      [ \"$current_pgid\" = \"$pgid\" ] || { echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80; }\n",
            "      agentapp_termination_stop_payload\n",
            "      if kill -0 \"-$pgid\" 2>/dev/null; then kill -TERM \"-$pgid\" 2>/dev/null || true; i=0; while kill -0 \"-$pgid\" 2>/dev/null && [ \"$i\" -lt 10 ]; do sleep 1; i=$((i + 1)); done; fi\n",
            "      if kill -0 \"-$pgid\" 2>/dev/null; then kill -KILL \"-$pgid\" 2>/dev/null || true; i=0; while kill -0 \"-$pgid\" 2>/dev/null && [ \"$i\" -lt 5 ]; do sleep 1; i=$((i + 1)); done; fi\n",
            "      ;;\n",
            "    1)\n",
            "      [ -n \"$stored_window_id\" ] || { echo AGENTAPP_TMUX_DEAD_PANE_IDENTITY_UNKNOWN >&2; exit 80; }\n",
            "      ;;\n",
            "    *) echo AGENTAPP_TMUX_PROCESS_IDENTITY_MISMATCH >&2; exit 80 ;;\n",
            "  esac\n",
            "elif kill -0 \"-$pgid\" 2>/dev/null; then\n",
            "  echo AGENTAPP_TMUX_PROCESS_IDENTITY_UNKNOWN >&2\n",
            "  exit 80\n",
            "fi\n",
            "agentapp_termination_probe_group \"$pgid\"\n",
            "case \"$agentapp_termination_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_PROCESS_GROUP_ALIVE >&2; exit 81 ;; *) echo AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN >&2; exit 80 ;; esac"
        )
        .to_string()
    }

    fn retire_confirmed_process_windows(&self, retire_watchdog: bool) -> String {
        let watchdog_retirement = if retire_watchdog {
            "tmux kill-window -t \"$session:$watchdog_window\" 2>/dev/null || true\n"
        } else {
            ""
        };
        format!(
            concat!(
                "if [ \"$window_exists\" -eq 1 ]; then tmux kill-window -t \"$current_window_id\" 2>/dev/null || true; fi\n",
                "if tmux list-windows -t \"$session\" -F '#{{window_name}}' 2>/dev/null | grep -Fqx \"$window\"; then echo AGENTAPP_TMUX_TERMINATION_UNCONFIRMED >&2; exit 78; fi\n",
                "{watchdog_retirement}",
                "tmux kill-window -t \"$session:__agentapp_keeper\" 2>/dev/null || true"
            ),
            watchdog_retirement = watchdog_retirement,
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
            "    tmux kill-window -t \"$expected_session:__agentapp_keeper\" 2>/dev/null || true\n",
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
        process_id = process_id,
        recovery_key = recovery_key,
    )
}

// A remote command can disappear before command.sh writes terminal descriptor
// fields. Reconciliation may retire that exact stale-running state only after
// proving that the descriptor is locally authoritative, its recorded process
// group is gone, and its exact command window is absent or is a retained dead
// pane whose native tmux identities match the descriptor. This deliberately
// records recovery loss rather than inventing a natural exit or claiming that
// a previously requested signal was delivered. Any live process, live pane,
// live transition, malformed identity, or failed tmux query remains ambiguous
// and fails closed.
fn stale_running_recovery_loss_fragment(agent_id: &str, process_id: &str) -> String {
    let recovery_key = stable_identifier(&format!("{agent_id}:{process_id}:stale-running"));
    format!(
        concat!(
            "  stale_terminal_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
            "  if [ \"$state\" = running ] && [ -e \"$root/go\" ]; then\n",
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
            "    agentapp_stale_command_window_state() {{\n",
            "      agentapp_stale_window_exists \"$expected_window\"\n",
            "      stale_command_window_dead=0\n",
            "      stale_command_window_id=\n",
            "      stale_pane_dead_status=-\n",
            "      if [ \"$stale_window_exists\" -eq 1 ]; then\n",
            "        stored_window_id=$(cat \"$root/window-id\" 2>/dev/null || true)\n",
            "        stored_pane_id=$(cat \"$root/pane-id\" 2>/dev/null || true)\n",
            "        [ -n \"$stored_window_id\" ] && [ -n \"$stored_pane_id\" ] || return 0\n",
            "        [ \"$(tmux list-panes -t \"$expected_session:$expected_window\" -F '#{{pane_id}}' 2>/dev/null | wc -l | tr -d ' ')\" = 1 ] || {{ echo AGENTAPP_TMUX_PANE_COUNT_MISMATCH >&2; exit 80; }}\n",
            "        pane_observation=$(tmux display-message -p -t \"$expected_session:$expected_window.0\" '#{{window_id}}|#{{pane_id}}|#{{pane_pid}}|#{{pane_dead}}|#{{pane_dead_status}}|#{{pane_dead_signal}}|end' 2>/dev/null || true)\n",
            "        old_ifs=$IFS; IFS='|'; set -- $pane_observation; IFS=$old_ifs\n",
            "        [ \"$#\" -eq 7 ] && [ \"$7\" = end ] || {{ echo AGENTAPP_TMUX_DEAD_PANE_IDENTITY_UNKNOWN >&2; exit 80; }}\n",
            "        if [ \"$1:$2:$3:$4\" = \"$stored_window_id:$stored_pane_id:$pane_pid:1\" ]; then\n",
            "          stale_command_window_dead=1\n",
            "          stale_command_window_id=$1\n",
            "          if [ -n \"$5\" ] && [ -z \"$6\" ]; then case \"$5\" in *[!0-9-]*) echo AGENTAPP_TMUX_DEAD_PANE_STATUS_UNKNOWN >&2; exit 80 ;; esac; stale_pane_dead_status=exit:$5; elif [ -z \"$5\" ] && [ -n \"$6\" ]; then case \"$6\" in *[!0-9A-Za-z_-]*) echo AGENTAPP_TMUX_DEAD_PANE_STATUS_UNKNOWN >&2; exit 80 ;; esac; stale_pane_dead_status=signal:$6; elif [ -z \"$5\" ] && [ -z \"$6\" ]; then stale_pane_dead_status=unknown; else echo AGENTAPP_TMUX_DEAD_PANE_STATUS_UNKNOWN >&2; exit 80; fi\n",
            "        fi\n",
            "      fi\n",
            "    }}\n",
            "    agentapp_stale_command_window_state\n",
            "    if [ \"$stale_window_exists\" -eq 0 ] || [ \"$stale_command_window_dead\" -eq 1 ]; then\n",
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
            "      stale_transition_kind=recovery\n",
            "      if [ -e \"$root/transition-claim\" ]; then\n",
            "        expected_stale_claim=$(cat \"$root/transition-claim\" 2>/dev/null || true)\n",
            "        old_ifs=$IFS; IFS='|'\n",
            "        read claim_kind claim_nonce claim_controller claim_operation_pid claim_operation_pgid claim_window claim_pane claim_pgid <<AGENTAPP_STALE_CLAIM_EOF\n",
            "$expected_stale_claim\n",
            "AGENTAPP_STALE_CLAIM_EOF\n",
            "        IFS=$old_ifs\n",
            "        case \"$claim_kind\" in recovery|bootstrap|interrupt|termination|expiry) ;; *) echo AGENTAPP_TMUX_TRANSITION_BUSY >&2; exit 79 ;; esac\n",
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
            "        stale_transition_kind=$claim_kind\n",
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
            "      agentapp_stale_command_window_state\n",
            "      payload_identity=$(cat \"$root/payload-identity\" 2>/dev/null || true)\n",
            "      if [ -n \"$payload_identity\" ] || [ -f \"$root/payload-ready\" ]; then\n",
            "        payload_pid=${{payload_identity%%:*}}\n",
            "        payload_pgid=${{payload_identity#*:}}\n",
            "        case \"$payload_pid:$payload_pgid\" in :|:*|*:|*[!0-9:]*) echo AGENTAPP_TMUX_PAYLOAD_IDENTITY_UNKNOWN >&2; exit 80 ;; esac\n",
            "        [ \"$payload_pid\" != \"$pane_pid\" ] && [ \"$payload_pgid\" = \"$pgid\" ] || {{ echo AGENTAPP_TMUX_PAYLOAD_GROUP_MISMATCH >&2; exit 80; }}\n",
            "        live_payload_pgid=$(command -p ps -o pgid= -p \"$payload_pid\" 2>/dev/null | tr -d ' ')\n",
            "        [ -z \"$live_payload_pgid\" ] || {{ echo AGENTAPP_TMUX_PAYLOAD_IDENTITY_MISMATCH >&2; exit 80; }}\n",
            "      fi\n",
            "      agentapp_require_stale_claim\n",
            "      if [ \"$stale_window_exists\" -eq 1 ]; then\n",
            "        [ \"$stale_command_window_dead\" -eq 1 ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
            "        printf '%s\\n' \"$stale_pane_dead_status\" > \"$root/pane-death-status.tmp\"\n",
            "        mv \"$root/pane-death-status.tmp\" \"$root/pane-death-status\"\n",
            "        agentapp_require_stale_claim\n",
            "        tmux kill-window -t \"$stale_command_window_id\" 2>/dev/null || true\n",
            "      fi\n",
            "      agentapp_stale_window_exists \"$expected_window\"\n",
            "      [ \"$stale_window_exists\" -eq 0 ] || {{ echo AGENTAPP_TMUX_TRANSITION_STATE_CHANGED >&2; exit 79; }}\n",
            "      agentapp_probe_process_group \"$pgid\"\n",
            "      case \"$agentapp_process_group_state\" in dead) ;; alive) echo AGENTAPP_TMUX_RECONCILE_PROCESS_WITHOUT_WINDOW >&2; exit 80 ;; *) echo AGENTAPP_TMUX_RECONCILE_PROCESS_QUERY_UNCERTAIN >&2; exit 80 ;; esac\n",
            "      agentapp_require_stale_claim\n",
            "      agentapp_stale_window_exists \"$watchdog_window\"\n",
            "      if [ \"$stale_window_exists\" -eq 1 ]; then tmux kill-window -t \"$expected_session:$watchdog_window\" 2>/dev/null || true; fi\n",
            "      agentapp_stale_window_exists \"$watchdog_window\"\n",
            "      [ \"$stale_window_exists\" -eq 0 ] || {{ echo AGENTAPP_TMUX_RECONCILE_WATCHDOG_PRESENT >&2; exit 78; }}\n",
            "      tmux kill-window -t \"$expected_session:__agentapp_keeper\" 2>/dev/null || true\n",
            "      agentapp_require_stale_claim\n",
            "      stale_terminal_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
            "      stale_terminal_status=$(cat \"$root/status\" 2>/dev/null || true)\n",
            "      terminal_state=\n",
            "      terminal_status=\n",
            "      if [ \"$stale_transition_kind:$stale_terminal_kind:$stale_terminal_status\" = termination:terminated: ]; then\n",
            "        terminal_state=terminated\n",
            "        terminal_status=143\n",
            "      else case \"$stale_terminal_kind:$stale_terminal_status\" in\n",
            "        completed:*[!0-9]*|completed:) terminal_state=recovery-lost; terminal_status=125 ;;\n",
            "        completed:*) terminal_state=completed; terminal_status=$stale_terminal_status ;;\n",
            "        terminated:143) terminal_state=terminated; terminal_status=143 ;;\n",
            "        expired:|expired:124) terminal_state=expired; terminal_status=124 ;;\n",
            "        recovery-lost:|recovery-lost:125) terminal_state=recovery-lost; terminal_status=125 ;;\n",
            "        launch-interrupted:125) terminal_state=launch-interrupted; terminal_status=125 ;;\n",
            "        :|terminated:) terminal_state=recovery-lost; terminal_status=125 ;;\n",
            "        *) echo AGENTAPP_TMUX_TERMINAL_STATE_UNKNOWN >&2; exit 82 ;;\n",
            "      esac; fi\n",
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
            "      if [ \"$terminal_state\" = expired ] && [ \"$(cat \"$root/tty\" 2>/dev/null || true)\" != 1 ] && [ ! -f \"$root/output-closed\" ]; then : > \"$root/output-closed.tmp\"; mv \"$root/output-closed.tmp\" \"$root/output-closed\"; fi\n",
            "      agentapp_wait_for_output_drain\n",
            "      agentapp_require_stale_claim\n",
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
            "{output_drain_function}",
        ),
        agent_id = agent_id,
        output_drain_function = output_drain_function_fragment(),
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
                "  for expected_session in agentapp_{agent_id}_{process_id} agentapp_{agent_id}; do\n",
                "    if session_probe=$(LC_ALL=C tmux has-session -t \"$expected_session\" 2>&1 >/dev/null); then\n",
                "      windows=$(LC_ALL=C tmux list-windows -t \"$expected_session:\" -F '#{{window_name}}' 2>&1) || {{ echo AGENTAPP_TMUX_RECONCILE_WINDOW_QUERY_FAILED >&2; exit 77; }}\n",
                "      if printf '%s\\n' \"$windows\" | grep -Fqx \"$expected_window\"; then echo AGENTAPP_TMUX_RECONCILE_ORPHAN_WINDOW >&2; exit 77; fi\n",
                "    else\n",
                "      session_status=$?\n",
                "      [ \"$session_status\" -eq 1 ] || {{ echo AGENTAPP_TMUX_RECONCILE_SESSION_QUERY_FAILED >&2; exit 77; }}\n",
                "      case \"$session_probe\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) ;; *) echo AGENTAPP_TMUX_RECONCILE_SESSION_QUERY_FAILED >&2; exit 77 ;; esac\n",
                "    fi\n",
                "  done\n",
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
                "  default_session=agentapp_{agent_id}_{process_id}\n",
                "  legacy_session=agentapp_{agent_id}\n",
                "  stored_session=$(cat \"$root/session\" 2>/dev/null || true)\n",
                "  if [ -z \"$stored_session\" ]; then expected_session=$legacy_session; elif [ \"$stored_session\" = \"$default_session\" ] || [ \"$stored_session\" = \"$legacy_session\" ]; then expected_session=$stored_session; else echo AGENTAPP_TMUX_RECONCILE_SESSION_NAME_CONFLICT >&2; exit 77; fi\n",
                "  state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "{prepared_rollback}",
                "{stale_running_recovery_loss}",
                "  state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "  case \"$state\" in completed|terminated|expired|recovery-lost|launch-interrupted) agentapp_wait_for_output_drain ;; esac\n",
                "  cursor=$(wc -c < \"$root/output\" 2>/dev/null || printf '0'); cursor=$(printf '%s' \"$cursor\" | tr -d ' ')\n",
                "  state=$(cat \"$root/state\" 2>/dev/null || true)\n",
                "  delivery_unknown=0\n",
                "  terminal_verified_dead=0\n",
                "  code=$(cat \"$root/status\" 2>/dev/null || printf '-')\n",
                "  case \"$state\" in completed) recovered=completed ;; terminated) recovered=terminated ;; expired) recovered=expired ;; recovery-lost) recovered=recovery-lost ;; launch-interrupted) recovered=launch-interrupted ;; running) if [ -e \"$root/go\" ]; then recovered=running; else recovered=unknown; fi ;; prepared) if [ -e \"$root/go\" ]; then recovered=running; else recovered=prepared; fi ;; *) recovered=unknown ;; esac\n",
                "  if [ \"$recovered\" = completed ] || [ \"$recovered\" = terminated ] || [ \"$recovered\" = expired ] || [ \"$recovered\" = recovery-lost ] || [ \"$recovered\" = launch-interrupted ]; then\n",
                "    process_identity=$(cat \"$root/process-identity\" 2>/dev/null || true)\n",
                "    pane_pid=${{process_identity%%:*}}; pgid=${{process_identity#*:}}\n",
                "    window=$(cat \"$root/window\" 2>/dev/null || true); expected_window=p_{process_id}\n",
                "    claim_kind=$(cat \"$root/terminal-claim/kind\" 2>/dev/null || true)\n",
                "    identity_valid=1\n",
                "    [ \"$window\" = \"$expected_window\" ] || identity_valid=0\n",
                "    case \"$recovered:$claim_kind\" in completed:completed|terminated:terminated|expired:expired|recovery-lost:recovery-lost|launch-interrupted:launch-interrupted) ;; *) identity_valid=0 ;; esac\n",
                "    if [ \"$recovered\" = completed ]; then case \"$code\" in ''|*[!0-9-]*) identity_valid=0 ;; esac; fi\n",
                "    if [ \"$recovered\" = expired ] && [ \"$code\" != 124 ]; then identity_valid=0; fi\n",
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
                "    if terminal_windows=$(LC_ALL=C tmux list-windows -t \"$expected_session:\" -F '#{{window_name}}' 2>&1); then\n",
                "      if ! printf '%s\\n' \"$terminal_windows\" | grep -Fqx \"$expected_window\"; then\n",
                "        window_absent=1\n",
                "      elif [ \"$process_dead\" -eq 1 ]; then\n",
                "        stored_window_id=$(cat \"$root/window-id\" 2>/dev/null || true)\n",
                "        stored_pane_id=$(cat \"$root/pane-id\" 2>/dev/null || true)\n",
                "        if [ -n \"$stored_window_id\" ] && [ -n \"$stored_pane_id\" ] && [ \"$(tmux list-panes -t \"$expected_session:$expected_window\" -F '#{{pane_id}}' 2>/dev/null | wc -l | tr -d ' ')\" = 1 ]; then\n",
                "          terminal_pane=$(tmux display-message -p -t \"$expected_session:$expected_window.0\" '#{{window_id}}:#{{pane_id}}:#{{pane_pid}}:#{{pane_dead}}' 2>/dev/null || true)\n",
                "          if [ \"$terminal_pane\" = \"$stored_window_id:$stored_pane_id:$pane_pid:1\" ]; then\n",
                "            tmux kill-window -t \"$stored_window_id\" 2>/dev/null || true\n",
                "            if terminal_windows=$(LC_ALL=C tmux list-windows -t \"$expected_session:\" -F '#{{window_name}}' 2>&1); then\n",
                "              if ! printf '%s\\n' \"$terminal_windows\" | grep -Fqx \"$expected_window\"; then window_absent=1; fi\n",
                "            else\n",
                "              case \"$terminal_windows\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) window_absent=1 ;; *) identity_valid=0 ;; esac\n",
                "            fi\n",
                "          fi\n",
                "        fi\n",
                "      fi\n",
                "    else\n",
                "      case \"$terminal_windows\" in *\"can't find session:\"*|*\"no server running on \"*|*\"failed to connect to server: No such file or directory\"*|*\"failed to connect to server: Connection refused\"*) window_absent=1 ;; *) identity_valid=0 ;; esac\n",
                "    fi\n",
                "    if [ \"$identity_valid\" -eq 1 ] && [ \"$process_dead\" -eq 1 ] && [ \"$window_absent\" -eq 1 ]; then\n",
                "      tmux kill-window -t \"$expected_session:w_{process_id}\" 2>/dev/null || true\n",
                "      tmux kill-window -t \"$expected_session:__agentapp_keeper\" 2>/dev/null || true\n",
                "      terminal_verified_dead=1\n",
                "    fi\n",
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
                    RecoveredExecutionStatus::Expired => ("expired".to_string(), "124".to_string()),
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
                RecoveredExecutionStatus::Expired => ("expired".to_string(), "124".to_string()),
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
            "case \"$expected_terminal_state\" in completed|terminated|expired|recovery-lost|launch-interrupted) ;; *) echo AGENTAPP_TMUX_ACK_PROOF_MISSING >&2; exit 78 ;; esac\n",
            "case \"$expected_exit_code\" in ''|*[!0-9-]*) echo AGENTAPP_TMUX_ACK_PROOF_MISSING >&2; exit 78 ;; *) ;; esac\n",
            "process_id=${{token%%-*}}\n",
            "case \"$process_id\" in ''|*[!0-9a-f]*) echo AGENTAPP_TMUX_ACK_BAD_TOKEN >&2; exit 78 ;; esac\n",
            "[ \"${{#process_id}}\" -eq 16 ] || {{ echo AGENTAPP_TMUX_ACK_BAD_TOKEN >&2; exit 78; }}\n",
            "token_proof=${{token#*-}}\n",
            "[ \"$token\" = \"$process_id-$token_proof\" ] && [ \"${{#token_proof}}\" -eq 64 ] || {{ echo AGENTAPP_TMUX_ACK_BAD_TOKEN >&2; exit 78; }}\n",
            "case \"$token_proof\" in *[!0-9a-f]*) echo AGENTAPP_TMUX_ACK_BAD_TOKEN >&2; exit 78 ;; esac\n",
            "root=\"$base/$process_id\"\n",
            "default_session=\"agentapp_{agent_id}_$process_id\"\n",
            "legacy_session=agentapp_{agent_id}\n",
            "stored_session=$(cat \"$root/session\" 2>/dev/null || true)\n",
            "if [ -z \"$stored_session\" ]; then session=$legacy_session; elif [ \"$stored_session\" = \"$default_session\" ] || [ \"$stored_session\" = \"$legacy_session\" ]; then session=$stored_session; else echo AGENTAPP_TMUX_ACK_SESSION_MISMATCH >&2; exit 78; fi\n",
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
            "    {{ [ -e \"$entry\" ] || [ -L \"$entry\" ]; }} || continue\n",
            "    name=${{entry##*/}}\n",
            "    case \"$name\" in output-closed) [ -f \"$entry\" ] && [ ! -L \"$entry\" ] || {{ echo AGENTAPP_TMUX_ACK_UNEXPECTED_OUTPUT_RECEIPT >&2; exit 78; }} ;; output-closed.*) output_receipt_generation=${{name#output-closed.}}; case \"$output_receipt_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_ACK_UNEXPECTED_OUTPUT_RECEIPT >&2; exit 78 ;; esac; [ -f \"$entry\" ] && [ ! -L \"$entry\" ] || {{ echo AGENTAPP_TMUX_ACK_UNEXPECTED_OUTPUT_RECEIPT >&2; exit 78; }} ;; command.sh|payload.sh|sentinel.sh|watchdog.sh|expiry.sh|terminal-cleanup.sh|output|output-pipe-generation|output-pipe-generation.tmp|stdin|go|go.tmp|supervisor-ready|supervisor-ready.tmp|payload-go|payload-go.tmp|payload-ready|payload-ready.tmp|payload-identity|payload-identity.tmp|sentinel-release|sentinel-release.tmp|sentinel-ready|sentinel-ready.tmp|sentinel-identity|sentinel-identity.tmp|release|status|status.tmp|state|state.tmp|owner|identity|thread-id|turn-id|call-id|attempt-generation|session-id|session|tty|acknowledgement-token|digest|window|window-id|window-id.tmp|pane-id|pane-id.tmp|pane-death-status|pane-death-status.tmp|process-identity|process-identity.tmp|controller|controller.tmp|lease|lease.tmp|lease-generation|lease-generation.tmp|created-at|recovery-required|recovery-required.tmp|transition-claim|terminal-claim|.transition-candidate.*|transition-claim.quarantine.*) ;; stdin-write-*.claim|stdin-write-*.result|.stdin-write-*) [ -f \"$entry\" ] && [ ! -L \"$entry\" ] || {{ echo AGENTAPP_TMUX_ACK_UNEXPECTED_STDIN_ENTRY >&2; exit 78; }} ;; proof-key|.proof-candidate.*) [ \"$root\" = \"$legacy_tombstone\" ] || {{ echo AGENTAPP_TMUX_ACK_UNEXPECTED_ENTRY >&2; exit 78; }} ;; *) echo AGENTAPP_TMUX_ACK_UNEXPECTED_ENTRY >&2; exit 78 ;; esac\n",
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
            "  rm -f \"$root/command.sh\" \"$root/payload.sh\" \"$root/sentinel.sh\" \"$root/watchdog.sh\" \"$root/expiry.sh\" \"$root/terminal-cleanup.sh\" \"$root/output\" \"$root/output-closed\" \"$root/output-pipe-generation\" \"$root/output-pipe-generation.tmp\" \"$root/stdin\" \"$root/go\" \"$root/go.tmp\" \"$root/supervisor-ready\" \"$root/supervisor-ready.tmp\" \"$root/payload-go\" \"$root/payload-go.tmp\" \"$root/payload-ready\" \"$root/payload-ready.tmp\" \"$root/payload-identity\" \"$root/payload-identity.tmp\" \"$root/sentinel-release\" \"$root/sentinel-release.tmp\" \"$root/sentinel-ready\" \"$root/sentinel-ready.tmp\" \"$root/sentinel-identity\" \"$root/sentinel-identity.tmp\" \"$root/release\" \"$root/status\" \"$root/status.tmp\" \"$root/state\" \"$root/state.tmp\" \"$root/owner\" \"$root/identity\" \"$root/thread-id\" \"$root/turn-id\" \"$root/call-id\" \"$root/attempt-generation\" \"$root/session-id\" \"$root/tty\" \"$root/acknowledgement-token\" \"$root/digest\" \"$root/window\" \"$root/window-id\" \"$root/window-id.tmp\" \"$root/pane-id\" \"$root/pane-id.tmp\" \"$root/pane-death-status\" \"$root/pane-death-status.tmp\" \"$root/process-identity\" \"$root/process-identity.tmp\" \"$root/controller\" \"$root/controller.tmp\" \"$root/lease\" \"$root/lease.tmp\" \"$root/lease-generation\" \"$root/lease-generation.tmp\" \"$root/created-at\" \"$root/recovery-required\" \"$root/recovery-required.tmp\" \"$root/terminal-claim/kind\"\n",
            "  rm -f \"$root/session\"\n",
            "  for output_receipt in \"$root\"/output-closed.*; do\n",
            "    {{ [ -e \"$output_receipt\" ] || [ -L \"$output_receipt\" ]; }} || continue\n",
            "    output_receipt_name=${{output_receipt##*/}}\n",
            "    output_receipt_generation=${{output_receipt_name#output-closed.}}\n",
            "    case \"$output_receipt_generation\" in ''|*[!0-9]*) echo AGENTAPP_TMUX_ACK_UNEXPECTED_OUTPUT_RECEIPT >&2; exit 78 ;; esac\n",
            "    [ -f \"$output_receipt\" ] && [ ! -L \"$output_receipt\" ] || {{ echo AGENTAPP_TMUX_ACK_UNEXPECTED_OUTPUT_RECEIPT >&2; exit 78; }}\n",
            "    rm -f \"$output_receipt\"\n",
            "  done\n",
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
            "  case \"$state\" in completed|terminated|expired|recovery-lost|launch-interrupted) ;; *) echo AGENTAPP_TMUX_ACK_NONTERMINAL >&2; exit 78 ;; esac\n",
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
            "  case \"$claim_kind\" in bootstrap|recovery|termination|expiry|adoption|acknowledgement) ;; *) echo AGENTAPP_TMUX_TRANSITION_CLAIM_MALFORMED >&2; exit 80 ;; esac\n",
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
            "tmux kill-window -t \"$session:__agentapp_keeper\" 2>/dev/null || true\n",
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
                "expired" => RecoveredExecutionStatus::Expired,
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

fn legacy_session_name(agent_id: &str) -> String {
    format!("agentapp_{agent_id}")
}

fn execution_session_name(agent_id: &str, process_id: &str) -> String {
    format!("{}_{process_id}", legacy_session_name(agent_id))
}

#[cfg(test)]
#[path = "ssh_tmux_tests.rs"]
mod tests;
