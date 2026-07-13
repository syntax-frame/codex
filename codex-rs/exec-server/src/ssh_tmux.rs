//! tmux-backed process continuity for SSH server-mode agents.
//!
//! Every agent owns one tmux session and every running tool process owns a
//! window in that session. Live output is mirrored to a remote log. If the SSH
//! transport drops, the monitor reconnects at the last delivered byte while
//! the command continues inside tmux.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use russh::ChannelMsg;
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::sync::watch;

use crate::ExecServerError;
use crate::StartedExecProcess;
use crate::process::ExecProcessEventLog;
use crate::protocol::ExecOutputStream;
use crate::protocol::ExecParams;

use super::ChannelCommand;
use super::PROCESS_EVENT_CHANNEL_CAPACITY;
use super::RETAINED_OUTPUT_BYTES_PER_PROCESS;
use super::SharedState;
use super::SshProcess;
use super::SshProcessBackend;
use super::build_remote_command_body;
use super::publish_closed;
use super::publish_exit;
use super::publish_output;
use super::shell_quote;
use super::with_remote_path;

const MONITOR_RECONNECT_ATTEMPTS: usize = 60;
const MONITOR_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);
const TMUX_BOOTSTRAP_ATTEMPTS: usize = 4;
const COMPLETED_WINDOW_RETENTION_SECONDS: u64 = 24 * 60 * 60;
const AGENT_SESSION_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;

pub(super) async fn start(
    backend: SshProcessBackend,
    params: ExecParams,
) -> Result<StartedExecProcess, ExecServerError> {
    let descriptor = TmuxProcessDescriptor::new(
        backend.session_key(),
        params.process_id.as_str(),
        params.tty,
    );
    let bootstrap = with_remote_path(&descriptor.bootstrap_command(&params));
    for attempt in 0..TMUX_BOOTSTRAP_ATTEMPTS {
        let error = match backend.transport().exec_control(&bootstrap, None).await {
            Ok(result) if result.exit_code == 0 => break,
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
    ));

    Ok(StartedExecProcess {
        process: Arc::new(SshProcess {
            process_id,
            tty: params.tty,
            tmux: true,
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
) {
    let mut delivered_bytes = 0u64;
    let mut reconnect_attempts = 0usize;
    let mut commands_open = true;
    let exit_code = 'monitor: loop {
        let mut channel = match backend.transport().open_work_channel().await {
            Ok(channel) => channel,
            Err(error) => {
                if reconnect_attempts >= MONITOR_RECONNECT_ATTEMPTS {
                    publish_monitor_failure(
                        &state,
                        &events,
                        &wake_tx,
                        &output_notify,
                        stream,
                        &error,
                    );
                    break 'monitor -1;
                }
                reconnect_attempts += 1;
                monitor_retry_delay(reconnect_attempts).await;
                continue;
            }
        };
        let monitor_command = descriptor.monitor_command(delivered_bytes + 1);
        if let Err(error) = channel.channel().exec(true, monitor_command).await {
            if reconnect_attempts >= MONITOR_RECONNECT_ATTEMPTS {
                publish_monitor_failure(&state, &events, &wake_tx, &output_notify, stream, &error);
                break 'monitor -1;
            }
            reconnect_attempts += 1;
            monitor_retry_delay(reconnect_attempts).await;
            continue;
        }

        let mut channel_exit = None;
        loop {
            tokio::select! {
                message = channel.channel_mut().wait() => {
                    let Some(message) = message else {
                        break;
                    };
                    match message {
                        ChannelMsg::Data { data } => {
                            delivered_bytes = delivered_bytes.saturating_add(data.len() as u64);
                            reconnect_attempts = 0;
                            publish_output(
                                &state,
                                &events,
                                &wake_tx,
                                &output_notify,
                                stream,
                                data.to_vec(),
                            );
                        }
                        ChannelMsg::ExtendedData { data, .. } => {
                            // The persisted process log is emitted on stdout. Monitor
                            // diagnostics on stderr must not advance that log offset,
                            // or a reconnect could skip real process output.
                            publish_output(
                                &state,
                                &events,
                                &wake_tx,
                                &output_notify,
                                stream,
                                data.to_vec(),
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
                        Some(ChannelCommand::Write { data, ack }) => {
                            let result = descriptor
                                .write(backend.transport(), &data)
                                .await
                                .map_err(|error| error.to_string());
                            let _ = ack.send(result);
                        }
                        Some(ChannelCommand::Signal(_)) => {
                            if let Err(error) = descriptor.interrupt(backend.transport()).await {
                                tracing::debug!(
                                    session_key = %backend.session_key(),
                                    error = %error,
                                    "failed to interrupt tmux process"
                                );
                            }
                        }
                        Some(ChannelCommand::Eof) => {
                            if let Err(error) = descriptor.terminate(backend.transport()).await {
                                tracing::debug!(
                                    session_key = %backend.session_key(),
                                    error = %error,
                                    "failed to terminate tmux process"
                                );
                            }
                        }
                        None => commands_open = false,
                    }
                }
            }

            if let Some(exit_code) = channel_exit {
                break 'monitor exit_code;
            }
        }

        if reconnect_attempts >= MONITOR_RECONNECT_ATTEMPTS {
            let error = "SSH monitor repeatedly disconnected; the command remains in tmux";
            publish_monitor_failure(&state, &events, &wake_tx, &output_notify, stream, &error);
            break 'monitor -1;
        }
        reconnect_attempts += 1;
        monitor_retry_delay(reconnect_attempts).await;
    };

    publish_exit(&state, &events, &wake_tx, &output_notify, exit_code);
    if exit_code != -1
        && let Err(error) = descriptor.cleanup(backend.transport()).await
    {
        tracing::debug!(
            session_key = %backend.session_key(),
            error = %error,
            "failed to clean completed tmux process"
        );
    }
    publish_closed(&state, &events, &wake_tx, &output_notify);
}

fn publish_monitor_failure(
    state: &Arc<StdMutex<SharedState>>,
    events: &ExecProcessEventLog,
    wake_tx: &watch::Sender<u64>,
    output_notify: &Arc<Notify>,
    stream: ExecOutputStream,
    error: &dyn std::fmt::Display,
) {
    let message = format!(
        "\n[AgentApp SSH monitor lost: {error}. The remote command remains available in tmux.]\n"
    );
    publish_output(
        state,
        events,
        wake_tx,
        output_notify,
        stream,
        message.into_bytes(),
    );
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
    session_name: String,
    window_name: String,
    tty: bool,
}

impl TmuxProcessDescriptor {
    fn new(agent_key: &str, process_key: &str, tty: bool) -> Self {
        let agent_id = stable_identifier(agent_key);
        let process_id = stable_identifier(process_key);
        Self {
            session_name: format!("agentapp_{agent_id}"),
            window_name: format!("p_{process_id}"),
            agent_id,
            process_id,
            tty,
        }
    }

    fn remote_directory(&self) -> String {
        format!("$HOME/.agentapp/tmux/{}/{}", self.agent_id, self.process_id)
    }

    fn target(&self) -> String {
        format!("{}:{}.0", self.session_name, self.window_name)
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
            "#!/bin/sh\nroot=\"{root}\"\nrm -f \"$root/status.tmp\"\n{invocation}\ncode=$?\nprintf '%s\\n' \"$code\" > \"$root/status.tmp\"\nmv \"$root/status.tmp\" \"$root/status\"\ni=0\nwhile [ \"$i\" -lt {COMPLETED_WINDOW_RETENTION_SECONDS} ] && [ ! -f \"$root/release\" ]; do\n  sleep 1\n  i=$((i + 1))\ndone\nexit \"$code\"\n"
        )
    }

    fn bootstrap_command(&self, params: &ExecParams) -> String {
        let root = self.remote_directory();
        let script = self.process_script(params);
        let start_command = format!(
            "while [ ! -f \"{root}/go\" ]; do sleep 0.05; done; exec /bin/sh \"{root}/command.sh\""
        );
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
            "set -eu\nif ! command -v tmux >/dev/null 2>&1; then echo AGENTAPP_TMUX_MISSING >&2; exit 127; fi\nroot=\"{root}\"\nsession={}\nwindow={}\nmkdir -p \"$root\"\nif ! tmux has-session -t \"$session\" 2>/dev/null; then\n  tmux new-session -d -s \"$session\" -n __agentapp_keeper {} || tmux has-session -t \"$session\"\nfi\ntmux respawn-pane -k -t \"$session:__agentapp_keeper.0\" {} >/dev/null 2>&1 || true\nif ! tmux list-windows -t \"$session\" -F '#{{window_name}}' | grep -Fqx \"$window\"; then\n  rm -f \"$root/go\" \"$root/release\" \"$root/status\" \"$root/status.tmp\" \"$root/output\" \"$root/stdin\"\n  : > \"$root/output\"\n  printf '%s' {} > \"$root/command.sh\"\n  chmod 700 \"$root/command.sh\"\n  tmux new-window -d -t \"$session:\" -n \"$window\" {}\nfi\ntarget=\"$session:$window.0\"\n{pipe_setup}\ntouch \"$root/go\"\nprintf 'AGENTAPP_TMUX_READY %s\\n' \"$target\"\n",
            shell_quote(&self.session_name),
            shell_quote(&self.window_name),
            shell_quote(&format!("sleep {AGENT_SESSION_RETENTION_SECONDS}")),
            shell_quote(&format!("sleep {AGENT_SESSION_RETENTION_SECONDS}")),
            shell_quote(&script),
            shell_quote(&start_command),
        )
    }

    fn monitor_command(&self, first_byte: u64) -> String {
        let root = self.remote_directory();
        format!(
            "root=\"{root}\"\noffset={first_byte}\nstable=0\nwhile :; do\n  bytes=0\n  if [ -f \"$root/output\" ]; then bytes=$(wc -c < \"$root/output\"); fi\n  if [ \"$bytes\" -ge \"$offset\" ]; then\n    count=$((bytes - offset + 1))\n    tail -c +\"$offset\" \"$root/output\" | head -c \"$count\"\n    offset=$((offset + count))\n    stable=0\n  elif [ -f \"$root/status\" ]; then\n    stable=$((stable + 1))\n    if [ \"$stable\" -ge 3 ]; then\n      code=$(cat \"$root/status\" 2>/dev/null || printf '125')\n      case \"$code\" in ''|*[!0-9]*) code=125 ;; esac\n      exit \"$code\"\n    fi\n  else\n    stable=0\n  fi\n  sleep 0.2\ndone\n"
        )
    }

    async fn write(
        &self,
        transport: &crate::ssh_transport::SshTransport,
        data: &[u8],
    ) -> Result<(), ExecServerError> {
        let command = if self.tty {
            let buffer = format!("agentapp_{}", self.process_id);
            format!(
                "tmux load-buffer -b {} - && tmux paste-buffer -d -b {} -t {}",
                shell_quote(&buffer),
                shell_quote(&buffer),
                shell_quote(&self.target())
            )
        } else {
            let root = self.remote_directory();
            format!("root=\"{root}\"; [ ! -f \"$root/status\" ] || exit 3; cat > \"$root/stdin\"")
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

    async fn interrupt(
        &self,
        transport: &crate::ssh_transport::SshTransport,
    ) -> Result<(), ExecServerError> {
        self.run_control(
            transport,
            &format!("tmux send-keys -t {} C-c", shell_quote(&self.target())),
            "interrupt",
        )
        .await
    }

    async fn terminate(
        &self,
        transport: &crate::ssh_transport::SshTransport,
    ) -> Result<(), ExecServerError> {
        let root = self.remote_directory();
        let command = format!(
            "root=\"{root}\"; if [ ! -f \"$root/status\" ]; then printf '143\\n' > \"$root/status.tmp\"; mv \"$root/status.tmp\" \"$root/status\"; fi; touch \"$root/release\"; tmux kill-window -t {} 2>/dev/null || true",
            shell_quote(&self.target())
        );
        self.run_control(transport, &command, "terminate").await
    }

    async fn cleanup(
        &self,
        transport: &crate::ssh_transport::SshTransport,
    ) -> Result<(), ExecServerError> {
        let root = self.remote_directory();
        let command = format!(
            "tmux kill-window -t {} 2>/dev/null || true; rm -rf \"{root}\"",
            shell_quote(&self.target())
        );
        self.run_control(transport, &command, "cleanup").await
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
