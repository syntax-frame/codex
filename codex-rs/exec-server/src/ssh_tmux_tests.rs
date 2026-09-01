use std::collections::HashMap;

use codex_utils_path_uri::PathUri;
use pretty_assertions::assert_eq;

use super::MonitorExitClassification;
use super::TmuxProcessDescriptor;
use super::acknowledgement_command;
use super::acknowledgement_release_command;
use super::exact_reconciliation_command;
use super::interrupt_outcome_from_control_result;
use super::orphaned_execution_session_reaper_command;
use super::parse_monitor_exit_classification;
use super::parse_recovered_executions;
use super::shell_quote;
use super::stable_identifier;
use super::validate_reconciliation_request;
use crate::AdoptionRequest;
use crate::EXECUTION_EXPIRY_SYSTEM_NOTICE;
use crate::GenerationSelection;
use crate::IncompleteExecution;
use crate::PreparedExecution;
use crate::ProcessId;
use crate::ProcessSignalOutcome;
use crate::ProcessSignalRejectionReason;
use crate::ReconciliationRequest;
use crate::RecoveredExecution;
use crate::RecoveredExecutionAcknowledgement;
use crate::RecoveredExecutionStatus;
use crate::RemoteExecutionProtocolEvidence;
use crate::TerminalAcknowledgementProof;
use crate::protocol::ExecParams;
use crate::protocol::ExecutionIdentity;
use crate::select_execution_generation;

fn exec_params(process_id: &str, command: &str) -> ExecParams {
    ExecParams {
        process_id: ProcessId::from(process_id),
        execution_identity: Some(ExecutionIdentity {
            thread_id: "thread".to_string(),
            turn_id: "turn".to_string(),
            call_id: process_id.to_string(),
            attempt_generation: 0,
        }),
        argv: vec!["sh".to_string(), "-lc".to_string(), command.to_string()],
        cwd: PathUri::from_host_native_path(std::env::current_dir().expect("cwd"))
            .expect("cwd URI"),
        env_policy: None,
        env: HashMap::new(),
        tty: false,
        pipe_stdin: true,
        arg0: None,
        sandbox: None,
        enforce_managed_network: false,
        managed_network: None,
        network_proxy: None,
    }
}

fn apply_ready_protocol(descriptor: &mut TmuxProcessDescriptor, output: &[u8]) {
    let output = std::str::from_utf8(output).expect("utf8 bootstrap output");
    let (target, controller) = output
        .lines()
        .find_map(|line| {
            let mut fields = line
                .strip_prefix("AGENTAPP_TMUX_READY ")?
                .split_whitespace();
            let target = fields.next()?;
            let controller = fields.next()?;
            fields.next().is_none().then_some((target, controller))
        })
        .expect("fenced bootstrap result");
    let target_suffix = format!(":{}.0", descriptor.window_name);
    let session = target
        .strip_suffix(&target_suffix)
        .expect("bootstrap target session");
    descriptor
        .apply_reported_session(session)
        .expect("compatible bootstrap session");
    descriptor.controller_id = controller.to_string();
}

fn apply_adopted_protocol(descriptor: &mut TmuxProcessDescriptor, output: &[u8]) {
    let output = std::str::from_utf8(output).expect("utf8 adoption output");
    let (controller, session) = output
        .lines()
        .find_map(|line| {
            let mut fields = line
                .strip_prefix("AGENTAPP_TMUX_ADOPTED ")?
                .split_whitespace();
            let controller = fields.next()?;
            let session = fields.next()?;
            fields.next().is_none().then_some((controller, session))
        })
        .expect("fenced adoption result");
    descriptor
        .apply_reported_session(session)
        .expect("compatible adoption session");
    descriptor.controller_id = controller.to_string();
}

#[test]
fn identifiers_are_stable_and_separate_agents() {
    assert_eq!(stable_identifier("agent-a"), "9c3f6a8a5ba885b0");
    assert_ne!(stable_identifier("agent-a"), stable_identifier("agent-b"));
}

#[test]
fn descriptor_uses_tmux_safe_names() {
    let mut params = exec_params("process/with:punctuation", "printf hello");
    params.tty = true;
    let descriptor = TmuxProcessDescriptor::new(
        "conversation:connection with spaces",
        "1720000000000-controller",
        &params,
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
    assert_eq!(
        descriptor.session_name,
        format!("agentapp_{}_{}", descriptor.agent_id, descriptor.process_id)
    );

    let other = TmuxProcessDescriptor::new(
        "conversation:connection with spaces",
        "1720000000000-controller",
        &exec_params("different-process", "printf hello"),
    );
    assert_ne!(descriptor.session_name, other.session_name);
}

#[test]
fn prepared_execution_digest_matches_the_exact_launched_params() {
    let params = exec_params("process", "printf immutable");
    let prepared = PreparedExecution::new(params.clone());
    let digest = prepared.command_digest().to_string();
    let descriptor = TmuxProcessDescriptor::new("agent", "controller", prepared.params());
    assert_eq!(descriptor.command_digest, digest);
    assert_eq!(
        prepared.into_params().execution_identity,
        params.execution_identity
    );
}

#[test]
fn adoption_is_exact_fenced_and_only_rolls_forward_a_committed_stale_launch() {
    let request = AdoptionRequest {
        identity: ExecutionIdentity {
            thread_id: "thread".to_string(),
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 1,
        },
        expected_command_digest: "digest".to_string(),
        original_session_id: Some(4242),
        committed_output_cursor: 17,
        tty: false,
    };
    let descriptor = TmuxProcessDescriptor::from_adoption("agent", "new-controller", &request);
    let command = descriptor.adoption_command();

    for proof in [
        "thread-id",
        "turn-id",
        "call-id",
        "attempt-generation",
        "session-id",
        "digest",
        "process-identity",
        "display-message",
        "kill -0",
        "transition-claim",
        "adoption|a_",
        "agentapp_adopt_probe_process_group \"$claim_operation_pgid\"",
        "[ \"$claim_operation_pgid\" != \"$pgid\" ]",
        "transition-claim.quarantine.$claim_nonce",
        "agentapp_adopt_authority",
        "agentapp_adopt_live_pane",
        "next_generation=$((observed_generation + 1))",
        "roll_forward_launch=1",
        "supervisor-ready",
        "payload-go",
        "resume_stale_termination",
        "session_created",
        "created-at",
        "expiry.sh",
        "terminal-cleanup.sh",
        "upgrade_watchdog_window",
    ] {
        assert!(command.contains(proof), "missing adoption proof: {proof}");
    }
    assert!(!command.contains("adoption-claim"));
    assert_eq!(command.matches("tmux new-window").count(), 1);
    assert!(
        !command.contains("tmux new-window -d -t \"$expected_session:\" -n \"$expected_window\"")
    );
    assert!(!command.contains("touch \"$root/go\""));
    assert!(!command.contains("command.sh"));
    assert!(!command.contains("kill-session"));
}

#[test]
fn adoption_monitor_starts_after_the_committed_cursor() {
    let request = AdoptionRequest {
        identity: ExecutionIdentity {
            thread_id: "thread".to_string(),
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
        },
        expected_command_digest: "digest".to_string(),
        original_session_id: None,
        committed_output_cursor: 29,
        tty: false,
    };
    let descriptor = TmuxProcessDescriptor::from_adoption("agent", "controller", &request);
    assert!(descriptor.monitor_command(30).contains("offset=30"));
}

#[test]
fn reconnect_monitor_starts_after_delivered_bytes() {
    let params = exec_params("process", "printf hello");
    let descriptor = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &params);
    let command = descriptor.monitor_command(4_097);

    assert!(command.contains("offset=4097"));
    assert!(command.contains("count=$((bytes - offset + 1))"));
    assert!(command.contains("lease.tmp"));
    assert!(command.contains("attachment_seconds=300"));
    assert!(command.contains("now - attached_at"));
    assert!(command.contains(&descriptor.controller_id));
    assert!(command.contains(&descriptor.command_digest));
}

#[cfg(unix)]
#[test]
fn real_tmux_monitor_attachment_expires_without_stopping_execution() {
    use std::time::Duration;
    use std::time::Instant;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62505", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "monitor-slice-controller", &params);
    fixture.bootstrap(&mut descriptor, &params);

    let bounded_monitor =
        descriptor
            .monitor_command(1)
            .replacen("attachment_seconds=300", "attachment_seconds=2", 1);
    assert_ne!(bounded_monitor, descriptor.monitor_command(1));
    let started = Instant::now();
    let monitor = fixture.run_shell(bounded_monitor);
    assert_eq!(monitor.status.code(), Some(124));
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert!(started.elapsed() < Duration::from_secs(10));

    let pane = fixture.tmux(&[
        "display-message",
        "-p",
        "-t",
        &descriptor.target(),
        "#{pane_dead}",
    ]);
    assert!(pane.status.success());
    assert_eq!(String::from_utf8_lossy(&pane.stdout).trim(), "0");

    let terminated = fixture.run_shell(descriptor.termination_command());
    assert!(
        terminated.status.success(),
        "{}",
        String::from_utf8_lossy(&terminated.stderr)
    );
}

#[test]
fn command_identity_is_stable_and_rejects_process_id_reuse_for_different_commands() {
    let mut first_params = exec_params("process", "printf first");
    first_params
        .env
        .insert("ZED".to_string(), "last".to_string());
    first_params
        .env
        .insert("ALPHA".to_string(), "first".to_string());
    let mut reordered_params = exec_params("process", "printf first");
    reordered_params
        .env
        .insert("ALPHA".to_string(), "first".to_string());
    reordered_params
        .env
        .insert("ZED".to_string(), "last".to_string());
    let first = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &first_params);
    let same = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &reordered_params);
    let different = TmuxProcessDescriptor::new(
        "agent",
        "1720000000000-controller",
        &exec_params("process", "printf second"),
    );

    assert_eq!(first.process_id, same.process_id);
    assert_eq!(first.command_digest, same.command_digest);
    assert_eq!(first.command_digest.len(), 64);
    assert_ne!(first.command_digest, different.command_digest);

    let mut different_policy = reordered_params;
    different_policy.arg0 = Some("custom-argv0".to_string());
    let different_policy =
        TmuxProcessDescriptor::new("agent", "1720000000000-controller", &different_policy);
    assert_ne!(first.command_digest, different_policy.command_digest);

    let different_call = TmuxProcessDescriptor::new(
        "agent",
        "1720000000000-controller",
        &exec_params("thread:call-b:attempt-1", "printf first"),
    );
    assert_ne!(first.window_name, different_call.window_name);
}

#[test]
fn bootstrap_compare_and_attach_is_exact_and_generation_fenced() {
    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &params);
    let command = descriptor.bootstrap_command(&params);

    assert!(command.contains("AGENTAPP_TMUX_IDENTITY_MISMATCH"));
    assert!(command.contains("AGENTAPP_TMUX_LEGACY_WINDOW_CONFLICT"));
    assert!(command.contains("AGENTAPP_TMUX_EXECUTION_STATE_UNKNOWN"));
    assert!(command.contains("AGENTAPP_TMUX_STALE_CONTROLLER"));
    assert!(!command.contains(".lifecycle-lock"));
    assert!(command.contains("mkdir \"$staging\""));
    assert!(command.contains("mv -n \"$staging\" \"$root\""));
    assert!(command.contains("AGENTAPP_TMUX_DESCRIPTOR_CAS_CONFLICT"));
    assert!(command.contains("lease-generation"));
    assert!(command.contains("controller-$candidate_controller"));
    assert!(command.contains("agentapp-tmux-v2"));
    assert!(command.contains("watchdog.sh"));
    assert!(command.contains("expiry.sh"));
    assert!(command.contains("terminal-cleanup.sh"));
    assert!(command.contains("printf '%s\\n' \"$session\" > \"$staging/session\""));
    assert!(command.contains("printf '%s\\n' \"$created_at\" > \"$staging/created-at\""));
    assert!(command.contains("AGENTAPP_TMUX_RESOURCE_EXHAUSTED"));
    assert!(command.contains("fork failed: Device not configured"));
    assert!(command.contains("ulimit -S -n \"$desired\""));
    assert!(command.contains("deadline=$(( $(date +%s) + 120 ))"));
    assert!(!command.contains("sleep 604800"));
    assert!(!command.contains("tmux respawn-pane -k"));
    assert!(
        command.find("tmux new-window -d -t \"$session:\" -n \"$watchdog_window\"")
            < command.find("tmux new-window -d -t \"$session:\" -n \"$window\"")
    );
    assert!(!command.contains("tmux kill-session"));
    let command_release = command
        .find("mv \"$root/go.tmp\" \"$root/go\"")
        .expect("command release");
    let keeper_release = command
        .find("mv \"$root/keeper-release.tmp\" \"$root/keeper-release\"")
        .expect("keeper release");
    let keeper_retirement = command
        .rfind("tmux kill-window -t \"$session:__agentapp_keeper\"")
        .expect("keeper retirement");
    assert!(command_release < keeper_release);
    assert!(keeper_release < keeper_retirement);
}

#[test]
fn durable_expiry_is_fenced_and_uses_a_transport_neutral_notice() {
    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "controller", &params);
    let expiry = descriptor.expiry_script();
    let terminal_cleanup = descriptor.terminal_cleanup_script();
    let watchdog = descriptor.watchdog_script();

    assert!(expiry.contains("max_lifetime=86400"));
    assert!(expiry.contains("created-at"));
    assert!(expiry.contains("[ \"$session\" = \"$default_session\" ] || exit 0"));
    assert!(expiry.contains("transition-claim"));
    assert!(expiry.contains("terminal-claim"));
    assert!(expiry.contains("printf '124\\n'"));
    assert!(expiry.contains("printf 'expired\\n'"));
    assert!(expiry.contains(EXECUTION_EXPIRY_SYSTEM_NOTICE));
    assert!(expiry.contains("output-closed"));
    assert!(expiry.contains("agentapp_termination_stop_payload"));
    let expiry_pipe_close = expiry
        .find("tmux pipe-pane -t \"$current_pane_id\"")
        .expect("expiry closes the exact TTY pipe");
    let expiry_receipt_wait = expiry
        .rfind("agentapp_wait_for_output_drain")
        .expect("expiry waits for output closure");
    assert!(expiry_pipe_close < expiry_receipt_wait);
    let cleanup_pipe_close = terminal_cleanup
        .find("tmux pipe-pane -t \"$current_pane_id\"")
        .expect("terminal cleanup closes the exact TTY pipe");
    let cleanup_receipt_wait = terminal_cleanup
        .rfind("agentapp_wait_for_output_drain")
        .expect("terminal cleanup waits for output closure");
    assert!(cleanup_pipe_close < cleanup_receipt_wait);
    assert!(!expiry.contains("rm -rf"));
    assert!(!expiry.contains("kill-session"));
    assert!(watchdog.contains("/bin/sh \"$root/expiry.sh\""));
    assert!(watchdog.contains("/bin/sh \"$root/terminal-cleanup.sh\""));
    assert!(
        expiry.find("printf 'expired\\n'").expect("terminal state")
            < expiry
                .find("tmux kill-window -t \"$current_window_id\"")
                .expect("command retirement")
    );
    assert_eq!(
        EXECUTION_EXPIRY_SYSTEM_NOTICE,
        "System notice: This execution reached its 24-hour limit and was safely closed. Start the task again if it is still needed; a fresh execution environment will be created automatically."
    );
    let notice = EXECUTION_EXPIRY_SYSTEM_NOTICE.to_ascii_lowercase();
    assert!(!notice.contains("ssh"));
    assert!(!notice.contains("tmux"));
}

#[test]
fn bootstrap_reaps_only_old_dead_acknowledged_modern_sessions_in_bounded_batches() {
    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "controller", &params);
    let reaper = orphaned_execution_session_reaper_command();
    let bootstrap = descriptor.bootstrap_command(&params);

    assert!(bootstrap.contains("agentapp_reap_acknowledged_sessions"));
    assert!(reaper.contains(".orphan-session-reaper"));
    assert!(reaper.contains("session_created"));
    assert!(reaper.contains("reaped\" -lt 128"));
    assert!(reaper.contains("now - created_at"));
    assert!(reaper.contains("-ge 86400"));
    assert!(reaper.contains("[ ! -e \"$root\" ] && [ ! -L \"$root\" ]"));
    assert!(reaper.contains("tmux list-panes -s -t \"$candidate\""));
    assert!(reaper.contains("[ \"$orphan_dead\" = 1 ]"));
    assert!(reaper.contains("tmux kill-window -t \"$orphan_window_id\""));
    assert!(!reaper.contains("tmux kill-session"));
    assert!(!reaper.contains("rm -rf"));
}

#[test]
fn bootstrap_protects_the_supervisor_and_pins_native_dead_pane_evidence_before_go() {
    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &params);
    let bootstrap = descriptor.bootstrap_command(&params);
    let process = descriptor.process_script(&params);
    let payload = descriptor.payload_script(&params);
    let sentinel = descriptor.group_sentinel_script();
    let supervisor = descriptor.supervisor_start_command();
    let watchdog = descriptor.watchdog_script();

    let caught_interrupt = supervisor
        .find("interrupt_seen=1")
        .expect("caught supervisor interrupt");
    let go_wait = supervisor.find("while [ ! -f").expect("supervisor go wait");
    let supervisor_ready = supervisor
        .find("supervisor-ready")
        .expect("supervisor readiness");
    let remain_on_exit = bootstrap
        .find("remain-on-exit on")
        .expect("retained dead pane");
    let native_ids = bootstrap
        .find("mv \"$root/pane-id.tmp\" \"$root/pane-id\"")
        .expect("persisted native pane identity");
    let release_go = bootstrap
        .find("mv \"$root/go.tmp\" \"$root/go\"")
        .expect("go release");
    let release_payload = bootstrap
        .find("mv \"$root/payload-go.tmp\" \"$root/payload-go\"")
        .expect("payload release");
    assert!(caught_interrupt < go_wait);
    assert!(supervisor_ready < go_wait);
    assert!(remain_on_exit < native_ids);
    assert!(native_ids < release_payload);
    assert!(release_payload < release_go);
    assert_eq!(
        bootstrap
            .matches("mv \"$root/payload-go.tmp\" \"$root/payload-go\"")
            .count(),
        1
    );
    assert!(bootstrap.contains("pane_count"));
    assert!(bootstrap.contains("show-options -w -v"));
    assert!(process.contains("/bin/sh \"$root/payload.sh\""));
    assert!(payload.contains("payload-identity"));
    assert!(payload.contains("while [ ! -f \"$root/payload-go\" ]"));
    assert!(process.contains("sentinel-ready"));
    assert!(process.contains("sentinel-release"));
    assert!(sentinel.contains("/bin/kill -KILL -- \"-$expected_pgid\""));
    assert!(bootstrap.contains("payload-ready"));
    assert!(bootstrap.contains("AGENTAPP_TMUX_PAYLOAD_RELEASE_MISSING"));
    assert!(!watchdog.contains("pane_dead"));
    assert!(!watchdog.contains("stored_window_id"));
    assert!(!watchdog.contains("kill-window"));
    assert!(!process.contains("COMPLETED_WINDOW_RETENTION_SECONDS"));
}

#[test]
fn bootstrap_uses_exact_descriptor_cas_without_a_global_remote_lock() {
    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &params);
    let command = descriptor.bootstrap_command(&params);

    assert!(!command.contains(".lifecycle-lock"));
    assert!(!command.contains("release_lock"));
    assert!(!command.contains("kill -0 \"$owner_pid\""));
    assert!(command.contains("staging=\"$agent_root/$staging_name\""));
    assert!(command.contains("[ -e \"$root\" ] || [ -L \"$root\" ]"));
    assert!(command.contains("if ! mv -n \"$staging\" \"$root\""));
    assert!(command.contains("[ -d \"$staging\" ]"));
    assert!(command.contains("[ -d \"$root/$staging_name\" ]"));
    assert!(command.contains("AGENTAPP_TMUX_DESCRIPTOR_CAS_CONFLICT"));
    assert!(command.contains("AGENTAPP_TMUX_DESCRIPTOR_PUBLISH_FAILED"));
}

#[test]
fn bootstrap_initializes_descriptor_before_atomic_publication() {
    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &params);
    let command = descriptor.bootstrap_command(&params);

    let stage = command.find("mkdir \"$staging\"").expect("private staging");
    let final_metadata = command
        .find("printf 'prepared\\n' > \"$staging/state\"")
        .expect("prepared state initialization");
    let publish = command
        .find("mv -n \"$staging\" \"$root\"")
        .expect("atomic descriptor publication");
    assert!(stage < final_metadata);
    assert!(final_metadata < publish);
    let before_publish = &command[..publish];
    assert!(!before_publish.contains("> \"$root/owner\""));
    assert!(!before_publish.contains("> \"$root/identity\""));
    assert!(!before_publish.contains("> \"$root/digest\""));
    assert!(!before_publish.contains("> \"$root/window\""));
    assert!(!before_publish.contains("> \"$root/output\""));
    assert!(!before_publish.contains("> \"$root/state\""));
}

#[cfg(unix)]
#[test]
fn bootstrap_interruption_before_publication_leaves_retryable_descriptor_path() {
    use std::fs;
    use std::process::Command;

    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "controller", &params);
    let (home, path) = bootstrap_shell_fixture();
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&descriptor.agent_id)
        .join(&descriptor.process_id);
    let cutpoint = "  if [ -e \"$root\" ] || [ -L \"$root\" ]; then";
    let interrupted_command = descriptor.bootstrap_command(&params).replacen(
        cutpoint,
        "  exit 70\n  if [ -e \"$root\" ] || [ -L \"$root\" ]; then",
        1,
    );
    let interrupted = Command::new("/bin/sh")
        .arg("-c")
        .arg(interrupted_command)
        .env("HOME", home.path())
        .env("PATH", &path)
        .output()
        .expect("interrupt bootstrap before publication");
    assert_eq!(interrupted.status.code(), Some(70));
    assert!(!root.exists());

    let published_command = descriptor.bootstrap_command(&params).replacen(
        "  owns_staging=0\n  trap - EXIT HUP INT TERM\n",
        "  owns_staging=0\n  trap - EXIT HUP INT TERM\n  exit 0\n",
        1,
    );
    let published = Command::new("/bin/sh")
        .arg("-c")
        .arg(published_command)
        .env("HOME", home.path())
        .env("PATH", &path)
        .output()
        .expect("retry bootstrap publication");
    assert!(
        published.status.success(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );
    assert_eq!(
        fs::read_dir(&root)
            .expect("published descriptor")
            .map(|entry| entry.expect("descriptor entry").file_name())
            .collect::<std::collections::HashSet<_>>(),
        [
            "acknowledgement-token",
            "attempt-generation",
            "call-id",
            "created-at",
            "digest",
            "identity",
            "output",
            "owner",
            "session",
            "session-id",
            "state",
            "thread-id",
            "tty",
            "turn-id",
            "window",
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    );
    let agent_root = root.parent().expect("agent descriptor root");
    assert_eq!(
        fs::read_dir(agent_root)
            .expect("agent descriptor entries")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".descriptor-stage-"))
            })
            .count(),
        0
    );
}

#[cfg(unix)]
#[test]
fn bootstrap_metadata_write_failure_is_not_reported_as_a_cas_collision() {
    use std::process::Command;

    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "controller", &params);
    let (home, path) = bootstrap_shell_fixture();
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&descriptor.agent_id)
        .join(&descriptor.process_id);
    let command = descriptor.bootstrap_command(&params).replacen(
        "  : > \"$staging/output\" || descriptor_publish_failed\n",
        "  false || descriptor_publish_failed\n",
        1,
    );
    let failed = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .env("HOME", home.path())
        .env("PATH", &path)
        .output()
        .expect("inject descriptor metadata publication failure");

    assert_eq!(failed.status.code(), Some(74));
    assert_eq!(
        String::from_utf8(failed.stderr).expect("utf8 stderr"),
        "AGENTAPP_TMUX_DESCRIPTOR_PUBLISH_FAILED\n"
    );
    assert!(!root.exists());
    assert_eq!(
        std::fs::read_dir(root.parent().expect("agent descriptor root"))
            .expect("agent descriptor entries")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".descriptor-stage-"))
            })
            .count(),
        0
    );
}

#[cfg(unix)]
#[test]
fn concurrent_bootstrap_creator_loser_preserves_winner_and_cleans_own_staging() {
    use std::fs;
    use std::process::Command;

    let params = exec_params("process", "sleep 30");
    let first = TmuxProcessDescriptor::new("agent", "controller-a", &params);
    let second = TmuxProcessDescriptor::new("agent", "controller-b", &params);
    let (home, path) = bootstrap_shell_fixture();
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&first.agent_id)
        .join(&first.process_id);
    let concurrent_command = |descriptor: &TmuxProcessDescriptor| {
        descriptor
            .bootstrap_command(&params)
            .replacen(
                "  if [ -e \"$root\" ] || [ -L \"$root\" ]; then",
                "  printf '%s\\n' \"$controller\" >> \"$HOME/bootstrap-ready\"\n  while [ \"$(wc -l < \"$HOME/bootstrap-ready\")\" -lt 2 ]; do :; done\n  if [ -e \"$root\" ] || [ -L \"$root\" ]; then",
                1,
            )
            .replacen(
                "  owns_staging=0\n  trap - EXIT HUP INT TERM\n",
                "  owns_staging=0\n  trap - EXIT HUP INT TERM\n  exit 0\n",
                1,
            )
    };
    let mut first_child = Command::new("/bin/sh")
        .arg("-c")
        .arg(concurrent_command(&first))
        .env("HOME", home.path())
        .env("PATH", &path)
        .spawn()
        .expect("spawn first bootstrap");
    let mut second_child = Command::new("/bin/sh")
        .arg("-c")
        .arg(concurrent_command(&second))
        .env("HOME", home.path())
        .env("PATH", &path)
        .spawn()
        .expect("spawn second bootstrap");
    let first_status = first_child.wait().expect("wait for first bootstrap");
    let second_status = second_child.wait().expect("wait for second bootstrap");
    let mut status_codes = [
        first_status.code().expect("first exit code"),
        second_status.code().expect("second exit code"),
    ];
    status_codes.sort_unstable();
    assert_eq!(status_codes, [0, 75]);
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("winner state"),
        "prepared\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("identity")).expect("winner identity"),
        format!("{}\n", first.process_id)
    );
    assert_eq!(
        fs::read_dir(root.parent().expect("agent descriptor root"))
            .expect("agent descriptor entries")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".descriptor-stage-"))
            })
            .count(),
        0
    );
    assert_eq!(
        fs::read_dir(&root)
            .expect("winner descriptor entries")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".descriptor-stage-"))
            })
            .count(),
        0
    );
}

#[cfg(unix)]
#[test]
fn bootstrap_preserves_non_directory_destination_conflicts() {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "controller", &params);

    for destination in ["file", "symlink"] {
        let (home, path) = bootstrap_shell_fixture();
        let root = home
            .path()
            .join(".agentapp/tmux")
            .join(&descriptor.agent_id)
            .join(&descriptor.process_id);
        fs::create_dir_all(root.parent().expect("agent descriptor root"))
            .expect("agent descriptor root");
        if destination == "file" {
            fs::write(&root, "genuine conflict").expect("conflicting file");
        } else {
            symlink("missing-target", &root).expect("conflicting symlink");
        }

        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(descriptor.bootstrap_command(&params))
            .env("HOME", home.path())
            .env("PATH", &path)
            .output()
            .expect("run conflicting bootstrap");
        assert_eq!(output.status.code(), Some(75));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("AGENTAPP_TMUX_DESCRIPTOR_CAS_CONFLICT")
        );
        if destination == "file" {
            assert_eq!(
                fs::read_to_string(&root).expect("preserved conflicting file"),
                "genuine conflict"
            );
        } else {
            assert_eq!(
                fs::read_link(&root).expect("preserved conflicting symlink"),
                std::path::Path::new("missing-target")
            );
        }
        assert_eq!(
            fs::read_dir(root.parent().expect("agent descriptor root"))
                .expect("agent descriptor entries")
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(".descriptor-stage-"))
                })
                .count(),
            0
        );
    }
}

#[test]
fn prepared_partial_launch_adopts_exact_pane_identity_before_start() {
    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &params);
    let command = descriptor.bootstrap_command(&params);

    let adopt = command
        .find("[ -z \"$process_identity\" ] && [ ! -f \"$root/go\" ]")
        .expect("partial-launch adoption guard");
    let publish = command[adopt..]
        .find("mv \"$root/process-identity.tmp\" \"$root/process-identity\"")
        .expect("adopted process identity publication");
    let release = command[adopt..]
        .find("mv \"$root/go.tmp\" \"$root/go\"")
        .expect("command start release");
    assert!(publish < release);
}

#[test]
fn bootstrap_serializes_and_publishes_running_before_releasing_fast_command() {
    let params = exec_params("process", "exit 0");
    let descriptor = TmuxProcessDescriptor::new("agent", "controller", &params);
    let command = descriptor.bootstrap_command(&params);

    let claim = command
        .find("ln \"$transition_candidate\" \"$root/transition-claim\"")
        .expect("transition claim");
    let state = command
        .find("printf 'running\\n' > \"$root/state.tmp\"")
        .expect("running state");
    let release = command
        .find("mv \"$root/go.tmp\" \"$root/go\"")
        .expect("atomic go publication");
    assert!(claim < state);
    assert!(state < release);
    assert!(command.contains("AGENTAPP_TMUX_TRANSITION_BUSY"));
    assert!(command.contains("release_transition_claim"));
}

#[test]
fn durable_stdin_claim_precedes_delivery_and_result_follows_it() {
    let descriptor =
        TmuxProcessDescriptor::new("agent", "controller", &exec_params("process", "read value"));
    let command = descriptor.durable_write_command(b"hello\n", "durable-write");
    let claim = command
        .find("ln \"$claim_candidate\" \"$claim\"")
        .expect("durable remote write claim");
    let delivery = command
        .find("cat \"$data_candidate\" > \"$root/stdin\"")
        .expect("stdin side effect");
    let result = command
        .find("mv \"$result_candidate\" \"$result\"")
        .expect("durable remote write result");
    assert!(claim < delivery);
    assert!(delivery < result);
    assert!(command[claim..delivery].contains("rm -f \"$claim_candidate\""));
    assert!(!command[claim..result].contains("rm -f \"$claim\""));
    assert!(command.contains("AGENTAPP_TMUX_STDIN_DELIVERY_UNKNOWN"));
}

#[cfg(unix)]
#[test]
fn durable_stdin_replay_returns_the_persisted_result_without_redelivery() {
    let input = b"hello durable stdin\n";
    let (home, root, descriptor) = durable_write_fixture();
    let fifo = root.join("stdin");
    let fifo_for_reader = fifo;
    let reader = std::thread::spawn(move || std::fs::read(fifo_for_reader).expect("read fifo"));
    let command = descriptor.durable_write_command(input, "write-call-1");
    let first = run_durable_write_command(&home, &command, input);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(reader.join().expect("join fifo reader"), input);

    let replay = run_durable_write_command(&home, &command, input);
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(
        std::fs::read_dir(&root)
            .expect("descriptor entries")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("stdin-write-"))
            })
            .count(),
        2
    );
}

#[cfg(unix)]
#[test]
fn durable_stdin_rpc_loss_after_delivery_fails_closed_without_redelivery() {
    let input = b"deliver only once\n";
    let (home, root, descriptor) = durable_write_fixture();
    let fifo_for_reader = root.join("stdin");
    let reader = std::thread::spawn(move || std::fs::read(fifo_for_reader).expect("read fifo"));
    let command = descriptor
        .durable_write_command(input, "write-call-cutpoint")
        .replacen(
            "cat \"$data_candidate\" > \"$root/stdin\"\n",
            "cat \"$data_candidate\" > \"$root/stdin\"\nkill -KILL $$\n",
            1,
        );
    let interrupted = run_durable_write_command(&home, &command, input);
    assert!(!interrupted.status.success());
    assert_eq!(reader.join().expect("join fifo reader"), input);

    let retry = run_durable_write_command(
        &home,
        &descriptor.durable_write_command(input, "write-call-cutpoint"),
        input,
    );
    assert!(!retry.status.success());
    assert!(
        String::from_utf8_lossy(&retry.stderr).contains("AGENTAPP_TMUX_STDIN_DELIVERY_UNKNOWN")
    );
    assert!(
        std::fs::read_dir(&root)
            .expect("descriptor entries")
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(".claim"))
            })
    );
}

#[test]
fn inert_legacy_descriptor_is_quarantined_but_live_window_is_refused() {
    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &params);
    let command = descriptor.bootstrap_command(&params);

    let refusal = command
        .find("AGENTAPP_TMUX_LEGACY_WINDOW_CONFLICT")
        .expect("live legacy refusal");
    let quarantine = command
        .find("mv \"$root\" \"$legacy\"")
        .expect("inert legacy quarantine");
    assert!(refusal < quarantine);
    assert!(command.contains("AGENTAPP_TMUX_LEGACY_QUARANTINE_FAILED"));
    assert!(!command.contains("rm -rf \"$root\""));
}

#[test]
fn reconciliation_queries_only_explicit_identity_paths() {
    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        pending_writes: Vec::new(),
        incomplete_executions: vec![0, 1]
            .into_iter()
            .map(|attempt_generation| IncompleteExecution {
                turn_id: "turn".to_string(),
                call_id: "call".to_string(),
                attempt_generation,
                expected_command_digest: Some("expected-digest".to_string()),
                expected_session_id: Some(42),
                expected_tty: Some(false),
                protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
            })
            .collect(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let expected_zero = stable_identifier("thread\0turn\0call\00");
    let expected_one = stable_identifier("thread\0turn\0call\01");

    assert!(command.contains(&format!("root=\"$base/{expected_zero}\"")));
    assert!(command.contains(&format!("root=\"$base/{expected_one}\"")));
    assert_eq!(command.matches(" missing - - 0 0 1 - -").count(), 2);
    assert_eq!(
        command
            .matches("AGENTAPP_TMUX_RECONCILE_ORPHAN_WINDOW")
            .count(),
        2
    );
    assert_eq!(
        command
            .matches("if session_probe=$(LC_ALL=C tmux has-session")
            .count(),
        2
    );
    assert_eq!(
        command
            .matches("windows=$(LC_ALL=C tmux list-windows")
            .count(),
        6
    );
    assert!(
        command
            .matches("AGENTAPP_TMUX_RECONCILE_WINDOW_QUERY_FAILED")
            .count()
            >= 2
    );
    assert_eq!(
        command
            .matches("AGENTAPP_TMUX_RECONCILE_SESSION_QUERY_FAILED")
            .count(),
        4
    );
    assert!(!command.contains("for root in"));
    assert!(!command.contains("\"$base\"/*"));
    assert!(command.contains("agentapp_terminate_pre_go_window"));
    assert!(command.contains("transition-claim"));
    assert!(command.contains("AGENTAPP_TMUX_RECONCILE_ATTEMPT_CONFLICT"));
}

#[test]
fn reconciliation_refuses_legacy_unknown_before_remote_query() {
    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "legacy".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::LegacyUnknown,
        }],
        pending_writes: Vec::new(),
    };
    assert!(validate_reconciliation_request(&request).is_err());
}

#[cfg(unix)]
#[test]
fn stale_recovery_markers_require_stable_older_epoch_and_independent_terminal_proof() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let agent_id = stable_identifier("agent");
    let process_id = stable_identifier("thread\0turn\0call\00");
    let expected_window = format!("p_{process_id}");

    for (name, marker, current_controller, symlink_marker, window_present, expected) in [
        (
            "stable-stale",
            "1:previous-controller",
            "2:current-controller",
            false,
            false,
            RecoveredExecutionStatus::Exited(0),
        ),
        (
            "stale-without-proof",
            "1:previous-controller",
            "2:current-controller",
            false,
            true,
            RecoveredExecutionStatus::Unknown,
        ),
        (
            "equal",
            "2:current-controller",
            "2:current-controller",
            false,
            false,
            RecoveredExecutionStatus::Unknown,
        ),
        (
            "future",
            "3:future-controller",
            "2:current-controller",
            false,
            false,
            RecoveredExecutionStatus::Unknown,
        ),
        (
            "malformed",
            "1:previous:controller",
            "2:current-controller",
            false,
            false,
            RecoveredExecutionStatus::Unknown,
        ),
        (
            "malformed-current-controller",
            "1:previous-controller",
            "2:current:controller",
            false,
            false,
            RecoveredExecutionStatus::Unknown,
        ),
        (
            "symlink",
            "1:previous-controller",
            "2:current-controller",
            true,
            false,
            RecoveredExecutionStatus::Unknown,
        ),
    ] {
        let home = tempfile::tempdir().expect("temp home");
        let bin = home.path().join("bin");
        fs::create_dir(&bin).expect("fake bin");
        let tmux = bin.join("tmux");
        fs::write(
            &tmux,
            if window_present {
                format!(
                    "#!/bin/sh\n[ \"$1\" = list-windows ] && printf '%s\\n' '{expected_window}'\n"
                )
            } else {
                "#!/bin/sh\nexit 0\n".to_string()
            },
        )
        .expect("fake tmux");
        fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");

        let root = home
            .path()
            .join(".agentapp/tmux")
            .join(&agent_id)
            .join(&process_id);
        fs::create_dir_all(root.join("terminal-claim")).expect("descriptor root");
        for (field, value) in [
            ("owner", "agentapp-tmux-v2"),
            ("identity", process_id.as_str()),
            ("thread-id", "dGhyZWFk"),
            ("turn-id", "dHVybg=="),
            ("call-id", "Y2FsbA=="),
            ("attempt-generation", "0"),
            ("session-id", "42"),
            ("tty", "0"),
            ("digest", "expected-digest"),
            ("acknowledgement-token", "token"),
            ("window", expected_window.as_str()),
            ("process-identity", "2147483646:2147483646"),
            ("controller", current_controller),
            ("state", "completed"),
            ("status", "0"),
            ("terminal-claim/kind", "completed"),
            ("output", ""),
        ] {
            fs::write(root.join(field), value).expect("descriptor field");
        }
        let recovery_marker = root.join("recovery-required");
        if symlink_marker {
            let target = root.join("recovery-marker-target");
            fs::write(&target, marker).expect("marker target");
            symlink(target, &recovery_marker).expect("marker symlink");
        } else {
            fs::write(&recovery_marker, marker).expect("recovery marker");
        }

        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&command)
            .env("HOME", home.path())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .output()
            .expect("run exact reconciliation");
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let recovered =
            parse_recovered_executions(&output.stdout).expect("parse reconciliation output");
        assert_eq!(recovered[0].status, expected, "{name}");
        assert!(
            recovery_marker.exists() || recovery_marker.is_symlink(),
            "{name}"
        );
    }
}

#[test]
fn reconciliation_refuses_descriptor_self_attested_digest() {
    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: None,
            expected_session_id: None,
            expected_tty: None,
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    validate_reconciliation_request(&request).expect("missing slot may lack launch intent");
    let command = exact_reconciliation_command("agent", &request);
    assert!(command.contains("AGENTAPP_TMUX_RECONCILE_LOCAL_DIGEST_MISSING"));
}

#[test]
fn reconciliation_compares_descriptor_digest_to_local_authority() {
    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("local-expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    assert!(command.contains("local-expected-digest"));
    assert!(command.contains("AGENTAPP_TMUX_RECONCILE_DIGEST_CONFLICT"));
}

#[test]
fn reconciliation_terminal_death_requires_complete_exact_identity_proof() {
    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);

    assert!(command.contains("case \"$process_identity\" in *:*:*) identity_valid=0"));
    assert!(command.contains("case \"$pane_pid\" in ''|*[!0-9]*) identity_valid=0"));
    assert!(command.contains("case \"$pgid\" in ''|*[!0-9]*) identity_valid=0"));
    assert!(command.contains("[ \"$pane_pid:$pgid\" = \"$process_identity\" ]"));
    assert!(command.contains("[ \"$window\" = \"$expected_window\" ]"));
    assert!(command.contains("completed:completed|terminated:terminated"));
    assert!(command.contains("agentapp_probe_process_group \"$pgid\""));
    assert!(command.contains("AGENTAPP_TMUX_RECONCILE_PROCESS_QUERY_UNCERTAIN"));
    assert!(command.contains("grep -Fqx \"$expected_window\""));
}

#[cfg(unix)]
#[test]
fn absent_or_malformed_process_identity_never_verifies_terminal_death() {
    use std::fs;
    use std::process::Command;

    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let agent_id = stable_identifier("agent");
    let process_id = stable_identifier("thread\0turn\0call\00");
    let expected_window = format!("p_{process_id}");

    for process_identity in [None, Some("missing-pgid"), Some("1:2:3"), Some("x:2")] {
        let home = tempfile::tempdir().expect("temp home");
        let root = home
            .path()
            .join(".agentapp/tmux")
            .join(&agent_id)
            .join(&process_id);
        fs::create_dir_all(root.join("terminal-claim")).expect("descriptor root");
        for (name, value) in [
            ("owner", "agentapp-tmux-v2"),
            ("identity", process_id.as_str()),
            ("thread-id", "dGhyZWFk"),
            ("turn-id", "dHVybg=="),
            ("call-id", "Y2FsbA=="),
            ("attempt-generation", "0"),
            ("session-id", "42"),
            ("tty", "0"),
            ("digest", "expected-digest"),
            ("acknowledgement-token", "token"),
            ("state", "completed"),
            ("status", "0"),
            ("window", expected_window.as_str()),
            ("terminal-claim/kind", "completed"),
            ("output", ""),
        ] {
            fs::write(root.join(name), value).expect("descriptor field");
        }
        if let Some(process_identity) = process_identity {
            fs::write(root.join("process-identity"), process_identity).expect("process identity");
        }

        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&command)
            .env("HOME", home.path())
            .output()
            .expect("run exact reconciliation");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stderr.is_empty(),
            "reconciliation control commands must not emit stderr because SSH \
             transports merge it with the protocol reply: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let recovered =
            parse_recovered_executions(&output.stdout).expect("parse reconciliation output");
        assert_eq!(recovered.len(), 1);
        assert!(
            !recovered[0].terminal_verified_dead,
            "identity {process_identity:?} must fail closed"
        );
    }
}

#[cfg(unix)]
#[test]
fn prepared_descriptor_without_go_rolls_back_before_repair() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(true),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let home = tempfile::tempdir().expect("temp home");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).expect("fake bin");
    let tmux = bin.join("tmux");
    fs::write(
        &tmux,
        "#!/bin/sh\ncase \"$1\" in list-windows) exit 0 ;; kill-window) exit 0 ;; *) exit 0 ;; esac\n",
    )
    .expect("fake tmux");
    fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");

    let agent_id = stable_identifier("agent");
    let process_id = stable_identifier("thread\0turn\0call\00");
    let expected_window = format!("p_{process_id}");
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&agent_id)
        .join(&process_id);
    fs::create_dir_all(&root).expect("descriptor root");
    for (name, value) in [
        ("owner", "agentapp-tmux-v2"),
        ("identity", process_id.as_str()),
        ("thread-id", "dGhyZWFk"),
        ("turn-id", "dHVybg=="),
        ("call-id", "Y2FsbA=="),
        ("attempt-generation", "0"),
        ("session-id", "42"),
        ("tty", "1"),
        ("digest", "expected-digest"),
        ("acknowledgement-token", "token"),
        ("window", expected_window.as_str()),
        ("state", "prepared"),
        ("output", ""),
        ("output-pipe-generation", "1"),
    ] {
        fs::write(root.join(name), value).expect("descriptor field");
    }

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .env("HOME", home.path())
        .env("PATH", path)
        .output()
        .expect("run exact reconciliation");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recovered =
        parse_recovered_executions(&output.stdout).expect("parse reconciliation output");
    assert_eq!(
        recovered[0].status,
        RecoveredExecutionStatus::LaunchInterrupted
    );
    assert!(recovered[0].terminal_verified_dead);
    assert!(!root.join("go").exists());
    assert_eq!(
        fs::read_to_string(root.join("terminal-claim/kind")).expect("claim kind"),
        "launch-interrupted\n"
    );
}

#[cfg(unix)]
#[test]
fn stale_running_descriptor_with_dead_process_and_missing_window_records_recovery_loss() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let home = tempfile::tempdir().expect("temp home");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).expect("fake bin");
    let tmux = bin.join("tmux");
    fs::write(
        &tmux,
        "#!/bin/sh\ncase \"$1\" in list-windows) exit 0 ;; kill-window) exit 0 ;; *) exit 0 ;; esac\n",
    )
    .expect("fake tmux");
    fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");

    let agent_id = stable_identifier("agent");
    let process_id = stable_identifier("thread\0turn\0call\00");
    let expected_window = format!("p_{process_id}");
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&agent_id)
        .join(&process_id);
    fs::create_dir_all(&root).expect("descriptor root");
    for (name, value) in [
        ("owner", "agentapp-tmux-v2"),
        ("identity", process_id.as_str()),
        ("thread-id", "dGhyZWFk"),
        ("turn-id", "dHVybg=="),
        ("call-id", "Y2FsbA=="),
        ("attempt-generation", "0"),
        ("session-id", "42"),
        ("tty", "0"),
        ("digest", "expected-digest"),
        ("acknowledgement-token", "token"),
        ("window", expected_window.as_str()),
        ("process-identity", "2147483646:2147483646"),
        ("controller", "7:previous-controller"),
        ("lease-generation", "7"),
        ("state", "running"),
        ("output", "captured output"),
        ("go", ""),
    ] {
        fs::write(root.join(name), value).expect("descriptor field");
    }

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .env("HOME", home.path())
        .env("PATH", path)
        .output()
        .expect("run exact reconciliation");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recovered =
        parse_recovered_executions(&output.stdout).expect("parse reconciliation output");
    assert_eq!(recovered[0].status, RecoveredExecutionStatus::RecoveryLost);
    assert!(recovered[0].terminal_verified_dead);
    assert_eq!(recovered[0].output, b"captured output");
    assert_eq!(
        fs::read_to_string(root.join("terminal-claim/kind")).expect("claim kind"),
        "recovery-lost\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("status")).expect("status"),
        "125\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("state"),
        "recovery-lost\n"
    );
    assert!(!root.join("transition-claim").exists());
}

#[cfg(unix)]
#[test]
fn stale_running_descriptor_recovers_dead_lifecycle_claims() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let agent_id = stable_identifier("agent");
    let process_id = stable_identifier("thread\0turn\0call\00");
    let expected_window = format!("p_{process_id}");

    for (claim_kind, claim_nonce, claim_identity) in [
        ("bootstrap", "b_crashed", "-:-".to_string()),
        (
            "interrupt",
            "i_2147483645_2147483645",
            "2147483646:2147483646".to_string(),
        ),
        ("recovery", "r_crashed", "2147483646:2147483646".to_string()),
        (
            "termination",
            "t_crashed",
            "2147483646:2147483646".to_string(),
        ),
    ] {
        let home = tempfile::tempdir().expect("temp home");
        let bin = home.path().join("bin");
        fs::create_dir(&bin).expect("fake bin");
        let tmux = bin.join("tmux");
        fs::write(
            &tmux,
            "#!/bin/sh\ncase \"$1\" in list-windows) exit 0 ;; kill-window) exit 0 ;; *) exit 0 ;; esac\n",
        )
        .expect("fake tmux");
        fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");

        let root = home
            .path()
            .join(".agentapp/tmux")
            .join(&agent_id)
            .join(&process_id);
        fs::create_dir_all(&root).expect("descriptor root");
        for (name, value) in [
            ("owner", "agentapp-tmux-v2"),
            ("identity", process_id.as_str()),
            ("thread-id", "dGhyZWFk"),
            ("turn-id", "dHVybg=="),
            ("call-id", "Y2FsbA=="),
            ("attempt-generation", "0"),
            ("session-id", "42"),
            ("tty", "0"),
            ("digest", "expected-digest"),
            ("acknowledgement-token", "token"),
            ("window", expected_window.as_str()),
            ("process-identity", "2147483646:2147483646"),
            ("controller", "7:previous-controller"),
            ("lease-generation", "7"),
            ("state", "running"),
            ("output", "captured output"),
            ("go", ""),
        ] {
            fs::write(root.join(name), value).expect("descriptor field");
        }
        let (claim_pane, claim_pgid) = claim_identity.split_once(':').expect("claim identity");
        let claim = format!(
            "{claim_kind}|{claim_nonce}|7:previous-controller|2147483645|2147483645|{expected_window}|{claim_pane}|{claim_pgid}\n"
        );
        let candidate = root.join(format!(".transition-candidate.{claim_nonce}.2147483645"));
        fs::write(&candidate, &claim).expect("orphaned transition candidate");
        fs::hard_link(&candidate, root.join("transition-claim"))
            .expect("orphaned transition claim");
        if claim_kind == "termination" {
            fs::create_dir(root.join("terminal-claim")).expect("termination claim");
            fs::write(root.join("terminal-claim/kind"), "terminated\n").expect("termination kind");
        }

        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&command)
            .env("HOME", home.path())
            .env("PATH", path)
            .output()
            .expect("run exact reconciliation");
        assert!(
            output.status.success(),
            "{claim_kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let recovered =
            parse_recovered_executions(&output.stdout).expect("parse reconciliation output");
        assert_eq!(
            recovered[0].status,
            if claim_kind == "termination" {
                RecoveredExecutionStatus::Terminated
            } else {
                RecoveredExecutionStatus::RecoveryLost
            }
        );
        assert!(recovered[0].terminal_verified_dead);
        assert!(!root.join("transition-claim").exists());
        assert!(!candidate.exists());
    }
}

#[cfg(unix)]
#[test]
fn stale_running_descriptor_rolls_forward_torn_terminal_tuple() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let agent_id = stable_identifier("agent");
    let process_id = stable_identifier("thread\0turn\0call\00");
    let expected_window = format!("p_{process_id}");

    for (kind, status, expected_state, expected_status) in [
        ("completed", Some("7"), "completed", "7\n"),
        ("completed", None, "recovery-lost", "125\n"),
        ("terminated", Some("143"), "terminated", "143\n"),
        ("terminated", None, "recovery-lost", "125\n"),
        ("recovery-lost", Some("125"), "recovery-lost", "125\n"),
    ] {
        let home = tempfile::tempdir().expect("temp home");
        let bin = home.path().join("bin");
        fs::create_dir(&bin).expect("fake bin");
        let tmux = bin.join("tmux");
        fs::write(&tmux, "#!/bin/sh\nexit 0\n").expect("fake tmux");
        fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");
        let root = home
            .path()
            .join(".agentapp/tmux")
            .join(&agent_id)
            .join(&process_id);
        fs::create_dir_all(root.join("terminal-claim")).expect("terminal claim");
        for (name, value) in [
            ("owner", "agentapp-tmux-v2"),
            ("identity", process_id.as_str()),
            ("thread-id", "dGhyZWFk"),
            ("turn-id", "dHVybg=="),
            ("call-id", "Y2FsbA=="),
            ("attempt-generation", "0"),
            ("session-id", "42"),
            ("tty", "0"),
            ("digest", "expected-digest"),
            ("acknowledgement-token", "token"),
            ("window", expected_window.as_str()),
            ("process-identity", "2147483646:2147483646"),
            ("controller", "7:previous-controller"),
            ("lease-generation", "7"),
            ("state", "running"),
            ("output", "captured output"),
            ("go", ""),
            ("terminal-claim/kind", kind),
        ] {
            fs::write(root.join(name), value).expect("descriptor field");
        }
        if let Some(status) = status {
            fs::write(root.join("status"), format!("{status}\n")).expect("terminal status");
        }

        let expected_state = format!("{expected_state}\n");
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&command)
            .env("HOME", home.path())
            .env("PATH", path)
            .output()
            .expect("run exact reconciliation");
        assert!(
            output.status.success(),
            "{kind}:{status:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(root.join("state")).expect("terminal state"),
            expected_state
        );
        assert_eq!(
            fs::read_to_string(root.join("status")).expect("terminal status"),
            expected_status
        );
    }
}

#[cfg(unix)]
#[test]
fn stale_running_descriptor_with_uncertain_process_query_fails_closed() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let home = tempfile::tempdir().expect("temp home");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).expect("fake bin");
    let tmux = bin.join("tmux");
    fs::write(&tmux, "#!/bin/sh\nexit 0\n").expect("fake tmux");
    fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");
    let kill = bin.join("kill");
    fs::write(
        &kill,
        "#!/bin/sh\necho 'Operation not permitted' >&2\nexit 1\n",
    )
    .expect("fake kill");
    fs::set_permissions(&kill, fs::Permissions::from_mode(0o755)).expect("kill mode");
    let command = command.replace("/bin/kill", &kill.to_string_lossy());

    let agent_id = stable_identifier("agent");
    let process_id = stable_identifier("thread\0turn\0call\00");
    let expected_window = format!("p_{process_id}");
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&agent_id)
        .join(&process_id);
    fs::create_dir_all(&root).expect("descriptor root");
    for (name, value) in [
        ("owner", "agentapp-tmux-v2"),
        ("identity", process_id.as_str()),
        ("thread-id", "dGhyZWFk"),
        ("turn-id", "dHVybg=="),
        ("call-id", "Y2FsbA=="),
        ("attempt-generation", "0"),
        ("session-id", "42"),
        ("tty", "0"),
        ("digest", "expected-digest"),
        ("acknowledgement-token", "token"),
        ("window", expected_window.as_str()),
        ("process-identity", "2147483646:2147483646"),
        ("controller", "7:previous-controller"),
        ("lease-generation", "7"),
        ("state", "running"),
        ("output", "captured output"),
        ("go", ""),
    ] {
        fs::write(root.join(name), value).expect("descriptor field");
    }

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .env("HOME", home.path())
        .env("PATH", path)
        .output()
        .expect("run exact reconciliation");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("AGENTAPP_TMUX_RECONCILE_PROCESS_QUERY_UNCERTAIN")
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("state"),
        "running"
    );
    assert!(!root.join("status").exists());
    assert!(!root.join("terminal-claim").exists());
}

#[cfg(unix)]
#[test]
fn stale_running_descriptor_recovers_an_empty_torn_terminal_claim() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let home = tempfile::tempdir().expect("temp home");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).expect("fake bin");
    let tmux = bin.join("tmux");
    fs::write(&tmux, "#!/bin/sh\nexit 0\n").expect("fake tmux");
    fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");

    let agent_id = stable_identifier("agent");
    let process_id = stable_identifier("thread\0turn\0call\00");
    let expected_window = format!("p_{process_id}");
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&agent_id)
        .join(&process_id);
    fs::create_dir_all(root.join("terminal-claim")).expect("torn terminal claim");
    for (name, value) in [
        ("owner", "agentapp-tmux-v2"),
        ("identity", process_id.as_str()),
        ("thread-id", "dGhyZWFk"),
        ("turn-id", "dHVybg=="),
        ("call-id", "Y2FsbA=="),
        ("attempt-generation", "0"),
        ("session-id", "42"),
        ("tty", "0"),
        ("digest", "expected-digest"),
        ("acknowledgement-token", "token"),
        ("window", expected_window.as_str()),
        ("process-identity", "2147483646:2147483646"),
        ("controller", "7:previous-controller"),
        ("lease-generation", "7"),
        ("state", "running"),
        ("output", "captured output"),
        ("go", ""),
    ] {
        fs::write(root.join(name), value).expect("descriptor field");
    }

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .env("HOME", home.path())
        .env("PATH", path)
        .output()
        .expect("run exact reconciliation");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recovered =
        parse_recovered_executions(&output.stdout).expect("parse reconciliation output");
    assert_eq!(recovered[0].status, RecoveredExecutionStatus::RecoveryLost);
    assert!(recovered[0].terminal_verified_dead);
    assert_eq!(
        fs::read_to_string(root.join("terminal-claim/kind")).expect("claim kind"),
        "recovery-lost\n"
    );
}

#[cfg(unix)]
#[test]
fn stale_running_descriptor_with_live_process_fails_closed() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let home = tempfile::tempdir().expect("temp home");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).expect("fake bin");
    let tmux = bin.join("tmux");
    fs::write(&tmux, "#!/bin/sh\nexit 0\n").expect("fake tmux");
    fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");

    let agent_id = stable_identifier("agent");
    let process_id = stable_identifier("thread\0turn\0call\00");
    let expected_window = format!("p_{process_id}");
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&agent_id)
        .join(&process_id);
    fs::create_dir_all(&root).expect("descriptor root");
    let current_pid = std::process::id();
    let current_pgid_output = Command::new("ps")
        .args(["-o", "pgid=", "-p", &current_pid.to_string()])
        .output()
        .expect("current process group");
    let current_pgid = String::from_utf8_lossy(&current_pgid_output.stdout)
        .trim()
        .to_string();
    for (name, value) in [
        ("owner", "agentapp-tmux-v2".to_string()),
        ("identity", process_id),
        ("thread-id", "dGhyZWFk".to_string()),
        ("turn-id", "dHVybg==".to_string()),
        ("call-id", "Y2FsbA==".to_string()),
        ("attempt-generation", "0".to_string()),
        ("session-id", "42".to_string()),
        ("tty", "0".to_string()),
        ("digest", "expected-digest".to_string()),
        ("acknowledgement-token", "token".to_string()),
        ("window", expected_window),
        ("process-identity", format!("{current_pid}:{current_pgid}")),
        ("controller", "7:previous-controller".to_string()),
        ("state", "running".to_string()),
        ("output", String::new()),
        ("go", String::new()),
    ] {
        fs::write(root.join(name), value).expect("descriptor field");
    }

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .env("HOME", home.path())
        .env("PATH", path)
        .output()
        .expect("run exact reconciliation");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("AGENTAPP_TMUX_RECONCILE_PROCESS_WITHOUT_WINDOW")
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("state"),
        "running"
    );
    assert!(!root.join("status").exists());
}

#[cfg(unix)]
#[test]
fn stale_running_descriptor_with_live_window_remains_running() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let home = tempfile::tempdir().expect("temp home");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).expect("fake bin");

    let agent_id = stable_identifier("agent");
    let process_id = stable_identifier("thread\0turn\0call\00");
    let expected_window = format!("p_{process_id}");
    let tmux = bin.join("tmux");
    fs::write(
        &tmux,
        format!(
            "#!/bin/sh\ncase \"$1\" in list-windows) printf '%s\\n' '{expected_window}' ;; *) exit 0 ;; esac\n"
        ),
    )
    .expect("fake tmux");
    fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");

    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&agent_id)
        .join(&process_id);
    fs::create_dir_all(&root).expect("descriptor root");
    for (name, value) in [
        ("owner", "agentapp-tmux-v2"),
        ("identity", process_id.as_str()),
        ("thread-id", "dGhyZWFk"),
        ("turn-id", "dHVybg=="),
        ("call-id", "Y2FsbA=="),
        ("attempt-generation", "0"),
        ("session-id", "42"),
        ("tty", "0"),
        ("digest", "expected-digest"),
        ("acknowledgement-token", "token"),
        ("window", expected_window.as_str()),
        ("process-identity", "2147483646:2147483646"),
        ("controller", "7:live-controller"),
        ("lease-generation", "7"),
        ("state", "running"),
        ("output", "still live"),
        ("go", ""),
    ] {
        fs::write(root.join(name), value).expect("descriptor field");
    }

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .env("HOME", home.path())
        .env("PATH", path)
        .output()
        .expect("run exact reconciliation");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recovered =
        parse_recovered_executions(&output.stdout).expect("parse reconciliation output");
    assert_eq!(recovered[0].status, RecoveredExecutionStatus::Running);
    assert!(!recovered[0].terminal_verified_dead);
    assert_eq!(recovered[0].output, b"still live");
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("state"),
        "running"
    );
    assert!(!root.join("status").exists());
}

#[cfg(unix)]
#[test]
fn stale_running_descriptor_with_malformed_identity_fails_closed() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let home = tempfile::tempdir().expect("temp home");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).expect("fake bin");
    let tmux = bin.join("tmux");
    fs::write(&tmux, "#!/bin/sh\nexit 0\n").expect("fake tmux");
    fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");

    let agent_id = stable_identifier("agent");
    let process_id = stable_identifier("thread\0turn\0call\00");
    let expected_window = format!("p_{process_id}");
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&agent_id)
        .join(&process_id);
    fs::create_dir_all(&root).expect("descriptor root");
    for (name, value) in [
        ("owner", "agentapp-tmux-v2"),
        ("identity", process_id.as_str()),
        ("thread-id", "dGhyZWFk"),
        ("turn-id", "dHVybg=="),
        ("call-id", "Y2FsbA=="),
        ("attempt-generation", "0"),
        ("session-id", "42"),
        ("tty", "0"),
        ("digest", "expected-digest"),
        ("acknowledgement-token", "token"),
        ("window", expected_window.as_str()),
        ("process-identity", "malformed"),
        ("controller", "7:previous-controller"),
        ("lease-generation", "7"),
        ("state", "running"),
        ("output", ""),
        ("go", ""),
    ] {
        fs::write(root.join(name), value).expect("descriptor field");
    }

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .env("HOME", home.path())
        .env("PATH", path)
        .output()
        .expect("run exact reconciliation");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("AGENTAPP_TMUX_RECONCILE_PROCESS_IDENTITY_UNKNOWN")
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("state"),
        "running"
    );
    assert!(!root.join("status").exists());
}

#[test]
fn recovered_delivery_unknown_is_parsed_truthfully() {
    let output = b"AGENTAPP_RECOVERED dGhyZWFk dHVybg== c3RkaW4tY2FsbA== 1 terminated 143 42 6 1 1 token digest b3V0cHV0\n";
    let recovered = parse_recovered_executions(output).expect("parse recovered execution");

    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].status, RecoveredExecutionStatus::Terminated);
    assert_eq!(recovered[0].identity.turn_id, "turn");
    assert!(recovered[0].delivery_unknown);
    assert_eq!(recovered[0].output, b"output");
    assert_eq!(recovered[0].committed_output_cursor, 6);
}

#[test]
fn recovered_pre_execution_rollback_is_distinct_and_terminal() {
    let output = b"AGENTAPP_RECOVERED dGhyZWFk dHVybg== Y2FsbA== 0 launch-interrupted 125 42 0 0 1 token digest -\n";
    let recovered = parse_recovered_executions(output).expect("parse recovered execution");

    assert_eq!(
        recovered[0].status,
        RecoveredExecutionStatus::LaunchInterrupted
    );
    assert!(recovered[0].terminal_verified_dead);
    assert_eq!(
        select_execution_generation(
            &recovered[0],
            &slot(1, RecoveredExecutionStatus::Missing, false)
        ),
        Ok(GenerationSelection::Selected(0))
    );
}

#[test]
fn recovered_output_cursor_mismatch_is_rejected_before_adoption() {
    let output = b"AGENTAPP_RECOVERED dGhyZWFk dHVybg== Y2FsbA== 0 running - 42 7 0 0 token digest b3V0cHV0\n";
    let error = parse_recovered_executions(output).expect_err("cursor mismatch must fail closed");
    assert!(
        error
            .to_string()
            .contains("output length does not match committed cursor")
    );
}

#[test]
fn reconciliation_serializes_exactly_the_captured_output_prefix() {
    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("expected-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command("agent", &request);
    let capture = command.find("cursor=$(wc -c").expect("cursor capture");
    let prefix = command
        .find("head -c \"$cursor\" \"$root/output\"")
        .expect("bounded output snapshot");
    let publish = command[prefix..]
        .find("printf 'AGENTAPP_RECOVERED")
        .expect("recovered row publication")
        + prefix;
    assert!(capture < prefix);
    assert!(prefix < publish);
}

#[test]
fn duplicate_reconciliation_slot_is_rejected() {
    let row = "AGENTAPP_RECOVERED dGhyZWFk dHVybg== Y2FsbA== 0 missing - - 0 0 1 - - -\n";
    let output = format!("{row}{row}");

    assert!(parse_recovered_executions(output.as_bytes()).is_err());
}

#[test]
fn different_turns_produce_distinct_descriptors_and_windows() {
    let first = exec_params("process", "printf hello");
    let mut second = first.clone();
    second
        .execution_identity
        .as_mut()
        .expect("execution identity")
        .turn_id = "other-turn".to_string();

    let first = TmuxProcessDescriptor::new("agent", "controller", &first);
    let second = TmuxProcessDescriptor::new("agent", "controller", &second);

    assert_ne!(first.process_id, second.process_id);
    assert_ne!(first.window_name, second.window_name);
    assert_ne!(first.remote_directory(), second.remote_directory());
}

fn slot(generation: u32, status: RecoveredExecutionStatus, dead: bool) -> RecoveredExecution {
    RecoveredExecution {
        identity: ExecutionIdentity {
            thread_id: "thread".to_string(),
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: generation,
        },
        command_digest: None,
        output: Vec::new(),
        status,
        terminal_verified_dead: dead,
        session_id: None,
        committed_output_cursor: 0,
        delivery_unknown: false,
        acknowledgement: RecoveredExecutionAcknowledgement::new("token".to_string()),
    }
}

#[test]
fn generation_selector_handles_missing_gap_and_retry() {
    assert_eq!(
        select_execution_generation(
            &slot(0, RecoveredExecutionStatus::Missing, false),
            &slot(1, RecoveredExecutionStatus::Missing, false)
        ),
        Ok(GenerationSelection::NotLaunched)
    );
    assert!(
        select_execution_generation(
            &slot(0, RecoveredExecutionStatus::Missing, false),
            &slot(1, RecoveredExecutionStatus::Running, false)
        )
        .is_err()
    );
    assert_eq!(
        select_execution_generation(
            &slot(0, RecoveredExecutionStatus::Exited(1), true),
            &slot(1, RecoveredExecutionStatus::Running, false)
        ),
        Ok(GenerationSelection::Selected(1))
    );
}

#[test]
fn generation_selector_fails_closed_for_two_live_slots() {
    assert!(
        select_execution_generation(
            &slot(0, RecoveredExecutionStatus::Running, false),
            &slot(1, RecoveredExecutionStatus::Running, false)
        )
        .is_err()
    );
    assert_eq!(
        select_execution_generation(
            &slot(0, RecoveredExecutionStatus::Exited(0), false),
            &slot(1, RecoveredExecutionStatus::Missing, false)
        ),
        Ok(GenerationSelection::NeedsTerminalVerification(0))
    );
}

#[test]
fn generation_selector_exhaustive_slot_table() {
    #[derive(Clone, Copy, Debug)]
    enum Kind {
        Missing,
        Prepared,
        Running,
        TerminalDead,
        TerminalLive,
        Unknown,
    }
    let kinds = [
        Kind::Missing,
        Kind::Prepared,
        Kind::Running,
        Kind::TerminalDead,
        Kind::TerminalLive,
        Kind::Unknown,
    ];
    let make = |generation, kind| match kind {
        Kind::Missing => slot(generation, RecoveredExecutionStatus::Missing, false),
        Kind::Prepared => slot(generation, RecoveredExecutionStatus::Prepared, false),
        Kind::Running => slot(generation, RecoveredExecutionStatus::Running, false),
        Kind::TerminalDead => slot(generation, RecoveredExecutionStatus::Exited(0), true),
        Kind::TerminalLive => slot(generation, RecoveredExecutionStatus::Exited(0), false),
        Kind::Unknown => slot(generation, RecoveredExecutionStatus::Unknown, false),
    };
    for generation_zero_kind in kinds {
        for generation_one_kind in kinds {
            let actual = select_execution_generation(
                &make(0, generation_zero_kind),
                &make(1, generation_one_kind),
            );
            let expected = match (generation_zero_kind, generation_one_kind) {
                (Kind::Missing, Kind::Missing) => Ok(GenerationSelection::NotLaunched),
                (Kind::Missing, _) => Err(()),
                (Kind::Prepared | Kind::Running, Kind::Missing) => {
                    Ok(GenerationSelection::Selected(0))
                }
                (Kind::Prepared | Kind::Running, _) => Err(()),
                (Kind::TerminalLive, _) => Ok(GenerationSelection::NeedsTerminalVerification(0)),
                (Kind::TerminalDead, Kind::Missing) => Ok(GenerationSelection::Selected(0)),
                (Kind::TerminalDead, Kind::Prepared | Kind::Running | Kind::TerminalDead) => {
                    Ok(GenerationSelection::Selected(1))
                }
                (Kind::TerminalDead, Kind::TerminalLive) => {
                    Ok(GenerationSelection::NeedsTerminalVerification(1))
                }
                (Kind::TerminalDead, Kind::Unknown) | (Kind::Unknown, _) => Err(()),
            };
            match expected {
                Ok(expected) => assert_eq!(
                    actual,
                    Ok(expected),
                    "g0={generation_zero_kind:?}, g1={generation_one_kind:?}"
                ),
                Err(()) => assert!(
                    actual.is_err(),
                    "g0={generation_zero_kind:?}, g1={generation_one_kind:?}: {actual:?}"
                ),
            }
        }
    }
}

#[test]
fn acknowledgement_resolves_one_descriptor_without_scanning() {
    let process_id = "0123456789abcdef";
    let command = acknowledgement_command(
        "agent",
        &terminal_acknowledgement(format!("{process_id}-deadbeef")),
    );

    assert!(command.contains("root=\"$base/$process_id\""));
    assert!(!command.contains("for root in"));
    assert!(!command.contains("\"$base\"/*"));
    assert!(command.contains("AGENTAPP_TMUX_ACK_NONTERMINAL"));
    assert!(command.contains("AGENTAPP_TMUX_ACK_PROCESS_GROUP_ALIVE"));
    assert!(command.contains("AGENTAPP_TMUX_ACK_WINDOW_QUERY_FAILED"));
    assert!(command.contains("\"$root/terminal-claim/kind\""));
    assert!(command.contains("acknowledgement|k_"));
    assert!(command.contains("ln \"$transition_candidate\" \"$root/transition-claim\""));
    assert!(command.contains("agentapp_ack_probe_process_group \"$claim_operation_pgid\""));
    assert!(command.contains("\"$root/controller.tmp\""));
    assert!(command.contains("\"$root/lease.tmp\""));
    assert!(command.contains("\"$root/state.tmp\""));
    assert!(command.contains("\"$root/status.tmp\""));
    assert!(command.contains("\"$root/process-identity.tmp\""));
    assert!(command.contains(".acknowledged-$process_id-"));
    assert!(command.contains("if [ -e \"$tombstone\" ]"));
    assert!(command.contains("AGENTAPP_TMUX_ACK_OUTPUT_DIGEST_CHANGED"));
    assert!(command.contains("AGENTAPP_TMUX_ACK_TERMINAL_STATUS_CHANGED"));
    assert!(command.contains("tail -c +$((expected_range_start + 1))"));
    assert!(command.contains("[ \"$code\" = \"$expected_exit_code\" ]"));

    let terminated_command = acknowledgement_command(
        "agent",
        &terminal_acknowledgement_with_status(
            format!("{process_id}-deadbeef"),
            RecoveredExecutionStatus::Terminated,
        ),
    );
    assert!(terminated_command.contains("expected_terminal_state='terminated'"));
    assert!(terminated_command.contains("expected_exit_code='143'"));
    let expired_command = acknowledgement_command(
        "agent",
        &terminal_acknowledgement_with_status(
            format!("{process_id}-deadbeef"),
            RecoveredExecutionStatus::Expired,
        ),
    );
    assert!(expired_command.contains("expected_terminal_state='expired'"));
    assert!(expired_command.contains("expected_exit_code='124'"));
    assert!(expired_command.contains("created-at"));
    assert!(expired_command.contains("expiry.sh"));
    let launch_interrupted_command = acknowledgement_command(
        "agent",
        &terminal_acknowledgement_with_status(
            format!("{process_id}-deadbeef"),
            RecoveredExecutionStatus::LaunchInterrupted,
        ),
    );
    assert!(launch_interrupted_command.contains("expected_terminal_state='launch-interrupted'"));
    assert!(launch_interrupted_command.contains("expected_exit_code='125'"));

    let rename = command
        .find("mv \"$root\" \"$tombstone\"")
        .expect("atomic tombstone commit");
    let destructive_cleanup = command
        .rfind("agentapp_cleanup_ack_tombstone")
        .expect("idempotent tombstone cleanup");
    assert!(rename < destructive_cleanup);

    let final_proof = command
        .rfind("agentapp_ack_terminal_proof")
        .expect("final proof before claim");
    let watchdog_retirement = command
        .rfind("tmux kill-window")
        .expect("watchdog retirement before claim");
    let preflight = command
        .rfind("agentapp_ack_preflight_root")
        .expect("descriptor preflight before claim");
    let claim = command
        .find("ln \"$transition_candidate\" \"$root/transition-claim\"")
        .expect("atomic acknowledgement claim");
    assert!(final_proof < watchdog_retirement);
    assert!(watchdog_retirement < preflight);
    assert!(preflight < claim);
    let claimed_transaction = &command[claim..rename];
    assert!(!claimed_transaction.contains("agentapp_ack_terminal_proof"));
    assert!(!claimed_transaction.contains("agentapp_ack_windows"));
    assert!(!claimed_transaction.contains("agentapp_ack_preflight_root"));
    assert!(!claimed_transaction.contains("tmux "));
}

#[cfg(unix)]
#[test]
fn acknowledgement_recovers_dead_stale_claim_and_replays_from_tombstone() {
    use std::fs;

    let token = "0123456789abcdef-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (home, root, path) = terminal_acknowledgement_fixture(token);
    let acknowledgement = terminal_acknowledgement(token.to_string());

    let first = run_acknowledgement(&home, &path, &acknowledgement);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(!root.exists());

    let base = root.parent().expect("agent descriptor base");
    let tombstones = fs::read_dir(base)
        .expect("read descriptor base")
        .map(|entry| entry.expect("descriptor entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".acknowledged-0123456789abcdef-"))
        })
        .collect::<Vec<_>>();
    assert_eq!(tombstones.len(), 1);
    assert_eq!(
        fs::read_dir(&tombstones[0])
            .expect("read acknowledgement tombstone")
            .count(),
        0
    );

    let replay = run_acknowledgement(&home, &path, &acknowledgement);
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(!root.exists());
    assert_eq!(
        fs::read_dir(&tombstones[0])
            .expect("read replayed acknowledgement tombstone")
            .count(),
        0
    );

    let conflicting = conflicting_terminal_acknowledgement(token);
    let conflicting_replay = run_acknowledgement(&home, &path, &conflicting);
    assert!(!conflicting_replay.status.success());
    assert!(
        String::from_utf8_lossy(&conflicting_replay.stderr).contains("AGENTAPP_TMUX_ACK_UNKNOWN")
    );
}

#[cfg(unix)]
#[test]
fn acknowledgement_signal_traps_release_the_exact_live_claim() {
    use std::fs;

    let token = "0123456789abcdef-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (home, root, path) = terminal_acknowledgement_fixture(token);
    let acknowledgement = terminal_acknowledgement(token.to_string());
    let command = acknowledgement_command("agent", &acknowledgement).replacen(
        "trap 'interrupt_ack_claim 143' TERM\n",
        "trap 'interrupt_ack_claim 143' TERM\nkill -TERM $$\n",
        1,
    );
    let interrupted = run_acknowledgement_command(&home, &path, command);
    assert!(!interrupted.status.success());
    assert!(root.exists());
    assert!(!root.join("transition-claim").exists());

    let replay = run_acknowledgement(&home, &path, &acknowledgement);
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(!root.exists());
    let tombstones = fs::read_dir(root.parent().expect("descriptor base"))
        .expect("read descriptor base")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".acknowledged-"))
        })
        .count();
    assert_eq!(tombstones, 1);
}

#[cfg(unix)]
#[test]
fn acknowledgement_untrappable_loss_is_quarantined_and_retried() {
    let token = "0123456789abcdef-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (home, root, path) = terminal_acknowledgement_fixture(token);
    let acknowledgement = terminal_acknowledgement(token.to_string());
    let command = acknowledgement_command("agent", &acknowledgement).replacen(
        "trap 'interrupt_ack_claim 143' TERM\n",
        "trap 'interrupt_ack_claim 143' TERM\nkill -KILL $$\n",
        1,
    );
    let interrupted = run_acknowledgement_command(&home, &path, command);
    assert!(!interrupted.status.success());
    assert!(root.join("transition-claim").exists());

    let replay = run_acknowledgement(&home, &path, &acknowledgement);
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(!root.exists());
}

#[cfg(unix)]
#[test]
fn acknowledgement_release_deletes_only_the_exact_empty_proof_tombstone() {
    use std::fs;

    let token = "0123456789abcdef-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (home, root, path) = terminal_acknowledgement_fixture(token);
    let acknowledgement = terminal_acknowledgement(token.to_string());
    let acknowledged = run_acknowledgement(&home, &path, &acknowledgement);
    assert!(
        acknowledged.status.success(),
        "{}",
        String::from_utf8_lossy(&acknowledged.stderr)
    );
    let base = root.parent().expect("agent descriptor base");
    let tombstone = fs::read_dir(base)
        .expect("read descriptor base")
        .map(|entry| entry.expect("descriptor entry").path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".acknowledged-0123456789abcdef-"))
        })
        .expect("proof-bound tombstone");

    let released = run_acknowledgement_release(&home, &path, &acknowledgement);
    assert!(
        released.status.success(),
        "{}",
        String::from_utf8_lossy(&released.stderr)
    );
    assert!(!tombstone.exists());

    let replay = run_acknowledgement_release(&home, &path, &acknowledgement);
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
}

#[cfg(unix)]
#[test]
fn acknowledgement_release_rejects_live_roots_and_unexpected_tombstone_contents() {
    use std::fs;

    let token = "0123456789abcdef-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (home, root, path) = terminal_acknowledgement_fixture(token);
    let acknowledgement = terminal_acknowledgement(token.to_string());
    assert!(
        run_acknowledgement(&home, &path, &acknowledgement)
            .status
            .success()
    );
    let base = root.parent().expect("agent descriptor base");
    let tombstone = fs::read_dir(base)
        .expect("read descriptor base")
        .map(|entry| entry.expect("descriptor entry").path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".acknowledged-0123456789abcdef-"))
        })
        .expect("proof-bound tombstone");
    fs::write(tombstone.join("unexpected"), "do not delete").expect("unexpected entry");
    let unexpected = run_acknowledgement_release(&home, &path, &acknowledgement);
    assert!(!unexpected.status.success());
    assert!(
        String::from_utf8_lossy(&unexpected.stderr)
            .contains("AGENTAPP_TMUX_RELEASE_UNEXPECTED_ENTRY")
    );
    assert!(tombstone.join("unexpected").exists());

    fs::remove_file(tombstone.join("unexpected")).expect("remove test entry");
    fs::create_dir(&root).expect("simulate conflicting live descriptor root");
    let live = run_acknowledgement_release(&home, &path, &acknowledgement);
    assert!(!live.status.success());
    assert!(
        String::from_utf8_lossy(&live.stderr).contains("AGENTAPP_TMUX_RELEASE_LIVE_ROOT_PRESENT")
    );
    assert!(tombstone.exists());
}

#[cfg(unix)]
#[test]
fn acknowledgement_accepts_only_regular_numeric_output_close_receipts() {
    use std::fs;
    use std::os::unix::fs::symlink;

    let token = "0123456789abcdef-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let (valid_home, valid_root, valid_path) = terminal_acknowledgement_fixture(token);
    fs::write(valid_root.join("output-closed.7"), []).expect("numeric output receipt");
    let valid = run_acknowledgement(
        &valid_home,
        &valid_path,
        &terminal_acknowledgement(token.to_string()),
    );
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert!(!valid_root.exists());

    let (malformed_home, malformed_root, malformed_path) = terminal_acknowledgement_fixture(token);
    fs::write(malformed_root.join("output-closed.not-a-generation"), [])
        .expect("malformed output receipt");
    let malformed = run_acknowledgement(
        &malformed_home,
        &malformed_path,
        &terminal_acknowledgement(token.to_string()),
    );
    assert!(!malformed.status.success());
    assert!(
        String::from_utf8_lossy(&malformed.stderr)
            .contains("AGENTAPP_TMUX_ACK_UNEXPECTED_OUTPUT_RECEIPT")
    );
    assert!(
        malformed_root
            .join("output-closed.not-a-generation")
            .exists()
    );

    let (symlink_home, symlink_root, symlink_path) = terminal_acknowledgement_fixture(token);
    symlink(
        symlink_root.join("output"),
        symlink_root.join("output-closed.8"),
    )
    .expect("symlink output receipt");
    let linked = run_acknowledgement(
        &symlink_home,
        &symlink_path,
        &terminal_acknowledgement(token.to_string()),
    );
    assert!(!linked.status.success());
    assert!(
        String::from_utf8_lossy(&linked.stderr)
            .contains("AGENTAPP_TMUX_ACK_UNEXPECTED_OUTPUT_RECEIPT")
    );
    assert!(symlink_root.join("output-closed.8").is_symlink());
}

#[cfg(unix)]
#[test]
fn acknowledgement_rejects_conflicting_proof_without_consuming_stale_claim() {
    use std::fs;

    let token = "0123456789abcdef-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (home, root, path) = terminal_acknowledgement_fixture(token);
    let acknowledgement = conflicting_terminal_acknowledgement(token);

    let output = run_acknowledgement(&home, &path, &acknowledgement);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("AGENTAPP_TMUX_ACK_OUTPUT_DIGEST_CHANGED")
    );
    assert!(root.exists());
    let transition_claim =
        fs::read_to_string(root.join("transition-claim")).expect("stale transition claim");
    assert!(transition_claim.starts_with("acknowledgement|k_"));
    assert_eq!(
        fs::read_dir(&root)
            .expect("stale descriptor entries")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".transition-candidate.k_"))
            })
            .count(),
        1
    );
    assert_eq!(
        fs::read_dir(root.parent().expect("agent descriptor base"))
            .expect("read descriptor base")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".acknowledged-"))
            })
            .count(),
        0
    );
}

#[cfg(unix)]
#[test]
fn acknowledgement_rejects_output_appended_after_the_committed_terminal_cursor() {
    use std::fs;

    let token = "0123456789abcdef-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (home, root, path) = terminal_acknowledgement_fixture(token);
    fs::write(root.join("output"), "abcdefx").expect("append uncommitted output byte");

    let output = run_acknowledgement(&home, &path, &terminal_acknowledgement(token.to_string()));
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("AGENTAPP_TMUX_ACK_OUTPUT_LENGTH_CHANGED")
    );
    assert!(root.exists());
    assert!(root.join("transition-claim").exists());
}

#[cfg(unix)]
#[test]
fn acknowledgement_rejects_noncanonical_token_and_digest_before_remote_lookup() {
    let home = tempfile::tempdir().expect("temp home");
    let invalid_token = terminal_acknowledgement("0123456789abcdef-deadbeef".to_string());
    let token_output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(acknowledgement_command("agent", &invalid_token))
        .env("HOME", home.path())
        .output()
        .expect("reject malformed acknowledgement token");
    assert!(!token_output.status.success());
    assert!(String::from_utf8_lossy(&token_output.stderr).contains("AGENTAPP_TMUX_ACK_BAD_TOKEN"));

    let token = "0123456789abcdef-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let invalid_digest = RecoveredExecutionAcknowledgement::new(token.to_string())
        .with_terminal_proof(TerminalAcknowledgementProof {
            range_start: 0,
            range_end: 6,
            output_sha256: "ABC".to_string(),
            status: RecoveredExecutionStatus::Exited(0),
        });
    let digest_output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(acknowledgement_command("agent", &invalid_digest))
        .env("HOME", home.path())
        .output()
        .expect("reject malformed acknowledgement digest");
    assert!(!digest_output.status.success());
    assert!(
        String::from_utf8_lossy(&digest_output.stderr)
            .contains("AGENTAPP_TMUX_ACK_PROOF_MALFORMED")
    );
}

#[cfg(unix)]
#[test]
fn acknowledgement_legacy_token_tombstone_is_bound_once_to_the_durable_terminal_proof() {
    use sha2::Digest;
    use sha2::Sha256;
    use std::fs;

    let token = "0123456789abcdef-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (home, root, path) = terminal_acknowledgement_fixture(token);
    let base = root.parent().expect("agent descriptor base");
    let legacy_key = format!("{:x}", Sha256::digest(token.as_bytes()));
    let legacy_tombstone = base.join(format!(".acknowledged-0123456789abcdef-{legacy_key}"));
    fs::remove_dir_all(&root).expect("simulate legacy acknowledgement cleanup");
    fs::create_dir(&legacy_tombstone).expect("legacy acknowledgement tombstone");

    let acknowledgement = terminal_acknowledgement(token.to_string());
    let migration = run_acknowledgement(&home, &path, &acknowledgement);
    assert!(
        migration.status.success(),
        "{}",
        String::from_utf8_lossy(&migration.stderr)
    );
    let proof_key = fs::read_to_string(legacy_tombstone.join("proof-key"))
        .expect("proof-bound legacy tombstone");
    assert_eq!(proof_key.len(), 65);

    let replay = run_acknowledgement(&home, &path, &acknowledgement);
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(
        fs::read_to_string(legacy_tombstone.join("proof-key"))
            .expect("replayed proof-bound legacy tombstone"),
        proof_key
    );

    let conflicting =
        run_acknowledgement(&home, &path, &conflicting_terminal_acknowledgement(token));
    assert!(!conflicting.status.success());
    assert!(
        String::from_utf8_lossy(&conflicting.stderr)
            .contains("AGENTAPP_TMUX_ACK_TOMBSTONE_PROOF_CONFLICT")
    );
    assert_eq!(
        fs::read_to_string(legacy_tombstone.join("proof-key"))
            .expect("unchanged proof-bound legacy tombstone"),
        proof_key
    );
}

#[test]
fn watchdog_classifies_expiry_and_exits_when_terminal_status_is_published() {
    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &params);
    let script = descriptor.watchdog_script();

    assert!(script.contains("now - lease"));
    assert!(script.contains("recovery-required.tmp"));
    assert!(script.contains("observed_generation=${observed%%:*}"));
    assert!(script.contains("observed_controller=${observed#*:}"));
    assert!(script.contains("printf '%s:%s\\n' \"$observed_generation\" \"$observed_controller\""));
    assert!(!script.contains("kill -TERM"));
    assert!(!script.contains("kill -KILL"));
    assert!(!script.contains("sleep 604800"));
    assert!(!script.contains("stored_window_id"));
    assert!(!script.contains("kill-window"));
    assert!(!script.contains("status.tmp"));
    assert!(!script.contains("terminal-claim/kind.tmp"));
    assert!(!script.contains("release"));
    assert!(!script.contains("controller.tmp"));
    assert!(!script.contains("lease-generation"));
    assert!(script.contains("sleep 5"));
}

#[test]
fn watchdog_never_competes_for_terminal_status() {
    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &params);
    let process = descriptor.process_script(&params);
    let watchdog = descriptor.watchdog_script();

    assert!(process.contains("mkdir \"$root/terminal-claim\""));
    assert!(process.contains("printf 'completed"));
    assert!(!watchdog.contains("mkdir \"$root/terminal-claim\""));
    assert!(!watchdog.contains("terminal-claim/kind.tmp"));
    assert!(!watchdog.contains("printf '124"));
    assert!(!watchdog.contains("printf '143"));
}

#[test]
fn repeated_monitor_transport_loss_only_reconnects_without_terminal_events() {
    let source = include_str!("ssh_tmux.rs");
    let monitor = source
        .split("async fn monitor_pump(")
        .nth(1)
        .expect("monitor pump")
        .split("fn publish_monitor_failure(")
        .next()
        .expect("monitor pump body");

    assert!(!monitor.contains("break 'monitor -1"));
    assert!(!monitor.contains("break 'monitor 143"));
    assert!(!monitor.contains("MONITOR_RECONNECT_ATTEMPTS"));
    assert_eq!(monitor.matches("terminate_with_retry(").count(), 1);
    assert!(monitor.contains("Some(ChannelCommand::Terminate { ack })"));
    assert!(monitor.contains("ack.send(result.map_err"));
}

#[test]
fn monitor_exit_requires_durable_terminal_classification() {
    assert!(matches!(
        parse_monitor_exit_classification(b"channel-lost\n").expect("classification"),
        MonitorExitClassification::ChannelLost
    ));
    assert!(matches!(
        parse_monitor_exit_classification(b"ownership-lost\n").expect("classification"),
        MonitorExitClassification::OwnershipLost
    ));
    assert!(matches!(
        parse_monitor_exit_classification(b"terminal 17\n").expect("classification"),
        MonitorExitClassification::Terminal(17)
    ));
    assert!(parse_monitor_exit_classification(b"terminal nope\n").is_err());
}

#[test]
fn monitor_exit_verification_checks_current_controller_before_terminal_status() {
    let source = include_str!("ssh_tmux.rs");
    let classify = source
        .split("async fn classify_monitor_exit(")
        .nth(1)
        .expect("classification method")
        .split("async fn write(")
        .next()
        .expect("classification body");

    let ownership = classify
        .find("$root/controller")
        .expect("controller verification");
    let terminal = classify
        .find("$root/terminal-claim")
        .expect("terminal claim verification");
    assert!(ownership < terminal);
    assert!(classify.contains("printf 'ownership-lost"));
}

#[test]
fn monitor_diagnostics_never_advance_or_pollute_remote_output_cursor() {
    let source = include_str!("ssh_tmux.rs");
    let arm = source
        .split("ChannelMsg::ExtendedData { data, .. } => {")
        .nth(1)
        .expect("extended-data arm")
        .split("ChannelMsg::ExitStatus")
        .next()
        .expect("extended-data body");
    assert!(arm.contains("ignored tmux monitor diagnostic"));
    assert!(!arm.contains("publish_output"));
    assert!(!arm.contains("delivered_bytes"));
    let failure = source
        .split("fn publish_monitor_failure(")
        .nth(1)
        .expect("monitor failure reporter")
        .split("async fn terminate_with_retry")
        .next()
        .expect("monitor failure body");
    assert!(failure.contains("tracing::warn!"));
    assert!(!failure.contains("publish_output"));
}

#[test]
fn termination_does_not_release_descriptor_before_rollout_repair() {
    let params = exec_params("process", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &params);
    let terminate = descriptor.confirmed_process_group_termination();

    assert!(!terminate.contains("touch \"$root/release\""));
    assert!(terminate.contains("agentapp_termination_probe_group"));
    assert!(terminate.contains("LC_ALL=C /bin/kill -0"));
    assert!(terminate.contains("\"No such process\""));
    assert!(terminate.contains("AGENTAPP_TMUX_PROCESS_GROUP_UNKNOWN"));
    assert!(!descriptor.process_script(&params).contains("rm -rf"));
}

#[test]
fn ownership_guard_is_scoped_to_agentapp_metadata() {
    let descriptor = TmuxProcessDescriptor::new(
        "agent",
        "1720000000000-controller",
        &exec_params("process", "printf hello"),
    );
    let guard = descriptor.ownership_guard();

    assert!(guard.contains("agentapp-tmux-v2"));
    assert!(guard.contains(&descriptor.controller_id));
    assert!(guard.contains(&descriptor.command_digest));
    assert!(guard.contains("AGENTAPP_TMUX_OWNERSHIP_MISMATCH"));
}

#[test]
fn interrupt_rejection_is_typed_only_for_exact_pre_delivery_marker() {
    assert_eq!(
        interrupt_outcome_from_control_result(80, b"AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH\n",)
            .expect("typed rejection"),
        ProcessSignalOutcome::RejectedBeforeDelivery(
            ProcessSignalRejectionReason::OwnershipMismatch
        )
    );
    assert_eq!(
        interrupt_outcome_from_control_result(0, b"").expect("accepted signal"),
        ProcessSignalOutcome::Accepted
    );
    assert!(
        interrupt_outcome_from_control_result(
            80,
            b"prefix AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH suffix\n",
        )
        .is_err()
    );
    assert!(
        interrupt_outcome_from_control_result(
            80,
            b"AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH\nunexpected trailing output\n",
        )
        .is_err()
    );
    assert!(
        interrupt_outcome_from_control_result(79, b"AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH\n",)
            .is_err()
    );
    assert!(
        interrupt_outcome_from_control_result(79, b"AGENTAPP_TMUX_TRANSITION_CHANGED\n").is_err()
    );
}

#[test]
fn interrupt_command_rechecks_authority_before_its_only_signal_operation() {
    let descriptor = TmuxProcessDescriptor::new(
        "agent",
        "1720000000000-controller",
        &exec_params("process", "sleep 30"),
    );
    let command = descriptor.interrupt_command();
    assert!(!command.contains("tmux send-keys"));
    assert_eq!(command.matches("/bin/kill -INT").count(), 1);
    let send = command.find("/bin/kill -INT").expect("signal operation");
    for required in [
        "payload-ready",
        "payload-identity",
        "rechecked_identity",
        "rechecked_pgid",
        "rechecked_payload_pgid",
        "require_interrupt_claim",
        "AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH",
    ] {
        assert!(
            command.find(required).is_some_and(|index| index < send),
            "{required} must precede signal delivery"
        );
    }
}

#[test]
fn termination_command_fences_controller_ownership_before_signaling() {
    let descriptor = TmuxProcessDescriptor::new(
        "agent",
        "1720000000000-controller",
        &exec_params("process", "sleep 30"),
    );
    let command = descriptor.termination_command();
    let claim = command
        .find("ln \"$transition_candidate\" \"$root/transition-claim\"")
        .expect("termination transition claim");
    let terminal_claim = command
        .find("mkdir \"$root/terminal-claim\"")
        .expect("terminal claim");
    let signal = command
        .find("/bin/kill -TERM -- \"-$payload_pgid\"")
        .expect("first payload signal");

    assert!(claim < terminal_claim);
    assert!(terminal_claim < signal);
    assert!(command[..signal].contains("require_termination_claim"));
    assert!(command[..signal].contains("current_controller"));
    assert!(command[..signal].contains("AGENTAPP_TMUX_OWNERSHIP_MISMATCH"));
    assert!(command.contains("termination|t_"));
    assert!(
        descriptor
            .adoption_command()
            .contains("resume_stale_termination=1")
    );
}

#[test]
fn retained_dead_pane_cleanup_never_signals_recorded_numeric_process_ids() {
    let descriptor = TmuxProcessDescriptor::new(
        "agent",
        "1720000000000-controller",
        &exec_params("process", "sleep 30"),
    );
    let command = descriptor.confirmed_process_group_termination();
    let dead_arm = command
        .split("    1)\n")
        .nth(1)
        .and_then(|tail| tail.split("    *)").next())
        .expect("retained dead pane branch");

    assert!(!dead_arm.contains("agentapp_termination_stop_payload"));
    assert!(!dead_arm.contains("/bin/kill"));
    assert!(dead_arm.contains("AGENTAPP_TMUX_DEAD_PANE_IDENTITY_UNKNOWN"));
}

#[cfg(unix)]
#[test]
fn interrupt_without_signal_safe_payload_is_rejected_before_delivery() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let home = tempfile::tempdir().expect("temp home");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).expect("fake bin");
    let tmux = bin.join("tmux");
    fs::write(
        &tmux,
        concat!(
            "#!/bin/sh\n",
            "case \"$1\" in\n",
            "  display-message)\n",
            "    printf '@1:%%fixture:%s:0\\n' \"$FAKE_PANE_PID\"\n",
            "    ;;\n",
            "  *) exit 64 ;;\n",
            "esac\n",
        ),
    )
    .expect("fake tmux");
    fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");

    let mut target = Command::new("/bin/sleep");
    target.arg("30").process_group(0);
    let mut target = target.spawn().expect("spawn target process group");
    let pane_pid = target.id();
    let pgid_output = Command::new("/bin/ps")
        .args(["-o", "pgid=", "-p", &pane_pid.to_string()])
        .output()
        .expect("read target process group");
    let pane_pgid = String::from_utf8(pgid_output.stdout)
        .expect("utf8 process group")
        .trim()
        .to_string();
    assert_eq!(pane_pgid, pane_pid.to_string());

    let descriptor =
        TmuxProcessDescriptor::new("agent", "1:controller", &exec_params("process", "sleep 30"));
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&descriptor.agent_id)
        .join(&descriptor.process_id);
    fs::create_dir_all(&root).expect("descriptor root");
    let process_identity = format!("{pane_pid}:{pane_pgid}");
    for (name, value) in [
        ("owner", "agentapp-tmux-v2"),
        ("controller", descriptor.controller_id.as_str()),
        ("digest", descriptor.command_digest.as_str()),
        ("process-identity", process_identity.as_str()),
        ("window", descriptor.window_name.as_str()),
        ("state", "running"),
    ] {
        fs::write(root.join(name), value).expect("descriptor field");
    }

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(descriptor.interrupt_command())
        .env("HOME", home.path())
        .env("PATH", path)
        .env("FAKE_PANE_PID", pane_pid.to_string())
        .output()
        .expect("run interrupt command");
    let _ = target.kill();
    let _ = target.wait();

    assert_eq!(output.status.code(), Some(80));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("utf8 stderr"),
        "AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH\n"
    );
    assert!(!root.join("transition-claim").exists());
    assert_eq!(
        fs::read_dir(&root)
            .expect("descriptor entries")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".transition-candidate."))
            })
            .count(),
        0
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_interrupt_preserves_the_supervisor_terminal_record() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62489", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "interrupt-controller", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);

    let interrupt = fixture.run_shell(descriptor.interrupt_command());
    assert!(
        interrupt.status.success(),
        "{}",
        String::from_utf8_lossy(&interrupt.stderr)
    );
    assert!(
        wait_for_file_value(&root.join("status"), "130\n"),
        "supervisor did not persist the interrupted payload status; status={:?}; state={:?}; pane={}",
        fs::read_to_string(root.join("status")),
        fs::read_to_string(root.join("state")),
        String::from_utf8_lossy(
            &fixture
                .tmux(&[
                    "display-message",
                    "-p",
                    "-t",
                    &descriptor.target(),
                    "#{window_id}:#{pane_id}:#{pane_pid}:#{pane_dead}:#{pane_dead_status}:#{pane_dead_signal}",
                ])
                .stdout
        )
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("terminal state"),
        "completed\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("terminal-claim/kind")).expect("terminal claim"),
        "completed\n"
    );
    assert!(
        fixture.wait_for_dead_pane(&descriptor),
        "completed supervisor pane did not reach retained-dead state"
    );
    let pane = fixture.tmux(&[
        "display-message",
        "-p",
        "-t",
        &descriptor.target(),
        "#{pane_dead}:#{pane_dead_status}:#{pane_dead_signal}",
    ]);
    assert!(
        pane.status.success(),
        "{}",
        String::from_utf8_lossy(&pane.stderr)
    );
    assert!(
        String::from_utf8_lossy(&pane.stdout)
            .trim()
            .starts_with("1:"),
        "remain-on-exit did not retain terminal pane evidence"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_terminal_cleanup_retires_only_its_execution_session() {
    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let first_params = exec_params("ephemeral-first", "sleep 1; printf 'first-finished\\n'");
    let second_params = exec_params("ephemeral-second", "sleep 30");
    let mut first =
        TmuxProcessDescriptor::new(&fixture.agent_key, "first-controller", &first_params);
    let mut second =
        TmuxProcessDescriptor::new(&fixture.agent_key, "second-controller", &second_params);

    fixture.bootstrap(&mut first, &first_params);
    fixture.bootstrap(&mut second, &second_params);
    assert_ne!(first.session_name, second.session_name);
    assert!(
        fixture
            .tmux(&["has-session", "-t", &first.session_name])
            .status
            .success()
    );
    assert!(
        fixture
            .tmux(&["has-session", "-t", &second.session_name])
            .status
            .success()
    );

    let first_root = fixture.descriptor_root(&first);
    assert!(
        wait_for_file_value(&first_root.join("status"), "0\n"),
        "first execution did not finish"
    );
    assert!(fixture.wait_for_dead_pane(&first));
    let cleanup = fixture.run_shell(first.cleanup_command());
    assert!(
        cleanup.status.success(),
        "{}",
        String::from_utf8_lossy(&cleanup.stderr)
    );
    assert!(
        !fixture
            .tmux(&["has-session", "-t", &first.session_name])
            .status
            .success(),
        "terminal execution session survived cleanup"
    );
    assert!(
        fixture
            .tmux(&["has-session", "-t", &second.session_name])
            .status
            .success(),
        "retiring one execution disturbed its concurrent sibling"
    );
    assert_eq!(
        std::fs::read_to_string(first_root.join("status")).expect("durable terminal status"),
        "0\n"
    );
    assert!(
        std::fs::read_to_string(first_root.join("output"))
            .expect("durable terminal output")
            .contains("first-finished")
    );

    let termination = fixture.run_shell(second.termination_command());
    assert!(
        termination.status.success(),
        "{}",
        String::from_utf8_lossy(&termination.stderr)
    );
    assert!(
        !fixture
            .tmux(&["has-session", "-t", &second.session_name])
            .status
            .success(),
        "last terminal execution left an idle tmux session"
    );
    assert!(
        !fixture
            .tmux(&["has-session", "-t", &format!("agentapp_{}", first.agent_id)])
            .status
            .success(),
        "new executions unexpectedly created a legacy agent-lifetime session"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_short_durable_expiry_closes_the_exact_execution_and_retains_proof() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62601", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "expiry-controller", &params);
    let bootstrap = descriptor
        .bootstrap_command(&params)
        .replacen("max_lifetime=86400", "max_lifetime=1", 1)
        .replacen("sleep 5\ndone", "sleep 1\ndone", 1);
    assert_ne!(bootstrap, descriptor.bootstrap_command(&params));
    let started = fixture.run_shell(bootstrap);
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    apply_ready_protocol(&mut descriptor, &started.stdout);
    let root = fixture.descriptor_root(&descriptor);

    assert!(
        wait_for_file_value(&root.join("status"), "124\n"),
        "expiry did not record its terminal status; state={:?}; claim={:?}",
        fs::read_to_string(root.join("state")),
        fs::read_to_string(root.join("terminal-claim/kind"))
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("expiry terminal state"),
        "expired\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("terminal-claim/kind")).expect("expiry terminal claim"),
        "expired\n"
    );
    assert!(
        root.join("output-closed").is_file(),
        "expiry did not close the durable output stream"
    );
    let expired_output = fs::read_to_string(root.join("output")).expect("expiry output");
    assert_eq!(
        expired_output
            .matches(EXECUTION_EXPIRY_SYSTEM_NOTICE)
            .count(),
        1,
        "expiry notice must be delivered exactly once: {expired_output:?}"
    );
    assert!(
        fixture.wait_for_session_exit(&descriptor.session_name),
        "expired modern execution session survived retirement"
    );
    assert!(root.is_dir(), "expiry discarded its durable descriptor");

    let reconciliation = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "62601".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some(descriptor.command_digest.clone()),
            expected_session_id: Some(62601),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let reconciled = fixture.run_shell(exact_reconciliation_command(
        &fixture.agent_key,
        &reconciliation,
    ));
    assert!(
        reconciled.status.success(),
        "{}",
        String::from_utf8_lossy(&reconciled.stderr)
    );
    let recovered =
        parse_recovered_executions(&reconciled.stdout).expect("parse expiry reconciliation");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].status, RecoveredExecutionStatus::Expired);
    assert!(recovered[0].terminal_verified_dead);
    assert!(
        root.is_dir(),
        "reconciliation removed the terminal descriptor"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_short_durable_tty_expiry_waits_for_its_output_close_receipt() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let mut params = exec_params("62603", "sleep 30");
    params.tty = true;
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "tty-expiry-controller", &params);
    let bootstrap = descriptor
        .bootstrap_command(&params)
        .replacen("max_lifetime=86400", "max_lifetime=1", 1)
        .replacen("sleep 5\ndone", "sleep 1\ndone", 1)
        .replacen(
            "tmux pipe-pane -O -t \"$target\" \"if cat",
            "tmux pipe-pane -O -t \"$target\" \"sleep 4; if cat",
            1,
        );
    assert_ne!(bootstrap, descriptor.bootstrap_command(&params));
    let started = fixture.run_shell(bootstrap);
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    apply_ready_protocol(&mut descriptor, &started.stdout);
    let root = fixture.descriptor_root(&descriptor);
    let output_closed = current_output_closed_path(&root);

    assert!(
        wait_for_file_value(&root.join("terminal-claim/kind"), "expired\n"),
        "TTY expiry did not acquire the terminal claim; state={:?}",
        fs::read_to_string(root.join("state"))
    );
    assert!(
        !root.join("status").exists(),
        "TTY expiry wrote a terminal status before the durable output-close receipt"
    );
    assert!(
        !output_closed.exists(),
        "TTY expiry observed a close receipt before the delayed pipe reader ran"
    );
    assert!(
        wait_for_file_value(&output_closed, ""),
        "TTY expiry did not publish the generation-bound output-close receipt"
    );
    assert!(
        wait_for_file_value(&root.join("status"), "124\n"),
        "TTY expiry did not record status after its output-close receipt; state={:?}",
        fs::read_to_string(root.join("state"))
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("TTY expiry state"),
        "expired\n"
    );
    assert!(
        fs::read_to_string(root.join("output"))
            .expect("TTY expiry output")
            .contains(EXECUTION_EXPIRY_SYSTEM_NOTICE)
    );
    assert!(
        fixture.wait_for_session_exit(&descriptor.session_name),
        "TTY expiry left its modern execution session running"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_expiry_resumes_after_crash_once_its_terminal_claim_is_durable() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62604", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "expiry-resume-controller", &params);
    let bootstrap =
        descriptor
            .bootstrap_command(&params)
            .replacen("sleep 5\ndone", "sleep 1\ndone", 1);
    assert_ne!(bootstrap, descriptor.bootstrap_command(&params));
    let started = fixture.run_shell(bootstrap);
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    apply_ready_protocol(&mut descriptor, &started.stdout);
    let root = fixture.descriptor_root(&descriptor);

    let resume_point = concat!(
        "require_expiry_claim\n",
        "if [ \"$(cat \"$root/tty\" 2>/dev/null || true)\" = 1 ]; then\n"
    );
    let crash_script = descriptor
        .expiry_script()
        .replacen("max_lifetime=86400", "max_lifetime=0", 1)
        .replacen(
            resume_point,
            concat!(
                "require_expiry_claim\n",
                "exit 91\n",
                "if [ \"$(cat \"$root/tty\" 2>/dev/null || true)\" = 1 ]; then\n"
            ),
            1,
        );
    assert_ne!(crash_script, descriptor.expiry_script());
    fs::write(root.join("expiry.sh"), crash_script).expect("install crashing expiry script");

    assert!(
        wait_for_file_value(&root.join("terminal-claim/kind"), "expired\n"),
        "expiry did not durably claim the execution before the injected crash"
    );
    assert!(
        !root.join("status").exists(),
        "injected expiry crash unexpectedly published terminal status"
    );

    let resumed_script =
        descriptor
            .expiry_script()
            .replacen("max_lifetime=86400", "max_lifetime=0", 1);
    fs::write(root.join("expiry.sh"), resumed_script).expect("install resumable expiry script");
    assert!(
        wait_for_file_value(&root.join("status"), "124\n"),
        "expiry did not resume from its durable terminal claim"
    );
    let output = fs::read_to_string(root.join("output")).expect("resumed expiry output");
    assert_eq!(output.matches(EXECUTION_EXPIRY_SYSTEM_NOTICE).count(), 1);
    assert!(
        fixture.wait_for_session_exit(&descriptor.session_name),
        "resumed expiry left its modern execution session running"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_natural_terminal_claim_wins_the_expiry_race() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62602", "printf 'natural completion\\n'");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "natural-race-controller", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    assert!(
        wait_for_file_value(&root.join("status"), "0\n"),
        "natural execution did not publish terminal status"
    );
    let expiry = descriptor
        .expiry_script()
        .replacen("max_lifetime=86400", "max_lifetime=0", 1);
    assert_ne!(expiry, descriptor.expiry_script());
    let raced = fixture.run_shell(expiry);
    assert!(
        raced.status.success(),
        "{}",
        String::from_utf8_lossy(&raced.stderr)
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("natural terminal state"),
        "completed\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("terminal-claim/kind")).expect("natural terminal claim"),
        "completed\n"
    );
    assert!(
        fixture.wait_for_session_exit(&descriptor.session_name),
        "watchdog did not automatically retire the normal terminal session"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_orphan_reaper_removes_only_dead_acknowledged_modern_sessions() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let orphan_agent = "1111111111111111";
    let orphan_process = "2222222222222222";
    let orphan_session = format!("agentapp_{orphan_agent}_{orphan_process}");
    let orphan_window = format!("p_{orphan_process}");
    let retained_agent = "3333333333333333";
    let retained_process = "4444444444444444";
    let retained_session = format!("agentapp_{retained_agent}_{retained_process}");
    let retained_window = format!("p_{retained_process}");
    let live_agent = "5555555555555555";
    let live_process = "6666666666666666";
    let live_session = format!("agentapp_{live_agent}_{live_process}");
    let live_window = format!("p_{live_process}");

    for (session, window) in [
        (&orphan_session, &orphan_window),
        (&retained_session, &retained_window),
        (&live_session, &live_window),
    ] {
        let created = fixture.tmux(&["new-session", "-d", "-s", session, "-n", window, "sleep 30"]);
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );
        let retained = fixture.tmux(&["set-option", "-w", "-t", session, "remain-on-exit", "on"]);
        assert!(
            retained.status.success(),
            "{}",
            String::from_utf8_lossy(&retained.stderr)
        );
    }

    for session in [&orphan_session, &retained_session] {
        let stopped = fixture.tmux(&["send-keys", "-t", session, "C-c"]);
        assert!(
            stopped.status.success(),
            "{}",
            String::from_utf8_lossy(&stopped.stderr)
        );
        let mut dead = false;
        for _ in 0..50 {
            let observed = fixture.tmux(&["display-message", "-p", "-t", session, "#{pane_dead}"]);
            if observed.status.success() && String::from_utf8_lossy(&observed.stdout).trim() == "1"
            {
                dead = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(dead, "{session} did not become a retained dead pane");
    }

    fs::create_dir_all(
        fixture
            .home
            .path()
            .join(".agentapp/tmux")
            .join(retained_agent)
            .join(retained_process),
    )
    .expect("retained descriptor root");

    let reaper = orphaned_execution_session_reaper_command().replacen("-ge 86400", "-ge 0", 1);
    assert_ne!(reaper, orphaned_execution_session_reaper_command());
    let reaped = fixture.run_shell(reaper);
    assert!(
        reaped.status.success(),
        "{}",
        String::from_utf8_lossy(&reaped.stderr)
    );
    assert!(
        !fixture
            .tmux(&["has-session", "-t", &orphan_session])
            .status
            .success(),
        "acknowledged dead modern session was not reaped"
    );
    assert!(
        fixture
            .tmux(&["has-session", "-t", &retained_session])
            .status
            .success(),
        "session with a durable descriptor was reaped"
    );
    assert!(
        fixture
            .tmux(&["has-session", "-t", &live_session])
            .status
            .success(),
        "live session was reaped"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_bootstrap_keeper_is_bounded_and_explicitly_releasable() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };

    let expiry_params = exec_params("keeper-expiry", "printf unused");
    let expiry =
        TmuxProcessDescriptor::new(&fixture.agent_key, "expiry-controller", &expiry_params);
    let expiry_root = fixture.descriptor_root(&expiry);
    fs::create_dir_all(&expiry_root).expect("expiry descriptor root");
    let expiry_keeper = expiry.bootstrap_keeper_command(1);
    let created = fixture.tmux(&[
        "new-session",
        "-d",
        "-s",
        &expiry.session_name,
        "-n",
        "__agentapp_keeper",
        &expiry_keeper,
    ]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let expiry_pid = fixture.pane_pid(&format!("{}:__agentapp_keeper.0", expiry.session_name));
    assert!(
        fixture.wait_for_session_exit(&expiry.session_name),
        "bootstrap keeper session survived its deadline"
    );
    assert!(
        fixture.wait_for_process_exit(expiry_pid),
        "expired bootstrap keeper left pane process {expiry_pid} alive"
    );

    let release_params = exec_params("keeper-release", "printf unused");
    let release =
        TmuxProcessDescriptor::new(&fixture.agent_key, "release-controller", &release_params);
    let release_root = fixture.descriptor_root(&release);
    fs::create_dir_all(&release_root).expect("release descriptor root");
    let release_keeper = release.bootstrap_keeper_command(30);
    let created = fixture.tmux(&[
        "new-session",
        "-d",
        "-s",
        &release.session_name,
        "-n",
        "__agentapp_keeper",
        &release_keeper,
    ]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let release_pid = fixture.pane_pid(&format!("{}:__agentapp_keeper.0", release.session_name));
    fs::write(release_root.join("keeper-release.tmp"), b"").expect("stage keeper release marker");
    fs::rename(
        release_root.join("keeper-release.tmp"),
        release_root.join("keeper-release"),
    )
    .expect("publish keeper release marker");
    assert!(
        fixture.wait_for_session_exit(&release.session_name),
        "bootstrap keeper ignored its release marker"
    );
    assert!(
        fixture.wait_for_process_exit(release_pid),
        "released bootstrap keeper left pane process {release_pid} alive"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_dash_supervisor_preserves_the_interrupted_payload_status() {
    if !std::path::Path::new("/bin/dash").is_file() {
        return;
    }
    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let mut params = exec_params("62494", "sleep 30");
    params.argv[0] = "/bin/dash".to_string();
    let mut descriptor = TmuxProcessDescriptor::new(&fixture.agent_key, "dash-controller", &params);
    fixture.bootstrap_with_shell(&mut descriptor, &params, "/bin/dash");
    let root = fixture.descriptor_root(&descriptor);

    let interrupt = fixture.run_shell(descriptor.interrupt_command());
    assert!(
        interrupt.status.success(),
        "{}",
        String::from_utf8_lossy(&interrupt.stderr)
    );
    assert!(
        wait_for_file_value(&root.join("status"), "130\n"),
        "dash supervisor did not persist interrupted payload status"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("state")).expect("terminal state"),
        "completed\n"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_pre_go_interrupt_keeps_the_supervisor_alive_until_release() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62492", "sleep 30");
    let descriptor = TmuxProcessDescriptor::new(&fixture.agent_key, "pre-go-controller", &params);
    let root = fixture.descriptor_root(&descriptor);
    fs::create_dir_all(&root).expect("descriptor root");
    fs::write(
        root.join("command.sh"),
        format!(
            "#!/bin/sh\nprintf 'survived\\n' > {}/pre-go-result\n",
            shell_quote(&root.to_string_lossy())
        ),
    )
    .expect("pre-go command");

    let session = fixture.tmux(&[
        "new-session",
        "-d",
        "-s",
        &descriptor.session_name,
        "-n",
        "__agentapp_keeper",
        "sleep 30",
    ]);
    assert!(
        session.status.success(),
        "{}",
        String::from_utf8_lossy(&session.stderr)
    );
    let window = fixture.tmux(&[
        "new-window",
        "-d",
        "-t",
        &format!("{}:", descriptor.session_name),
        "-n",
        &descriptor.window_name,
        &descriptor.supervisor_start_command(),
    ]);
    assert!(
        window.status.success(),
        "{}",
        String::from_utf8_lossy(&window.stderr)
    );
    let pane = fixture.tmux(&[
        "display-message",
        "-p",
        "-t",
        &descriptor.target(),
        "#{pane_pid}",
    ]);
    assert!(pane.status.success());
    let pane_pid = String::from_utf8(pane.stdout)
        .expect("pane pid")
        .trim()
        .parse::<u32>()
        .expect("numeric pane pid");
    let pgid = fixture.run_shell(format!("ps -o pgid= -p {pane_pid} | tr -d ' '"));
    assert!(pgid.status.success());
    let pgid = String::from_utf8(pgid.stdout).expect("pane pgid");
    let signaled = std::process::Command::new("/bin/kill")
        .args(["-INT", "--", &format!("-{}", pgid.trim())])
        .status()
        .expect("signal supervisor group");
    assert!(signaled.success());
    std::thread::sleep(std::time::Duration::from_millis(200));
    let pane_state = fixture.tmux(&[
        "display-message",
        "-p",
        "-t",
        &descriptor.target(),
        "#{pane_dead}",
    ]);
    assert_eq!(String::from_utf8_lossy(&pane_state.stdout).trim(), "0");

    fs::write(root.join("go"), []).expect("release supervisor");
    assert!(
        wait_for_file_value(&root.join("pre-go-result"), "survived\n"),
        "supervisor did not survive the pre-go interrupt"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_bootstrap_retry_cannot_leave_a_running_payload_gated() {
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62496", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "bootstrap-cut-controller", &params);
    let cutpoint = "  [ -f \"$root/supervisor-ready\" ] || { echo AGENTAPP_TMUX_SUPERVISOR_START_TIMEOUT >&2; exit 80; }\n";
    let held = descriptor.bootstrap_command(&params).replacen(
        cutpoint,
        concat!(
            "  [ -f \"$root/supervisor-ready\" ] || { echo AGENTAPP_TMUX_SUPERVISOR_START_TIMEOUT >&2; exit 80; }\n",
            "  : > \"$root/bootstrap-held\"\n",
            "  while :; do sleep 1; done\n"
        ),
        1,
    );
    assert_ne!(held, descriptor.bootstrap_command(&params));
    let mut bootstrap = Command::new("/bin/sh");
    bootstrap
        .arg("-c")
        .arg(held)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut bootstrap = bootstrap.spawn().expect("spawn held bootstrap");
    let root = fixture.descriptor_root(&descriptor);
    assert!(
        wait_for_file_value(&root.join("bootstrap-held"), ""),
        "bootstrap did not reach its pre-commit cutpoint"
    );
    let bootstrap_group = bootstrap.id().to_string();
    let killed = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{bootstrap_group}")])
        .status()
        .expect("kill bootstrap operation group");
    assert!(killed.success());
    let _ = bootstrap.wait();
    assert!(root.join("transition-claim").exists());
    assert!(!root.join("go").exists());
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("prepared state"),
        "prepared\n"
    );

    fixture.bootstrap(&mut descriptor, &params);
    assert!(root.join("payload-go").exists());
    assert!(root.join("go").exists());
    assert!(root.join("payload-ready").exists());
    assert!(root.join("payload-identity").exists());
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("running state"),
        "running\n"
    );
    assert!(!root.join("transition-claim").exists());

    let termination = fixture.run_shell(descriptor.termination_command());
    assert!(
        termination.status.success(),
        "{}",
        String::from_utf8_lossy(&termination.stderr)
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_bootstrap_retry_recovers_sigkill_immediately_after_claim() {
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62501", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "bootstrap-claim-controller", &params);
    let cutpoint = "  release_transition_claim() {";
    let held = descriptor.bootstrap_command(&params).replacen(
        cutpoint,
        concat!(
            "  : > \"$root/bootstrap-claim-held\"\n",
            "  while :; do sleep 1; done\n",
            "  release_transition_claim() {"
        ),
        1,
    );
    assert_ne!(held, descriptor.bootstrap_command(&params));
    let mut bootstrap = Command::new("/bin/sh");
    bootstrap
        .arg("-c")
        .arg(held)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut bootstrap = bootstrap.spawn().expect("spawn held bootstrap");
    let root = fixture.descriptor_root(&descriptor);
    assert!(
        wait_for_file_value(&root.join("bootstrap-claim-held"), ""),
        "bootstrap did not reach the immediate post-claim cutpoint"
    );
    let bootstrap_group = bootstrap.id().to_string();
    assert!(
        Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{bootstrap_group}")])
            .status()
            .expect("kill bootstrap operation group")
            .success()
    );
    let _ = bootstrap.wait();
    assert!(root.join("transition-claim").exists());
    assert!(!root.join("process-identity").exists());
    assert!(!root.join("go").exists());

    fixture.bootstrap(&mut descriptor, &params);
    assert!(root.join("go").exists());
    assert!(root.join("payload-ready").exists());
    assert!(!root.join("transition-claim").exists());
    let termination = fixture.run_shell(descriptor.termination_command());
    assert!(
        termination.status.success(),
        "{}",
        String::from_utf8_lossy(&termination.stderr)
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_adoption_rolls_forward_a_sigkill_stale_bootstrap_claim() {
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62500", "sleep 30");
    let descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "bootstrap-owner-controller", &params);
    let cutpoint = "  [ -f \"$root/supervisor-ready\" ] || { echo AGENTAPP_TMUX_SUPERVISOR_START_TIMEOUT >&2; exit 80; }\n";
    let held = descriptor.bootstrap_command(&params).replacen(
        cutpoint,
        concat!(
            "  [ -f \"$root/supervisor-ready\" ] || { echo AGENTAPP_TMUX_SUPERVISOR_START_TIMEOUT >&2; exit 80; }\n",
            "  : > \"$root/bootstrap-adoption-held\"\n",
            "  while :; do sleep 1; done\n"
        ),
        1,
    );
    assert_ne!(held, descriptor.bootstrap_command(&params));
    let mut bootstrap = Command::new("/bin/sh");
    bootstrap
        .arg("-c")
        .arg(held)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut bootstrap = bootstrap.spawn().expect("spawn held bootstrap");
    let root = fixture.descriptor_root(&descriptor);
    assert!(
        wait_for_file_value(&root.join("bootstrap-adoption-held"), ""),
        "bootstrap did not reach its pre-commit cutpoint"
    );
    let bootstrap_group = bootstrap.id().to_string();
    assert!(
        Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{bootstrap_group}")])
            .status()
            .expect("kill bootstrap operation group")
            .success()
    );
    let _ = bootstrap.wait();
    assert!(root.join("transition-claim").exists());
    assert!(!root.join("go").exists());

    let adoption = AdoptionRequest {
        identity: params.execution_identity.expect("execution identity"),
        expected_command_digest: descriptor.command_digest,
        original_session_id: Some(62500),
        committed_output_cursor: 0,
        tty: false,
    };
    let mut adopter = TmuxProcessDescriptor::from_adoption(
        &fixture.agent_key,
        "replacement-bootstrap-controller",
        &adoption,
    );
    let adopted = fixture.run_shell(adopter.adoption_command());
    assert!(
        adopted.status.success(),
        "{}",
        String::from_utf8_lossy(&adopted.stderr)
    );
    apply_adopted_protocol(&mut adopter, &adopted.stdout);
    assert!(root.join("go").exists());
    assert!(root.join("payload-go").exists());
    assert!(root.join("payload-ready").exists());
    assert_eq!(
        std::fs::read_to_string(root.join("state")).expect("running state"),
        "running\n"
    );
    assert!(!root.join("transition-claim").exists());

    let termination = fixture.run_shell(adopter.termination_command());
    assert!(
        termination.status.success(),
        "{}",
        String::from_utf8_lossy(&termination.stderr)
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_adoption_upgrades_a_running_modern_session_to_durable_expiry() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62603", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "pre-expiry-controller", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    fs::remove_file(root.join("created-at")).expect("remove simulated legacy created-at");
    fs::remove_file(root.join("expiry.sh")).expect("remove simulated legacy expiry script");
    fs::remove_file(root.join("terminal-cleanup.sh"))
        .expect("remove simulated legacy cleanup script");
    fs::write(root.join("watchdog.sh"), "#!/bin/sh\nexit 99\n")
        .expect("simulate legacy watchdog script");

    let adoption = AdoptionRequest {
        identity: params
            .execution_identity
            .clone()
            .expect("execution identity"),
        expected_command_digest: descriptor.command_digest.clone(),
        original_session_id: Some(62603),
        committed_output_cursor: 0,
        tty: false,
    };
    let mut adopter =
        TmuxProcessDescriptor::from_adoption(&fixture.agent_key, "expiry-upgrade", &adoption);
    let adopted = fixture.run_shell(adopter.adoption_command());
    assert!(
        adopted.status.success(),
        "{}",
        String::from_utf8_lossy(&adopted.stderr)
    );
    apply_adopted_protocol(&mut adopter, &adopted.stdout);

    let observed_created = fixture.tmux(&[
        "display-message",
        "-p",
        "-t",
        &adopter.session_name,
        "#{session_created}",
    ]);
    assert!(
        observed_created.status.success(),
        "{}",
        String::from_utf8_lossy(&observed_created.stderr)
    );
    assert_eq!(
        fs::read_to_string(root.join("created-at"))
            .expect("migrated created-at")
            .trim(),
        String::from_utf8(observed_created.stdout)
            .expect("session creation timestamp")
            .trim()
    );
    assert!(
        fs::read_to_string(root.join("expiry.sh"))
            .expect("migrated expiry script")
            .contains(EXECUTION_EXPIRY_SYSTEM_NOTICE)
    );
    assert!(
        fs::read_to_string(root.join("terminal-cleanup.sh"))
            .expect("migrated cleanup script")
            .contains("completed:completed")
    );
    assert!(
        fs::read_to_string(root.join("watchdog.sh"))
            .expect("migrated watchdog script")
            .contains("/bin/sh \"$root/expiry.sh\"")
    );
    let windows = fixture.tmux(&[
        "list-windows",
        "-t",
        &adopter.session_name,
        "-F",
        "#{window_name}",
    ]);
    assert!(
        windows.status.success(),
        "{}",
        String::from_utf8_lossy(&windows.stderr)
    );
    let windows = String::from_utf8(windows.stdout).expect("window listing");
    assert_eq!(
        windows
            .lines()
            .filter(|window| *window == adopter.watchdog_window_name)
            .count(),
        1
    );
    assert!(!windows.lines().any(|window| window.starts_with("u_")));

    let termination = fixture.run_shell(adopter.termination_command());
    assert!(
        termination.status.success(),
        "{}",
        String::from_utf8_lossy(&termination.stderr)
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_tty_payload_is_foreground_and_can_read_input() {
    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let mut params = exec_params("62493", "IFS= read -r line; printf 'tty:%s\\n' \"$line\"");
    params.tty = true;
    let mut descriptor = TmuxProcessDescriptor::new(&fixture.agent_key, "tty-controller", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);

    let text = fixture.tmux(&["send-keys", "-t", &descriptor.target(), "-l", "--", "hello"]);
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    let enter = fixture.tmux(&["send-keys", "-t", &descriptor.target(), "Enter"]);
    assert!(
        enter.status.success(),
        "{}",
        String::from_utf8_lossy(&enter.stderr)
    );
    assert!(
        wait_for_file_value(&root.join("status"), "0\n"),
        "TTY payload did not complete; state={:?}; output={:?}; pane={}; processes={}",
        std::fs::read_to_string(root.join("state")),
        std::fs::read_to_string(root.join("output")),
        String::from_utf8_lossy(
            &fixture
                .tmux(&[
                    "display-message",
                    "-p",
                    "-t",
                    &descriptor.target(),
                    "#{pane_dead}:#{pane_pid}:#{pane_current_command}",
                ])
                .stdout
        ),
        String::from_utf8_lossy(
            &fixture
                .run_shell(
                    "ps -axo pid=,ppid=,pgid=,tpgid=,state=,command= | grep -E '62493|tty:%s|payload-go|read -r' | grep -v grep"
                        .to_string()
                )
                .stdout
        )
    );
    assert!(
        wait_for_file_contains(&root.join("output"), "tty:hello"),
        "TTY payload did not receive foreground input; output={:?}",
        std::fs::read_to_string(root.join("output"))
    );
    let output_closed = current_output_closed_path(&root);
    assert!(
        wait_for_file_value(&output_closed, ""),
        "TTY pipe did not publish its generation-bound durable close barrier"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_monitor_waits_for_delayed_tty_pipe_close_and_tail() {
    use std::time::Instant;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let mut params = exec_params("62499", "printf 'late-tty-tail\\n'");
    params.tty = true;
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "tty-drain-controller", &params);
    let bootstrap = descriptor.bootstrap_command(&params).replacen(
        "tmux pipe-pane -O -t \"$target\" \"if cat",
        "tmux pipe-pane -O -t \"$target\" \"sleep 8; if cat",
        1,
    );
    assert_ne!(bootstrap, descriptor.bootstrap_command(&params));
    let started = fixture.run_shell(bootstrap);
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    apply_ready_protocol(&mut descriptor, &started.stdout);
    let root = fixture.descriptor_root(&descriptor);
    let output_closed = current_output_closed_path(&root);
    assert!(
        !output_closed.exists(),
        "delayed pipe unexpectedly closed before monitor attachment"
    );

    let attached = Instant::now();
    let monitor = fixture.run_shell(descriptor.monitor_command(1));
    assert_eq!(monitor.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&monitor.stdout).contains("late-tty-tail"),
        "{}",
        String::from_utf8_lossy(&monitor.stdout)
    );
    assert!(
        attached.elapsed() >= std::time::Duration::from_secs(4),
        "monitor crossed the terminal boundary before the delayed TTY pipe closed"
    );
    assert!(output_closed.exists());
    assert_eq!(
        std::fs::read_to_string(root.join("status")).expect("terminal status"),
        "0\n"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_bootstrap_roll_forward_ignores_a_stale_tty_pipe_close_receipt() {
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;
    use std::time::Instant;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let mut params = exec_params("62500", "printf 'generation-tail\\n'");
    params.tty = true;
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "tty-generation-controller", &params);
    let payload_release = "  if [ ! -f \"$root/payload-go\" ]; then";
    let held = descriptor.bootstrap_command(&params).replacen(
        payload_release,
        concat!(
            "  : > \"$root/tty-pipe-held\"\n",
            "  while :; do sleep 1; done\n",
            "  if [ ! -f \"$root/payload-go\" ]; then"
        ),
        1,
    );
    assert_ne!(held, descriptor.bootstrap_command(&params));
    let mut bootstrap = Command::new("/bin/sh");
    bootstrap
        .arg("-c")
        .arg(held)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut bootstrap = bootstrap.spawn().expect("spawn held TTY bootstrap");
    let root = fixture.descriptor_root(&descriptor);
    assert!(
        wait_for_file_value(&root.join("tty-pipe-held"), ""),
        "bootstrap did not reach its post-pipe pre-go cutpoint"
    );
    let first_generation =
        fs::read_to_string(root.join("output-pipe-generation")).expect("first generation");
    let first_generation = first_generation.trim().to_string();
    let bootstrap_group = bootstrap.id().to_string();
    let killed = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{bootstrap_group}")])
        .status()
        .expect("kill held TTY bootstrap");
    assert!(killed.success());
    let _ = bootstrap.wait();
    assert!(root.join("transition-claim").exists());
    assert!(!root.join("go").exists());

    let retry = descriptor.bootstrap_command(&params).replacen(
        "tmux pipe-pane -O -t \"$target\" \"if cat",
        "tmux pipe-pane -O -t \"$target\" \"sleep 8; if cat",
        1,
    );
    assert_ne!(retry, descriptor.bootstrap_command(&params));
    let started = fixture.run_shell(retry);
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    apply_ready_protocol(&mut descriptor, &started.stdout);
    let current_generation =
        fs::read_to_string(root.join("output-pipe-generation")).expect("current generation");
    let current_generation = current_generation.trim().to_string();
    assert_ne!(current_generation, first_generation);
    assert!(
        wait_for_file_value(&root.join(format!("output-closed.{first_generation}")), ""),
        "replaced pipe did not publish its stale generation receipt"
    );
    let current_closed = root.join(format!("output-closed.{current_generation}"));
    assert!(
        !current_closed.exists(),
        "stale receipt was mistaken for the current pipe generation"
    );

    let attached = Instant::now();
    let monitor = fixture.run_shell(descriptor.monitor_command(1));
    assert_eq!(monitor.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&monitor.stdout).contains("generation-tail"),
        "{}",
        String::from_utf8_lossy(&monitor.stdout)
    );
    assert!(
        attached.elapsed() >= std::time::Duration::from_secs(4),
        "monitor crossed the terminal boundary using a stale pipe receipt"
    );
    assert!(current_closed.exists());
}

#[cfg(unix)]
#[test]
fn real_tmux_pre_go_tty_pipe_generation_crash_reconciles_without_a_receipt() {
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let mut params = exec_params("62502", "printf 'must-not-run\\n'");
    params.tty = true;
    let descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "tty-pre-go-controller", &params);
    let generation_cutpoint =
        "mv \"$root/output-pipe-generation.tmp\" \"$root/output-pipe-generation\"\n";
    let held = descriptor.bootstrap_command(&params).replacen(
        generation_cutpoint,
        concat!(
            "mv \"$root/output-pipe-generation.tmp\" \"$root/output-pipe-generation\"\n",
            ": > \"$root/tty-generation-held\"\n",
            "while :; do sleep 1; done\n"
        ),
        1,
    );
    assert_ne!(held, descriptor.bootstrap_command(&params));
    let mut bootstrap = Command::new("/bin/sh");
    bootstrap
        .arg("-c")
        .arg(held)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut bootstrap = bootstrap.spawn().expect("spawn held pre-go TTY bootstrap");
    let root = fixture.descriptor_root(&descriptor);
    assert!(
        wait_for_file_value(&root.join("tty-generation-held"), ""),
        "bootstrap did not reach the generation-persisted pre-pipe cutpoint"
    );
    let generation =
        fs::read_to_string(root.join("output-pipe-generation")).expect("pipe generation");
    assert_eq!(generation, "1\n");
    assert!(!root.join("output-closed.1").exists());
    assert!(!root.join("go").exists());

    let bootstrap_group = bootstrap.id().to_string();
    assert!(
        Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{bootstrap_group}")])
            .status()
            .expect("kill pre-go TTY bootstrap")
            .success()
    );
    let _ = bootstrap.wait();

    let reconciliation = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "62502".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some(descriptor.command_digest),
            expected_session_id: Some(62502),
            expected_tty: Some(true),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let reconciled = fixture.run_shell(exact_reconciliation_command(
        &fixture.agent_key,
        &reconciliation,
    ));
    assert!(
        reconciled.status.success(),
        "{}",
        String::from_utf8_lossy(&reconciled.stderr)
    );
    let recovered =
        parse_recovered_executions(&reconciled.stdout).expect("parse reconciliation output");
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0].status,
        RecoveredExecutionStatus::LaunchInterrupted
    );
    assert!(recovered[0].terminal_verified_dead);
    assert_eq!(
        fs::read_to_string(root.join("status")).expect("launch-interrupted status"),
        "125\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("launch-interrupted state"),
        "launch-interrupted\n"
    );
    assert!(!root.join("output-closed.1").exists());
    assert!(!root.join("go").exists());
}

#[cfg(unix)]
#[test]
fn real_tmux_reconciliation_waits_for_the_current_tty_pipe_tail() {
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let mut params = exec_params("62501", "printf 'reconciliation-tail\\n'; sleep 30");
    params.tty = true;
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "tty-reconciliation-controller", &params);
    let gated_pipe = descriptor.bootstrap_command(&params).replacen(
        "tmux pipe-pane -O -t \"$target\" \"if cat",
        "tmux pipe-pane -O -t \"$target\" \"while [ ! -f \\\"$root/pipe-release\\\" ]; do sleep 1; done; if cat",
        1,
    );
    assert_ne!(gated_pipe, descriptor.bootstrap_command(&params));
    let started = fixture.run_shell(gated_pipe);
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    apply_ready_protocol(&mut descriptor, &started.stdout);
    let root = fixture.descriptor_root(&descriptor);
    let current_closed = current_output_closed_path(&root);
    assert!(!current_closed.exists());

    let kill_window = "if [ \"$window_exists\" -eq 1 ]; then tmux kill-window -t \"$current_window_id\" 2>/dev/null || true; fi\n";
    let held_termination = descriptor.termination_command().replacen(
        kill_window,
        concat!(
            "if [ \"$window_exists\" -eq 1 ]; then tmux kill-window -t \"$current_window_id\" 2>/dev/null || true; fi\n",
            ": > \"$root/termination-after-window-removal\"\n",
            "while :; do sleep 1; done\n"
        ),
        1,
    );
    assert_ne!(held_termination, descriptor.termination_command());
    let mut terminator = Command::new("/bin/sh");
    terminator
        .arg("-c")
        .arg(held_termination)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut terminator = terminator.spawn().expect("spawn held TTY termination");
    assert!(
        (0..4).any(|_| { wait_for_file_value(&root.join("termination-after-window-removal"), "") }),
        "termination did not remove the TTY pane"
    );
    let termination_group = terminator.id().to_string();
    let killed = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{termination_group}")])
        .status()
        .expect("kill TTY termination controller");
    assert!(killed.success());
    let _ = terminator.wait();
    assert!(!root.join("status").exists());
    assert!(!current_closed.exists());

    let reconciliation = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "62501".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some(descriptor.command_digest),
            expected_session_id: Some(62501),
            expected_tty: Some(true),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let mut reconciliation_process = Command::new("/bin/sh");
    reconciliation_process
        .arg("-c")
        .arg(exact_reconciliation_command(
            &fixture.agent_key,
            &reconciliation,
        ))
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut reconciliation_process = reconciliation_process
        .spawn()
        .expect("spawn TTY reconciliation");
    std::thread::sleep(std::time::Duration::from_millis(1_500));
    assert!(
        reconciliation_process
            .try_wait()
            .expect("poll reconciliation")
            .is_none(),
        "reconciliation crossed the terminal cursor before the TTY pipe closed"
    );
    assert!(!root.join("status").exists());

    fs::write(root.join("pipe-release"), []).expect("release delayed pipe");
    let reconciled = reconciliation_process
        .wait_with_output()
        .expect("wait for reconciliation");
    assert!(
        reconciled.status.success(),
        "{}",
        String::from_utf8_lossy(&reconciled.stderr)
    );
    let recovered =
        parse_recovered_executions(&reconciled.stdout).expect("parse recovered execution");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].status, RecoveredExecutionStatus::Terminated);
    assert!(
        String::from_utf8_lossy(&recovered[0].output).contains("reconciliation-tail"),
        "{:?}",
        recovered[0].output
    );
    assert!(current_closed.exists());
}

#[cfg(unix)]
#[test]
fn real_tmux_termination_blocks_adoption_and_rolls_forward_after_controller_loss() {
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62497", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "termination-race-controller", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    let cutpoint = "claimed=0\n";
    let held = descriptor.termination_command().replacen(
        cutpoint,
        concat!(
            "  : > \"$root/termination-held\"\n",
            "  while [ ! -f \"$root/termination-release\" ]; do sleep 1; done\n",
            "claimed=0\n"
        ),
        1,
    );
    let mut terminator = Command::new("/bin/sh");
    terminator
        .arg("-c")
        .arg(held)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut terminator = terminator.spawn().expect("spawn held termination");
    assert!(
        wait_for_file_value(&root.join("termination-held"), ""),
        "termination did not reach its fenced cutpoint"
    );

    let identity = params
        .execution_identity
        .clone()
        .expect("execution identity");
    let adoption = AdoptionRequest {
        identity,
        expected_command_digest: descriptor.command_digest.clone(),
        original_session_id: Some(62497),
        committed_output_cursor: 0,
        tty: false,
    };
    let adopter = TmuxProcessDescriptor::from_adoption(
        &fixture.agent_key,
        "replacement-controller",
        &adoption,
    );
    let blocked = fixture.run_shell(adopter.adoption_command());
    assert_eq!(blocked.status.code(), Some(79));
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("AGENTAPP_TMUX_ADOPT_BUSY"));

    let operation_group = terminator.id().to_string();
    let killed = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{operation_group}")])
        .status()
        .expect("kill obsolete termination controller");
    assert!(killed.success());
    let _ = terminator.wait();
    assert!(root.join("transition-claim").exists());
    assert!(!root.join("status").exists());

    let takeover_cutpoint = "if [ \"$resume_stale_termination\" -eq 1 ]; then\n";
    let held_takeover = adopter.adoption_command().replacen(
        takeover_cutpoint,
        concat!(
            "if [ \"$resume_stale_termination\" -eq 1 ]; then\n",
            "  : > \"$root/termination-takeover-held\"\n",
            "  while :; do sleep 1; done\n"
        ),
        1,
    );
    assert_ne!(held_takeover, adopter.adoption_command());
    let mut takeover = Command::new("/bin/sh");
    takeover
        .arg("-c")
        .arg(held_takeover)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut takeover = takeover.spawn().expect("spawn held termination takeover");
    assert!(
        wait_for_file_value(&root.join("termination-takeover-held"), ""),
        "adoption did not reach the stale-termination takeover cutpoint"
    );
    assert_eq!(
        fs::read_to_string(root.join("terminal-claim/kind")).expect("terminal intent"),
        "terminated\n"
    );
    assert!(
        root.join("transition-claim").exists(),
        "stale termination lost its transition claim before replacement"
    );
    let takeover_group = takeover.id().to_string();
    let killed = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{takeover_group}")])
        .status()
        .expect("kill stale-termination takeover");
    assert!(killed.success());
    let _ = takeover.wait();
    assert!(
        root.join("transition-claim").exists(),
        "SIGKILL at takeover cutpoint left terminal intent claimless"
    );

    let resumed = fixture.run_shell(adopter.adoption_command());
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&resumed.stdout).contains("AGENTAPP_TMUX_ADOPTED"),
        "{}",
        String::from_utf8_lossy(&resumed.stdout)
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("terminal state"),
        "terminated\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("status")).expect("terminal status"),
        "143\n"
    );
    assert!(!root.join("transition-claim").exists());
}

#[cfg(unix)]
#[test]
fn real_tmux_caught_signal_preserves_normal_termination_ownership() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62505", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "signal-safe-terminator", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    let process_identity =
        fs::read_to_string(root.join("process-identity")).expect("process identity");
    let (_, payload_pgid) = process_identity
        .trim()
        .split_once(':')
        .expect("supervisor pid and process group");

    let terminal_intent_cutpoint =
        "  mv \"$root/terminal-claim/kind.tmp\" \"$root/terminal-claim/kind\"\n";
    let interrupted_termination = descriptor.termination_command().replacen(
        terminal_intent_cutpoint,
        concat!(
            "  mv \"$root/terminal-claim/kind.tmp\" \"$root/terminal-claim/kind\"\n",
            "  kill -TERM $$\n"
        ),
        1,
    );
    assert_ne!(interrupted_termination, descriptor.termination_command());

    let terminated = fixture.run_shell(interrupted_termination);
    assert!(
        terminated.status.success(),
        "{}",
        String::from_utf8_lossy(&terminated.stderr)
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("terminal state"),
        "terminated\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("status")).expect("terminal status"),
        "143\n"
    );
    assert!(!root.join("transition-claim").exists());
    assert!(
        wait_for_process_group_death(payload_pgid),
        "caught TERM abandoned the live payload group"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_caught_signal_preserves_stale_termination_takeover_ownership() {
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62506", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "signal-safe-takeover-owner", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    let process_identity =
        fs::read_to_string(root.join("process-identity")).expect("process identity");
    let (_, payload_pgid) = process_identity
        .trim()
        .split_once(':')
        .expect("supervisor pid and process group");

    let held_termination = descriptor.termination_command().replacen(
        "claimed=0\n",
        concat!(
            ": > \"$root/signal-takeover-held\"\n",
            "while :; do sleep 1; done\n",
            "claimed=0\n"
        ),
        1,
    );
    let mut terminator = Command::new("/bin/sh");
    terminator
        .arg("-c")
        .arg(held_termination)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut terminator = terminator.spawn().expect("spawn stale termination owner");
    assert!(
        wait_for_file_value(&root.join("signal-takeover-held"), ""),
        "termination did not publish its stale-claim fixture"
    );
    let terminator_group = terminator.id().to_string();
    assert!(
        Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{terminator_group}")])
            .status()
            .expect("kill stale termination owner")
            .success()
    );
    let _ = terminator.wait();
    fs::create_dir_all(root.join("terminal-claim")).expect("terminal claim directory");
    fs::write(root.join("terminal-claim/kind"), "terminated\n")
        .expect("durable termination intent");

    let adoption = AdoptionRequest {
        identity: params
            .execution_identity
            .clone()
            .expect("execution identity"),
        expected_command_digest: descriptor.command_digest.clone(),
        original_session_id: Some(62506),
        committed_output_cursor: 0,
        tty: false,
    };
    let adopter =
        TmuxProcessDescriptor::from_adoption(&fixture.agent_key, "signal-safe-takeover", &adoption);
    let replacement_cutpoint = "  mv \"$transition_publish\" \"$root/transition-claim\"\n";
    let interrupted_takeover = adopter.adoption_command().replacen(
        replacement_cutpoint,
        concat!(
            "  mv \"$transition_publish\" \"$root/transition-claim\"\n",
            "  kill -TERM $$\n"
        ),
        1,
    );
    assert_ne!(interrupted_takeover, adopter.adoption_command());

    let resumed = fixture.run_shell(interrupted_takeover);
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("terminal state"),
        "terminated\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("status")).expect("terminal status"),
        "143\n"
    );
    assert!(!root.join("transition-claim").exists());
    assert!(
        wait_for_process_group_death(payload_pgid),
        "caught TERM abandoned the payload during takeover"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_stale_termination_takeover_has_exactly_one_adopter() {
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62503", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "termination-owner", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);

    let held_termination = descriptor.termination_command().replacen(
        "claimed=0\n",
        concat!(
            ": > \"$root/termination-race-held\"\n",
            "while :; do sleep 1; done\n",
            "claimed=0\n"
        ),
        1,
    );
    let mut terminator = Command::new("/bin/sh");
    terminator
        .arg("-c")
        .arg(held_termination)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut terminator = terminator.spawn().expect("spawn held termination");
    assert!(
        wait_for_file_value(&root.join("termination-race-held"), ""),
        "termination did not publish its stale-claim fixture"
    );
    let terminator_group = terminator.id().to_string();
    assert!(
        Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{terminator_group}")])
            .status()
            .expect("kill stale termination owner")
            .success()
    );
    let _ = terminator.wait();
    assert!(root.join("transition-claim").exists());
    assert!(!root.join("status").exists());
    fs::create_dir_all(root.join("terminal-claim")).expect("terminal claim directory");
    fs::write(root.join("terminal-claim/kind"), "terminated\n")
        .expect("durable termination intent");

    let adoption = AdoptionRequest {
        identity: params
            .execution_identity
            .clone()
            .expect("execution identity"),
        expected_command_digest: descriptor.command_digest.clone(),
        original_session_id: Some(62503),
        committed_output_cursor: 0,
        tty: false,
    };
    let adopter_a =
        TmuxProcessDescriptor::from_adoption(&fixture.agent_key, "takeover-a", &adoption);
    let adopter_b =
        TmuxProcessDescriptor::from_adoption(&fixture.agent_key, "takeover-b", &adoption);
    let takeover_cutpoint = "  takeover_arbiter=\"$root/.transition-candidate.takeover.$claim_nonce.$claim_operation_pid\"\n";
    let command_a = adopter_a.adoption_command().replacen(
        takeover_cutpoint,
        concat!(
            "  : > \"$root/takeover-a-ready\"\n",
            "  while [ ! -f \"$root/takeover-race-release\" ]; do sleep 1; done\n",
            "  takeover_arbiter=\"$root/.transition-candidate.takeover.$claim_nonce.$claim_operation_pid\"\n"
        ),
        1,
    );
    let command_b = adopter_b.adoption_command().replacen(
        takeover_cutpoint,
        concat!(
            "  : > \"$root/takeover-b-ready\"\n",
            "  while [ ! -f \"$root/takeover-race-release\" ]; do sleep 1; done\n",
            "  takeover_arbiter=\"$root/.transition-candidate.takeover.$claim_nonce.$claim_operation_pid\"\n"
        ),
        1,
    );
    assert_ne!(command_a, adopter_a.adoption_command());
    assert_ne!(command_b, adopter_b.adoption_command());

    let spawn_adopter = |command: String| {
        let mut child = Command::new("/bin/sh");
        child
            .arg("-c")
            .arg(command)
            .env("HOME", fixture.home.path())
            .env("PATH", &fixture.path)
            .env_remove("TMUX")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        child.spawn().expect("spawn competing termination adopter")
    };
    let adopter_a_process = spawn_adopter(command_a);
    let adopter_b_process = spawn_adopter(command_b);
    assert!(
        wait_for_file_value(&root.join("takeover-a-ready"), "")
            && wait_for_file_value(&root.join("takeover-b-ready"), ""),
        "both adopters did not reach the pre-publication barrier"
    );
    fs::write(root.join("takeover-race-release"), []).expect("release takeover race");

    let output_a = adopter_a_process
        .wait_with_output()
        .expect("wait for adopter A");
    let output_b = adopter_b_process
        .wait_with_output()
        .expect("wait for adopter B");
    let successes = [output_a.status.success(), output_b.status.success()]
        .into_iter()
        .filter(|success| *success)
        .count();
    assert_eq!(
        successes,
        1,
        "expected one takeover winner; A={:?} stderr={}; B={:?} stderr={}",
        output_a.status.code(),
        String::from_utf8_lossy(&output_a.stderr),
        output_b.status.code(),
        String::from_utf8_lossy(&output_b.stderr)
    );
    let loser = if output_a.status.success() {
        &output_b
    } else {
        &output_a
    };
    assert_eq!(
        loser.status.code(),
        Some(79),
        "{}",
        String::from_utf8_lossy(&loser.stderr)
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("terminal state"),
        "terminated\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("status")).expect("terminal status"),
        "143\n"
    );
    assert!(!root.join("transition-claim").exists());
    assert_eq!(
        fs::read_dir(&root)
            .expect("descriptor entries")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".transition-candidate.takeover."))
            })
            .count(),
        0
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_stale_termination_takeover_serializes_dead_arbiter_reclamation() {
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62504", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "termination-chain-owner", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    let process_identity =
        fs::read_to_string(root.join("process-identity")).expect("process identity");
    let (_, payload_pgid) = process_identity
        .trim()
        .split_once(':')
        .expect("supervisor pid and process group");

    let held_termination = descriptor.termination_command().replacen(
        "claimed=0\n",
        concat!(
            ": > \"$root/termination-chain-held\"\n",
            "while :; do sleep 1; done\n",
            "claimed=0\n"
        ),
        1,
    );
    let mut terminator = Command::new("/bin/sh");
    terminator
        .arg("-c")
        .arg(held_termination)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut terminator = terminator.spawn().expect("spawn held termination");
    assert!(
        wait_for_file_value(&root.join("termination-chain-held"), ""),
        "termination did not publish its stale-claim fixture"
    );
    let terminator_group = terminator.id().to_string();
    assert!(
        Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{terminator_group}")])
            .status()
            .expect("kill original termination owner")
            .success()
    );
    let _ = terminator.wait();
    fs::create_dir_all(root.join("terminal-claim")).expect("terminal claim directory");
    fs::write(root.join("terminal-claim/kind"), "terminated\n")
        .expect("durable termination intent");

    let stale_claim =
        fs::read_to_string(root.join("transition-claim")).expect("stale termination claim");
    let stale_fields = stale_claim.trim().split('|').collect::<Vec<_>>();
    assert_eq!(stale_fields.len(), 8, "{stale_claim:?}");
    assert_eq!(stale_fields[0], "termination");
    let stale_nonce = stale_fields[1];
    let stale_operation_pid = stale_fields[3];
    let current_controller = stale_fields[2];
    let expected_window = stale_fields[5];
    let pane_pid = stale_fields[6];
    assert_eq!(stale_fields[7], payload_pgid);

    let mut dead_takeover_owner = Command::new("/bin/sh");
    dead_takeover_owner.arg("-c").arg("exit 0").process_group(0);
    let mut dead_takeover_owner = dead_takeover_owner
        .spawn()
        .expect("spawn first takeover owner");
    let dead_takeover_pid = dead_takeover_owner.id().to_string();
    assert!(
        dead_takeover_owner
            .wait()
            .expect("wait for first takeover owner")
            .success()
    );
    assert!(
        wait_for_process_group_death(&dead_takeover_pid),
        "first takeover owner process group remained alive"
    );
    let dead_takeover_nonce = "ta_seed_dead";
    let dead_takeover_claim = format!(
        "termination|{dead_takeover_nonce}|{current_controller}|{dead_takeover_pid}|{dead_takeover_pid}|{expected_window}|{pane_pid}|{payload_pgid}\n"
    );
    let dead_takeover_candidate = root.join(format!(
        ".transition-candidate.{dead_takeover_nonce}.{dead_takeover_pid}"
    ));
    let dead_takeover_arbiter = root.join(format!(
        ".transition-candidate.takeover.{stale_nonce}.{stale_operation_pid}"
    ));
    fs::write(&dead_takeover_candidate, &dead_takeover_claim).expect("dead takeover candidate");
    fs::hard_link(&dead_takeover_candidate, &dead_takeover_arbiter).expect("dead takeover arbiter");

    let adoption = AdoptionRequest {
        identity: params
            .execution_identity
            .clone()
            .expect("execution identity"),
        expected_command_digest: descriptor.command_digest.clone(),
        original_session_id: Some(62504),
        committed_output_cursor: 0,
        tty: false,
    };
    let adopter_a =
        TmuxProcessDescriptor::from_adoption(&fixture.agent_key, "chain-takeover-a", &adoption);
    let adopter_b =
        TmuxProcessDescriptor::from_adoption(&fixture.agent_key, "chain-takeover-b", &adoption);
    let publication_cutpoint =
        "  ln \"$transition_candidate\" \"$takeover_arbiter\" 2>/dev/null ||";
    let command_a = adopter_a.adoption_command().replacen(
        publication_cutpoint,
        concat!(
            "  : > \"$root/chain-takeover-a-ready\"\n",
            "  while [ ! -f \"$root/chain-takeover-release\" ]; do sleep 1; done\n",
            "  ln \"$transition_candidate\" \"$takeover_arbiter\" 2>/dev/null ||"
        ),
        1,
    );
    let command_b = adopter_b.adoption_command().replacen(
        publication_cutpoint,
        concat!(
            "  : > \"$root/chain-takeover-b-ready\"\n",
            "  while [ ! -f \"$root/chain-takeover-release\" ]; do sleep 1; done\n",
            "  ln \"$transition_candidate\" \"$takeover_arbiter\" 2>/dev/null ||"
        ),
        1,
    );
    assert_ne!(command_a, adopter_a.adoption_command());
    assert_ne!(command_b, adopter_b.adoption_command());

    let spawn_adopter = |command: String| {
        let mut child = Command::new("/bin/sh");
        child
            .arg("-c")
            .arg(command)
            .env("HOME", fixture.home.path())
            .env("PATH", &fixture.path)
            .env_remove("TMUX")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        child.spawn().expect("spawn chained termination adopter")
    };
    let adopter_a_process = spawn_adopter(command_a);
    let adopter_b_process = spawn_adopter(command_b);
    assert!(
        wait_for_file_value(&root.join("chain-takeover-a-ready"), "")
            && wait_for_file_value(&root.join("chain-takeover-b-ready"), ""),
        "both adopters did not validate the dead owner chain"
    );
    fs::write(root.join("chain-takeover-release"), []).expect("release chained takeover race");

    let output_a = adopter_a_process
        .wait_with_output()
        .expect("wait for chained adopter A");
    let output_b = adopter_b_process
        .wait_with_output()
        .expect("wait for chained adopter B");
    let successes = [output_a.status.success(), output_b.status.success()]
        .into_iter()
        .filter(|success| *success)
        .count();
    assert_eq!(
        successes,
        1,
        "expected one chained takeover winner; A={:?} stderr={}; B={:?} stderr={}",
        output_a.status.code(),
        String::from_utf8_lossy(&output_a.stderr),
        output_b.status.code(),
        String::from_utf8_lossy(&output_b.stderr)
    );
    let loser = if output_a.status.success() {
        &output_b
    } else {
        &output_a
    };
    assert_eq!(
        loser.status.code(),
        Some(79),
        "{}",
        String::from_utf8_lossy(&loser.stderr)
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("terminal state"),
        "terminated\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("status")).expect("terminal status"),
        "143\n"
    );
    assert!(!root.join("transition-claim").exists());
    assert!(
        dead_takeover_candidate.exists() && dead_takeover_arbiter.exists(),
        "immutable dead-owner evidence was removed"
    );
    assert!(
        wait_for_process_group_death(payload_pgid),
        "the winning takeover did not terminate the payload group"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_natural_completion_reaps_same_group_background_descendants() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62494", "sleep 30 & printf 'background-launched\\n'");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "descendant-controller", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    let process_identity =
        fs::read_to_string(root.join("process-identity")).expect("process identity");
    let (_, pgid) = process_identity
        .trim()
        .split_once(':')
        .expect("supervisor pid and pgid");

    assert!(
        wait_for_file_value(&root.join("status"), "0\n"),
        "natural completion did not publish status; state={:?}; output={:?}",
        fs::read_to_string(root.join("state")),
        fs::read_to_string(root.join("output"))
    );
    assert!(
        wait_for_file_contains(&root.join("output"), "background-launched"),
        "payload output was not retained"
    );
    assert!(
        fixture.wait_for_dead_pane(&descriptor),
        "completed supervisor pane was not retained"
    );
    assert!(
        wait_for_process_group_death(pgid),
        "background descendant kept process group {pgid} alive"
    );

    let cleanup = fixture.run_shell(descriptor.cleanup_command());
    assert!(
        cleanup.status.success(),
        "{}",
        String::from_utf8_lossy(&cleanup.stderr)
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_sentinel_reaps_payload_when_the_supervisor_dies_independently() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62495", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "sentinel-controller", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    let process_identity =
        fs::read_to_string(root.join("process-identity")).expect("process identity");
    let (supervisor_pid, pgid) = process_identity
        .trim()
        .split_once(':')
        .expect("supervisor pid and pgid");
    assert!(root.join("sentinel-ready").exists());

    let killed = std::process::Command::new("/bin/kill")
        .args(["-KILL", supervisor_pid])
        .status()
        .expect("kill only the supervisor");
    assert!(killed.success());
    assert!(
        fixture.wait_for_dead_pane(&descriptor),
        "remain-on-exit did not preserve the dead supervisor pane"
    );
    assert!(
        wait_for_process_group_death(pgid),
        "sentinel did not reap process group {pgid}"
    );
    assert!(!root.join("status").exists());

    let recovered = fixture.run_shell(descriptor.recover_dead_execution_command());
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&recovered.stdout), "terminal 125\n");
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("recovery state"),
        "recovery-lost\n"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_sentinel_stays_armed_through_residual_descendant_cleanup() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params(
        "62498",
        "trap '' TERM; while :; do sleep 1; done & printf 'payload-finished\\n'",
    );
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "sentinel-cleanup-controller", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    let process_identity =
        fs::read_to_string(root.join("process-identity")).expect("process identity");
    let (supervisor_pid, pgid) = process_identity
        .trim()
        .split_once(':')
        .expect("supervisor pid and pgid");
    assert!(
        wait_for_file_contains(&root.join("output"), "payload-finished"),
        "payload did not reach the residual-cleanup cutpoint"
    );
    std::thread::sleep(std::time::Duration::from_millis(1_500));
    assert!(
        !root.join("sentinel-release").exists(),
        "sentinel was disarmed before residual cleanup completed"
    );
    assert!(
        !root.join("status").exists(),
        "supervisor unexpectedly terminalized a live residual group"
    );

    let killed = std::process::Command::new("/bin/kill")
        .args(["-KILL", supervisor_pid])
        .status()
        .expect("kill supervisor during residual cleanup");
    assert!(killed.success());
    assert!(
        wait_for_process_group_death(pgid),
        "armed sentinel did not reap residual group {pgid}"
    );
    assert!(
        fixture.wait_for_dead_pane(&descriptor),
        "remain-on-exit did not retain the cleanup-cutpoint pane"
    );
    assert!(!root.join("status").exists());
}

#[cfg(unix)]
#[test]
fn real_tmux_termination_stops_the_payload_group_before_removing_the_pane() {
    use std::fs;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62491", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "termination-controller", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    let payload_identity =
        fs::read_to_string(root.join("payload-identity")).expect("payload identity");
    let (_, payload_pgid) = payload_identity
        .trim()
        .split_once(':')
        .expect("payload pid and pgid");

    let termination = fixture.run_shell(descriptor.cleanup_command());
    assert!(
        termination.status.success(),
        "{}",
        String::from_utf8_lossy(&termination.stderr)
    );
    let payload_probe = std::process::Command::new("/bin/kill")
        .args(["-0", "--", &format!("-{payload_pgid}")])
        .status()
        .expect("probe payload process group");
    assert!(!payload_probe.success(), "payload process group survived");
    assert!(
        !fixture
            .tmux(&["has-session", "-t", &descriptor.session_name])
            .status
            .success(),
        "terminated payload left its execution session alive"
    );
}

#[cfg(unix)]
#[test]
fn real_tmux_start_of_turn_recovery_persists_pane_evidence_before_removal() {
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62504", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "reconciliation-evidence", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    let process_identity =
        fs::read_to_string(root.join("process-identity")).expect("process identity");
    let (_, pgid) = process_identity
        .trim()
        .split_once(':')
        .expect("pid and pgid");
    assert!(
        Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{pgid}")])
            .status()
            .expect("kill isolated tmux process group")
            .success()
    );
    assert!(
        fixture.wait_for_dead_pane(&descriptor),
        "remain-on-exit did not preserve the killed pane"
    );
    assert!(!root.join("status").exists());

    let reconciliation = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "62504".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some(descriptor.command_digest.clone()),
            expected_session_id: Some(62504),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let command = exact_reconciliation_command(&fixture.agent_key, &reconciliation);
    let removal_cutpoint =
        "        tmux kill-window -t \"$stale_command_window_id\" 2>/dev/null || true\n";
    let held = command.replacen(
        removal_cutpoint,
        concat!(
            "        : > \"$root/reconciliation-evidence-held\"\n",
            "        while :; do sleep 1; done\n",
            "        tmux kill-window -t \"$stale_command_window_id\" 2>/dev/null || true\n"
        ),
        1,
    );
    assert_ne!(held, command);
    let mut recovery = Command::new("/bin/sh");
    recovery
        .arg("-c")
        .arg(held)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut recovery = recovery.spawn().expect("spawn held start-of-turn recovery");
    assert!(
        wait_for_file_value(&root.join("reconciliation-evidence-held"), ""),
        "reconciliation did not reach the evidence-before-removal cutpoint"
    );
    assert_eq!(
        fs::read_to_string(root.join("pane-death-status")).expect("pane death telemetry"),
        "signal:kill\n"
    );
    assert!(
        fixture.wait_for_dead_pane(&descriptor),
        "reconciliation removed the pane before the evidence cutpoint"
    );
    assert!(root.join("transition-claim").exists());
    assert!(!root.join("status").exists());

    let recovery_group = recovery.id().to_string();
    assert!(
        Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{recovery_group}")])
            .status()
            .expect("kill held start-of-turn recovery")
            .success()
    );
    let _ = recovery.wait();

    let resumed = fixture.run_shell(exact_reconciliation_command(
        &fixture.agent_key,
        &reconciliation,
    ));
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let recovered =
        parse_recovered_executions(&resumed.stdout).expect("parse reconciliation output");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].status, RecoveredExecutionStatus::RecoveryLost);
    assert!(recovered[0].terminal_verified_dead);
    assert_eq!(
        fs::read_to_string(root.join("pane-death-status")).expect("retained pane death telemetry"),
        "signal:kill\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("status")).expect("recovery status"),
        "125\n"
    );
    assert!(!root.join("transition-claim").exists());
}

#[cfg(unix)]
#[test]
fn real_tmux_statusless_pane_death_converges_to_start_of_turn_recovery_loss() {
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    let Some(fixture) = RealTmuxFixture::new() else {
        return;
    };
    let params = exec_params("62490", "sleep 30");
    let mut descriptor =
        TmuxProcessDescriptor::new(&fixture.agent_key, "recovery-controller", &params);
    fixture.bootstrap(&mut descriptor, &params);
    let root = fixture.descriptor_root(&descriptor);
    let process_identity =
        fs::read_to_string(root.join("process-identity")).expect("process identity");
    let (_, pgid) = process_identity
        .trim()
        .split_once(':')
        .expect("pid and pgid");
    let killed = std::process::Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{pgid}")])
        .status()
        .expect("kill isolated tmux process group");
    assert!(killed.success());
    assert!(
        fixture.wait_for_dead_pane(&descriptor),
        "remain-on-exit did not preserve the killed pane"
    );
    assert!(!root.join("status").exists());
    fs::write(root.join("output"), b"final-output-tail\n").expect("seed final output tail");

    let monitor = fixture.run_shell(descriptor.monitor_command(1));
    assert_eq!(monitor.status.code(), Some(125));
    assert_eq!(monitor.stdout, b"final-output-tail\n");

    let recovery_cutpoint = "[ -e \"$root/output\" ] || : > \"$root/output\"\n";
    let held_recovery = descriptor.recover_dead_execution_command().replacen(
        recovery_cutpoint,
        concat!(
            ": > \"$root/recovery-held\"\n",
            "while :; do sleep 1; done\n",
            "[ -e \"$root/output\" ] || : > \"$root/output\"\n"
        ),
        1,
    );
    assert_ne!(held_recovery, descriptor.recover_dead_execution_command());
    let mut recovery = Command::new("/bin/sh");
    recovery
        .arg("-c")
        .arg(held_recovery)
        .env("HOME", fixture.home.path())
        .env("PATH", &fixture.path)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut recovery = recovery.spawn().expect("spawn held live recovery");
    assert!(
        wait_for_file_value(&root.join("recovery-held"), ""),
        "live recovery did not reach the post-pane-removal cutpoint"
    );
    assert!(root.join("transition-claim").exists());
    assert!(!root.join("status").exists());
    let recovery_group = recovery.id().to_string();
    let killed = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{recovery_group}")])
        .status()
        .expect("kill live recovery operation group");
    assert!(killed.success());
    let _ = recovery.wait();

    let recovered_live = fixture.run_shell(descriptor.recover_dead_execution_command());
    assert!(
        recovered_live.status.success(),
        "{}; pane={}",
        String::from_utf8_lossy(&recovered_live.stderr),
        String::from_utf8_lossy(
            &fixture
                .tmux(&[
                    "display-message",
                    "-p",
                    "-t",
                    &descriptor.target(),
                    "#{window_id}:#{pane_id}:#{pane_pid}:#{pane_dead}:#{pane_dead_status}:#{pane_dead_signal}",
                ])
                .stdout
        )
    );
    assert_eq!(
        String::from_utf8_lossy(&recovered_live.stdout),
        "terminal 125\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("state")).expect("recovery state"),
        "recovery-lost\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("status")).expect("recovery status"),
        "125\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("pane-death-status")).expect("pane death telemetry"),
        "signal:kill\n"
    );
    assert!(!root.join("transition-claim").exists());
    assert_eq!(
        fs::read_dir(&root)
            .expect("descriptor entries")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".transition-candidate."))
            })
            .count(),
        0
    );

    let reconciliation = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "62490".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some(descriptor.command_digest.clone()),
            expected_session_id: Some(62490),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    let output = fixture.run_shell(exact_reconciliation_command(
        &fixture.agent_key,
        &reconciliation,
    ));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recovered = parse_recovered_executions(&output.stdout).expect("recovered execution");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].status, RecoveredExecutionStatus::RecoveryLost);
    assert!(recovered[0].terminal_verified_dead);
    let windows = fixture.tmux(&[
        "list-windows",
        "-t",
        &format!("{}:", descriptor.session_name),
        "-F",
        "#{window_name}",
    ]);
    assert!(
        !String::from_utf8_lossy(&windows.stdout)
            .lines()
            .any(|window| window == descriptor.window_name)
    );
}

#[cfg(unix)]
#[test]
fn generated_remote_shell_is_syntactically_valid() {
    use std::io::Write;
    use std::process::Command;
    use std::process::Stdio;

    let params = exec_params("process", "printf hello");
    let descriptor = TmuxProcessDescriptor::new("agent", "1720000000000-controller", &params);
    let acknowledgement = terminal_acknowledgement(format!("{}-deadbeef", descriptor.process_id));
    let reconciliation = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };
    for command in [
        descriptor.bootstrap_command(&params),
        descriptor.supervisor_start_command(),
        descriptor.adoption_command(),
        descriptor.process_script(&params),
        descriptor.payload_script(&params),
        descriptor.group_sentinel_script(),
        descriptor.watchdog_script(),
        descriptor.expiry_script(),
        descriptor.terminal_cleanup_script(),
        orphaned_execution_session_reaper_command(),
        descriptor.monitor_command(1),
        descriptor.recover_dead_execution_command(),
        descriptor.interrupt_command(),
        descriptor.termination_command(),
        descriptor.ownership_guard(),
        exact_reconciliation_command("agent", &reconciliation),
        acknowledgement_command("agent", &acknowledgement),
    ] {
        let mut child = Command::new("/bin/sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn sh");
        child
            .stdin
            .take()
            .expect("sh stdin")
            .write_all(command.as_bytes())
            .expect("write shell");
        assert!(child.wait().expect("wait for sh").success(), "{command}");
    }
}

fn terminal_acknowledgement(token: String) -> RecoveredExecutionAcknowledgement {
    terminal_acknowledgement_with_status(token, RecoveredExecutionStatus::Exited(0))
}

fn terminal_acknowledgement_with_status(
    token: String,
    status: RecoveredExecutionStatus,
) -> RecoveredExecutionAcknowledgement {
    RecoveredExecutionAcknowledgement::new(token).with_terminal_proof(
        TerminalAcknowledgementProof {
            range_start: 0,
            range_end: 6,
            output_sha256: "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
                .to_string(),
            status,
        },
    )
}

fn conflicting_terminal_acknowledgement(token: &str) -> RecoveredExecutionAcknowledgement {
    RecoveredExecutionAcknowledgement::new(token.to_string()).with_terminal_proof(
        TerminalAcknowledgementProof {
            range_start: 0,
            range_end: 6,
            output_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            status: RecoveredExecutionStatus::Exited(0),
        },
    )
}

#[cfg(unix)]
fn terminal_acknowledgement_fixture(
    token: &str,
) -> (tempfile::TempDir, std::path::PathBuf, String) {
    use sha2::Digest;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().expect("temp home");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).expect("fake bin");
    let tmux = bin.join("tmux");
    fs::write(
        &tmux,
        "#!/bin/sh\ncase \"$1\" in\n  list-windows) echo \"can't find session: fixture\" >&2; exit 1 ;;\n  kill-window) exit 0 ;;\n  *) exit 1 ;;\nesac\n",
    )
    .expect("fake tmux");
    fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");

    let process_id = token.split_once('-').expect("acknowledgement token").0;
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(stable_identifier("agent"))
        .join(process_id);
    fs::create_dir_all(root.join("terminal-claim")).expect("descriptor root");
    for (name, value) in [
        ("acknowledgement-token", token),
        ("owner", "agentapp-tmux-v2"),
        ("state", "completed"),
        ("status", "0"),
        ("output", "abcdef"),
        ("terminal-claim/kind", "completed"),
        ("window", "p_0123456789abcdef"),
        ("controller", "0:controller"),
    ] {
        fs::write(root.join(name), value).expect("descriptor field");
    }
    let legacy_key = format!("{:x}", sha2::Sha256::digest(token.as_bytes()));
    let claim = format!(
        "acknowledgement|k_{legacy_key}|0:controller|2147483647|2147483647|p_0123456789abcdef|-|-\n"
    );
    let transition_candidate =
        root.join(format!(".transition-candidate.k_{legacy_key}.2147483647"));
    fs::write(&transition_candidate, &claim).expect("stale acknowledgement candidate");
    fs::hard_link(&transition_candidate, root.join("transition-claim"))
        .expect("stale acknowledgement claim hard link");

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    (home, root, path)
}

#[cfg(unix)]
fn run_acknowledgement(
    home: &tempfile::TempDir,
    path: &str,
    acknowledgement: &RecoveredExecutionAcknowledgement,
) -> std::process::Output {
    run_acknowledgement_command(
        home,
        path,
        acknowledgement_command("agent", acknowledgement),
    )
}

#[cfg(unix)]
fn run_acknowledgement_command(
    home: &tempfile::TempDir,
    path: &str,
    command: String,
) -> std::process::Output {
    use std::os::unix::process::CommandExt;

    let mut child = std::process::Command::new("/bin/sh");
    child
        .arg("-c")
        .arg(command)
        .env("HOME", home.path())
        .env("PATH", path)
        .process_group(0);
    child.output().expect("run acknowledgement")
}

#[cfg(unix)]
fn run_acknowledgement_release(
    home: &tempfile::TempDir,
    path: &str,
    acknowledgement: &RecoveredExecutionAcknowledgement,
) -> std::process::Output {
    std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(acknowledgement_release_command("agent", acknowledgement))
        .env("HOME", home.path())
        .env("PATH", path)
        .output()
        .expect("run acknowledgement release")
}

#[cfg(unix)]
fn durable_write_fixture() -> (tempfile::TempDir, std::path::PathBuf, TmuxProcessDescriptor) {
    use std::fs;

    let home = tempfile::tempdir().expect("temp home");
    let descriptor =
        TmuxProcessDescriptor::new("agent", "controller", &exec_params("process", "read value"));
    let root = home
        .path()
        .join(".agentapp/tmux")
        .join(&descriptor.agent_id)
        .join(&descriptor.process_id);
    fs::create_dir_all(&root).expect("descriptor root");
    for (name, value) in [
        ("owner", "agentapp-tmux-v2"),
        ("controller", descriptor.controller_id.as_str()),
        ("digest", descriptor.command_digest.as_str()),
    ] {
        fs::write(root.join(name), value).expect("descriptor authority");
    }
    let fifo = root.join("stdin");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("create stdin fifo");
    assert!(status.success());
    (home, root, descriptor)
}

#[cfg(unix)]
fn run_durable_write_command(
    home: &tempfile::TempDir,
    command: &str,
    input: &[u8],
) -> std::process::Output {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .env("HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run durable stdin command");
    child
        .stdin
        .take()
        .expect("durable stdin pipe")
        .write_all(input)
        .expect("send durable stdin bytes");
    child.wait_with_output().expect("wait for durable stdin")
}

#[cfg(unix)]
struct RealTmuxFixture {
    home: tempfile::TempDir,
    path: String,
    tmux_wrapper: std::path::PathBuf,
    agent_key: String,
}

#[cfg(unix)]
impl RealTmuxFixture {
    fn new() -> Option<Self> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let discovered = Command::new("/bin/sh")
            .args(["-c", "command -v tmux"])
            .env_remove("TMUX")
            .output()
            .ok()?;
        if !discovered.status.success() {
            return None;
        }
        let real_tmux = String::from_utf8(discovered.stdout).ok()?;
        let real_tmux = real_tmux.trim();
        if real_tmux.is_empty() {
            return None;
        }

        let home = tempfile::tempdir().expect("real tmux fixture home");
        let bin = home.path().join("bin");
        fs::create_dir(&bin).expect("real tmux fixture bin");
        let tmux_wrapper = bin.join("tmux");
        let fixture_id = uuid::Uuid::new_v4().simple().to_string();
        let socket_name = format!("agentapp-test-{fixture_id}");
        fs::write(
            &tmux_wrapper,
            format!(
                "#!/bin/sh\nexec {} -L {} \"$@\"\n",
                shell_quote(real_tmux),
                shell_quote(&socket_name)
            ),
        )
        .expect("real tmux wrapper");
        fs::set_permissions(&tmux_wrapper, fs::Permissions::from_mode(0o755))
            .expect("real tmux wrapper mode");
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Some(Self {
            home,
            path,
            tmux_wrapper,
            agent_key: format!("real-tmux-{fixture_id}"),
        })
    }

    fn run_shell(&self, command: String) -> std::process::Output {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .env("HOME", self.home.path())
            .env("PATH", &self.path)
            .env_remove("TMUX")
            .output()
            .expect("run real tmux shell")
    }

    fn tmux(&self, args: &[&str]) -> std::process::Output {
        std::process::Command::new(&self.tmux_wrapper)
            .args(args)
            .env("HOME", self.home.path())
            .env("PATH", &self.path)
            .env_remove("TMUX")
            .output()
            .expect("run isolated tmux")
    }

    fn bootstrap(&self, descriptor: &mut TmuxProcessDescriptor, params: &ExecParams) {
        self.bootstrap_with_shell(descriptor, params, "/bin/sh");
    }

    fn bootstrap_with_shell(
        &self,
        descriptor: &mut TmuxProcessDescriptor,
        params: &ExecParams,
        shell: &str,
    ) {
        let command = descriptor.bootstrap_command(params);
        let command = if shell == "/bin/sh" {
            command
        } else {
            command.replace("/bin/sh", shell)
        };
        let output = self.run_shell(command);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        apply_ready_protocol(descriptor, &output.stdout);
    }

    fn descriptor_root(&self, descriptor: &TmuxProcessDescriptor) -> std::path::PathBuf {
        self.home
            .path()
            .join(".agentapp/tmux")
            .join(&descriptor.agent_id)
            .join(&descriptor.process_id)
    }

    fn wait_for_dead_pane(&self, descriptor: &TmuxProcessDescriptor) -> bool {
        for _ in 0..50 {
            let output = self.tmux(&[
                "display-message",
                "-p",
                "-t",
                &descriptor.target(),
                "#{pane_dead}",
            ]);
            if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "1" {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    }

    fn pane_pid(&self, target: &str) -> u32 {
        let pane = self.tmux(&["display-message", "-p", "-t", target, "#{pane_pid}"]);
        assert!(
            pane.status.success(),
            "{}",
            String::from_utf8_lossy(&pane.stderr)
        );
        String::from_utf8(pane.stdout)
            .expect("pane pid")
            .trim()
            .parse()
            .expect("numeric pane pid")
    }

    fn wait_for_session_exit(&self, session: &str) -> bool {
        for _ in 0..50 {
            if !self.tmux(&["has-session", "-t", session]).status.success() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    }

    fn wait_for_process_exit(&self, pid: u32) -> bool {
        let pid = pid.to_string();
        for _ in 0..50 {
            if !std::process::Command::new("/bin/kill")
                .args(["-0", &pid])
                .status()
                .is_ok_and(|status| status.success())
            {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    }
}

#[cfg(unix)]
impl Drop for RealTmuxFixture {
    fn drop(&mut self) {
        let _ = std::process::Command::new(&self.tmux_wrapper)
            .args(["kill-server"])
            .env("HOME", self.home.path())
            .env("PATH", &self.path)
            .env_remove("TMUX")
            .status();
    }
}

#[cfg(unix)]
fn wait_for_file_value(path: &std::path::Path, expected: &str) -> bool {
    for _ in 0..50 {
        if std::fs::read_to_string(path).is_ok_and(|value| value == expected) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

fn current_output_closed_path(root: &std::path::Path) -> std::path::PathBuf {
    let generation = std::fs::read_to_string(root.join("output-pipe-generation"))
        .expect("output pipe generation");
    let generation = generation.trim();
    assert!(
        !generation.is_empty()
            && generation
                .chars()
                .all(|character| character.is_ascii_digit()),
        "invalid output pipe generation: {generation:?}"
    );
    root.join(format!("output-closed.{generation}"))
}

#[cfg(unix)]
fn wait_for_file_contains(path: &std::path::Path, expected: &str) -> bool {
    for _ in 0..50 {
        if std::fs::read_to_string(path).is_ok_and(|value| value.contains(expected)) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

#[cfg(unix)]
fn wait_for_process_group_death(pgid: &str) -> bool {
    for _ in 0..80 {
        let status = std::process::Command::new("/bin/kill")
            .args(["-0", "--", &format!("-{}", pgid.trim())])
            .stderr(std::process::Stdio::null())
            .status()
            .expect("probe process group");
        if !status.success() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

#[cfg(unix)]
fn bootstrap_shell_fixture() -> (tempfile::TempDir, String) {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().expect("temp home");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).expect("fake bin");
    let tmux = bin.join("tmux");
    fs::write(&tmux, "#!/bin/sh\nexit 0\n").expect("fake tmux");
    fs::set_permissions(&tmux, fs::Permissions::from_mode(0o755)).expect("tmux mode");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    (home, path)
}
