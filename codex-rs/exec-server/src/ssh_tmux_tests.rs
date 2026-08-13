use std::collections::HashMap;

use codex_utils_path_uri::PathUri;
use pretty_assertions::assert_eq;

use super::MonitorExitClassification;
use super::TmuxProcessDescriptor;
use super::acknowledgement_command;
use super::acknowledgement_release_command;
use super::exact_reconciliation_command;
use super::interrupt_outcome_from_control_result;
use super::parse_monitor_exit_classification;
use super::parse_recovered_executions;
use super::stable_identifier;
use super::validate_reconciliation_request;
use crate::AdoptionRequest;
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
fn adoption_is_exact_fenced_and_never_enters_launch_path() {
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
    ] {
        assert!(command.contains(proof), "missing adoption proof: {proof}");
    }
    assert!(!command.contains("adoption-claim"));
    assert!(!command.contains("printf 'running\\n' > \"$root/state.tmp\""));
    assert!(!command.contains("new-window"));
    assert!(!command.contains("touch \"$root/go\""));
    assert!(!command.contains("command.sh"));
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
    assert!(command.contains(&descriptor.controller_id));
    assert!(command.contains(&descriptor.command_digest));
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
    assert!(
        command.find("tmux new-window -d -t \"$session:\" -n \"$watchdog_window\"")
            < command.find("tmux new-window -d -t \"$session:\" -n \"$window\"")
    );
    assert!(!command.contains("tmux kill-session"));
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
    assert!(!command.contains("> \"$root/owner\""));
    assert!(!command.contains("> \"$root/identity\""));
    assert!(!command.contains("> \"$root/digest\""));
    assert!(!command.contains("> \"$root/window\""));
    assert!(!command.contains("> \"$root/output\""));
    assert!(!command.contains("> \"$root/state\""));
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
            "digest",
            "identity",
            "output",
            "owner",
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
        4
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
        ("state", "prepared"),
        ("output", ""),
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
fn stale_running_descriptor_recovers_dead_bootstrap_and_interrupt_claims() {
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
        assert_eq!(recovered[0].status, RecoveredExecutionStatus::RecoveryLost);
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
fn watchdog_classifies_expiry_without_destructive_takeover() {
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
    assert!(!script.contains("kill-window"));
    assert!(!script.contains("status.tmp"));
    assert!(!script.contains("terminal-claim"));
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
    assert!(!watchdog.contains("terminal-claim"));
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
    assert_eq!(command.matches("tmux send-keys").count(), 1);
    let send = command.find("tmux send-keys").expect("signal operation");
    for required in [
        "rechecked_identity",
        "rechecked_pgid",
        "require_interrupt_claim",
        "AGENTAPP_TMUX_INTERRUPT_OWNERSHIP_MISMATCH",
    ] {
        assert!(
            command.find(required).is_some_and(|index| index < send),
            "{required} must precede signal delivery"
        );
    }
}

#[cfg(unix)]
#[test]
fn interrupt_second_identity_mismatch_is_rejected_before_signal_and_releases_claim() {
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
            "    count=$(cat \"$HOME/tmux-display-count\" 2>/dev/null || printf 0)\n",
            "    count=$((count + 1))\n",
            "    printf '%s\\n' \"$count\" > \"$HOME/tmux-display-count\"\n",
            "    if [ \"$count\" -eq 1 ]; then\n",
            "      printf '%%fixture:%s\\n' \"$FAKE_PANE_PID\"\n",
            "    else\n",
            "      printf '%%changed:%s\\n' \"$FAKE_PANE_PID\"\n",
            "    fi\n",
            "    ;;\n",
            "  send-keys)\n",
            "    : > \"$HOME/tmux-send-keys-called\"\n",
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
    assert!(!home.path().join("tmux-send-keys-called").exists());
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
        descriptor.adoption_command(),
        descriptor.process_script(&params),
        descriptor.watchdog_script(),
        descriptor.monitor_command(1),
        descriptor.interrupt_command(),
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
