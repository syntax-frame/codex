//! Opt-in real-host regression for durable SSH/tmux restart recovery.
//!
//! Set `CODEX_REAL_SSH_TMUX_RESTART_TEST=1` plus the host, user, and private-key
//! variables below, then run this ignored test explicitly. The test owns a
//! nonce-scoped tmux session and descriptor tree and releases both on success.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use codex_utils_path_uri::PathUri;
use sha2::Digest;
use sha2::Sha256;

use crate::AdoptionRequest;
use crate::ExecBackend;
use crate::ExecProcessEvent;
use crate::ExecutionIdentity;
use crate::IncompleteExecution;
use crate::PreparedExecution;
use crate::ProcessId;
use crate::ReconciliationRequest;
use crate::RecoveredExecution;
use crate::RecoveredExecutionStatus;
use crate::RemoteExecutionProtocolEvidence;
use crate::SshAuthentication;
use crate::SshProcessBackend;
use crate::SshTmuxMode;
use crate::TerminalAcknowledgementProof;
use crate::WriteStatus;
use crate::protocol::ExecParams;

const OPT_IN_ENV: &str = "CODEX_REAL_SSH_TMUX_RESTART_TEST";
const HOST_ENV: &str = "CODEX_REAL_SSH_HOST";
const PORT_ENV: &str = "CODEX_REAL_SSH_PORT";
const USER_ENV: &str = "CODEX_REAL_SSH_USER";
const KEY_ENV: &str = "CODEX_REAL_SSH_KEY_PATH";
const FINGERPRINT_ENV: &str = "CODEX_REAL_SSH_HOST_FINGERPRINT";
const HELPER_PHASE_ENV: &str = "CODEX_REAL_SSH_RESTART_HELPER_PHASE";
const TEST_NONCE_ENV: &str = "CODEX_REAL_SSH_RESTART_NONCE";

#[test]
#[ignore = "requires explicit real SSH host configuration"]
fn real_ssh_tmux_survives_process_boundary_without_duplicate_execution() {
    if std::env::var(OPT_IN_ENV).as_deref() != Ok("1") {
        return;
    }
    let config = RealSshConfig::from_env();
    let nonce = required_env(TEST_NONCE_ENV).unwrap_or_else(|| {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        format!("{}-{nanos}", std::process::id())
    });

    if let Ok(phase) = std::env::var(HELPER_PHASE_ENV) {
        let runtime = tokio::runtime::Runtime::new().expect("create Tokio runtime");
        runtime.block_on(run_helper(&config, &nonce, &phase));
        return;
    }

    run_helper_process(&config, &nonce, "launch");
    run_helper_process(&config, &nonce, "recover");
}

#[derive(Clone)]
struct RealSshConfig {
    host: String,
    port: u16,
    user: String,
    key_path: String,
    fingerprint: Option<String>,
}

impl RealSshConfig {
    fn from_env() -> Self {
        let host = required_env(HOST_ENV);
        let user = required_env(USER_ENV);
        let key_path = required_env(KEY_ENV);
        let missing = [
            (HOST_ENV, host.is_none()),
            (USER_ENV, user.is_none()),
            (KEY_ENV, key_path.is_none()),
        ]
        .into_iter()
        .filter_map(|(name, missing)| missing.then_some(name))
        .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "{OPT_IN_ENV}=1 requires: {}; optional: {PORT_ENV} (default 22), {FINGERPRINT_ENV}",
            missing.join(", ")
        );
        let key_path = key_path.expect("validated key path");
        assert!(
            Path::new(&key_path).is_file(),
            "{KEY_ENV} does not name a readable private-key file: {key_path}"
        );
        let port = std::env::var(PORT_ENV)
            .map(|value| {
                value
                    .parse::<u16>()
                    .unwrap_or_else(|error| panic!("{PORT_ENV} must be a TCP port: {error}"))
            })
            .unwrap_or(22);
        Self {
            host: host.expect("validated host"),
            port,
            user: user.expect("validated user"),
            key_path,
            fingerprint: required_env(FINGERPRINT_ENV),
        }
    }

    fn backend(&self, nonce: &str) -> SshProcessBackend {
        SshProcessBackend::with_authentication_and_keys(
            self.host.clone(),
            self.port,
            self.user.clone(),
            SshAuthentication::PrivateKeyPath(self.key_path.clone()),
            self.fingerprint.clone(),
            format!("build121-real-restart-connection-{nonce}"),
            format!("build121-real-restart-session-{nonce}"),
            SshTmuxMode::Required,
        )
    }
}

fn required_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn run_helper_process(config: &RealSshConfig, nonce: &str, phase: &str) {
    let executable = std::env::current_exe().expect("locate test executable");
    let mut child = Command::new(executable);
    child
        .arg("--exact")
        .arg("ssh_process_boundary_restart_real_tests::real_ssh_tmux_survives_process_boundary_without_duplicate_execution")
        .arg("--ignored")
        .arg("--nocapture")
        .env(OPT_IN_ENV, "1")
        .env(HOST_ENV, &config.host)
        .env(PORT_ENV, config.port.to_string())
        .env(USER_ENV, &config.user)
        .env(KEY_ENV, &config.key_path)
        .env(HELPER_PHASE_ENV, phase)
        .env(TEST_NONCE_ENV, nonce);
    if let Some(fingerprint) = &config.fingerprint {
        child.env(FINGERPRINT_ENV, fingerprint);
    }
    let output = child.output().expect("launch restart helper process");
    assert!(
        output.status.success(),
        "{phase} helper failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn run_helper(config: &RealSshConfig, nonce: &str, phase: &str) {
    let backend = config.backend(nonce);
    let prepared = prepared_execution(nonce);
    match phase {
        "launch" => {
            backend
                .start_prepared(prepared)
                .await
                .expect("launch owned tmux execution");
        }
        "recover" => recover_and_retire(&backend, prepared, nonce).await,
        other => panic!("unknown restart helper phase: {other}"),
    }
}

fn prepared_execution(nonce: &str) -> PreparedExecution {
    let marker = format!("BUILD121-RUN-{nonce}");
    PreparedExecution::new(ExecParams {
        process_id: ProcessId::from("121"),
        execution_identity: Some(identity(nonce)),
        argv: vec![
            "sh".to_string(),
            "-lc".to_string(),
            concat!(
                "printf '%s\\n' \"$1\"; ",
                "(sleep 60; kill -TERM $$ 2>/dev/null) & watchdog=$!; ",
                "IFS= read -r gate; ",
                "kill \"$watchdog\" 2>/dev/null || true; ",
                "wait \"$watchdog\" 2>/dev/null || true; ",
                "[ \"$gate\" = continue ] || exit 42; ",
                "printf '%s\\n' BUILD121-DONE"
            )
            .to_string(),
            "agentapp-build121-restart-test".to_string(),
            marker,
        ],
        cwd: PathUri::from_host_native_path("/tmp").expect("remote /tmp URI"),
        env_policy: None,
        env: HashMap::new(),
        tty: false,
        pipe_stdin: true,
        arg0: None,
        sandbox: None,
        enforce_managed_network: false,
        managed_network: None,
        network_proxy: None,
    })
}

fn identity(nonce: &str) -> ExecutionIdentity {
    ExecutionIdentity {
        thread_id: format!("build121-thread-{nonce}"),
        turn_id: format!("build121-turn-{nonce}"),
        call_id: format!("build121-call-{nonce}"),
        attempt_generation: 0,
    }
}

async fn recover_and_retire(backend: &SshProcessBackend, prepared: PreparedExecution, nonce: &str) {
    let request = reconciliation_request(&prepared, nonce);
    let first = backend
        .reconcile(request.clone())
        .await
        .expect("reconcile after helper-process restart");
    let recovered = exact_generation(&first);
    assert!(
        matches!(
            recovered.status,
            RecoveredExecutionStatus::Prepared | RecoveredExecutionStatus::Running
        ),
        "launch helper did not leave one live execution to adopt: {recovered:?}"
    );
    let started = backend
        .adopt_execution(AdoptionRequest {
            identity: identity(nonce),
            expected_command_digest: prepared.command_digest().to_string(),
            original_session_id: Some(121),
            committed_output_cursor: 0,
            tty: false,
        })
        .await
        .expect("adopt tmux execution after process restart");
    let mut events = started.process.subscribe_events();
    let write = started
        .process
        .write_with_id(
            b"continue\n".to_vec(),
            format!("build121-real-stdin-{nonce}"),
        )
        .await
        .expect("write to adopted process");
    assert_eq!(write.status, WriteStatus::Accepted);
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match events.recv().await.expect("observe adopted process") {
                ExecProcessEvent::Closed { .. } => break,
                ExecProcessEvent::Failed(error) => {
                    panic!("adopted process failed: {error}");
                }
                ExecProcessEvent::Output(_) | ExecProcessEvent::Exited { .. } => {}
            }
        }
    })
    .await
    .expect("adopted tmux execution did not finish");

    let terminal = backend
        .reconcile(request)
        .await
        .expect("reconcile terminal execution");
    let recovered = exact_generation(&terminal);
    assert_eq!(recovered.status, RecoveredExecutionStatus::Exited(0));
    assert!(recovered.terminal_verified_dead);
    let output = String::from_utf8_lossy(&recovered.output);
    let marker = format!("BUILD121-RUN-{nonce}");
    assert_eq!(
        output.matches(&marker).count(),
        1,
        "execution was missing or duplicated:\n{output}"
    );
    assert!(output.contains("BUILD121-DONE"));

    let output_sha256 = format!("{:x}", Sha256::digest(&recovered.output));
    let acknowledgement =
        recovered
            .acknowledgement
            .clone()
            .with_terminal_proof(TerminalAcknowledgementProof {
                range_start: 0,
                range_end: recovered.output.len() as u64,
                output_sha256,
                status: recovered.status.clone(),
            });
    backend
        .acknowledge_consumed(acknowledgement.clone())
        .await
        .expect("acknowledge exact terminal proof");
    backend
        .release_acknowledged(acknowledgement)
        .await
        .expect("release exact proof metadata");

    let after_release = backend
        .reconcile(reconciliation_request(&prepared, nonce))
        .await
        .expect("verify owned remote metadata release");
    assert!(
        after_release
            .iter()
            .all(|execution| execution.status == RecoveredExecutionStatus::Missing),
        "owned remote descriptor or tmux session remained after release: {after_release:?}"
    );
}

fn reconciliation_request(prepared: &PreparedExecution, nonce: &str) -> ReconciliationRequest {
    ReconciliationRequest {
        thread_id: identity(nonce).thread_id,
        incomplete_executions: vec![IncompleteExecution {
            turn_id: identity(nonce).turn_id,
            call_id: identity(nonce).call_id,
            attempt_generation: 0,
            expected_command_digest: Some(prepared.command_digest().to_string()),
            expected_session_id: Some(121),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    }
}

fn exact_generation(executions: &[RecoveredExecution]) -> &RecoveredExecution {
    assert_eq!(
        executions.len(),
        1,
        "expected one exact recovered generation: {executions:?}"
    );
    &executions[0]
}
