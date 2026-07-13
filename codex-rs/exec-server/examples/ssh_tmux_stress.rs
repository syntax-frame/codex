//! Concurrent host test for the pooled, tmux-backed SSH execution path.
//!
//! Defaults to 30 agents against localhost. Override `SSH_STRESS_HOST`,
//! `SSH_STRESS_PORT`, `SSH_STRESS_USER`, `SSH_STRESS_KEY`, `SSH_STRESS_CWD`, or
//! `SSH_STRESS_COUNT` for another test server.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use codex_exec_server::ExecBackend;
use codex_exec_server::ExecParams;
use codex_exec_server::ExecProcess;
use codex_exec_server::ProcessId;
use codex_exec_server::SshAuthentication;
use codex_exec_server::SshProcessBackend;
use codex_exec_server::SshTmuxMode;
use codex_utils_path_uri::PathUri;
use tokio::task::JoinSet;

struct StressConfig {
    host: String,
    port: u16,
    user: String,
    key_path: String,
    cwd: PathBuf,
    count: usize,
}

impl StressConfig {
    fn from_env() -> Self {
        let home = std::env::var("HOME").expect("HOME");
        Self {
            host: std::env::var("SSH_STRESS_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: std::env::var("SSH_STRESS_PORT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(22),
            user: std::env::var("SSH_STRESS_USER")
                .or_else(|_| std::env::var("USER"))
                .expect("SSH_STRESS_USER or USER"),
            key_path: std::env::var("SSH_STRESS_KEY")
                .unwrap_or_else(|_| format!("{home}/.ssh/agentapp_key")),
            cwd: PathBuf::from(
                std::env::var("SSH_STRESS_CWD").unwrap_or_else(|_| "/tmp".to_string()),
            ),
            count: std::env::var("SSH_STRESS_COUNT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(30),
        }
    }
}

fn exec_params(process_id: &str, cwd: &PathBuf, command: String) -> ExecParams {
    ExecParams {
        process_id: ProcessId::from(process_id),
        argv: vec!["sh".to_string(), "-lc".to_string(), command],
        cwd: PathUri::from_host_native_path(cwd).expect("cwd URI"),
        env_policy: None,
        env: HashMap::new(),
        tty: false,
        pipe_stdin: false,
        arg0: None,
        sandbox: None,
        enforce_managed_network: false,
        managed_network: None,
    }
}

async fn read_until_exit(process: &dyn ExecProcess) -> Result<(Vec<u8>, Option<i32>), String> {
    let mut after_seq = None;
    let mut output = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err("timed out waiting for remote process".to_string());
        }
        let response = process
            .read(after_seq, None, Some(2_000))
            .await
            .map_err(|error| error.to_string())?;
        for chunk in response.chunks {
            after_seq = Some(chunk.seq);
            output.extend_from_slice(&chunk.chunk.0);
        }
        if response.exited {
            return Ok((output, response.exit_code));
        }
    }
}

async fn run_agent(index: usize, config: &StressConfig) -> Result<(), String> {
    let backend = SshProcessBackend::with_authentication_and_keys(
        config.host.clone(),
        config.port,
        config.user.clone(),
        SshAuthentication::PrivateKeyPath(config.key_path.clone()),
        None,
        "agentapp-ssh-stress",
        format!("stress-agent-{index}"),
        SshTmuxMode::Required,
    );
    let process_id = format!("stress-process-{index}");
    let command =
        format!("printf 'agent-{index}-begin\\n'; sleep 1; printf 'agent-{index}-end\\n'");
    let started = backend
        .start(exec_params(&process_id, &config.cwd, command))
        .await
        .map_err(|error| format!("agent {index} start: {error}"))?;
    let (output, exit_code) = read_until_exit(started.process.as_ref()).await?;
    let output = String::from_utf8_lossy(&output);
    if exit_code != Some(0)
        || !output.contains(&format!("agent-{index}-begin"))
        || !output.contains(&format!("agent-{index}-end"))
    {
        return Err(format!(
            "agent {index} failed: exit={exit_code:?} output={output:?}"
        ));
    }
    Ok(())
}

fn stable_identifier(value: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

async fn cleanup(config: &StressConfig) -> Result<(), String> {
    let commands = (0..config.count)
        .map(|index| {
            let agent_id = stable_identifier(&format!("stress-agent-{index}"));
            format!(
                "tmux kill-session -t agentapp_{agent_id} 2>/dev/null || true; rm -rf \"$HOME/.agentapp/tmux/{agent_id}\""
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let backend = SshProcessBackend::with_authentication_and_keys(
        config.host.clone(),
        config.port,
        config.user.clone(),
        SshAuthentication::PrivateKeyPath(config.key_path.clone()),
        None,
        "agentapp-ssh-stress",
        "stress-cleanup",
        SshTmuxMode::Disabled,
    );
    let started = backend
        .start(exec_params("stress-cleanup", &config.cwd, commands))
        .await
        .map_err(|error| error.to_string())?;
    let (_, exit_code) = read_until_exit(started.process.as_ref()).await?;
    if exit_code == Some(0) {
        Ok(())
    } else {
        Err(format!("cleanup exited with {exit_code:?}"))
    }
}

#[tokio::main]
async fn main() {
    let config = StressConfig::from_env();
    println!(
        "starting {} concurrent tmux-backed agents against {}@{}:{}",
        config.count, config.user, config.host, config.port
    );
    let started_at = Instant::now();
    let mut agents = JoinSet::new();
    for index in 0..config.count {
        let config = StressConfig {
            host: config.host.clone(),
            port: config.port,
            user: config.user.clone(),
            key_path: config.key_path.clone(),
            cwd: config.cwd.clone(),
            count: config.count,
        };
        agents.spawn(async move { run_agent(index, &config).await });
    }

    let mut failures = Vec::new();
    while let Some(result) = agents.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(error),
            Err(error) => failures.push(format!("task join: {error}")),
        }
    }
    if let Err(error) = cleanup(&config).await {
        failures.push(format!("cleanup: {error}"));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    println!(
        "SSH_TMUX_STRESS_OK agents={} elapsed={:.2}s",
        config.count,
        started_at.elapsed().as_secs_f64()
    );
}
