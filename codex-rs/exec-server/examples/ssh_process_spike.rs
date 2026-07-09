//! Standalone host-test for the SSH-backed `ExecBackend`.
//!
//! Connects to a local sshd over russh, runs a command, reads its output via
//! the `ExecProcess::read` API, then exercises interactive stdin with `cat`.
//!
//! Run with:
//!   cargo run -p codex-exec-server --example ssh_process_spike
//!
//! On success it prints the remote output and a final `SSH_PROCESS_OK` line.

use std::collections::HashMap;
use std::time::Duration;

use codex_exec_server::ExecBackend;
use codex_exec_server::ExecParams;
use codex_exec_server::ExecProcess;
use codex_exec_server::ProcessId;
use codex_exec_server::SshProcessBackend;
use codex_utils_path_uri::PathUri;

fn exec_params(process_id: &str, argv: Vec<&str>, tty: bool, pipe_stdin: bool) -> ExecParams {
    ExecParams {
        process_id: ProcessId::from(process_id),
        argv: argv.into_iter().map(str::to_string).collect(),
        cwd: PathUri::from_host_native_path(std::env::temp_dir()).expect("cwd URI"),
        env_policy: None,
        env: HashMap::new(),
        tty,
        pipe_stdin,
        arg0: None,
        sandbox: None,
        enforce_managed_network: false,
        managed_network: None,
    }
}

/// Read until the process reports `exited`, accumulating all stdout/stderr.
async fn read_until_exit(process: &dyn ExecProcess) -> (Vec<u8>, Option<i32>) {
    let mut after_seq: Option<u64> = None;
    let mut buf = Vec::new();
    let exit_code;

    loop {
        let response = process
            .read(
                after_seq,
                /*max_bytes*/ None,
                /*wait_ms*/ Some(2_000),
            )
            .await
            .expect("read");
        for chunk in &response.chunks {
            buf.extend_from_slice(&chunk.chunk.0);
            after_seq = Some(chunk.seq);
        }
        if let Some(seq) = response.next_seq.checked_sub(1) {
            after_seq = Some(after_seq.map_or(seq, |a| a.max(seq)));
        }
        if response.exited {
            exit_code = response.exit_code;
            break;
        }
    }
    (buf, exit_code)
}

#[tokio::main]
async fn main() {
    let home = std::env::var("HOME").expect("HOME");
    let key_path = format!("{home}/.ssh/agentapp_key");

    let backend = SshProcessBackend::new("127.0.0.1", 22, "ivica", key_path);

    // ---- Part 1: non-interactive command ----
    println!("== running: echo hello; whoami; uname -n ==");
    let started = backend
        .start(exec_params(
            "ssh-spike-echo",
            vec!["sh", "-c", "echo hello; whoami; uname -n"],
            /*tty*/ false,
            /*pipe_stdin*/ false,
        ))
        .await
        .expect("start echo process");
    let process = started.process;

    let (output, exit_code) = read_until_exit(process.as_ref()).await;
    let text = String::from_utf8_lossy(&output);
    println!("---- remote output ----");
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    println!("---- exit code: {exit_code:?} ----");

    assert!(text.contains("hello"), "expected 'hello' in output");
    assert_eq!(exit_code, Some(0), "echo command should exit 0");

    // ---- Part 2: interactive stdin via `cat` (echoes stdin to stdout) ----
    println!("\n== interactive stdin: cat ==");
    let started = backend
        .start(exec_params(
            "ssh-spike-cat",
            vec!["cat"],
            /*tty*/ false,
            /*pipe_stdin*/ true,
        ))
        .await
        .expect("start cat process");
    let process = started.process;

    let write_response = process
        .write(b"ping\n".to_vec())
        .await
        .expect("write to cat stdin");
    println!("write status: {:?}", write_response.status);

    // Read back the echoed line (cat is still running, so don't wait for exit).
    let mut echoed = Vec::new();
    let mut after_seq = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let response = process
            .read(after_seq, None, Some(500))
            .await
            .expect("read cat echo");
        for chunk in &response.chunks {
            echoed.extend_from_slice(&chunk.chunk.0);
            after_seq = Some(chunk.seq);
        }
        if echoed.windows(5).any(|w| w == b"ping\n") {
            break;
        }
    }
    let echoed_text = String::from_utf8_lossy(&echoed);
    println!("echoed back from cat: {echoed_text:?}");
    assert!(echoed_text.contains("ping"), "cat should echo 'ping'");

    // Terminate: EOF closes cat's stdin -> cat exits.
    process.terminate().await.expect("terminate cat");
    let (_tail, cat_exit) = read_until_exit(process.as_ref()).await;
    println!("cat exit code: {cat_exit:?}");

    println!("\nSSH_PROCESS_OK");
}
