//! Host harness: drive ONE real Codex turn in SERVER MODE end-to-end and PROVE
//! that the turn's shell/exec tools actually ran over SSH (`SshProcessBackend`)
//! rather than being spawned as a LOCAL native process.
//!
//! The old version of this harness was AMBIGUOUS: on macOS, a local spawn and an
//! SSH-to-localhost session both report `whoami == ivica` / `uname -n == atlas`,
//! so a passing run did NOT actually prove the SSH path was taken.
//!
//! The definitive signal is `$SSH_CONNECTION`: sshd sets it ONLY for real SSH
//! sessions (e.g. `127.0.0.1 53xxx 127.0.0.1 22`); it is EMPTY for a local
//! spawn. So we ask the model to run:
//!     echo "SSHCONN=[$SSH_CONNECTION]" && whoami && uname -n
//! and require `SSHCONN=[...]` to be NON-EMPTY. If it is empty, exec fell back
//! to a local spawn and the fix did NOT work.
//!
//! OAuth token is read from ~/.codex/auth.json (never printed), exactly like
//! `drive_turn.rs`.
//!
//! Run:
//!   cargo run -p codex-ios --example drive_turn_server_mode
//!
//! On success (real SSH) it prints `SERVER_MODE_SSH_VERIFIED`.
//! If exec stayed local it prints `STILL_LOCAL` and exits non-zero.

use codex_ios::ServerMode;
use codex_ios::run_turn_streaming;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;

#[derive(Default)]
struct Capture {
    answer: String,
    tool_calls: String,
    // The full rollout JSON emitted at TurnComplete. This carries the
    // FunctionCallOutput items, i.e. the VERBATIM, shell-EXPANDED command output
    // (`SSHCONN=[127.0.0.1 ...]`) — the only reliable place to read what sshd
    // actually substituted for `$SSH_CONNECTION`. The KIND_TOOL_CALL events, by
    // contrast, only carry the unexpanded command string.
    history: String,
    saw_error: bool,
}

extern "C" fn on_event(ctx: *mut c_void, kind: c_int, text: *const c_char) {
    let s = if text.is_null() {
        String::new()
    } else {
        unsafe { std::ffi::CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned()
    };
    let cap = unsafe { &mut *(ctx as *mut Capture) };
    match kind {
        0 => {} // reasoning delta (ignore)
        1 => {
            // text delta
            print!("{s}");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            cap.answer.push_str(&s);
        }
        4 => {
            // KIND_HISTORY: full rollout JSON (includes FunctionCallOutput with
            // the expanded shell output). Captured for SSHCONN verification.
            cap.history.push_str(&s);
            cap.history.push('\n');
        }
        5 => {
            // KIND_TOOL_CALL
            println!("\n  [TOOL] {s}");
            cap.tool_calls.push_str(&s);
            cap.tool_calls.push('\n');
        }
        2 => println!("\n  «done»"),
        3 => {
            println!("\n  «ERROR: {s}»");
            cap.saw_error = true;
        }
        _ => {}
    }
}

fn main() {
    let home = std::env::var("HOME").expect("HOME");
    let raw =
        std::fs::read_to_string(format!("{home}/.codex/auth.json")).expect("read ~/.codex/auth.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse auth.json");
    let token = v["tokens"]["access_token"].as_str().unwrap().to_string();
    let id = v["tokens"]["id_token"].as_str().unwrap().to_string();
    let account = v["tokens"]["account_id"].as_str().unwrap().to_string();

    // SSH params: connect back to THIS Mac, matching the spike harness.
    let server = ServerMode {
        host: "127.0.0.1".to_string(),
        port: 22,
        user: "ivica".to_string(),
        key_path: format!("{home}/.ssh/agentapp_key"),
        host_fingerprint: Some(
            "SHA256:CY78+2WDrz98u7UEHZx8AhuwLAeHU5wbpBfULEh6jVc".to_string(),
        ),
    };

    let mut cap = Capture::default();

    // `$SSH_CONNECTION` is populated by sshd ONLY for a real SSH session and is
    // EMPTY for a local spawn. Verbatim output proves whether exec went over SSH.
    let prompt = "Run this exact shell command and report its full verbatim output, \
        including the SSHCONN line, without modifying it: \
        echo \"SSHCONN=[$SSH_CONNECTION]\" && whoami && uname -n";
    println!("=== SERVER MODE SSH VERIFICATION ===");
    print!("answer: ");

    let workspace = std::env::temp_dir().join("codex_server_mode_ws");
    let _ = std::fs::create_dir_all(&workspace);

    unsafe {
        run_turn_streaming(
            token,
            id,
            account,
            "gpt-5.4".to_string(),
            prompt.to_string(),
            String::new(),
            workspace.to_string_lossy().into_owned(),
            Some(server),
            &mut cap as *mut Capture as *mut c_void,
            on_event,
        );
    }

    println!("\n--- verifying the command ACTUALLY ran over SSH ---");
    // Search the rollout history (verbatim FunctionCallOutput, most reliable),
    // then the model's answer, then the raw tool-call payloads. Note: the
    // tool_calls payload carries the UNEXPANDED command string, so a match there
    // alone would be `SSHCONN=[$SSH_CONNECTION]` and would not prove SSH; the
    // empty-vs-populated distinction only holds for the expanded output, which
    // lives in `history` (and is echoed by the model into `answer`).
    let haystack = format!("{}\n{}\n{}", cap.history, cap.answer, cap.tool_calls);
    let used_shell_tool = cap.tool_calls.contains("\"shell")
        || cap.tool_calls.contains("exec_command")
        || cap.tool_calls.contains("shell_command")
        || cap.tool_calls.contains("\"command\"");

    // Collect the contents of EVERY `SSHCONN=[...]` marker. Some occurrences are
    // the UNEXPANDED command string (`SSHCONN=[$SSH_CONNECTION]`, from the
    // tool-call args / FunctionCall echo) — those must be ignored. We want the
    // EXPANDED output, where sshd has substituted either a real connection
    // (`127.0.0.1 53xxx 127.0.0.1 22`) or an empty string (local spawn).
    let mut markers: Vec<String> = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = haystack[search_from..].find("SSHCONN=[") {
        let start = search_from + rel + "SSHCONN=[".len();
        if let Some(end_rel) = haystack[start..].find(']') {
            markers.push(haystack[start..start + end_rel].to_string());
            search_from = start + end_rel + 1;
        } else {
            break;
        }
    }
    // Drop the literal/unexpanded markers; keep only expanded ones (which may be
    // empty for a local spawn — that's the STILL_LOCAL signal we want to catch).
    let expanded: Vec<&String> = markers
        .iter()
        .filter(|m| !m.contains("$SSH_CONNECTION"))
        .collect();
    // Prefer a non-empty expanded marker; otherwise fall back to the first
    // expanded marker (empty => local). If none expanded, report not-found.
    let sshconn_inner: Option<String> = expanded
        .iter()
        .find(|m| !m.trim().is_empty())
        .or_else(|| expanded.first())
        .map(|m| (*m).clone());

    match &sshconn_inner {
        Some(inner) => println!("  SSHCONN=[{inner}]"),
        None => println!("  SSHCONN marker not found in output"),
    }
    println!("  used_shell_tool = {used_shell_tool}");
    println!("  saw_error       = {}", cap.saw_error);

    // Real SSH iff the marker exists AND is non-empty (carries an address/port).
    let went_over_ssh = sshconn_inner
        .as_deref()
        .map(|inner| !inner.trim().is_empty())
        .unwrap_or(false);

    if !cap.saw_error && used_shell_tool && went_over_ssh {
        // $SSH_CONNECTION was populated => the command ran inside a real sshd
        // session, i.e. exec went through SshProcessBackend, not a local spawn.
        println!("SERVER_MODE_SSH_VERIFIED");
    } else if sshconn_inner.as_deref().map(str::trim) == Some("") {
        // Marker present but empty => exec fell back to a LOCAL native spawn.
        eprintln!(
            "STILL_LOCAL: SSHCONN came back empty, so exec did NOT go over SSH \
             (it was spawned locally). The server-mode routing fix is not working."
        );
        std::process::exit(1);
    } else {
        eprintln!(
            "SERVER_MODE_SSH_UNVERIFIED (error={}, shell_tool={used_shell_tool}, \
             went_over_ssh={went_over_ssh}); could not confirm SSH from output.",
            cap.saw_error
        );
        std::process::exit(1);
    }
}
