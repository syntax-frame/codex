//! Host harness: drive ONE real Codex turn in SERVER MODE end-to-end. The
//! turn's shell/exec tools run on the Mac over SSH (`SshProcessBackend`), so a
//! prompt asking for `whoami && uname -n && pwd` must come back with this host's
//! identity (`ivica` / `atlas.fritz.box` / `/Users/ivica`).
//!
//! OAuth token is read from ~/.codex/auth.json (never printed), exactly like
//! `drive_turn.rs`.
//!
//! Run:
//!   cargo run -p codex-ios --example drive_turn_server_mode
//!
//! On success it prints a single `SERVER_MODE_SHELL_OK` line.

use codex_ios::ServerMode;
use codex_ios::run_turn_streaming;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;

#[derive(Default)]
struct Capture {
    answer: String,
    tool_calls: String,
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
        4 => {} // KIND_HISTORY (ignore)
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

    let prompt = "Run the shell command `whoami && uname -n && pwd` and tell me the exact output.";
    println!("=== SERVER MODE SHELL SPIKE ===");
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

    println!("\n--- verifying the command ran ON THIS MAC ---");
    let haystack = format!("{}\n{}", cap.answer, cap.tool_calls).to_lowercase();
    let used_shell_tool = cap.tool_calls.contains("\"shell")
        || cap.tool_calls.contains("exec_command")
        || cap.tool_calls.contains("shell_command")
        || cap.tool_calls.contains("\"command\"");
    let mentions_user = haystack.contains("ivica");
    let mentions_host = haystack.contains("atlas");
    let mentions_pwd = haystack.contains("/users/ivica");

    println!("  used_shell_tool = {used_shell_tool}");
    println!("  mentions ivica  = {mentions_user}");
    println!("  mentions host   = {mentions_host}");
    println!("  mentions pwd    = {mentions_pwd}");

    // The model phrasing of the hostname can vary; require the user identity
    // plus at least one more Mac-specific marker, and that a shell tool ran.
    let proved_on_mac = mentions_user && (mentions_host || mentions_pwd);
    if !cap.saw_error && used_shell_tool && proved_on_mac {
        println!("SERVER_MODE_SHELL_OK");
    } else {
        eprintln!(
            "SERVER_MODE_SHELL_FAILED (error={}, shell_tool={used_shell_tool}, on_mac={proved_on_mac})",
            cap.saw_error
        );
        std::process::exit(1);
    }
}
