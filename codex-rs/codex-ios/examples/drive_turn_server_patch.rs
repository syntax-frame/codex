//! Host harness: drive ONE real Codex turn in SERVER MODE and PROVE that
//! `apply_patch` edits a file on the REMOTE host (here, this Mac over SSH)
//! through the SFTP-backed `SshFileSystem`, not the phone's local disk.
//!
//! Flow:
//!   1. Write a known file on the Mac at /tmp/agentapp_patch_test.txt
//!      containing `hello world\n` (via std::fs — local disk, fine here).
//!   2. Run a server-mode turn asking the model to use apply_patch to change
//!      the line `hello world` to `hello SSH` in that file. File ops route over
//!      SSH/SFTP to 127.0.0.1, so the edit lands on this same Mac's disk.
//!   3. Read the file back from disk and assert it now contains `hello SSH`.
//!   4. Print `SERVER_APPLY_PATCH_OK` iff the on-disk file actually changed.
//!      Otherwise print `PATCH_DID_NOT_LAND` and report what the turn did.
//!
//! OAuth token is read from ~/.codex/auth.json (never printed), exactly like
//! `drive_turn_server_mode.rs`.
//!
//! Run:
//!   cargo run -p codex-ios --example drive_turn_server_patch

use codex_ios::ServerMode;
use codex_ios::run_turn_streaming;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;

const TEST_PATH: &str = "/tmp/agentapp_patch_test.txt";
const ORIGINAL: &str = "hello world\n";
const EXPECTED_SUBSTRING: &str = "hello SSH";

#[derive(Default)]
struct Capture {
    answer: String,
    tool_calls: String,
    history: String,
    saw_error: bool,
    error_text: String,
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
            print!("{s}");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            cap.answer.push_str(&s);
        }
        4 => {
            // KIND_HISTORY: full rollout JSON (FunctionCall + FunctionCallOutput).
            cap.history.push_str(&s);
            cap.history.push('\n');
        }
        5 => {
            println!("\n  [TOOL] {s}");
            cap.tool_calls.push_str(&s);
            cap.tool_calls.push('\n');
        }
        2 => println!("\n  «done»"),
        3 => {
            println!("\n  «ERROR: {s}»");
            cap.saw_error = true;
            cap.error_text.push_str(&s);
            cap.error_text.push('\n');
        }
        _ => {}
    }
}

fn main() {
    let home = std::env::var("HOME").expect("HOME");
    let raw = std::fs::read_to_string(format!("{home}/.codex/auth.json"))
        .expect("read ~/.codex/auth.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse auth.json");
    let token = v["tokens"]["access_token"].as_str().unwrap().to_string();
    let id = v["tokens"]["id_token"].as_str().unwrap().to_string();
    let account = v["tokens"]["account_id"].as_str().unwrap().to_string();

    // 1. Seed the known file on the Mac (local disk write is fine — same host).
    std::fs::write(TEST_PATH, ORIGINAL).expect("seed test file");
    println!("=== SERVER MODE apply_patch VERIFICATION ===");
    println!("seeded {TEST_PATH} with {ORIGINAL:?}");

    // SSH params: connect back to THIS Mac, matching the spike harness.
    let server = ServerMode {
        host: "127.0.0.1".to_string(),
        port: 22,
        user: "ivica".to_string(),
        key_path: format!("{home}/.ssh/agentapp_key"),
        host_fingerprint: Some("SHA256:CY78+2WDrz98u7UEHZx8AhuwLAeHU5wbpBfULEh6jVc".to_string()),
    };

    let mut cap = Capture::default();

    let prompt = format!(
        "Use apply_patch to change the line 'hello world' to 'hello SSH' in {TEST_PATH}. \
         Do not use any shell command; use the apply_patch tool. After applying, confirm \
         the change."
    );
    print!("answer: ");

    // 2. Run the turn with workspace/cwd = /tmp (exists on the Mac).
    unsafe {
        run_turn_streaming(
            token,
            id,
            account,
            "gpt-5.4".to_string(),
            prompt,
            String::new(),
            "/tmp".to_string(),
            Some(server),
            &mut cap as *mut Capture as *mut c_void,
            on_event,
        );
    }

    println!("\n--- verifying the file on the Mac actually changed ---");

    // 3. Read the file back from disk (local Mac — std::fs is correct here).
    let on_disk = std::fs::read_to_string(TEST_PATH).unwrap_or_default();
    println!("  on-disk contents now: {on_disk:?}");

    let used_apply_patch = cap.tool_calls.contains("apply_patch")
        || cap.history.contains("apply_patch")
        || cap.answer.contains("apply_patch");
    println!("  used_apply_patch = {used_apply_patch}");
    println!("  saw_error        = {}", cap.saw_error);
    if cap.saw_error {
        println!("  error_text       = {}", cap.error_text.trim());
    }

    // 4. The deliverable signal: the on-disk file changed to contain "hello SSH"
    //    and no longer contains the original "hello world".
    let landed =
        on_disk.contains(EXPECTED_SUBSTRING) && !on_disk.contains("hello world");

    if landed {
        println!("SERVER_APPLY_PATCH_OK");
    } else {
        eprintln!(
            "PATCH_DID_NOT_LAND: file still {on_disk:?} (expected to contain {EXPECTED_SUBSTRING:?}). \
             used_apply_patch={used_apply_patch}, saw_error={}, error={}",
            cap.saw_error,
            cap.error_text.trim(),
        );
        std::process::exit(1);
    }
}
