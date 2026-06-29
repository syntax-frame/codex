//! Host harness: drive the REAL Codex turn loop FFI with a live OAuth token read
//! from ~/.codex/auth.json (token never printed) and stream events to stdout.
//! Run: `cargo run -p codex-ios --example drive_turn -- "your prompt"`

use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;

use codex_ios::codex_run_turn_streaming;

extern "C" fn on_event(_ctx: *mut c_void, kind: c_int, text: *const c_char) {
    let s = if text.is_null() {
        String::new()
    } else {
        unsafe { std::ffi::CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned()
    };
    let label = match kind {
        0 => "REASONING",
        1 => "TEXT",
        2 => "DONE",
        3 => "ERROR",
        _ => "?",
    };
    println!("[{label}] {s}");
}

fn main() {
    let prompt = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Say hello from the real Codex loop in exactly five words.".to_string());

    let home = std::env::var("HOME").expect("HOME");
    let auth_path = format!("{home}/.codex/auth.json");
    let raw = std::fs::read_to_string(&auth_path).expect("read auth.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse auth.json");
    let token = v["tokens"]["access_token"].as_str().expect("access_token").to_string();
    let id_token = v["tokens"]["id_token"].as_str().expect("id_token").to_string();
    let account = v["tokens"]["account_id"].as_str().expect("account_id").to_string();

    println!("(driving real turn loop; model=gpt-5.4; token len {} hidden)", token.len());

    let c_token = CString::new(token).unwrap();
    let c_id = CString::new(id_token).unwrap();
    let c_account = CString::new(account).unwrap();
    let c_model = CString::new("gpt-5.4").unwrap();
    let c_prompt = CString::new(prompt).unwrap();

    codex_run_turn_streaming(
        c_token.as_ptr(),
        c_id.as_ptr(),
        c_account.as_ptr(),
        c_model.as_ptr(),
        c_prompt.as_ptr(),
        std::ptr::null_mut(),
        on_event,
    );
}
