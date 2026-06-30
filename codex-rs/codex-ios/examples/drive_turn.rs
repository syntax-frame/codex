//! Host harness: drive the REAL Codex turn loop FFI with a live OAuth token from
//! ~/.codex/auth.json (token never printed). Runs TWO turns to verify per-node
//! history: turn 1 states a fact, turn 2 asks it back using the rollout returned
//! by turn 1. Run: `cargo run -p codex-ios --example drive_turn`

use codex_ios::codex_run_turn_streaming;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;

struct Capture {
    history: String,
    answer: String,
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
        0 => {}                                   // reasoning delta (ignore here)
        1 => {                                     // text delta
            print!("{s}");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            cap.answer.push_str(&s);
        }
        4 => cap.history = s,                       // KIND_HISTORY (full rollout)
        5 => println!("\n  [TOOL] {s}"),            // KIND_TOOL_CALL
        2 => println!("\n  «done»"),                // done
        3 => println!("\n  «ERROR: {s}»"),          // error
        _ => {}
    }
}

fn run(token: &str, id: &str, account: &str, prompt: &str, history: &str, cap: &mut Capture) {
    cap.answer.clear();
    let c = |s: &str| CString::new(s).unwrap();
    let ws = std::env::temp_dir().join("codex_drive_turn_ws");
    let _ = std::fs::create_dir_all(&ws);
    let (ct, ci, ca, cm, cp, ch, cw) = (
        c(token), c(id), c(account), c("gpt-5.4"), c(prompt), c(history),
        c(ws.to_str().unwrap()),
    );
    codex_run_turn_streaming(
        ct.as_ptr(), ci.as_ptr(), ca.as_ptr(), cm.as_ptr(), cp.as_ptr(), ch.as_ptr(), cw.as_ptr(),
        cap as *mut Capture as *mut c_void, on_event,
    );
}

fn main() {
    let home = std::env::var("HOME").expect("HOME");
    let raw = std::fs::read_to_string(format!("{home}/.codex/auth.json")).expect("auth.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse");
    let token = v["tokens"]["access_token"].as_str().unwrap().to_string();
    let id = v["tokens"]["id_token"].as_str().unwrap().to_string();
    let account = v["tokens"]["account_id"].as_str().unwrap().to_string();

    let mut cap = Capture { history: String::new(), answer: String::new() };

    println!("=== SPAWN AGENT SPIKE ===");
    print!("answer: ");
    run(&token, &id, &account,
        "Use your spawn_agent tool to spawn a sub-agent that computes 2+2 and reports the result. Wait for it (wait_agent) and then tell me what it returned. If you don't have a spawn_agent tool, say so explicitly.",
        "", &mut cap);
    println!("\n--- workspace contents on disk ---");
    let ws = std::env::temp_dir().join("codex_drive_turn_ws");
    if let Ok(entries) = std::fs::read_dir(&ws) {
        for e in entries.flatten() {
            let p = e.path();
            let body = std::fs::read_to_string(&p).unwrap_or_default();
            println!("  {} => {:?}", p.file_name().unwrap().to_string_lossy(), body);
        }
    }
}
