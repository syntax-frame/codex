//! Live OAuth catalog and native turn smoke with one fixed arithmetic tool.
//! Run `cargo run -p codex-ios --example model_catalog_smoke -- <model-slug>`.
//! Credentials are read from the existing auth file and remain in memory. A
//! bounded child owns the runtime; its private context is removed after exit.

use codex_ios::codex_free_string;
use codex_ios::codex_interrupt_turn;
use codex_ios::codex_list_models_json;
use codex_ios::codex_run_turn_streaming;
use serde_json::Value;
use serde_json::json;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::process::Command;
use std::process::ExitCode;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

const CACHE_ROOT: &str = "/Users/ivica/Library/Caches/AgentAppNext/model-smoke";
const WORKER_ARGUMENT: &str = "--internal-model-smoke-worker";
const DEADLINE: Duration = Duration::from_secs(120);

// Public C ABI symbol, not re-exported as a Rust item.
unsafe extern "C" {
    fn codex_respond_dynamic_tool(
        turn_handle: u64,
        call_id: *const c_char,
        response_json: *const c_char,
    ) -> c_int;
}

#[derive(Default)]
struct Capture {
    handle: u64,
    completed: bool,
    answer_is_42: bool,
    tool_calls: usize,
    error_code: Option<&'static str>,
    http_status: Option<u64>,
    last_startup_stage: Option<&'static str>,
}

// The protected Core event already exposes a numeric status without an error
// message. Keep only that field; never format or retain other tracing values.
struct StatusSubscriber(Arc<Mutex<TraceCapture>>);

#[derive(Default)]
struct TraceCapture {
    protected_error_seen: bool,
    http_status: Option<u64>,
}

#[derive(Default)]
struct StatusVisitor(Option<u64>);

impl tracing::field::Visit for StatusVisitor {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "http_status" && (100..=599).contains(&value) {
            self.0 = Some(value);
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if let Ok(value) = u64::try_from(value) {
            self.record_u64(field, value);
        }
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}
}

impl tracing::Subscriber for StatusSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.is_event()
            && metadata.target() == "codex_core::session::turn"
            && metadata.fields().field("http_status").is_some()
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        if self.enabled(event.metadata()) {
            let mut visitor = StatusVisitor::default();
            event.record(&mut visitor);
            if let Ok(mut captured) = self.0.lock() {
                captured.protected_error_seen = true;
                captured.http_status = visitor.0;
            }
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

fn interrupt(handle: u64) {
    // The FFI submits through block_on, so do not call it inside its runtime.
    std::thread::spawn(move || codex_interrupt_turn(handle));
}

extern "C" fn on_event(context: *mut c_void, kind: c_int, text: *const c_char) {
    if context.is_null() || text.is_null() {
        return;
    }
    // SAFETY: the caller retains this mutex until the synchronous FFI returns;
    // the library owns a valid C string for the duration of this callback.
    let capture = unsafe { &*context.cast::<Mutex<Capture>>() };
    let text = unsafe { CStr::from_ptr(text) }.to_bytes();
    let Ok(mut state) = capture.lock() else {
        return;
    };
    match kind {
        2 => state.completed = true,
        3 => {
            state.error_code.get_or_insert("turn_error");
        }
        4 => {
            if let Ok(projection) = serde_json::from_slice::<Value>(text) {
                state.answer_is_42 = projection[0]["content"][0]["text"]
                    .as_str()
                    .is_some_and(|answer| answer.trim() == "42");
            }
        }
        5 => {
            let call = serde_json::from_slice::<Value>(text).unwrap_or(Value::Null);
            if call["tool"].as_str() != Some("addNumbers") {
                state.error_code = Some("unexpected_native_tool");
                interrupt(state.handle);
            }
        }
        7 => {
            state.tool_calls += 1;
            let call = serde_json::from_slice::<Value>(text).unwrap_or(Value::Null);
            let handle = call["turn_handle"].as_u64().unwrap_or(0);
            let args = &call["arguments"];
            let valid = state.tool_calls == 1
                && handle == state.handle
                && call["tool"].as_str() == Some("addNumbers")
                && call["namespace"].is_null()
                && args.as_object().is_some_and(|args| args.len() == 2)
                && args["a"].as_i64() == Some(20)
                && args["b"].as_i64() == Some(22);
            let call_id = call["call_id"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 256)
                .and_then(|id| CString::new(id).ok());
            if !valid || call_id.is_none() {
                state.error_code = Some("invalid_dynamic_tool_call");
                interrupt(state.handle);
                return;
            }
            if let Some(call_id) = call_id {
                // SAFETY: both strings remain valid throughout the call and
                // the handle/call ID came from the active callback payload.
                let status = unsafe {
                    codex_respond_dynamic_tool(
                        handle,
                        call_id.as_ptr(),
                        c"{\"text\":\"42\",\"success\":true}".as_ptr(),
                    )
                };
                if status != 0 {
                    state.error_code = Some("dynamic_tool_response_rejected");
                    interrupt(state.handle);
                }
            }
        }
        8 | 17 => {
            state.handle = std::str::from_utf8(text)
                .ok()
                .and_then(|text| text.parse().ok())
                .unwrap_or(0);
        }
        16 => {
            state.error_code.get_or_insert("turn_aborted");
        }
        18 => {
            let error = serde_json::from_slice::<Value>(text).unwrap_or(Value::Null);
            state.http_status = error["http_status_code"]
                .as_u64()
                .filter(|status| (100..=599).contains(status));
            let code = match error["code"].as_str() {
                Some("context_window_exceeded") => "context_window_exceeded",
                Some("session_budget_exceeded") => "session_budget_exceeded",
                Some("usage_limit_exceeded") => "usage_limit_exceeded",
                Some("server_overloaded") => "server_overloaded",
                Some("unauthorized") => "unauthorized",
                Some("bad_request") => "bad_request",
                Some("other") => "other",
                Some("cyber_policy") => "cyber_policy",
                Some("sandbox_error") => "sandbox_error",
                Some("http_connection_failed") => "http_connection_failed",
                Some("response_stream_connection_failed") => "response_stream_connection_failed",
                Some("response_stream_disconnected") => "response_stream_disconnected",
                Some("internal_server_error") => "internal_server_error",
                Some("response_too_many_failed_attempts") => "response_too_many_failed_attempts",
                _ => "structured_turn_error",
            };
            state.error_code.get_or_insert(code);
        }
        19 => {
            state.last_startup_stage = match std::str::from_utf8(text) {
                Ok("run_turn_async_entered") => Some("run_turn_async_entered"),
                Ok("thread_reused") => Some("thread_reused"),
                Ok("auth_ready") => Some("auth_ready"),
                Ok("config_ready") => Some("config_ready"),
                Ok("exact_execution_reconciled") => Some("exact_execution_reconciled"),
                Ok("thread_resumed") => Some("thread_resumed"),
                Ok("thread_ready") => Some("thread_ready"),
                Ok("history_inject_begin") => Some("history_inject_begin"),
                Ok("history_inject_end") => Some("history_inject_end"),
                Ok("prompt_image_submit_begin") => Some("prompt_image_submit_begin"),
                Ok("prompt_image_submit_end") => Some("prompt_image_submit_end"),
                Ok("prompt_submit_begin") => Some("prompt_submit_begin"),
                Ok("prompt_submit_end") => Some("prompt_submit_end"),
                Ok("prompt_image_first_event_wait") => Some("prompt_image_first_event_wait"),
                Ok("thread_cached") => Some("thread_cached"),
                _ => Some("unknown_startup_stage"),
            };
        }
        _ => {}
    }
}

fn run_worker(model: &str, root: &Path) -> Result<Value, &'static str> {
    let expected_parent = Path::new(CACHE_ROOT)
        .canonicalize()
        .map_err(|_| "invalid_private_root")?;
    let root = root.canonicalize().map_err(|_| "invalid_private_root")?;
    if root.parent() != Some(expected_parent.as_path()) {
        return Err("invalid_private_root");
    }
    let traced_status = Arc::new(Mutex::new(TraceCapture::default()));
    tracing::subscriber::set_global_default(StatusSubscriber(traced_status.clone()))
        .map_err(|_| "diagnostic_subscriber_unavailable")?;
    let auth_path = Path::new("/Users/ivica/.codex/auth.json");
    let auth: Value =
        serde_json::from_slice(&std::fs::read(auth_path).map_err(|_| "auth_unreadable")?)
            .map_err(|_| "auth_invalid")?;
    let auth_field = |name: &str| {
        auth["tokens"][name]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("auth_incomplete")
            .and_then(|value| CString::new(value).map_err(|_| "auth_invalid"))
    };
    let access_token = auth_field("access_token")?;
    let id_token = auth_field("id_token")?;
    let account_id = auth_field("account_id")?;
    let catalog = codex_list_models_json(
        access_token.as_ptr(),
        id_token.as_ptr(),
        account_id.as_ptr(),
    );
    if catalog.is_null() {
        return Err("catalog_missing");
    }
    // SAFETY: the FFI returned its owned, NUL-terminated allocation. Copy only
    // parsed JSON, then release it with the corresponding allocator function.
    let catalog_json = unsafe { CStr::from_ptr(catalog) }.to_bytes();
    let catalog_value = serde_json::from_slice::<Value>(catalog_json);
    codex_free_string(catalog);
    let catalog_value = catalog_value.map_err(|_| "catalog_unavailable")?;
    let models = catalog_value.as_array().ok_or("catalog_invalid")?;
    let Some(preset) = models.iter().find(|preset| {
        preset["model"].as_str() == Some(model) && preset["show_in_picker"].as_bool() == Some(true)
    }) else {
        return Ok(json!({"ok": false, "catalog_count": models.len(),
            "model_visible": false, "completed": false, "tool_calls": 0,
            "answer": null, "error_code": "model_not_visible"}));
    };
    let low_supported = preset["supported_reasoning_efforts"]
        .as_array()
        .is_some_and(|efforts| efforts.iter().any(|effort| effort["effort"] == "low"));
    let model = CString::new(model).map_err(|_| "invalid_model")?;
    let context = CString::new(root.join("context").as_os_str().as_encoded_bytes())
        .map_err(|_| "invalid_private_root")?;
    let workspace = CString::new(root.join("workspace").as_os_str().as_encoded_bytes())
        .map_err(|_| "invalid_private_root")?;
    let capture = Mutex::new(Capture::default());
    codex_run_turn_streaming(
        access_token.as_ptr(),
        id_token.as_ptr(),
        account_id.as_ptr(),
        model.as_ptr(),
        if low_supported { c"low" } else { c"" }.as_ptr(),
        c"default".as_ptr(),
        c"Call addNumbers exactly once with a=20 and b=22. Use no other tools. After receiving its result, reply with exactly 42 and nothing else. This is a synthetic arithmetic service check.".as_ptr(),
        c"[]".as_ptr(),
        context.as_ptr(),
        workspace.as_ptr(),
        c"[{\"type\":\"function\",\"name\":\"addNumbers\",\"description\":\"Return the sum of the supplied integers.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"integer\"},\"b\":{\"type\":\"integer\"}},\"required\":[\"a\",\"b\"],\"additionalProperties\":false}}]".as_ptr(),
        c"[]".as_ptr(),
        (&capture as *const Mutex<Capture>).cast_mut().cast(),
        on_event,
    );
    let state = capture.lock().map_err(|_| "callback_failed")?;
    let trace = traced_status
        .lock()
        .map_err(|_| "diagnostic_capture_failed")?;
    let http_status = state.http_status.or(trace.http_status);
    let cache_path = root.join("context/models_cache.json");
    let cache = std::fs::read(&cache_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let cached_model = cache
        .as_ref()
        .and_then(|cache| cache["models"].as_array())
        .and_then(|models| {
            models.iter().find(|cached| {
                cached["slug"]
                    .as_str()
                    .is_some_and(|slug| slug.as_bytes() == model.as_bytes())
            })
        });
    Ok(json!({
        "ok": state.completed && state.error_code.is_none()
            && state.tool_calls == 1 && state.answer_is_42,
        "catalog_count": models.len(), "model_visible": true,
        "completed": state.completed, "tool_calls": state.tool_calls,
        "answer": state.answer_is_42.then_some(42),
        "error_code": state.error_code, "http_status": http_status,
        "last_startup_stage": state.last_startup_stage,
        "protected_error_seen": trace.protected_error_seen,
        "models_cache_present": cache_path.is_file(),
        "models_cache_valid": cache.is_some(),
        "models_cache_version_compatible": cache.as_ref()
            .is_some_and(|cache| cache["client_version"] == codex_models_manager::client_version_to_whole()),
        "cached_model_present": cached_model.is_some(),
        "cached_model_uses_responses_lite": cached_model
            .is_some_and(|model| model["use_responses_lite"] == true),
    }))
}

fn supervise(model: &str) -> Result<Value, &'static str> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(CACHE_ROOT)
        .map_err(|_| "private_root_creation_failed")?;
    let private = tempfile::Builder::new()
        .prefix("model-")
        .tempdir_in(CACHE_ROOT)
        .map_err(|_| "private_root_creation_failed")?;
    let workspace = private.path().join("workspace");
    std::fs::create_dir(&workspace).map_err(|_| "workspace_creation_failed")?;
    let mut child = Command::new(std::env::current_exe().map_err(|_| "executable_unavailable")?)
        .arg(WORKER_ARGUMENT)
        .arg(model)
        .arg(private.path())
        .current_dir(workspace)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "worker_start_failed")?;
    let started = Instant::now();
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < DEADLINE => {
                std::thread::sleep(Duration::from_millis(25));
            }
            _ => {
                timed_out = true;
                let _ = child.kill();
                break;
            }
        }
    }
    // Waiting before closing the TempDir also releases Core's warm-thread
    // cache and all its background file handles, including on deadline expiry.
    let output = child.wait_with_output().map_err(|_| "worker_wait_failed")?;
    let mut result = if timed_out {
        json!({"ok": false, "error_code": "deadline_exceeded"})
    } else {
        serde_json::from_slice::<Value>(&output.stdout)
            .unwrap_or_else(|_| json!({"ok": false, "error_code": "worker_failed"}))
    };
    result["elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
    result["cleaned"] = json!(private.close().is_ok());
    if result["cleaned"] != true {
        result["ok"] = json!(false);
        result["error_code"] = json!("cleanup_failed");
    }
    Ok(result)
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let result = match arguments.as_slice() {
        [model] if valid_model(model) => supervise(model),
        [mode, model, root] if mode == WORKER_ARGUMENT && valid_model(model) => {
            run_worker(model, Path::new(root))
        }
        _ => Err("expected_model_slug"),
    }
    .unwrap_or_else(|code| json!({"ok": false, "error_code": code}));
    println!("{result}");
    if result["ok"] == true {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn valid_model(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 128
        && model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
