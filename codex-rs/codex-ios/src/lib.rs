//! C-ABI smoke-test shim that performs a single OpenAI Responses API round-trip
//! through the existing `codex-api` crate. Intended for an iOS port smoke test.
//!
//! The two exported functions take an OAuth bearer token and ChatGPT account id
//! as *runtime* arguments; nothing is ever logged, persisted, or read from disk.

use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Arc;
use std::time::Duration;

use codex_api::AuthProvider;
use codex_api::Provider;
use codex_api::ReqwestTransport;
use codex_api::ResponseEvent;
use codex_api::ResponsesApiRequest;
use codex_api::ResponsesClient;
use codex_api::ResponsesOptions;
use codex_api::RetryConfig;
use codex_api::SharedAuthProvider;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;
use futures::StreamExt;
use http::HeaderMap;
use http::HeaderName;
use http::HeaderValue;

mod turn;
pub use turn::EventCallback;
pub use turn::ServerFileUpload;
pub use turn::ServerMode;
pub use turn::codex_run_turn_streaming;
pub use turn::codex_steer_turn;
pub use turn::run_turn_streaming;

/// Header-only auth provider that injects the OAuth bearer token and the
/// `ChatGPT-Account-ID` header on every outbound request.
struct StaticAuth {
    token: String,
    account_id: String,
}

impl AuthProvider for StaticAuth {
    fn add_auth_headers(&self, headers: &mut HeaderMap) {
        if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", self.token)) {
            headers.insert(http::header::AUTHORIZATION, value);
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(b"ChatGPT-Account-ID"),
            HeaderValue::from_str(&self.account_id),
        ) {
            headers.insert(name, value);
        }
    }
}

/// Convert a borrowed C string into an owned Rust `String`.
///
/// Returns `Err` with a human-readable reason if the pointer is null or the
/// bytes are not valid UTF-8.
fn c_str_to_string(ptr: *const c_char, field: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{field} pointer was null"));
    }
    // SAFETY: caller guarantees a NUL-terminated C string for non-null pointers.
    let c_str = unsafe { CStr::from_ptr(ptr) };
    c_str
        .to_str()
        .map(str::to_owned)
        .map_err(|e| format!("{field} was not valid UTF-8: {e}"))
}

/// Allocate a C string (via the global allocator that `codex_free_string`
/// matches). Falls back to a static empty error string only if allocation of
/// the message itself fails, which should not happen for our inputs.
fn into_c_string(s: String) -> *mut c_char {
    match CString::new(s.clone()) {
        Ok(c) => c.into_raw(),
        Err(_) => {
            // Input contained an interior NUL; strip it and retry.
            let sanitized: String = s.chars().filter(|&c| c != '\0').collect();
            CString::new(sanitized)
                .unwrap_or_else(|_| CString::new("ERROR: failed to allocate result").unwrap())
                .into_raw()
        }
    }
}

fn error_string(message: impl AsRef<str>) -> *mut c_char {
    into_c_string(format!("ERROR: {}", message.as_ref()))
}

fn build_provider() -> Provider {
    Provider {
        name: "openai-codex".to_string(),
        base_url: "https://chatgpt.com/backend-api/codex".to_string(),
        query_params: None,
        headers: {
            let mut h = HeaderMap::new();
            // The ChatGPT backend gates Codex-model access on the originator header.
            h.insert("originator", http::HeaderValue::from_static("codex_cli_rs"));
            h.insert(
                http::header::USER_AGENT,
                http::HeaderValue::from_static("codex_cli_rs/0.0.0 (iOS 26.5; arm64) CodexIOS"),
            );
            h
        },
        retry: RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(500),
            retry_429: true,
            retry_5xx: true,
            retry_transport: true,
        },
        stream_idle_timeout: Duration::from_secs(60),
    }
}

fn build_request(model: String, prompt: String) -> ResponsesApiRequest {
    let user_message = ResponseItem::Message {
        id: None,
        role: "user".to_string(),
        content: vec![ContentItem::InputText { text: prompt }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    };

    ResponsesApiRequest {
        model,
        instructions: "You are a helpful assistant.".to_string(),
        input: vec![user_message],
        tools: None,
        tool_choice: "auto".to_string(),
        parallel_tool_calls: false,
        reasoning: None,
        store: false,
        stream: true,
        include: vec![],
        service_tier: None,
        prompt_cache_key: None,
        text: None,
        client_metadata: None::<HashMap<String, String>>,
    }
}

/// Drive the streaming request to completion and accumulate the assistant text.
async fn run_prompt_async(
    token: String,
    account_id: String,
    model: String,
    prompt: String,
) -> Result<String, String> {
    let transport = ReqwestTransport::new(reqwest::Client::new());
    let provider = build_provider();
    let auth: SharedAuthProvider = Arc::new(StaticAuth { token, account_id });

    let client = ResponsesClient::new(transport, provider, auth);
    let request = build_request(model, prompt);

    let mut stream = client
        .stream_request(request, ResponsesOptions::default())
        .await
        .map_err(|e| format!("stream_request failed: {e}"))?;

    let mut text = String::new();

    while let Some(event) = stream.next().await {
        let event = event.map_err(|e| format!("stream error: {e}"))?;
        match event {
            ResponseEvent::OutputTextDelta(delta) => {
                text.push_str(&delta);
            }
            ResponseEvent::OutputItemDone(item) => {
                // Fallback: if no deltas were emitted, collect assistant text
                // from the finalized message item.
                if text.is_empty()
                    && let ResponseItem::Message { role, content, .. } = item
                    && role == "assistant"
                {
                    for c in content {
                        if let ContentItem::OutputText { text: t } = c {
                            text.push_str(&t);
                        }
                    }
                }
            }
            ResponseEvent::Completed { .. } => break,
            _ => {}
        }
    }

    Ok(text)
}

/// Perform one Responses API round-trip and return the model's text reply.
///
/// On any failure returns a string beginning with `ERROR: `. The returned
/// pointer is heap-allocated and must be released with [`codex_free_string`].
///
/// # Safety
/// All four pointers must be either null or valid NUL-terminated C strings.
#[unsafe(no_mangle)]
pub extern "C" fn codex_run_prompt(
    access_token: *const c_char,
    account_id: *const c_char,
    model: *const c_char,
    prompt: *const c_char,
) -> *mut c_char {
    // Never let a panic unwind across the FFI boundary.
    let result = std::panic::catch_unwind(|| {
        let token = c_str_to_string(access_token, "access_token")?;
        let account = c_str_to_string(account_id, "account_id")?;
        let model = c_str_to_string(model, "model")?;
        let prompt = c_str_to_string(prompt, "prompt")?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

        runtime.block_on(run_prompt_async(token, account, model, prompt))
    });

    match result {
        Ok(Ok(text)) => into_c_string(text),
        Ok(Err(message)) => error_string(message),
        Err(_) => error_string("panic during request"),
    }
}

/// Return the authenticated Codex model catalog as a JSON array of ModelPreset
/// objects. The result is account-aware and picker-ready; release it with
/// [`codex_free_string`].
///
/// # Safety
/// All pointers must be valid NUL-terminated C strings.
#[unsafe(no_mangle)]
pub extern "C" fn codex_list_models_json(
    access_token: *const c_char,
    id_token: *const c_char,
    account_id: *const c_char,
) -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        let token = c_str_to_string(access_token, "access_token")?;
        let id_token = c_str_to_string(id_token, "id_token")?;
        let account = c_str_to_string(account_id, "account_id")?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to build tokio runtime: {e}"))?;
        runtime.block_on(turn::list_oauth_models_json(token, id_token, account))
    });

    match result {
        Ok(Ok(json)) => into_c_string(json),
        Ok(Err(message)) => error_string(message),
        Err(_) => error_string("panic while listing models"),
    }
}

/// Free a string previously returned by [`codex_run_prompt`].
///
/// # Safety
/// `s` must be a pointer returned by this library (or null).
#[unsafe(no_mangle)]
pub extern "C" fn codex_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: reclaims the CString allocated in `into_c_string`.
    unsafe {
        drop(CString::from_raw(s));
    }
}

pub mod ssh;
