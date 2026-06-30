//! On-device HTTP tool for the mobile build's LOCAL nodes: make an HTTP request
//! (fetch a URL, call a REST API) directly from the device. No shell, no
//! environment — a plain async `reqwest` call, with a hard timeout and a
//! response-size cap so it can never hang the turn or blow up the context.
//!
//! Scoped to local (Type-A) nodes: server (Type-B) nodes use the shell instead.

use crate::function_tool::FunctionCallError;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::context::boxed_tool_output;
use crate::tools::registry::CoreToolRuntime;
use crate::tools::registry::ToolExecutor;
use codex_protocol::models::FunctionCallOutputPayload;
use codex_protocol::models::ResponseInputItem;
use codex_tools::JsonSchema;
use codex_tools::ResponsesApiTool;
use codex_tools::ToolName;
use codex_tools::ToolSpec;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::time::Duration;

/// Hard wall-clock cap for a single request — never hang the turn.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// Max response body returned to the model (protects the context window).
const MAX_BODY_BYTES: usize = 100 * 1024;

struct TextToolOutput {
    text: String,
    ok: bool,
}

impl ToolOutput for TextToolOutput {
    fn log_preview(&self) -> String {
        self.text.chars().take(80).collect()
    }

    fn success_for_logging(&self) -> bool {
        self.ok
    }

    fn to_response_item(&self, call_id: &str, _payload: &ToolPayload) -> ResponseInputItem {
        let mut output = FunctionCallOutputPayload::from_text(self.text.clone());
        output.success = Some(self.ok);
        ResponseInputItem::FunctionCallOutput {
            call_id: call_id.to_string(),
            output,
        }
    }

    fn code_mode_result(&self, _payload: &ToolPayload) -> JsonValue {
        JsonValue::String(self.text.clone())
    }
}

fn ok_output(text: String) -> Box<dyn ToolOutput> {
    boxed_tool_output(TextToolOutput { text, ok: true })
}

fn err_output(text: String) -> Box<dyn ToolOutput> {
    boxed_tool_output(TextToolOutput { text, ok: false })
}

#[derive(Deserialize)]
struct HttpArgs {
    url: String,
    #[serde(default)]
    method: Option<String>,
    /// Optional request headers as a flat string->string map.
    #[serde(default)]
    headers: Option<BTreeMap<String, String>>,
    /// Optional raw request body (for POST/PUT/PATCH).
    #[serde(default)]
    body: Option<String>,
}

pub struct HttpRequestHandler;

impl ToolExecutor<ToolInvocation> for HttpRequestHandler {
    fn tool_name(&self) -> ToolName {
        ToolName::plain("http_request")
    }

    fn spec(&self) -> ToolSpec {
        let props = BTreeMap::from([
            (
                "url".to_string(),
                JsonSchema::string(Some(
                    "The absolute URL to request (http or https).".to_string(),
                )),
            ),
            (
                "method".to_string(),
                JsonSchema::string(Some(
                    "HTTP method: GET (default), POST, PUT, PATCH, DELETE.".to_string(),
                )),
            ),
            (
                "headers".to_string(),
                JsonSchema::object(
                    BTreeMap::new(),
                    Some(vec![]),
                    // allow arbitrary string->string header pairs
                    Some(true.into()),
                ),
            ),
            (
                "body".to_string(),
                JsonSchema::string(Some(
                    "Optional request body (for POST/PUT/PATCH). For JSON, set a Content-Type header and pass the JSON as a string.".to_string(),
                )),
            ),
        ]);
        ToolSpec::Function(ResponsesApiTool {
            name: "http_request".to_string(),
            description:
                "Make an HTTP request to a URL or REST API and return the status, content-type, and response body (UTF-8, truncated to 100KB). 30s timeout."
                    .to_string(),
            strict: false,
            defer_loading: None,
            parameters: JsonSchema::object(props, Some(vec!["url".to_string()]), Some(false.into())),
            output_schema: None,
        })
    }

    fn handle(&self, invocation: ToolInvocation) -> codex_tools::ToolExecutorFuture<'_> {
        Box::pin(async move {
            let ToolPayload::Function { arguments } = &invocation.payload else {
                return Err(FunctionCallError::RespondToModel(
                    "http_request received unsupported payload".to_string(),
                ));
            };
            let args: HttpArgs = serde_json::from_str(arguments).map_err(|e| {
                FunctionCallError::RespondToModel(format!("failed to parse arguments: {e}"))
            })?;

            let method_str = args.method.as_deref().unwrap_or("GET").to_uppercase();
            let method = reqwest::Method::from_bytes(method_str.as_bytes()).map_err(|_| {
                FunctionCallError::RespondToModel(format!("invalid HTTP method: {method_str}"))
            })?;

            let client = match reqwest::Client::builder().timeout(HTTP_TIMEOUT).build() {
                Ok(c) => c,
                Err(e) => return Ok(err_output(format!("failed to build HTTP client: {e}"))),
            };

            let mut req = client.request(method, &args.url);
            if let Some(headers) = &args.headers {
                for (k, v) in headers {
                    req = req.header(k, v);
                }
            }
            if let Some(body) = args.body {
                req = req.body(body);
            }

            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => return Ok(err_output(format!("request to {} failed: {e}", args.url))),
            };

            let status = resp.status();
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => return Ok(err_output(format!("failed to read response body: {e}"))),
            };
            let truncated = bytes.len() > MAX_BODY_BYTES;
            let slice = &bytes[..bytes.len().min(MAX_BODY_BYTES)];
            let body_text = String::from_utf8_lossy(slice);

            let mut out = format!("HTTP {status}\n");
            if !content_type.is_empty() {
                out.push_str(&format!("content-type: {content_type}\n"));
            }
            out.push('\n');
            out.push_str(&body_text);
            if truncated {
                out.push_str(&format!(
                    "\n\n[truncated: {} of {} bytes shown]",
                    MAX_BODY_BYTES,
                    bytes.len()
                ));
            }

            Ok(ok_output(out))
        })
    }
}

impl CoreToolRuntime for HttpRequestHandler {}
