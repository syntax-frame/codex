use crate::auth::SharedAuthProvider;
use crate::common::ResponseEvent;
use crate::common::ResponseStream;
use crate::common::ResponsesApiRequest;
use crate::endpoint::session::EndpointSession;
use crate::error::ApiError;
use crate::provider::Provider;
use codex_client::EncodedJsonBody;
use codex_client::HttpTransport;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;
use eventsource_stream::Eventsource;
use futures::StreamExt;
use http::HeaderValue;
use http::Method;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::debug;
use tracing::instrument;

pub struct ChatCompletionsClient<T: HttpTransport> {
    session: EndpointSession<T>,
}

impl<T: HttpTransport> ChatCompletionsClient<T> {
    pub fn new(transport: T, provider: Provider, auth: SharedAuthProvider) -> Self {
        Self {
            session: EndpointSession::new(transport, provider, auth),
        }
    }

    #[instrument(
        name = "chat_completions.stream_request",
        level = "info",
        skip_all,
        fields(
            transport = "chat_completions_http",
            http.method = "POST",
            api.path = "chat/completions"
        )
    )]
    pub async fn stream_request(
        &self,
        request: ResponsesApiRequest,
    ) -> Result<ResponseStream, ApiError> {
        let body = chat_request_from_responses_request(request)?;
        let body = EncodedJsonBody::encode(&body).map_err(|e| {
            ApiError::Stream(format!("failed to encode chat completions request: {e}"))
        })?;
        let stream_response = self
            .session
            .stream_encoded_json_with(
                Method::POST,
                "chat/completions",
                http::HeaderMap::new(),
                Some(body),
                |req| {
                    req.headers.insert(
                        http::header::ACCEPT,
                        HeaderValue::from_static("text/event-stream"),
                    );
                },
            )
            .await?;

        let upstream_request_id = stream_response
            .headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let (tx_event, rx_event) = mpsc::channel::<Result<ResponseEvent, ApiError>>(1600);
        let idle_timeout = self.session.provider().stream_idle_timeout;
        tokio::spawn(async move {
            let _ = tx_event.send(Ok(ResponseEvent::Created)).await;
            process_chat_sse(stream_response.bytes, tx_event, idle_timeout).await;
        });

        Ok(ResponseStream {
            rx_event,
            upstream_request_id,
        })
    }
}

#[derive(Debug, Serialize)]
struct ChatCompletionsRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<Value>>,
    tool_choice: String,
    #[serde(skip_serializing_if = "is_false")]
    parallel_tool_calls: bool,
    stream: bool,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<ChatToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Serialize)]
struct ChatToolCall {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    function: ChatToolCallFunction,
}

#[derive(Debug, Serialize)]
struct ChatToolCallFunction {
    name: String,
    arguments: String,
}

fn chat_request_from_responses_request(
    request: ResponsesApiRequest,
) -> Result<ChatCompletionsRequest, ApiError> {
    let mut tools = request
        .tools
        .unwrap_or_default()
        .into_iter()
        .flat_map(chat_tools_from_responses_tool)
        .collect::<Vec<_>>();
    let mut messages = Vec::new();

    // The model can emit several tool calls in ONE assistant turn (parallel tool
    // calls). Chat Completions requires those to be a SINGLE assistant message
    // whose `tool_calls` array holds them all, immediately followed by one `tool`
    // message per call_id — NOT one assistant message per call (that makes the
    // first call's result "missing", since the next message is another call, and
    // the provider rejects the whole request). Buffer consecutive tool calls and
    // flush them as one assistant message the moment a non-tool-call item arrives.
    let mut pending_tool_calls: Vec<ChatToolCall> = Vec::new();

    fn flush_tool_calls(messages: &mut Vec<ChatMessage>, pending: &mut Vec<ChatToolCall>) {
        if !pending.is_empty() {
            messages.push(ChatMessage {
                role: "assistant".to_string(),
                content: None,
                tool_calls: Some(std::mem::take(pending)),
                tool_call_id: None,
            });
        }
    }

    if !request.instructions.trim().is_empty() {
        messages.push(ChatMessage {
            role: "system".to_string(),
            content: Some(request.instructions),
            tool_calls: None,
            tool_call_id: None,
        });
    }

    for item in request.input {
        match item {
            ResponseItem::AdditionalTools { tools: more, .. } => {
                tools.extend(more.into_iter().flat_map(chat_tools_from_responses_tool));
            }
            ResponseItem::Message { role, content, .. } => {
                flush_tool_calls(&mut messages, &mut pending_tool_calls);
                let Some(text) = content_items_to_text(&content) else {
                    continue;
                };
                let role = match role.as_str() {
                    "assistant" => "assistant",
                    "user" => "user",
                    "system" | "developer" => "system",
                    _ => "user",
                };
                messages.push(ChatMessage {
                    role: role.to_string(),
                    content: Some(text),
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
            ResponseItem::FunctionCall {
                name,
                namespace,
                arguments,
                call_id,
                ..
            } => {
                pending_tool_calls.push(ChatToolCall {
                    id: call_id,
                    kind: "function".to_string(),
                    function: ChatToolCallFunction {
                        name: namespaced_tool_name(namespace.as_deref(), &name),
                        arguments,
                    },
                });
            }
            ResponseItem::CustomToolCall {
                name,
                namespace,
                input,
                call_id,
                ..
            } => {
                pending_tool_calls.push(ChatToolCall {
                    id: call_id,
                    kind: "function".to_string(),
                    function: ChatToolCallFunction {
                        name: namespaced_tool_name(namespace.as_deref(), &name),
                        arguments: input,
                    },
                });
            }
            ResponseItem::FunctionCallOutput {
                call_id, output, ..
            }
            | ResponseItem::CustomToolCallOutput {
                call_id, output, ..
            } => {
                // Emit the buffered assistant tool_calls message right before its
                // results, so every tool_call_id is immediately answered.
                flush_tool_calls(&mut messages, &mut pending_tool_calls);
                messages.push(ChatMessage {
                    role: "tool".to_string(),
                    content: Some(output.to_string()),
                    tool_calls: None,
                    tool_call_id: Some(call_id),
                });
            }
            _ => {}
        }
    }
    // Any trailing tool calls with no results yet (e.g. mid-turn) still go out as
    // one well-formed assistant message.
    flush_tool_calls(&mut messages, &mut pending_tool_calls);

    Ok(ChatCompletionsRequest {
        model: request.model,
        messages,
        tools: (!tools.is_empty()).then_some(tools),
        tool_choice: request.tool_choice,
        parallel_tool_calls: request.parallel_tool_calls,
        stream: true,
    })
}

fn content_items_to_text(content: &[ContentItem]) -> Option<String> {
    let mut parts = Vec::new();
    for item in content {
        match item {
            ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                if !text.is_empty() {
                    parts.push(text.as_str());
                }
            }
            ContentItem::InputImage { image_url, .. } => {
                parts.push(image_url.as_str());
            }
            ContentItem::InputAudio { audio_url } => {
                parts.push(audio_url.as_str());
            }
        }
    }
    (!parts.is_empty()).then(|| parts.join("\n"))
}

fn chat_tools_from_responses_tool(tool: Value) -> Vec<Value> {
    match tool.get("type").and_then(Value::as_str) {
        Some("function") => responses_function_to_chat_tool(None, &tool)
            .into_iter()
            .collect(),
        Some("namespace") => {
            let namespace = tool.get("name").and_then(Value::as_str);
            tool.get("tools")
                .and_then(Value::as_array)
                .map(|tools| {
                    tools
                        .iter()
                        .filter_map(|child| responses_function_to_chat_tool(namespace, child))
                        .collect()
                })
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

fn responses_function_to_chat_tool(namespace: Option<&str>, tool: &Value) -> Option<Value> {
    if tool.get("type").and_then(Value::as_str) != Some("function") {
        return None;
    }
    let name = tool.get("name").and_then(Value::as_str)?;
    let name = namespaced_tool_name(namespace, name);
    let description = tool
        .get("description")
        .cloned()
        .unwrap_or_else(|| Value::String(String::new()));
    let parameters = tool
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| json!({"type":"object","properties":{}}));
    Some(json!({
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": parameters
        }
    }))
}

fn namespaced_tool_name(namespace: Option<&str>, name: &str) -> String {
    match namespace {
        Some(namespace) if !namespace.is_empty() => format!("{namespace}__{name}"),
        _ => name.to_string(),
    }
}

async fn process_chat_sse(
    bytes: codex_client::ByteStream,
    tx_event: mpsc::Sender<Result<ResponseEvent, ApiError>>,
    idle_timeout: std::time::Duration,
) {
    let mut stream = bytes.eventsource();
    let mut response_id: Option<String> = None;
    let mut tool_calls: Vec<AccumulatedToolCall> = Vec::new();
    let mut assistant_text = String::new();

    loop {
        let next = timeout(idle_timeout, stream.next()).await;
        let Some(sse_result) = (match next {
            Ok(value) => value,
            Err(_) => {
                let _ = tx_event
                    .send(Err(ApiError::Stream(format!(
                        "stream idle timeout after {} ms",
                        idle_timeout.as_millis()
                    ))))
                    .await;
                break;
            }
        }) else {
            break;
        };

        let event = match sse_result {
            Ok(event) => event,
            Err(err) => {
                let _ = tx_event
                    .send(Err(ApiError::Stream(format!(
                        "chat completions SSE error: {err}"
                    ))))
                    .await;
                break;
            }
        };

        if event.data.trim() == "[DONE]" {
            break;
        }

        let chunk: ChatCompletionChunk = match serde_json::from_str(&event.data) {
            Ok(chunk) => chunk,
            Err(err) => {
                debug!(
                    "failed to parse chat completions SSE chunk: {err}; data={}",
                    event.data
                );
                continue;
            }
        };
        if response_id.is_none() {
            response_id = chunk.id.clone();
        }

        for choice in chunk.choices {
            if let Some(content) = choice.delta.content
                && !content.is_empty()
            {
                assistant_text.push_str(&content);
                let _ = tx_event
                    .send(Ok(ResponseEvent::OutputTextDelta(content)))
                    .await;
            }
            if let Some(delta_tool_calls) = choice.delta.tool_calls {
                for delta in delta_tool_calls {
                    let index = delta.index.unwrap_or(tool_calls.len());
                    while tool_calls.len() <= index {
                        tool_calls.push(AccumulatedToolCall::default());
                    }
                    let acc = &mut tool_calls[index];
                    if let Some(id) = delta.id {
                        acc.id = id;
                    }
                    if let Some(function) = delta.function {
                        if let Some(name) = function.name {
                            acc.name.push_str(&name);
                        }
                        if let Some(arguments) = function.arguments {
                            acc.arguments.push_str(&arguments);
                        }
                    }
                }
            }
        }
    }

    if !assistant_text.is_empty() {
        let item = ResponseItem::Message {
            id: None,
            role: "assistant".to_string(),
            content: vec![ContentItem::OutputText {
                text: assistant_text,
            }],
            phase: None,
            internal_chat_message_metadata_passthrough: None,
        };
        let _ = tx_event.send(Ok(ResponseEvent::OutputItemDone(item))).await;
    }

    for (index, tool_call) in tool_calls.into_iter().enumerate() {
        if tool_call.name.is_empty() {
            continue;
        }
        let call_id = if tool_call.id.is_empty() {
            format!("call_chat_{index}")
        } else {
            tool_call.id
        };
        let (namespace, name) = split_namespaced_tool_name(&tool_call.name);
        let item = ResponseItem::FunctionCall {
            id: None,
            name,
            namespace,
            arguments: tool_call.arguments,
            call_id,
            internal_chat_message_metadata_passthrough: None,
        };
        let _ = tx_event.send(Ok(ResponseEvent::OutputItemDone(item))).await;
    }

    let _ = tx_event
        .send(Ok(ResponseEvent::Completed {
            response_id: response_id.unwrap_or_else(|| "chatcmpl".to_string()),
            token_usage: None,
            end_turn: Some(true),
        }))
        .await;
}

fn split_namespaced_tool_name(name: &str) -> (Option<String>, String) {
    if let Some((namespace, tool_name)) = name.split_once("__") {
        (Some(namespace.to_string()), tool_name.to_string())
    } else {
        (None, name.to_string())
    }
}

#[derive(Debug, Default)]
struct AccumulatedToolCall {
    id: String,
    name: String,
    arguments: String,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionChunk {
    id: Option<String>,
    choices: Vec<ChatCompletionChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionChoice {
    delta: ChatCompletionDelta,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionDelta {
    content: Option<String>,
    tool_calls: Option<Vec<ChatCompletionDeltaToolCall>>,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionDeltaToolCall {
    index: Option<usize>,
    id: Option<String>,
    function: Option<ChatCompletionDeltaFunction>,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionDeltaFunction {
    name: Option<String>,
    arguments: Option<String>,
}
