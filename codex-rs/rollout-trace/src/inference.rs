//! Hot-path helpers for recording upstream inference attempts.
//!
//! The model client should not need to know whether rollout tracing is enabled.
//! A disabled context records nothing, which keeps one-shot HTTP calls,
//! WebSocket reuse, and retry/fallback attempts on the same code path.

use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use codex_protocol::dynamic_tools::DynamicToolArgumentPolicy;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::TokenUsage;
use http::HeaderMap;
use http::HeaderValue;
use serde::Serialize;
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::model::AgentThreadId;
use crate::model::CodexTurnId;
use crate::model::InferenceCallId;
use crate::payload::RawPayloadKind;
use crate::raw_event::RawTraceEventContext;
use crate::raw_event::RawTraceEventPayload;
use crate::writer::TraceWriter;

const INFERENCE_CALL_ID_HEADER: &str = "x-codex-inference-call-id";
const PROVIDER_REFLECTION_FIELDS: [&str; 3] =
    ["previous_response_id", "response_id", "upstream_request_id"];

fn redact_provider_reflection_metadata(value: &mut JsonValue) {
    match value {
        JsonValue::Array(values) => {
            for value in values {
                redact_provider_reflection_metadata(value);
            }
        }
        JsonValue::Object(object) => {
            for field in PROVIDER_REFLECTION_FIELDS {
                if let Some(value) = object.get_mut(field) {
                    *value = JsonValue::Null;
                }
            }
            for value in object.values_mut() {
                redact_provider_reflection_metadata(value);
            }
        }
        _ => {}
    }
}

/// Turn-local inference tracing context.
///
/// This is intentionally a no-op capable handle instead of an `Option` at each
/// transport callsite. Whether tracing is enabled is a session concern; retry,
/// fallback, and stream mapping code should always be able to say what happened
/// without first branching on trace availability.
#[derive(Clone, Debug)]
pub struct InferenceTraceContext {
    state: InferenceTraceContextState,
}

#[derive(Clone, Debug)]
enum InferenceTraceContextState {
    Disabled(InferenceTraceArgumentPolicy),
    Enabled(EnabledInferenceTraceContext),
}

#[derive(Clone, Debug)]
struct EnabledInferenceTraceContext {
    writer: Arc<TraceWriter>,
    thread_id: AgentThreadId,
    codex_turn_id: CodexTurnId,
    model: String,
    provider_name: String,
    argument_policy: InferenceTraceArgumentPolicy,
}

/// Dynamic-tool argument projection applied to inference trace payloads.
pub type InferenceTraceArgumentPolicy = DynamicToolArgumentPolicy;

/// One concrete upstream request attempt.
///
/// A Codex turn can create multiple attempts when auth recovery retries the
/// HTTP request or WebSocket setup falls back to HTTP. Completion is often
/// observed after the client returns the response stream, so the attempt owns
/// the terminal guard that prevents duplicate lifecycle events.
#[derive(Debug)]
pub struct InferenceTraceAttempt {
    state: InferenceTraceAttemptState,
}

#[derive(Debug)]
enum InferenceTraceAttemptState {
    Disabled(InferenceTraceArgumentPolicy),
    Enabled(EnabledInferenceTraceAttempt),
}

#[derive(Debug)]
struct EnabledInferenceTraceAttempt {
    context: EnabledInferenceTraceContext,
    inference_call_id: InferenceCallId,
    terminal_recorded: AtomicBool,
}

/// Non-delta response payload saved for completed or interrupted inference streams.
///
/// We intentionally record completed output items instead of every stream delta
/// here. The raw stream can be added later as a separate payload class; this
/// response summary gives the reducer stable response identity when available
/// plus model-visible output without duplicating high-volume text deltas.
#[derive(Serialize)]
struct TracedResponseStreamOutput<'a> {
    response_id: Option<&'a str>,
    upstream_request_id: Option<&'a str>,
    token_usage: Option<&'a TokenUsage>,
    output_items: Vec<JsonValue>,
}

impl InferenceTraceContext {
    /// Builds a context that accepts trace calls and records nothing.
    pub fn disabled() -> Self {
        Self::disabled_with_argument_policy(InferenceTraceArgumentPolicy::default())
    }

    pub fn disabled_with_argument_policy(argument_policy: InferenceTraceArgumentPolicy) -> Self {
        Self {
            state: InferenceTraceContextState::Disabled(argument_policy),
        }
    }

    /// Builds an enabled context for all upstream attempts made by one Codex turn.
    pub fn enabled(
        writer: Arc<TraceWriter>,
        thread_id: AgentThreadId,
        codex_turn_id: CodexTurnId,
        model: String,
        provider_name: String,
    ) -> Self {
        Self::enabled_with_argument_policy(
            writer,
            thread_id,
            codex_turn_id,
            model,
            provider_name,
            InferenceTraceArgumentPolicy::default(),
        )
    }

    pub fn enabled_with_argument_policy(
        writer: Arc<TraceWriter>,
        thread_id: AgentThreadId,
        codex_turn_id: CodexTurnId,
        model: String,
        provider_name: String,
        argument_policy: InferenceTraceArgumentPolicy,
    ) -> Self {
        Self {
            state: InferenceTraceContextState::Enabled(EnabledInferenceTraceContext {
                writer,
                thread_id,
                codex_turn_id,
                model,
                provider_name,
                argument_policy,
            }),
        }
    }

    /// Starts a new attempt after the concrete provider request has been built.
    pub fn start_attempt(&self) -> InferenceTraceAttempt {
        let context = match &self.state {
            InferenceTraceContextState::Disabled(argument_policy) => {
                return InferenceTraceAttempt::disabled_with_argument_policy(
                    argument_policy.clone(),
                );
            }
            InferenceTraceContextState::Enabled(context) => context,
        };

        InferenceTraceAttempt {
            state: InferenceTraceAttemptState::Enabled(EnabledInferenceTraceAttempt {
                context: context.clone(),
                inference_call_id: next_inference_call_id(),
                terminal_recorded: AtomicBool::new(false),
            }),
        }
    }

    /// Whether protected dynamic-tool argument/input blobs and the known
    /// response-id/error reflection surfaces must be projected before durable
    /// telemetry or cache writes for this turn.
    ///
    /// This is not general provider-output DLP; unrelated response metadata and
    /// ordinary model output retain their normal persistence behavior.
    pub fn protects_arguments(&self) -> bool {
        match &self.state {
            InferenceTraceContextState::Disabled(argument_policy) => !argument_policy.is_empty(),
            InferenceTraceContextState::Enabled(context) => !context.argument_policy.is_empty(),
        }
    }
}

impl InferenceTraceAttempt {
    pub fn protects_arguments(&self) -> bool {
        match &self.state {
            InferenceTraceAttemptState::Disabled(argument_policy) => !argument_policy.is_empty(),
            InferenceTraceAttemptState::Enabled(attempt) => {
                !attempt.context.argument_policy.is_empty()
            }
        }
    }

    /// Projects an output item for any cache or replay surface that outlives
    /// the live stream delivery. The caller may still forward the original item
    /// synchronously to the active trusted host.
    pub fn project_response_item(&self, item: &ResponseItem) -> ResponseItem {
        match &self.state {
            InferenceTraceAttemptState::Disabled(argument_policy) => {
                argument_policy.redact_response_item(item)
            }
            InferenceTraceAttemptState::Enabled(attempt) => {
                attempt.context.argument_policy.redact_response_item(item)
            }
        }
    }

    /// Builds an attempt that records nothing.
    pub fn disabled() -> Self {
        Self::disabled_with_argument_policy(InferenceTraceArgumentPolicy::default())
    }

    pub fn disabled_with_argument_policy(argument_policy: InferenceTraceArgumentPolicy) -> Self {
        Self {
            state: InferenceTraceAttemptState::Disabled(argument_policy),
        }
    }

    fn inference_call_id(&self) -> Option<&str> {
        match &self.state {
            InferenceTraceAttemptState::Disabled(_) => None,
            InferenceTraceAttemptState::Enabled(attempt) => {
                Some(attempt.inference_call_id.as_str())
            }
        }
    }

    /// Adds rollout-trace propagation headers for this attempt when tracing is enabled.
    pub fn add_request_headers(&self, headers: &mut HeaderMap) {
        let Some(inference_call_id) = self.inference_call_id() else {
            return;
        };
        let Ok(inference_call_id) = HeaderValue::from_str(inference_call_id) else {
            // These IDs are generated internally as UUID strings, so rejection
            // should be impossible in practice. Tracing remains best-effort,
            // though, and must never make provider requests fail.
            return;
        };

        headers.insert(INFERENCE_CALL_ID_HEADER, inference_call_id);
    }

    /// Records the request payload replay should treat as the model-visible inference input.
    ///
    /// This is usually the exact provider request. Callers may instead pass a
    /// logical request when the transport omits already-sent input, such as
    /// websocket reuse after an untraced warmup response.
    pub fn record_started(&self, request: &impl Serialize) {
        let InferenceTraceAttemptState::Enabled(attempt) = &self.state else {
            return;
        };
        let request_payload = if attempt.context.argument_policy.is_empty() {
            write_json_payload_best_effort(
                &attempt.context.writer,
                RawPayloadKind::InferenceRequest,
                request,
            )
        } else {
            let Ok(mut projected) = serde_json::to_value(request) else {
                return;
            };
            attempt.context.argument_policy.redact_json(&mut projected);
            redact_provider_reflection_metadata(&mut projected);
            write_json_payload_best_effort(
                &attempt.context.writer,
                RawPayloadKind::InferenceRequest,
                &projected,
            )
        };
        let Some(request_payload) = request_payload else {
            return;
        };

        append_with_context_best_effort(
            &attempt.context,
            RawTraceEventPayload::InferenceStarted {
                inference_call_id: attempt.inference_call_id.clone(),
                thread_id: attempt.context.thread_id.clone(),
                codex_turn_id: attempt.context.codex_turn_id.clone(),
                model: attempt.context.model.clone(),
                provider_name: attempt.context.provider_name.clone(),
                request_payload,
            },
        );
    }

    /// Records successful provider completion and serializes the observed output items.
    ///
    /// Callers pass protocol-native response items so this crate owns the
    /// trace-specific serialization rules. That keeps codex-core focused on
    /// transport behavior while preserving trace evidence that normal request
    /// serialization intentionally omits.
    pub fn record_completed(
        &self,
        response_id: &str,
        upstream_request_id: Option<&str>,
        token_usage: &Option<TokenUsage>,
        output_items: &[ResponseItem],
    ) {
        let Some(attempt) = self.take_terminal_attempt() else {
            return;
        };
        let provider_metadata_allowed = attempt.context.argument_policy.is_empty();
        let durable_response_id = provider_metadata_allowed.then_some(response_id);
        let durable_upstream_request_id = provider_metadata_allowed
            .then_some(upstream_request_id)
            .flatten();
        let Some(response_payload) = write_response_payload_best_effort(
            attempt,
            durable_response_id,
            durable_upstream_request_id,
            token_usage.as_ref(),
            output_items,
        ) else {
            return;
        };

        append_with_context_best_effort(
            &attempt.context,
            RawTraceEventPayload::InferenceCompleted {
                inference_call_id: attempt.inference_call_id.clone(),
                response_id: durable_response_id.map(str::to_string),
                upstream_request_id: durable_upstream_request_id.map(str::to_string),
                response_payload,
            },
        );
    }

    /// Records pre-response and mid-stream failures.
    pub fn record_failed(
        &self,
        error: impl Display,
        upstream_request_id: Option<&str>,
        output_items: &[ResponseItem],
    ) {
        let Some(attempt) = self.take_terminal_attempt() else {
            return;
        };
        let durable_upstream_request_id = attempt
            .context
            .argument_policy
            .is_empty()
            .then_some(upstream_request_id)
            .flatten();
        let partial_response_payload = if output_items.is_empty() {
            None
        } else {
            write_response_payload_best_effort(
                attempt,
                /*response_id*/ None,
                durable_upstream_request_id,
                /*token_usage*/ None,
                output_items,
            )
        };
        append_with_context_best_effort(
            &attempt.context,
            RawTraceEventPayload::InferenceFailed {
                inference_call_id: attempt.inference_call_id.clone(),
                upstream_request_id: durable_upstream_request_id.map(str::to_string),
                error: if attempt.context.argument_policy.is_empty() {
                    error.to_string()
                } else {
                    "inference failed while transient tool arguments were active".to_string()
                },
                partial_response_payload,
            },
        );
    }

    /// Records a provider stream that Codex intentionally stopped consuming.
    ///
    /// This happens when the turn is interrupted or when mailbox delivery
    /// preempts the current sampling request. Complete output items observed
    /// before that point are retained as partial response evidence.
    pub fn record_cancelled(
        &self,
        reason: impl Display,
        upstream_request_id: Option<&str>,
        output_items: &[ResponseItem],
    ) {
        let Some(attempt) = self.take_terminal_attempt() else {
            return;
        };
        let durable_upstream_request_id = attempt
            .context
            .argument_policy
            .is_empty()
            .then_some(upstream_request_id)
            .flatten();
        let partial_response_payload = if output_items.is_empty() {
            None
        } else {
            write_response_payload_best_effort(
                attempt,
                /*response_id*/ None,
                durable_upstream_request_id,
                /*token_usage*/ None,
                output_items,
            )
        };
        append_with_context_best_effort(
            &attempt.context,
            RawTraceEventPayload::InferenceCancelled {
                inference_call_id: attempt.inference_call_id.clone(),
                upstream_request_id: durable_upstream_request_id.map(str::to_string),
                reason: if attempt.context.argument_policy.is_empty() {
                    reason.to_string()
                } else {
                    "inference cancelled while transient tool arguments were active".to_string()
                },
                partial_response_payload,
            },
        );
    }

    fn take_terminal_attempt(&self) -> Option<&EnabledInferenceTraceAttempt> {
        let attempt = match &self.state {
            InferenceTraceAttemptState::Disabled(_) => return None,
            InferenceTraceAttemptState::Enabled(attempt) => attempt,
        };
        if attempt.terminal_recorded.swap(true, Ordering::AcqRel) {
            return None;
        }
        Some(attempt)
    }
}

/// Serializes a response item for trace evidence rather than future request construction.
///
/// The protocol serializer intentionally omits some readable reasoning content
/// when shaping items for later model requests. Rollout traces need the item as
/// Codex received it, so this helper restores that content in the raw payload.
pub(crate) fn trace_response_item_json(item: &ResponseItem) -> JsonValue {
    let mut value = serde_json::to_value(item).unwrap_or_else(|err| {
        serde_json::json!({
            "serialization_error": err.to_string(),
        })
    });

    if let ResponseItem::Reasoning {
        content: Some(content),
        ..
    } = item
        && let JsonValue::Object(object) = &mut value
    {
        object.insert(
            "content".to_string(),
            serde_json::to_value(content).unwrap_or_else(|err| {
                serde_json::json!({
                    "serialization_error": err.to_string(),
                })
            }),
        );
    }

    value
}

fn next_inference_call_id() -> InferenceCallId {
    Uuid::new_v4().to_string()
}

fn write_json_payload_best_effort(
    writer: &TraceWriter,
    kind: RawPayloadKind,
    payload: &impl Serialize,
) -> Option<crate::RawPayloadRef> {
    writer.write_json_payload(kind, payload).ok()
}

fn write_response_payload_best_effort(
    attempt: &EnabledInferenceTraceAttempt,
    response_id: Option<&str>,
    upstream_request_id: Option<&str>,
    token_usage: Option<&TokenUsage>,
    output_items: &[ResponseItem],
) -> Option<crate::RawPayloadRef> {
    let provider_metadata_allowed = attempt.context.argument_policy.is_empty();
    let response_payload = TracedResponseStreamOutput {
        response_id: provider_metadata_allowed.then_some(response_id).flatten(),
        upstream_request_id: provider_metadata_allowed
            .then_some(upstream_request_id)
            .flatten(),
        token_usage,
        output_items: output_items
            .iter()
            .map(|item| {
                let mut item = trace_response_item_json(item);
                attempt.context.argument_policy.redact_json(&mut item);
                item
            })
            .collect(),
    };
    write_json_payload_best_effort(
        &attempt.context.writer,
        RawPayloadKind::InferenceResponse,
        &response_payload,
    )
}

fn append_with_context_best_effort(
    context: &EnabledInferenceTraceContext,
    payload: RawTraceEventPayload,
) {
    let event_context = RawTraceEventContext {
        thread_id: Some(context.thread_id.clone()),
        codex_turn_id: Some(context.codex_turn_id.clone()),
    };
    let _ = context.writer.append_with_context(event_context, payload);
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    use codex_protocol::ResponseItemId;
    use codex_protocol::dynamic_tools::DynamicToolArgumentIdentity;
    use codex_protocol::dynamic_tools::DynamicToolArgumentPolicySpec;
    use codex_protocol::dynamic_tools::DynamicToolSpec;
    use codex_protocol::models::ReasoningItemContent;
    use codex_protocol::models::ReasoningItemReasoningSummary;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::model::ExecutionStatus;
    use crate::replay_bundle;

    const SENTINEL: &str = "RAW_BROWSER_ARGUMENT_SENTINEL";

    fn protected_browser_policy() -> DynamicToolArgumentPolicy {
        DynamicToolArgumentPolicy::from_dynamic_tools(&[DynamicToolSpec::ArgumentPolicy(
            DynamicToolArgumentPolicySpec::trusted_transient(vec![DynamicToolArgumentIdentity {
                namespace: None,
                name: "agentapp_browser_act".to_string(),
                match_any_namespace: true,
                match_case_insensitive: true,
            }])
            .expect("trusted browser policy"),
        )])
    }

    fn read_artifact_tree(root: &Path) -> anyhow::Result<String> {
        let mut artifact = String::new();
        for entry in fs::read_dir(root)? {
            let path = entry?.path();
            if path.is_dir() {
                artifact.push_str(&read_artifact_tree(&path)?);
            } else {
                artifact.push_str(&String::from_utf8_lossy(&fs::read(path)?));
            }
        }
        Ok(artifact)
    }

    #[test]
    fn disabled_attempt_adds_no_request_headers() {
        let mut headers = HeaderMap::new();

        InferenceTraceAttempt::disabled().add_request_headers(&mut headers);

        assert!(headers.is_empty());
    }

    #[test]
    fn enabled_attempt_adds_inference_request_header() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let writer = Arc::new(TraceWriter::create(
            temp.path(),
            "trace-1".to_string(),
            "rollout-1".to_string(),
            "thread-root".to_string(),
        )?);
        let context = InferenceTraceContext::enabled(
            writer,
            "thread-root".to_string(),
            "turn-1".to_string(),
            "gpt-test".to_string(),
            "test-provider".to_string(),
        );
        let attempt = context.start_attempt();
        let mut headers = HeaderMap::new();

        attempt.add_request_headers(&mut headers);

        let header = headers
            .get(INFERENCE_CALL_ID_HEADER)
            .expect("inference header present");
        assert_eq!(Some(header.to_str()?), attempt.inference_call_id());
        assert!(Uuid::parse_str(header.to_str()?).is_ok());
        Ok(())
    }

    #[test]
    fn enabled_context_records_replayable_inference_attempt() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let writer = Arc::new(TraceWriter::create(
            temp.path(),
            "trace-1".to_string(),
            "rollout-1".to_string(),
            "thread-root".to_string(),
        )?);
        writer.append(RawTraceEventPayload::ThreadStarted {
            thread_id: "thread-root".to_string(),
            agent_path: "/root".to_string(),
            metadata_payload: None,
        })?;
        writer.append(RawTraceEventPayload::CodexTurnStarted {
            codex_turn_id: "turn-1".to_string(),
            thread_id: "thread-root".to_string(),
        })?;
        let context = InferenceTraceContext::enabled(
            writer,
            "thread-root".to_string(),
            "turn-1".to_string(),
            "gpt-test".to_string(),
            "test-provider".to_string(),
        );

        let attempt = context.start_attempt();
        attempt.record_started(&json!({
            "model": "gpt-test",
            "input": [{
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "hello"}]
            }],
        }));
        attempt.record_completed("resp-1", Some("req-1"), &None, &[]);

        let rollout = replay_bundle(temp.path())?;
        let inference = rollout
            .inference_calls
            .values()
            .next()
            .expect("recorded inference call");

        assert_eq!(rollout.inference_calls.len(), 1);
        assert_eq!(inference.thread_id, "thread-root");
        assert_eq!(inference.codex_turn_id, "turn-1");
        assert_eq!(inference.execution.status, ExecutionStatus::Completed);
        assert_eq!(inference.upstream_request_id, Some("req-1".to_string()));
        assert_eq!(rollout.raw_payloads.len(), 2);

        Ok(())
    }

    #[test]
    fn protected_inference_artifacts_project_completed_failed_and_cancelled_arguments()
    -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let writer = Arc::new(TraceWriter::create(
            temp.path(),
            "trace-protected".to_string(),
            "rollout-protected".to_string(),
            "thread-root".to_string(),
        )?);
        writer.append(RawTraceEventPayload::ThreadStarted {
            thread_id: "thread-root".to_string(),
            agent_path: "/root".to_string(),
            metadata_payload: None,
        })?;
        writer.append(RawTraceEventPayload::CodexTurnStarted {
            codex_turn_id: "turn-protected".to_string(),
            thread_id: "thread-root".to_string(),
        })?;
        let context = InferenceTraceContext::enabled_with_argument_policy(
            Arc::clone(&writer),
            "thread-root".to_string(),
            "turn-protected".to_string(),
            "gpt-test".to_string(),
            "test-provider".to_string(),
            protected_browser_policy(),
        );
        let request = json!({
            "model": "gpt-test",
            "previous_response_id": SENTINEL,
            "input": [{
                "type": "function_call",
                "name": "agentapp_browser_act",
                "call_id": "browser-call-request",
                "arguments": {
                    "aliases": {
                        "pwd": SENTINEL,
                        "encoded": "UkFXX0JST1dTRVJfQVJHVU1FTlRfU0VOVElORUw=",
                    }
                },
            }],
        });
        let output_item = ResponseItem::FunctionCall {
            id: None,
            name: "agentapp_browser_act".to_string(),
            namespace: None,
            arguments: format!(r#"{{"otp":"004201","nested":{{"value":"{SENTINEL}"}}}}"#),
            call_id: "browser-call-output".to_string(),
            internal_chat_message_metadata_passthrough: None,
        };

        let completed = context.start_attempt();
        completed.record_started(&request);
        completed.record_completed(
            SENTINEL,
            Some(SENTINEL),
            &None,
            std::slice::from_ref(&output_item),
        );

        let failed = context.start_attempt();
        failed.record_started(&request);
        failed.record_failed(
            format!("provider failure {SENTINEL}"),
            Some(SENTINEL),
            std::slice::from_ref(&output_item),
        );

        let cancelled = context.start_attempt();
        cancelled.record_started(&request);
        cancelled.record_cancelled(
            format!("user interrupted {SENTINEL}"),
            Some(SENTINEL),
            std::slice::from_ref(&output_item),
        );

        let artifact = read_artifact_tree(temp.path())?;
        assert!(!artifact.contains(SENTINEL));
        assert!(!artifact.contains("UkFXX0JST1dTRVJfQVJHVU1FTlRfU0VOVElORUw="));
        assert!(artifact.contains("agentapp_browser_act"));
        assert!(artifact.contains("browser-call-output"));
        assert!(artifact.contains("inference failed while transient tool arguments were active"));
        assert!(
            artifact.contains("inference cancelled while transient tool arguments were active")
        );

        let rollout = replay_bundle(temp.path())?;
        assert_eq!(rollout.inference_calls.len(), 3);
        assert!(
            rollout
                .inference_calls
                .values()
                .all(|inference| inference.upstream_request_id.is_none())
        );
        Ok(())
    }

    #[test]
    fn traced_response_item_preserves_reasoning_content_omitted_by_normal_serializer() {
        let item = ResponseItem::Reasoning {
            id: Some(ResponseItemId::with_suffix("rs", "1")),
            summary: vec![ReasoningItemReasoningSummary::SummaryText {
                text: "summary".to_string(),
            }],
            content: Some(vec![ReasoningItemContent::Text {
                text: "raw reasoning".to_string(),
            }]),
            encrypted_content: Some("encoded".to_string()),
            internal_chat_message_metadata_passthrough: None,
        };

        let normal = serde_json::to_value(&item).expect("response item serializes");
        let traced = trace_response_item_json(&item);

        assert_eq!(normal.get("content"), None);
        assert_eq!(
            traced,
            json!({
                "type": "reasoning",
                "id": "rs_1",
                "summary": [{"type": "summary_text", "text": "summary"}],
                "content": [{"type": "text", "text": "raw reasoning"}],
                "encrypted_content": "encoded",
            }),
        );
    }
}
