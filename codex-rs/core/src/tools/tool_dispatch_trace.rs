//! Adapter between core tool dispatch objects and rollout-trace events.
//!
//! `codex-rollout-trace` owns the event schema and writer behavior. This module
//! keeps the core-specific mapping from registry invocations/results out of the
//! registry control flow.

use crate::function_tool::FunctionCallError;
use crate::tools::argument_privacy;
use crate::tools::context::ToolCallSource;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use codex_protocol::dynamic_tools::DynamicToolArgumentHandling;
use codex_rollout_trace::ExecutionStatus;
use codex_rollout_trace::ToolDispatchInvocation;
use codex_rollout_trace::ToolDispatchPayload;
use codex_rollout_trace::ToolDispatchRequester;
use codex_rollout_trace::ToolDispatchResult;
use codex_rollout_trace::ToolDispatchTraceContext;

/// Keeps registry early-return paths paired with trace end events.
pub(crate) struct ToolDispatchTrace {
    context: ToolDispatchTraceContext,
    argument_handling: DynamicToolArgumentHandling,
}

impl ToolDispatchTrace {
    pub(crate) fn start(
        invocation: &ToolInvocation,
        argument_handling: DynamicToolArgumentHandling,
    ) -> Self {
        let context = invocation
            .session
            .services
            .rollout_thread_trace
            .start_tool_dispatch_trace(|| tool_dispatch_invocation(invocation, argument_handling));
        Self {
            context,
            argument_handling,
        }
    }

    pub(crate) fn record_completed(
        &self,
        invocation: &ToolInvocation,
        call_id: &str,
        payload: &ToolPayload,
        result: &dyn ToolOutput,
    ) {
        if !self.context.is_enabled() {
            return;
        }

        let Some(result_payload) =
            tool_dispatch_result(invocation, call_id, payload, result, self.argument_handling)
        else {
            return;
        };
        let status = if result.success_for_logging() {
            ExecutionStatus::Completed
        } else {
            ExecutionStatus::Failed
        };
        self.context.record_completed(status, result_payload);
    }

    pub(crate) fn record_failed(&self, error: &FunctionCallError) {
        self.context.record_failed(error);
    }
}

fn tool_dispatch_invocation(
    invocation: &ToolInvocation,
    argument_handling: DynamicToolArgumentHandling,
) -> Option<ToolDispatchInvocation> {
    let requester = match &invocation.source {
        ToolCallSource::Direct => ToolDispatchRequester::Model {
            model_visible_call_id: invocation.call_id.clone(),
        },
        ToolCallSource::CodeMode {
            cell_id,
            runtime_tool_call_id,
        } => ToolDispatchRequester::CodeCell {
            runtime_cell_id: cell_id.clone(),
            runtime_tool_call_id: runtime_tool_call_id.clone(),
        },
    };

    Some(ToolDispatchInvocation {
        thread_id: invocation.session.thread_id.to_string(),
        codex_turn_id: invocation.turn.sub_id.clone(),
        tool_call_id: invocation.call_id.clone(),
        tool_name: invocation.tool_name.name.clone(),
        tool_namespace: invocation.tool_name.namespace.clone(),
        requester,
        payload: tool_dispatch_payload(&argument_privacy::projected_payload(
            &invocation.payload,
            argument_handling,
        )),
    })
}

fn tool_dispatch_result(
    invocation: &ToolInvocation,
    call_id: &str,
    payload: &ToolPayload,
    result: &dyn ToolOutput,
    argument_handling: DynamicToolArgumentHandling,
) -> Option<ToolDispatchResult> {
    let projected_payload = argument_privacy::projected_payload(payload, argument_handling);
    match invocation.source {
        ToolCallSource::Direct => Some(ToolDispatchResult::DirectResponse {
            response_item: result.to_response_item(call_id, &projected_payload),
        }),
        ToolCallSource::CodeMode { .. } => Some(ToolDispatchResult::CodeModeResponse {
            value: result.code_mode_result(&projected_payload),
        }),
    }
}

fn tool_dispatch_payload(payload: &ToolPayload) -> ToolDispatchPayload {
    match payload {
        ToolPayload::Function { arguments } => ToolDispatchPayload::Function {
            arguments: arguments.clone(),
        },
        ToolPayload::ToolSearch { arguments } => ToolDispatchPayload::ToolSearch {
            arguments: arguments.clone(),
        },
        ToolPayload::Custom { input } => ToolDispatchPayload::Custom {
            input: input.clone(),
        },
    }
}

#[cfg(test)]
#[path = "tool_dispatch_trace_tests.rs"]
mod tests;
