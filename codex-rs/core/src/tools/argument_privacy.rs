use std::borrow::Cow;

use crate::session::turn_context::TurnContext;
use crate::tools::context::ToolPayload;
use codex_protocol::dynamic_tools::DynamicToolArgumentHandling;
use codex_protocol::dynamic_tools::DynamicToolArgumentPolicy;
use codex_tools::ToolName;

pub(crate) const TRANSIENT_ARGUMENTS_PREVIEW: &str = "[arguments transient]";

pub(crate) fn handling_for(
    turn_context: &TurnContext,
    tool_name: &ToolName,
) -> DynamicToolArgumentHandling {
    policy_for_turn(turn_context).handling_for(tool_name.namespace.as_deref(), &tool_name.name)
}

pub(crate) fn policy_for_turn(turn_context: &TurnContext) -> DynamicToolArgumentPolicy {
    DynamicToolArgumentPolicy::from_dynamic_tools(&turn_context.dynamic_tools)
}

pub(crate) fn protects_arguments(turn_context: &TurnContext) -> bool {
    !policy_for_turn(turn_context).is_empty()
}

pub(crate) fn log_payload<'a>(
    payload: &'a ToolPayload,
    handling: DynamicToolArgumentHandling,
) -> Cow<'a, str> {
    if handling.redacts_arguments() {
        Cow::Borrowed(TRANSIENT_ARGUMENTS_PREVIEW)
    } else {
        payload.log_payload()
    }
}

pub(crate) fn projected_payload(
    payload: &ToolPayload,
    handling: DynamicToolArgumentHandling,
) -> ToolPayload {
    if handling.is_persistent() {
        return payload.clone();
    }
    match payload {
        ToolPayload::Function { .. } => ToolPayload::Function {
            arguments: "{}".to_string(),
        },
        ToolPayload::ToolSearch { arguments } => ToolPayload::ToolSearch {
            arguments: arguments.clone(),
        },
        ToolPayload::Custom { .. } => ToolPayload::Custom {
            input: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "RAW_BROWSER_ARGUMENT_SENTINEL";

    #[test]
    fn transient_log_and_trace_payloads_are_content_free() {
        let payload = ToolPayload::Function {
            arguments: format!(r#"{{"password":"{SENTINEL}"}}"#),
        };

        assert_eq!(
            log_payload(&payload, DynamicToolArgumentHandling::Transient),
            TRANSIENT_ARGUMENTS_PREVIEW
        );
        assert_eq!(
            projected_payload(&payload, DynamicToolArgumentHandling::Transient),
            ToolPayload::Function {
                arguments: "{}".to_string(),
            }
        );
        assert!(!log_payload(&payload, DynamicToolArgumentHandling::Transient).contains(SENTINEL));
    }

    #[test]
    fn persistent_payloads_retain_debugging_provenance() {
        let payload = ToolPayload::Function {
            arguments: r#"{"query":"ordinary"}"#.to_string(),
        };

        assert_eq!(
            log_payload(&payload, DynamicToolArgumentHandling::Persistent),
            payload.log_payload()
        );
        assert_eq!(
            projected_payload(&payload, DynamicToolArgumentHandling::Persistent),
            payload
        );
    }
}
