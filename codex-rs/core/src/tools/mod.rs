mod approvals;
#[cfg(feature = "code-mode")]
pub(crate) mod code_mode;
pub(crate) mod context;
pub(crate) mod events;
pub(crate) mod handlers;
pub(crate) mod hook_names;
pub(crate) mod hosted_spec;
pub(crate) mod lifecycle;
pub(crate) mod network_approval;
pub(crate) mod orchestrator;
pub(crate) mod parallel;
pub(crate) mod registry;
pub(crate) mod router;
pub(crate) mod runtimes;
pub(crate) mod sandboxing;
pub(crate) mod spec_plan;
pub(crate) mod tool_dispatch_trace;

use std::borrow::Cow;

use crate::session::turn_context::TurnContext;
use codex_features::Feature;
use codex_protocol::exec_output::ExecToolCallOutput;
use codex_protocol::openai_models::ToolMode;
use codex_tools::ToolName;
use codex_utils_output_truncation::TruncationPolicy;
use codex_utils_output_truncation::formatted_truncate_text;
use codex_utils_output_truncation::truncate_text;
pub use router::ToolRouter;

// Telemetry preview limits: keep log events smaller than model budgets.
pub(crate) const TELEMETRY_PREVIEW_MAX_BYTES: usize = 2 * 1024; // 2 KiB
pub(crate) const TELEMETRY_PREVIEW_MAX_LINES: usize = 64; // lines
pub(crate) const TELEMETRY_PREVIEW_TRUNCATION_NOTICE: &str =
    "[... telemetry preview truncated ...]";

/// Legacy boundaries such as hook payloads, telemetry tags, and Responses tool
/// names still require a single flattened string. Keep comparisons and sorting
/// on `ToolName` itself; use this only when crossing those boundaries.
pub(crate) fn flat_tool_name(tool_name: &ToolName) -> Cow<'_, str> {
    match tool_name.namespace.as_deref() {
        Some(namespace) => {
            let mut name = String::with_capacity(namespace.len() + tool_name.name.len());
            name.push_str(namespace);
            name.push_str(&tool_name.name);
            Cow::Owned(name)
        }
        None => Cow::Borrowed(tool_name.name.as_str()),
    }
}

pub(crate) fn tool_user_shell_type(
    user_shell: &crate::shell::Shell,
) -> codex_tools::ToolUserShellType {
    match user_shell.shell_type {
        crate::shell::ShellType::Zsh => codex_tools::ToolUserShellType::Zsh,
        crate::shell::ShellType::Bash => codex_tools::ToolUserShellType::Bash,
        crate::shell::ShellType::PowerShell => codex_tools::ToolUserShellType::PowerShell,
        crate::shell::ShellType::Sh => codex_tools::ToolUserShellType::Sh,
        crate::shell::ShellType::Cmd => codex_tools::ToolUserShellType::Cmd,
    }
}

fn effective_tool_mode(turn_context: &TurnContext) -> ToolMode {
    resolve_effective_tool_mode(
        turn_context.model_info.tool_mode,
        turn_context.config.features.enabled(Feature::CodeMode),
        turn_context.config.features.enabled(Feature::CodeModeOnly),
        cfg!(feature = "code-mode"),
    )
}

fn resolve_effective_tool_mode(
    model_tool_mode: Option<ToolMode>,
    code_mode_enabled: bool,
    code_mode_only_enabled: bool,
    code_mode_runtime_available: bool,
) -> ToolMode {
    // Builds without the V8 code-mode runtime (notably iOS) cannot honor a
    // model's code_mode/code_mode_only preference. Falling back to direct tools
    // keeps shell and other client-executed tools usable instead of hiding them
    // without providing the replacement `code` tool.
    if !code_mode_runtime_available {
        return ToolMode::Direct;
    }

    model_tool_mode.unwrap_or_else(|| {
        if code_mode_only_enabled {
            ToolMode::CodeModeOnly
        } else if code_mode_enabled {
            ToolMode::CodeMode
        } else {
            ToolMode::Direct
        }
    })
}

#[cfg(test)]
mod effective_tool_mode_tests {
    use super::resolve_effective_tool_mode;
    use codex_protocol::openai_models::ToolMode;

    #[test]
    fn unavailable_code_mode_runtime_forces_direct_tools() {
        for requested in [Some(ToolMode::CodeMode), Some(ToolMode::CodeModeOnly), None] {
            assert_eq!(
                resolve_effective_tool_mode(
                    requested, /*code_mode_enabled*/ true,
                    /*code_mode_only_enabled*/ true,
                    /*code_mode_runtime_available*/ false,
                ),
                ToolMode::Direct
            );
        }
    }

    #[test]
    fn available_code_mode_runtime_honors_model_selector() {
        assert_eq!(
            resolve_effective_tool_mode(
                Some(ToolMode::CodeModeOnly),
                /*code_mode_enabled*/ false,
                /*code_mode_only_enabled*/ false,
                /*code_mode_runtime_available*/ true,
            ),
            ToolMode::CodeModeOnly
        );
    }
}

/// Format the combined exec output for sending back to the model.
/// Includes exit code and duration metadata; truncates large bodies safely.
pub fn format_exec_output_for_model(
    exec_output: &ExecToolCallOutput,
    truncation_policy: TruncationPolicy,
) -> String {
    // round to 1 decimal place
    let duration_seconds = ((exec_output.duration.as_secs_f32()) * 10.0).round() / 10.0;

    let content = build_content_with_timeout(exec_output);

    let total_lines = content.lines().count();

    let formatted_output = truncate_text(&content, truncation_policy);

    let mut sections = Vec::new();

    sections.push(format!("Exit code: {}", exec_output.exit_code));
    sections.push(format!("Wall time: {duration_seconds} seconds"));
    if total_lines != formatted_output.lines().count() {
        sections.push(format!("Total output lines: {total_lines}"));
    }

    sections.push("Output:".to_string());
    sections.push(formatted_output);

    sections.join("\n")
}

pub fn format_exec_output_str(
    exec_output: &ExecToolCallOutput,
    truncation_policy: TruncationPolicy,
) -> String {
    let content = build_content_with_timeout(exec_output);

    // Truncate for model consumption before serialization.
    formatted_truncate_text(&content, truncation_policy)
}

/// Extracts exec output content and prepends a timeout message if the command timed out.
fn build_content_with_timeout(exec_output: &ExecToolCallOutput) -> String {
    if exec_output.timed_out {
        format!(
            "command timed out after {} milliseconds\n{}",
            exec_output.duration.as_millis(),
            exec_output.aggregated_output.text
        )
    } else {
        exec_output.aggregated_output.text.clone()
    }
}
