pub mod account;
mod agent_path;
pub mod auth;
mod response_item_id;
mod session_id;
mod thread_id;
mod tool_name;
pub use agent_path::AgentPath;
pub use response_item_id::ResponseItemId;
pub use session_id::SessionId;
pub use thread_id::ThreadId;
pub use tool_name::ToolName;
pub mod approvals;
pub mod capabilities;
mod compacted_item;
pub mod config_types;
pub mod dynamic_tools;
pub mod error;
pub mod exec_output;
pub mod items;
mod legacy_events;
pub mod mcp;
pub mod mcp_approval_meta;
pub mod memory_citation;
pub mod models;
pub mod network_policy;
pub mod num_format;
pub mod openai_models;
pub mod parse_command;
pub mod permissions;
pub mod plan_tool;
pub mod protocol;
pub mod request_permissions;
pub mod request_user_input;
pub mod review_format;
pub mod shell_environment;
pub mod user_input;

/// Reviewed Codex API compatibility for this maintained fork, independent of
/// its Cargo package version and truthful source version in the User-Agent.
///
/// The catalog query/cache version and OpenAI provider `version` header must
/// agree: the backend gates both model discovery and turn execution on them.
/// Supported metadata includes Responses Lite, tool-mode selectors, and
/// Max/Ultra reasoning levels. Hosts retain their feature-gated tool handling,
/// including iOS's direct-tool fallback when Code Mode is unavailable.
/// This does not claim the entire upstream 0.153 release is included; advance
/// only after reviewing catalog metadata and validating live turn behavior.
pub const CODEX_API_COMPATIBILITY_VERSION: &str = "0.153.0";
