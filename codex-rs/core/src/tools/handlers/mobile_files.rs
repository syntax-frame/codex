//! On-device file tools for the mobile build: read/write/list within the turn's
//! working directory (the node's workspace). All operations are jailed to `cwd`
//! and use plain filesystem APIs — no shell, no subprocess, no environment.

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
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

/// Generic text result for a file tool.
struct TextToolOutput {
    text: String,
    ok: bool,
}

impl ToolOutput for TextToolOutput {
    fn log_preview(&self) -> String {
        let head: String = self.text.chars().take(80).collect();
        head
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

/// Parse a Function tool call's JSON arguments.
fn parse_args<T: DeserializeOwned>(payload: &ToolPayload) -> Result<T, FunctionCallError> {
    let ToolPayload::Function { arguments } = payload else {
        return Err(FunctionCallError::RespondToModel(
            "file tool received unsupported payload".to_string(),
        ));
    };
    serde_json::from_str::<T>(arguments)
        .map_err(|e| FunctionCallError::RespondToModel(format!("failed to parse arguments: {e}")))
}

/// Resolve a model-supplied relative path against `cwd`, refusing anything that
/// escapes the workspace (absolute paths or `..` components).
fn resolve_jailed(cwd: &Path, rel: &str) -> Result<PathBuf, FunctionCallError> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return Err(FunctionCallError::RespondToModel(
            "path must be relative to the working directory".to_string(),
        ));
    }
    if rel_path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(FunctionCallError::RespondToModel(
            "path must stay within the working directory (no \"..\")".to_string(),
        ));
    }
    Ok(cwd.join(rel_path))
}

// ---------------------------------------------------------------------------
// read_file
// ---------------------------------------------------------------------------

pub struct ReadFileHandler;

#[derive(Deserialize)]
struct ReadFileArgs {
    path: String,
}

impl ToolExecutor<ToolInvocation> for ReadFileHandler {
    fn tool_name(&self) -> ToolName {
        ToolName::plain("read_file")
    }

    fn spec(&self) -> ToolSpec {
        let props = BTreeMap::from([(
            "path".to_string(),
            JsonSchema::string(Some(
                "Path to the file to read, relative to the working directory.".to_string(),
            )),
        )]);
        ToolSpec::Function(ResponsesApiTool {
            name: "read_file".to_string(),
            description:
                "Read a UTF-8 text file from the working directory and return its contents."
                    .to_string(),
            strict: false,
            defer_loading: None,
            parameters: JsonSchema::object(
                props,
                Some(vec!["path".to_string()]),
                Some(false.into()),
            ),
            output_schema: None,
        })
    }

    fn handle(&self, invocation: ToolInvocation) -> codex_tools::ToolExecutorFuture<'_> {
        Box::pin(async move {
            let cwd = invocation.turn.cwd.clone();
            let args: ReadFileArgs = parse_args(&invocation.payload)?;
            let path = resolve_jailed(cwd.as_path(), &args.path)?;
            match std::fs::read_to_string(&path) {
                Ok(content) => Ok(ok_output(content)),
                Err(e) => Ok(err_output(format!("error reading {}: {e}", args.path))),
            }
        })
    }
}

impl CoreToolRuntime for ReadFileHandler {}

// ---------------------------------------------------------------------------
// write_file
// ---------------------------------------------------------------------------

pub struct WriteFileHandler;

#[derive(Deserialize)]
struct WriteFileArgs {
    path: String,
    content: String,
}

impl ToolExecutor<ToolInvocation> for WriteFileHandler {
    fn tool_name(&self) -> ToolName {
        ToolName::plain("write_file")
    }

    fn spec(&self) -> ToolSpec {
        let props = BTreeMap::from([
            (
                "path".to_string(),
                JsonSchema::string(Some(
                    "Path to the file to write, relative to the working directory. Created (with parent dirs) if absent; overwritten if present."
                        .to_string(),
                )),
            ),
            (
                "content".to_string(),
                JsonSchema::string(Some("The full UTF-8 contents to write.".to_string())),
            ),
        ]);
        ToolSpec::Function(ResponsesApiTool {
            name: "write_file".to_string(),
            description: "Create or overwrite a UTF-8 text file in the working directory."
                .to_string(),
            strict: false,
            defer_loading: None,
            parameters: JsonSchema::object(
                props,
                Some(vec!["path".to_string(), "content".to_string()]),
                Some(false.into()),
            ),
            output_schema: None,
        })
    }

    fn handle(&self, invocation: ToolInvocation) -> codex_tools::ToolExecutorFuture<'_> {
        Box::pin(async move {
            let cwd = invocation.turn.cwd.clone();
            let args: WriteFileArgs = parse_args(&invocation.payload)?;
            let path = resolve_jailed(cwd.as_path(), &args.path)?;
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::write(&path, args.content.as_bytes()) {
                Ok(()) => Ok(ok_output(format!(
                    "wrote {} bytes to {}",
                    args.content.len(),
                    args.path
                ))),
                Err(e) => Ok(err_output(format!("error writing {}: {e}", args.path))),
            }
        })
    }
}

impl CoreToolRuntime for WriteFileHandler {}

// ---------------------------------------------------------------------------
// list_dir
// ---------------------------------------------------------------------------

pub struct ListDirHandler;

#[derive(Deserialize)]
struct ListDirArgs {
    #[serde(default)]
    path: String,
}

impl ToolExecutor<ToolInvocation> for ListDirHandler {
    fn tool_name(&self) -> ToolName {
        ToolName::plain("list_dir")
    }

    fn spec(&self) -> ToolSpec {
        let props = BTreeMap::from([(
            "path".to_string(),
            JsonSchema::string(Some(
                "Directory to list, relative to the working directory. Empty = the working directory itself."
                    .to_string(),
            )),
        )]);
        ToolSpec::Function(ResponsesApiTool {
            name: "list_dir".to_string(),
            description: "List the entries of a directory in the working directory.".to_string(),
            strict: false,
            defer_loading: None,
            parameters: JsonSchema::object(props, Some(vec![]), Some(false.into())),
            output_schema: None,
        })
    }

    fn handle(&self, invocation: ToolInvocation) -> codex_tools::ToolExecutorFuture<'_> {
        Box::pin(async move {
            let cwd = invocation.turn.cwd.clone();
            let args: ListDirArgs = parse_args(&invocation.payload)?;
            let dir = if args.path.is_empty() {
                cwd.as_path().to_path_buf()
            } else {
                resolve_jailed(cwd.as_path(), &args.path)?
            };
            match std::fs::read_dir(&dir) {
                Ok(entries) => {
                    let mut lines: Vec<String> = Vec::new();
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        let suffix = match entry.file_type() {
                            Ok(ft) if ft.is_dir() => "/",
                            _ => "",
                        };
                        lines.push(format!("{name}{suffix}"));
                    }
                    lines.sort();
                    let body = if lines.is_empty() {
                        "(empty)".to_string()
                    } else {
                        lines.join("\n")
                    };
                    Ok(ok_output(body))
                }
                Err(e) => Ok(err_output(format!("error listing {}: {e}", args.path))),
            }
        })
    }
}

impl CoreToolRuntime for ListDirHandler {}
