use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use codex_protocol::dynamic_tools::DynamicToolArgumentHandling;
use codex_protocol::dynamic_tools::DynamicToolArgumentIdentity;
use codex_protocol::dynamic_tools::DynamicToolArgumentPolicySpec;
use codex_protocol::dynamic_tools::DynamicToolSpec;
use codex_protocol::protocol::SessionSource;
use codex_rollout_trace::ExecutionStatus;
use codex_rollout_trace::ThreadStartedTraceMetadata;
use codex_rollout_trace::ToolCallRequester;
use pretty_assertions::assert_eq;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use crate::function_tool::FunctionCallError;
use crate::session::session::Session;
use crate::session::step_context::StepContext;
use crate::session::tests::make_session_and_context;
use crate::session::turn_context::TurnContext;
use crate::tools::code_mode::CodeModeWaitHandler;
use crate::tools::code_mode::WAIT_TOOL_NAME;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::ToolCallSource;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::registry::CoreToolRuntime;
use crate::tools::registry::ToolExecutor;
use crate::tools::registry::ToolRegistry;
use crate::turn_diff_tracker::TurnDiffTracker;

struct TestHandler {
    tool_name: codex_tools::ToolName,
    allows_transient_arguments: bool,
}

impl ToolExecutor<ToolInvocation> for TestHandler {
    fn tool_name(&self) -> codex_tools::ToolName {
        self.tool_name.clone()
    }

    fn spec(&self) -> codex_tools::ToolSpec {
        codex_tools::ToolSpec::Function(codex_tools::ResponsesApiTool {
            name: self.tool_name.name.clone(),
            description: "Test tool.".to_string(),
            strict: false,
            defer_loading: None,
            parameters: codex_tools::JsonSchema::default(),
            output_schema: None,
        })
    }

    fn handle(&self, _invocation: ToolInvocation) -> codex_tools::ToolExecutorFuture<'_> {
        Box::pin(async {
            Ok(
                Box::new(FunctionToolOutput::from_text("ok".to_string(), Some(true)))
                    as Box<dyn crate::tools::context::ToolOutput>,
            )
        })
    }
}

impl CoreToolRuntime for TestHandler {
    fn allows_transient_arguments(&self) -> bool {
        self.allows_transient_arguments
    }
}

#[tokio::test]
async fn dispatch_lifecycle_trace_records_direct_and_code_mode_requesters() -> anyhow::Result<()> {
    let temp = TempDir::new()?;
    let (mut session, turn) = make_session_and_context().await;
    attach_test_trace(&mut session, &turn, temp.path())?;
    session.services.rollout_thread_trace.start_code_cell_trace(
        turn.sub_id.as_str(),
        "cell-1",
        "call-code",
        "await tools.test_tool({})",
    );

    let registry = ToolRegistry::with_handler_for_test(Arc::new(TestHandler {
        tool_name: codex_tools::ToolName::plain("test_tool"),
        allows_transient_arguments: false,
    }));
    let session = Arc::new(session);
    let turn = Arc::new(turn);

    registry
        .dispatch_any_with_terminal_outcome(
            test_invocation(
                Arc::clone(&session),
                Arc::clone(&turn),
                "direct-call",
                "test_tool",
                ToolCallSource::Direct,
                "{}",
            ),
            /*terminal_outcome_reached*/ None,
        )
        .await?;
    registry
        .dispatch_any_with_terminal_outcome(
            test_invocation(
                session,
                turn,
                "code-mode-call",
                "test_tool",
                ToolCallSource::CodeMode {
                    cell_id: "cell-1".to_string(),
                    runtime_tool_call_id: "tool-1".to_string(),
                },
                "{}",
            ),
            /*terminal_outcome_reached*/ None,
        )
        .await?;

    let replayed = codex_rollout_trace::replay_bundle(single_bundle_dir(temp.path())?)?;
    assert_eq!(
        replayed.tool_calls["direct-call"].model_visible_call_id,
        Some("direct-call".to_string()),
    );
    assert_eq!(
        replayed.tool_calls["direct-call"].requester,
        ToolCallRequester::Model,
    );
    assert!(
        replayed.tool_calls["direct-call"]
            .raw_invocation_payload_id
            .is_some(),
        "dispatch tracing should keep the tool invocation payload",
    );
    assert!(
        replayed.tool_calls["direct-call"]
            .raw_result_payload_id
            .is_some(),
        "direct calls should keep the model-facing result payload",
    );
    assert_eq!(
        replayed.tool_calls["code-mode-call"].model_visible_call_id,
        None,
    );
    assert_eq!(
        replayed.tool_calls["code-mode-call"].code_mode_runtime_tool_id,
        Some("tool-1".to_string()),
    );
    assert_eq!(
        replayed.tool_calls["code-mode-call"].requester,
        ToolCallRequester::CodeCell {
            code_cell_id: "code_cell:call-code".to_string(),
        },
    );
    assert!(
        replayed.tool_calls["code-mode-call"]
            .raw_result_payload_id
            .is_some(),
        "code-mode calls should keep the result returned to JavaScript",
    );

    Ok(())
}

#[tokio::test]
async fn dispatch_lifecycle_trace_records_unsupported_tool_failures() -> anyhow::Result<()> {
    let temp = TempDir::new()?;
    let (mut session, turn) = make_session_and_context().await;
    attach_test_trace(&mut session, &turn, temp.path())?;

    let registry = ToolRegistry::empty_for_test();
    let session = Arc::new(session);
    let turn = Arc::new(turn);

    let result = registry
        .dispatch_any_with_terminal_outcome(
            test_invocation(
                session,
                turn,
                "unsupported-call",
                "missing_tool",
                ToolCallSource::Direct,
                "{}",
            ),
            /*terminal_outcome_reached*/ None,
        )
        .await;

    assert!(matches!(result, Err(FunctionCallError::RespondToModel(_))));
    let replayed = codex_rollout_trace::replay_bundle(single_bundle_dir(temp.path())?)?;
    let tool_call = &replayed.tool_calls["unsupported-call"];
    assert_eq!(tool_call.execution.status, ExecutionStatus::Failed);
    assert!(tool_call.raw_result_payload_id.is_some());

    Ok(())
}

#[tokio::test]
async fn dispatch_lifecycle_trace_records_incompatible_payload_failures() -> anyhow::Result<()> {
    let temp = TempDir::new()?;
    let (mut session, turn) = make_session_and_context().await;
    attach_test_trace(&mut session, &turn, temp.path())?;

    let registry = ToolRegistry::with_handler_for_test(Arc::new(TestHandler {
        tool_name: codex_tools::ToolName::plain("test_tool"),
        allows_transient_arguments: false,
    }));
    let session = Arc::new(session);
    let turn = Arc::new(turn);

    let result = registry
        .dispatch_any_with_terminal_outcome(
            test_invocation_with_payload(
                session,
                turn,
                "incompatible-call",
                codex_tools::ToolName::plain("test_tool"),
                ToolCallSource::Direct,
                ToolPayload::Custom {
                    input: "{}".to_string(),
                },
            ),
            /*terminal_outcome_reached*/ None,
        )
        .await;

    assert!(matches!(result, Err(FunctionCallError::Fatal(_))));
    let replayed = codex_rollout_trace::replay_bundle(single_bundle_dir(temp.path())?)?;
    let tool_call = &replayed.tool_calls["incompatible-call"];
    assert_eq!(tool_call.execution.status, ExecutionStatus::Failed);
    assert!(tool_call.raw_result_payload_id.is_some());

    Ok(())
}

#[tokio::test]
async fn transient_dispatch_trace_preserves_provenance_without_argument_bytes() -> anyhow::Result<()>
{
    const SENTINEL: &str = "RAW_BROWSER_ARGUMENT_SENTINEL";
    let temp = TempDir::new()?;
    let (mut session, mut turn) = make_session_and_context().await;
    let tool_name = "agentapp_browser_act";
    turn.dynamic_tools = vec![
        DynamicToolSpec::Function(codex_protocol::dynamic_tools::DynamicToolFunctionSpec {
            name: tool_name.to_string(),
            description: "Test browser tool.".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            defer_loading: false,
            argument_handling: DynamicToolArgumentHandling::Transient,
        }),
        DynamicToolSpec::ArgumentPolicy(
            DynamicToolArgumentPolicySpec::trusted_transient(vec![DynamicToolArgumentIdentity {
                namespace: None,
                name: tool_name.to_string(),
                match_any_namespace: true,
                match_case_insensitive: true,
            }])
            .expect("trusted policy"),
        ),
    ];
    attach_test_trace(&mut session, &turn, temp.path())?;

    let registry = ToolRegistry::with_handler_for_test(Arc::new(TestHandler {
        tool_name: codex_tools::ToolName::plain(tool_name),
        allows_transient_arguments: true,
    }));
    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let call_id = "protected-dispatch-call";

    registry
        .dispatch_any_with_terminal_outcome(
            test_invocation(
                session,
                turn,
                call_id,
                tool_name,
                ToolCallSource::Direct,
                &serde_json::json!({
                    "aliases": {"pwd": SENTINEL},
                    "encoded": "UkFXX0JST1dTRVJfQVJHVU1FTlRfU0VOVElORUw=",
                })
                .to_string(),
            ),
            /*terminal_outcome_reached*/ None,
        )
        .await?;

    let bundle = single_bundle_dir(temp.path())?;
    let replayed = codex_rollout_trace::replay_bundle(&bundle)?;
    let tool_call = &replayed.tool_calls[call_id];
    assert_eq!(tool_call.model_visible_call_id, Some(call_id.to_string()));
    assert_eq!(tool_call.execution.status, ExecutionStatus::Completed);
    assert!(tool_call.raw_invocation_payload_id.is_some());
    assert!(tool_call.raw_result_payload_id.is_some());
    let artifact_bytes = artifact_tree_bytes(&bundle)?;
    assert!(
        !artifact_bytes
            .windows(SENTINEL.len())
            .any(|window| window == SENTINEL.as_bytes()),
        "transient dispatch trace must retain only its content-free projection"
    );

    Ok(())
}

#[tokio::test]
async fn missing_code_mode_wait_traces_only_the_wait_tool_call() -> anyhow::Result<()> {
    let temp = TempDir::new()?;
    let (mut session, turn) = make_session_and_context().await;
    attach_test_trace(&mut session, &turn, temp.path())?;

    let registry = ToolRegistry::with_handler_for_test(Arc::new(CodeModeWaitHandler));
    let session = Arc::new(session);
    let turn = Arc::new(turn);

    registry
        .dispatch_any_with_terminal_outcome(
            test_invocation(
                session,
                turn,
                "wait-call",
                WAIT_TOOL_NAME,
                ToolCallSource::Direct,
                r#"{"cell_id":"noop","terminate":true}"#,
            ),
            /*terminal_outcome_reached*/ None,
        )
        .await?;

    let replayed = codex_rollout_trace::replay_bundle(single_bundle_dir(temp.path())?)?;
    assert_eq!(replayed.code_cells.len(), 0);
    assert!(
        replayed.tool_calls["wait-call"]
            .raw_result_payload_id
            .is_some()
    );

    Ok(())
}

fn test_invocation(
    session: Arc<Session>,
    turn: Arc<TurnContext>,
    call_id: &str,
    tool_name: &str,
    source: ToolCallSource,
    arguments: &str,
) -> ToolInvocation {
    test_invocation_with_payload(
        session,
        turn,
        call_id,
        codex_tools::ToolName::plain(tool_name),
        source,
        ToolPayload::Function {
            arguments: arguments.to_string(),
        },
    )
}

fn test_invocation_with_payload(
    session: Arc<Session>,
    turn: Arc<TurnContext>,
    call_id: &str,
    tool_name: codex_tools::ToolName,
    source: ToolCallSource,
    payload: ToolPayload,
) -> ToolInvocation {
    let step_context = StepContext::for_test(Arc::clone(&turn));
    ToolInvocation {
        session,
        step_context,
        turn,
        cancellation_token: CancellationToken::new(),
        tracker: Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::new())),
        call_id: call_id.to_string(),
        tool_name,
        source,
        payload,
    }
}

fn attach_test_trace(session: &mut Session, turn: &TurnContext, root: &Path) -> anyhow::Result<()> {
    let thread_id = session.thread_id;
    let rollout_thread_trace =
        codex_rollout_trace::ThreadTraceContext::start_root_in_root_for_test(
            root,
            ThreadStartedTraceMetadata {
                thread_id: thread_id.to_string(),
                agent_path: "/root".to_string(),
                task_name: None,
                nickname: None,
                agent_role: None,
                session_source: SessionSource::Exec,
                cwd: PathBuf::from("/workspace"),
                rollout_path: None,
                model: "gpt-test".to_string(),
                provider_name: "test-provider".to_string(),
                approval_policy: "never".to_string(),
                sandbox_policy: "danger-full-access".to_string(),
            },
        )?;
    rollout_thread_trace.record_codex_turn_started(turn.sub_id.as_str());
    session.services.rollout_thread_trace = rollout_thread_trace;
    Ok(())
}

fn single_bundle_dir(root: &Path) -> anyhow::Result<PathBuf> {
    let mut entries = fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    assert_eq!(entries.len(), 1);
    Ok(entries.remove(0))
}

fn artifact_tree_bytes(root: &Path) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                pending.push(path);
            } else {
                bytes.extend(fs::read(path)?);
            }
        }
    }
    Ok(bytes)
}
