use std::sync::Arc;

use codex_core::test_support::thread_manager_with_models_provider_and_home;
use codex_exec_server::ExecBackend;
use codex_exec_server::ExecBackendFuture;
use codex_exec_server::ExecBackendReconcileFuture;
use codex_exec_server::ExecParams;
use codex_exec_server::ExecServerError;
use codex_exec_server::IncompleteExecution;
use codex_exec_server::ReconciliationRequest;
use codex_exec_server::RemoteExecutionProtocolEvidence;
use codex_login::CodexAuth;
use codex_model_provider_info::ModelProviderInfo;
use codex_protocol::error::CodexErr;
use pretty_assertions::assert_eq;
use tempfile::tempdir;

#[derive(Clone, Copy)]
enum ReconciliationFailure {
    Backend,
    InvalidDescriptorCount,
}

struct FailingResumeBackend {
    failure: ReconciliationFailure,
}

impl ExecBackend for FailingResumeBackend {
    fn start(&self, _params: ExecParams) -> ExecBackendFuture<'_> {
        Box::pin(async {
            Err(ExecServerError::Protocol(
                "resume reconciliation fixture must not start a process".to_string(),
            ))
        })
    }

    fn reconcile(&self, _request: ReconciliationRequest) -> ExecBackendReconcileFuture<'_> {
        Box::pin(async move {
            match self.failure {
                ReconciliationFailure::Backend => Err(ExecServerError::Protocol(
                    "private backend reconciliation detail".to_string(),
                )),
                ReconciliationFailure::InvalidDescriptorCount => Ok(Vec::new()),
            }
        })
    }
}

#[tokio::test]
async fn resume_reconciliation_failures_are_lifecycle_unresolved() {
    let request = ReconciliationRequest {
        thread_id: "thread".to_string(),
        incomplete_executions: vec![IncompleteExecution {
            turn_id: "turn".to_string(),
            call_id: "call".to_string(),
            attempt_generation: 0,
            expected_command_digest: Some("command-digest".to_string()),
            expected_session_id: Some(42),
            expected_tty: Some(false),
            protocol_evidence: RemoteExecutionProtocolEvidence::V2Proven,
        }],
        pending_writes: Vec::new(),
    };

    for (failure, expected_suffix) in [
        (
            ReconciliationFailure::Backend,
            "failed to reconcile exact remote executions: exec-server protocol error: \
             private backend reconciliation detail",
        ),
        (
            ReconciliationFailure::InvalidDescriptorCount,
            "exact remote execution reconciliation returned an invalid descriptor count \
             (0; expected 1)",
        ),
    ] {
        let codex_home = tempdir().expect("temporary Codex home");
        let environment_manager = Arc::new(
            codex_exec_server::EnvironmentManager::with_exec_backend_for_tests(
                "resume-reconciliation",
                Arc::new(FailingResumeBackend { failure }),
                /*durable_remote_exec_recovery*/ true,
            ),
        );
        let manager = thread_manager_with_models_provider_and_home(
            CodexAuth::from_api_key("dummy"),
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            codex_home.path().to_path_buf(),
            environment_manager,
        );

        let error = manager
            .reconcile_remote_executions_for_resume(request.clone())
            .await
            .expect_err("unproven remote lifecycle must block native resume");
        let CodexErr::Fatal(detail) = error else {
            panic!("expected a fatal lifecycle error, got {error:?}");
        };
        assert_eq!(
            detail,
            format!("remote execution lifecycle unresolved: {expected_suffix}")
        );
    }
}
