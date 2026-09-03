use codex_context_engine::AttachmentKind;
use codex_context_engine::ContentPart;
use codex_context_engine::Message;
use codex_context_engine::MessagePhase;
use codex_context_engine::MessageRole;
use codex_context_engine::MessageRoute;
use codex_context_engine::MessageVisibility;
use codex_context_engine::ModelContextItem;
use codex_context_engine::ModelContextPayload;
use codex_context_engine::OpaquePayload;
use codex_context_engine::ProviderLineage;
use codex_context_engine::ProviderOpaqueItem;
use codex_context_engine::ToolPhase;
use codex_context_engine::ToolRecord;
use codex_protocol::AgentPath;
use codex_protocol::ResponseItemId;
use codex_protocol::models::AgentMessageInputContent;
use codex_protocol::models::ContentItem;
use codex_protocol::models::FunctionCallOutputBody;
use codex_protocol::models::FunctionCallOutputPayload;
use codex_protocol::models::LocalShellAction;
use codex_protocol::models::LocalShellExecAction;
use codex_protocol::models::LocalShellStatus;
use codex_protocol::models::MessagePhase as CodexMessagePhase;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::InterAgentCommunication;
use pretty_assertions::assert_eq;
use serde_json::json;

use crate::AttachmentMaterializer;
use crate::CodexAdapterError;
use crate::CodexContextAdapter;
use crate::MaterializedAttachment;
use crate::PreparedCodexInputItem;

struct TestMaterializer;

impl AttachmentMaterializer for TestMaterializer {
    fn materialize(
        &self,
        attachment_id: &str,
        media_type: &str,
        kind: &AttachmentKind,
    ) -> Option<MaterializedAttachment> {
        match (attachment_id, media_type, kind) {
            ("photo-1", "image/png", AttachmentKind::Image) => Some(MaterializedAttachment {
                source: "data:image/png;base64,cGl4ZWxz".to_string(),
            }),
            _ => None,
        }
    }
}

#[test]
fn prepares_semantic_messages_and_materializes_images_per_request() {
    let materializer = TestMaterializer;
    let adapter = adapter().with_attachment_materializer(&materializer);
    let input = model_item(ModelContextPayload::Message(Message {
        role: MessageRole::User,
        visibility: MessageVisibility::TranscriptAndModel,
        content: vec![
            ContentPart::Text {
                text: "describe this".to_string(),
            },
            ContentPart::Attachment {
                attachment_id: "photo-1".to_string(),
                media_type: "image/png".to_string(),
                kind: AttachmentKind::Image,
            },
        ],
        phase: Some(MessagePhase::Commentary),
        route: None,
    }));

    assert_eq!(
        adapter.prepare_response_items(&[input]),
        Ok(vec![ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![
                ContentItem::InputText {
                    text: "describe this".to_string(),
                },
                ContentItem::InputImage {
                    image_url: "data:image/png;base64,cGl4ZWxz".to_string(),
                    detail: None,
                },
            ],
            phase: Some(CodexMessagePhase::Commentary),
            internal_chat_message_metadata_passthrough: None,
        }])
    );
}

#[test]
fn prepares_plain_routed_messages_as_codex_agent_messages() {
    let input = model_item(ModelContextPayload::Message(Message {
        role: MessageRole::Assistant,
        visibility: MessageVisibility::ModelOnly,
        content: vec![ContentPart::Text {
            text: "review complete".to_string(),
        }],
        phase: Some(MessagePhase::Commentary),
        route: Some(MessageRoute {
            author: "/root/reviewer".to_string(),
            recipients: vec!["/root".to_string(), "/root/observer".to_string()],
            delivery: None,
        }),
    }));

    assert_eq!(
        adapter().prepare_response_items(&[input]),
        Ok(vec![ResponseItem::AgentMessage {
            id: None,
            author: "/root/reviewer".to_string(),
            recipient: "/root".to_string(),
            content: vec![AgentMessageInputContent::InputText {
                text: "review complete".to_string(),
            }],
            internal_chat_message_metadata_passthrough: None,
        }])
    );
}

#[test]
fn round_trips_function_calls_and_failed_outputs() {
    let call = model_item(ModelContextPayload::Tool(ToolRecord {
        call_id: "call-1".to_string(),
        name: "exec_command".to_string(),
        phase: ToolPhase::Requested,
        data: json!({
            "kind": "function",
            "namespace": "functions",
            "arguments": "{\"cmd\":\"pwd\"}",
        }),
    }));
    let output = model_item(ModelContextPayload::Tool(ToolRecord {
        call_id: "call-1".to_string(),
        name: "function_call".to_string(),
        phase: ToolPhase::Failed,
        data: json!({
            "kind": "function",
            "output": "permission denied",
            "success": false,
        }),
    }));

    assert_eq!(
        adapter().prepare_response_items(&[call, output]),
        Ok(vec![
            ResponseItem::FunctionCall {
                id: None,
                name: "exec_command".to_string(),
                namespace: Some("functions".to_string()),
                arguments: "{\"cmd\":\"pwd\"}".to_string(),
                call_id: "call-1".to_string(),
                internal_chat_message_metadata_passthrough: None,
            },
            ResponseItem::FunctionCallOutput {
                id: None,
                call_id: "call-1".to_string(),
                output: FunctionCallOutputPayload {
                    body: FunctionCallOutputBody::Text("permission denied".to_string()),
                    success: Some(false),
                },
                internal_chat_message_metadata_passthrough: None,
            },
        ])
    );
}

#[test]
fn prepares_local_shell_records_with_their_terminal_phase() {
    let action = LocalShellAction::Exec(LocalShellExecAction {
        command: vec!["pwd".to_string()],
        timeout_ms: Some(1_000),
        working_directory: Some("/workspace".to_string()),
        env: None,
        user: None,
    });
    let input = model_item(ModelContextPayload::Tool(ToolRecord {
        call_id: "shell-1".to_string(),
        name: "local_shell".to_string(),
        phase: ToolPhase::Completed,
        data: json!({ "kind": "local_shell", "action": action }),
    }));

    assert_eq!(
        adapter().prepare_response_items(&[input]),
        Ok(vec![ResponseItem::LocalShellCall {
            id: None,
            call_id: Some("shell-1".to_string()),
            status: LocalShellStatus::Completed,
            action,
            internal_chat_message_metadata_passthrough: None,
        }])
    );
}

#[test]
fn restores_known_opaque_items_and_retains_the_original_json() {
    let raw = br#"{
  "type": "reasoning",
  "id": "rs_1",
  "summary": [],
  "encrypted_content": "ciphertext"
}"#;
    let input = opaque_model_item("rs_1", "codex.reasoning", raw, lineage());

    let prepared = adapter()
        .prepare_model_input(&[input])
        .expect("prepare opaque reasoning");
    assert_eq!(prepared[0].original_json(), Some(raw.as_slice()));
    let Some(ResponseItem::Reasoning {
        id,
        encrypted_content,
        ..
    }) = prepared[0].response_item()
    else {
        panic!("expected typed reasoning");
    };
    assert_eq!(id.as_ref().map(ResponseItemId::as_str), Some("rs_1"));
    assert_eq!(encrypted_content.as_deref(), Some("ciphertext"));
    assert!(!format!("{:?}", prepared[0]).contains("ciphertext"));
}

#[test]
fn restores_encrypted_inter_agent_communication_for_codex() {
    let communication = InterAgentCommunication::new_encrypted(
        AgentPath::try_from("/root/reviewer").expect("author"),
        AgentPath::root(),
        Vec::new(),
        "encrypted-child-message".to_string(),
        false,
    );
    let raw = serde_json::to_vec(&communication).expect("serialize communication");
    let input = opaque_model_item(
        "agent-message",
        "codex.inter_agent_communication",
        &raw,
        lineage(),
    );

    let prepared = adapter()
        .prepare_response_items(&[input])
        .expect("prepare communication");
    let ResponseItem::AgentMessage { content, .. } = &prepared[0] else {
        panic!("expected agent message");
    };
    assert!(matches!(
        content.last(),
        Some(AgentMessageInputContent::EncryptedContent { encrypted_content })
            if encrypted_content == "encrypted-child-message"
    ));
}

#[test]
fn rejects_incompatible_opaque_lineage() {
    let raw = br#"{"type":"compaction","id":"cmp_1","encrypted_content":"cipher"}"#;
    let other_lineage = ProviderLineage {
        provider: "openai".to_string(),
        protocol: "responses".to_string(),
        lineage_id: "other-account".to_string(),
    };
    let input = opaque_model_item("cmp_1", "codex.compaction", raw, other_lineage.clone());

    assert_eq!(
        adapter().prepare_model_input(&[input]),
        Err(CodexAdapterError::IncompatibleLineage {
            item_id: "cmp_1".to_string(),
            expected: lineage(),
            actual: other_lineage,
        })
    );
}

#[test]
fn unknown_provider_items_require_the_raw_transport() {
    let raw = br#"{"type":"future_continuation","token":"keep-me"}"#;
    let input = opaque_model_item("future-1", "codex.unknown_response_item", raw, lineage());

    let prepared = adapter()
        .prepare_model_input(std::slice::from_ref(&input))
        .expect("prepare raw item");
    assert!(matches!(
        &prepared[0],
        PreparedCodexInputItem::RawOpaque { item_id, .. } if item_id == "future-1"
    ));
    assert_eq!(prepared[0].original_json(), Some(raw.as_slice()));
    assert_eq!(
        adapter().prepare_response_items(&[input]),
        Err(CodexAdapterError::RawTransportRequired {
            item_id: "future-1".to_string(),
        })
    );
}

#[test]
fn missing_attachment_materializer_fails_without_exposing_stored_bytes() {
    let input = model_item(ModelContextPayload::Message(Message {
        role: MessageRole::User,
        visibility: MessageVisibility::TranscriptAndModel,
        content: vec![ContentPart::Attachment {
            attachment_id: "photo-1".to_string(),
            media_type: "image/png".to_string(),
            kind: AttachmentKind::Image,
        }],
        phase: None,
        route: None,
    }));

    assert_eq!(
        adapter().prepare_response_items(&[input]),
        Err(CodexAdapterError::MissingAttachmentMaterializer {
            kind: AttachmentKind::Image,
        })
    );
}

#[test]
fn shadow_audit_reports_equivalence_without_returning_prompt_content() {
    let source = vec![
        ResponseItem::Message {
            id: Some(ResponseItemId::from_server("msg_1".to_string())),
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "private prompt text".to_string(),
            }],
            phase: None,
            internal_chat_message_metadata_passthrough: None,
        },
        ResponseItem::FunctionCall {
            id: Some(ResponseItemId::from_server("fc_1".to_string())),
            name: "exec_command".to_string(),
            namespace: None,
            arguments: "{\"cmd\":\"pwd\"}".to_string(),
            call_id: "call-1".to_string(),
            internal_chat_message_metadata_passthrough: None,
        },
    ];

    let report = adapter().audit_response_items("conversation-1", &source);
    assert!(report.is_equivalent());
    assert_eq!(report.source_items, 2);
    assert_eq!(report.compared_items, 2);
    assert_eq!(report.ignored_items, 0);
    assert!(!format!("{report:?}").contains("private prompt text"));
}

#[test]
fn shadow_audit_classifies_lossy_reasoning_without_exposing_it() {
    let source = vec![ResponseItem::Reasoning {
        id: None,
        summary: Vec::new(),
        content: Some(vec![codex_protocol::models::ReasoningItemContent::Text {
            text: "private thought".to_string(),
        }]),
        encrypted_content: Some("ciphertext".to_string()),
        internal_chat_message_metadata_passthrough: None,
    }];

    let report = adapter().audit_response_items("conversation-1", &source);
    assert!(!report.is_equivalent());
    assert_eq!(report.failures.len(), 1);
    assert_eq!(
        report.failures[0].stage,
        crate::CodexInputParityStage::Import
    );
    let debug = format!("{report:?}");
    assert!(!debug.contains("private thought"));
    assert!(!debug.contains("ciphertext"));
}

fn adapter() -> CodexContextAdapter<'static> {
    CodexContextAdapter::new(lineage())
}

fn lineage() -> ProviderLineage {
    ProviderLineage {
        provider: "openai".to_string(),
        protocol: "responses".to_string(),
        lineage_id: "oauth-account:model-family".to_string(),
    }
}

fn model_item(payload: ModelContextPayload) -> ModelContextItem {
    ModelContextItem {
        id: "model-item".to_string(),
        source_sequence: Some(1),
        payload,
    }
}

fn opaque_model_item(
    item_id: &str,
    kind: &str,
    raw: &[u8],
    lineage: ProviderLineage,
) -> ModelContextItem {
    model_item(ModelContextPayload::ProviderOpaque(ProviderOpaqueItem {
        lineage,
        provider_item_id: item_id.to_string(),
        kind: kind.to_string(),
        payload: OpaquePayload::new(raw.to_vec()),
    }))
}
