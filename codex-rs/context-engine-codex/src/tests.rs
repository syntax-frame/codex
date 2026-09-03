use codex_context_engine::AttachmentKind;
use codex_context_engine::CompactionMode;
use codex_context_engine::ContentPart;
use codex_context_engine::ContextEvent;
use codex_context_engine::ContextEventPayload;
use codex_context_engine::ImageDetail as ContextImageDetail;
use codex_context_engine::MessageDelivery;
use codex_context_engine::MessagePhase;
use codex_context_engine::MessageVisibility;
use codex_context_engine::ModelContextPayload;
use codex_context_engine::ProviderLineage;
use codex_context_engine::ToolPhase;
use codex_protocol::AgentPath;
use codex_protocol::ResponseItemId;
use codex_protocol::models::ContentItem;
use codex_protocol::models::FunctionCallOutputBody;
use codex_protocol::models::FunctionCallOutputPayload;
use codex_protocol::models::ImageDetail;
use codex_protocol::models::MessagePhase as CodexMessagePhase;
use codex_protocol::models::ReasoningItemContent;
use codex_protocol::models::ReasoningItemReasoningSummary;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::CompactedItem;
use codex_protocol::protocol::InterAgentCommunication;
use codex_protocol::protocol::RolloutItem;
use pretty_assertions::assert_eq;

use super::*;

struct TestAttachments;

impl AttachmentResolver for TestAttachments {
    fn resolve(&self, source: &str, kind: &AttachmentKind) -> Option<ResolvedAttachment> {
        match (source, kind) {
            ("upload://photo", AttachmentKind::Image) => Some(ResolvedAttachment {
                attachment_id: "attachment-photo".to_string(),
                media_type: "image/png".to_string(),
            }),
            _ => None,
        }
    }
}

#[test]
fn maps_messages_and_replaces_provider_media_urls_with_attachment_ids() {
    let attachments = TestAttachments;
    let adapter = adapter().with_attachment_resolver(&attachments);
    let item = ResponseItem::Message {
        id: Some(ResponseItemId::from_server("msg_1".to_string())),
        role: "user".to_string(),
        content: vec![
            ContentItem::InputText {
                text: "inspect this".to_string(),
            },
            ContentItem::InputImage {
                image_url: "upload://photo".to_string(),
                detail: Some(ImageDetail::High),
            },
        ],
        phase: Some(CodexMessagePhase::Commentary),
        internal_chat_message_metadata_passthrough: None,
    };

    let event = expect_event(
        adapter
            .adapt_response_item(metadata("event-1", 1), &item, None)
            .expect("adapt message"),
    );
    let ContextEventPayload::Message(message) = event.payload else {
        panic!("expected message");
    };
    assert_eq!(message.visibility, MessageVisibility::TranscriptAndModel);
    assert_eq!(message.phase, Some(MessagePhase::Commentary));
    assert_eq!(
        message.content,
        vec![
            ContentPart::Text {
                text: "inspect this".to_string(),
            },
            ContentPart::Attachment {
                attachment_id: "attachment-photo".to_string(),
                media_type: "image/png".to_string(),
                kind: AttachmentKind::Image,
                image_detail: Some(ContextImageDetail::High),
            },
        ]
    );
}

#[test]
fn refuses_to_persist_unresolved_provider_media_urls() {
    let item = ResponseItem::Message {
        id: None,
        role: "user".to_string(),
        content: vec![ContentItem::InputImage {
            image_url: "data:image/png;base64,secret".to_string(),
            detail: None,
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    };

    assert_eq!(
        adapter().adapt_response_item(metadata("event-1", 1), &item, None),
        Err(CodexAdapterError::UnresolvedAttachment {
            kind: AttachmentKind::Image,
        })
    );
}

#[test]
fn preserves_original_reasoning_json_as_exact_opaque_bytes() {
    let raw = br#"{
  "type": "reasoning",
  "id": "rs_1",
  "summary": [{"type":"summary_text","text":"private summary"}],
  "encrypted_content": "ciphertext-value"
}"#;
    let item: ResponseItem = serde_json::from_slice(raw).expect("reasoning JSON");

    let event = expect_event(
        adapter()
            .adapt_response_item(metadata("event-2", 2), &item, Some(raw))
            .expect("adapt reasoning"),
    );
    let ContextEventPayload::ProviderOpaque(opaque) = event.payload else {
        panic!("expected opaque reasoning");
    };
    assert_eq!(opaque.provider_item_id, "rs_1");
    assert_eq!(opaque.kind, "codex.reasoning");
    assert_eq!(opaque.lineage, lineage());
    assert_eq!(opaque.payload.as_bytes(), raw);
    assert!(!format!("{opaque:?}").contains("ciphertext-value"));
}

#[test]
fn preserves_hosted_web_search_as_exact_lineage_bound_state() {
    let raw = br#"{
  "type": "web_search_call",
  "id": "ws_1",
  "status": "completed",
  "action": {"type":"search","query":"current weather"}
}"#;
    let item: ResponseItem = serde_json::from_slice(raw).expect("web search JSON");

    let event = expect_event(
        adapter()
            .adapt_response_item(metadata("web-search", 3), &item, Some(raw))
            .expect("adapt hosted web search"),
    );
    let ContextEventPayload::ProviderOpaque(opaque) = event.payload else {
        panic!("expected opaque hosted search");
    };
    assert_eq!(opaque.kind, "codex.web_search_call");
    assert_eq!(opaque.lineage, lineage());
    assert_eq!(opaque.payload.as_bytes(), raw);
}

#[test]
fn omits_local_only_reasoning_from_the_neutral_provider_payload() {
    let item = ResponseItem::Reasoning {
        id: None,
        summary: vec![ReasoningItemReasoningSummary::SummaryText {
            text: "summary".to_string(),
        }],
        content: Some(vec![ReasoningItemContent::Text {
            text: "provider-only thought".to_string(),
        }]),
        encrypted_content: Some("ciphertext".to_string()),
        internal_chat_message_metadata_passthrough: None,
    };

    let event = expect_event(
        adapter()
            .adapt_response_item(metadata("event-2", 2), &item, None)
            .expect("adapt reasoning without persisting local text"),
    );
    let ContextEventPayload::ProviderOpaque(opaque) = event.payload else {
        panic!("expected opaque reasoning");
    };
    let decoded: ResponseItem =
        serde_json::from_slice(opaque.payload.as_bytes()).expect("decode provider payload");
    let ResponseItem::Reasoning {
        content,
        encrypted_content,
        ..
    } = decoded
    else {
        panic!("expected reasoning payload");
    };
    assert_eq!(content, None);
    assert_eq!(encrypted_content.as_deref(), Some("ciphertext"));
    assert!(!String::from_utf8_lossy(opaque.payload.as_bytes()).contains("provider-only thought"));
}

#[test]
fn keeps_noncanonical_message_text_shape_provider_opaque() {
    let item = ResponseItem::Message {
        id: None,
        role: "assistant".to_string(),
        content: vec![ContentItem::InputText {
            text: "assistant input text".to_string(),
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    };

    let event = expect_event(
        adapter()
            .adapt_response_item(metadata("message", 3), &item, None)
            .expect("adapt noncanonical message"),
    );
    let ContextEventPayload::ProviderOpaque(opaque) = event.payload else {
        panic!("expected provider-opaque message");
    };
    assert_eq!(opaque.kind, "codex.message");
    assert_eq!(
        serde_json::from_slice::<ResponseItem>(opaque.payload.as_bytes())
            .expect("decode opaque message"),
        item
    );
}

#[test]
fn normalizes_local_tool_calls_and_keeps_failure_status() {
    let call = ResponseItem::FunctionCall {
        id: None,
        name: "exec_command".to_string(),
        namespace: Some("functions".to_string()),
        arguments: "{\"cmd\":\"pwd\"}".to_string(),
        call_id: "call-1".to_string(),
        internal_chat_message_metadata_passthrough: None,
    };
    let output = ResponseItem::FunctionCallOutput {
        id: None,
        call_id: "call-1".to_string(),
        output: FunctionCallOutputPayload {
            body: FunctionCallOutputBody::Text("permission denied".to_string()),
            success: Some(false),
        },
        internal_chat_message_metadata_passthrough: None,
    };

    let call = expect_tool(
        adapter()
            .adapt_response_item(metadata("event-3", 3), &call, None)
            .expect("adapt call"),
    );
    assert_eq!(call.name, "exec_command");
    assert_eq!(call.phase, ToolPhase::Requested);
    assert_eq!(call.data["arguments"], "{\"cmd\":\"pwd\"}");

    let output = expect_tool(
        adapter()
            .adapt_response_item(metadata("event-4", 4), &output, None)
            .expect("adapt output"),
    );
    assert_eq!(output.call_id, "call-1");
    assert_eq!(output.phase, ToolPhase::Failed);
    assert_eq!(output.data["output"], "permission denied");
}

#[test]
fn retains_plain_inter_agent_routing_and_delivery_semantics() {
    let communication = InterAgentCommunication::new(
        AgentPath::try_from("/root/researcher").expect("author"),
        AgentPath::root(),
        vec![AgentPath::try_from("/root/reviewer").expect("other recipient")],
        "evidence is ready".to_string(),
        true,
    );

    let event = expect_event(
        adapter()
            .adapt_rollout_item(
                metadata("event-5", 5),
                &RolloutItem::InterAgentCommunication(communication),
            )
            .expect("adapt communication"),
    );
    let ContextEventPayload::Message(message) = event.payload else {
        panic!("expected message");
    };
    assert_eq!(message.visibility, MessageVisibility::ModelOnly);
    let route = message.route.expect("message route");
    assert_eq!(route.author, "/root/researcher");
    assert_eq!(route.recipients, ["/root", "/root/reviewer"]);
    assert_eq!(route.delivery, Some(MessageDelivery::TriggerTurn));
}

#[test]
fn keeps_encrypted_inter_agent_communication_opaque() {
    let communication = InterAgentCommunication::new_encrypted(
        AgentPath::try_from("/root/researcher").expect("author"),
        AgentPath::root(),
        Vec::new(),
        "encrypted-child-message".to_string(),
        false,
    );

    let event = expect_event(
        adapter()
            .adapt_rollout_item(
                metadata("encrypted-message", 6),
                &RolloutItem::InterAgentCommunication(communication.clone()),
            )
            .expect("adapt encrypted communication"),
    );
    let ContextEventPayload::ProviderOpaque(opaque) = event.payload else {
        panic!("expected opaque communication");
    };
    assert_eq!(opaque.kind, "codex.inter_agent_communication");
    let decoded: InterAgentCommunication =
        serde_json::from_slice(opaque.payload.as_bytes()).expect("decode opaque communication");
    assert_eq!(decoded, communication);
}

#[test]
fn marks_compaction_native_when_replacement_contains_opaque_state() {
    let replacement_history = vec![
        ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "continue".to_string(),
            }],
            phase: None,
            internal_chat_message_metadata_passthrough: None,
        },
        ResponseItem::Reasoning {
            id: Some(ResponseItemId::from_server("rs_2".to_string())),
            summary: Vec::new(),
            content: None,
            encrypted_content: Some("encrypted-checkpoint".to_string()),
            internal_chat_message_metadata_passthrough: None,
        },
    ];
    let compacted = CompactedItem {
        message: "summary".to_string(),
        replacement_history: Some(replacement_history),
        window_number: Some(2),
        first_window_id: Some("window-1".to_string()),
        previous_window_id: Some("window-1".to_string()),
        window_id: Some("window-2".to_string()),
    };

    let event = expect_event(
        adapter()
            .adapt_rollout_item(
                metadata("compaction-event", 8),
                &RolloutItem::Compacted(compacted),
            )
            .expect("adapt compaction"),
    );
    let ContextEventPayload::Compaction(checkpoint) = event.payload else {
        panic!("expected checkpoint");
    };
    assert_eq!(checkpoint.id, "window-2");
    assert_eq!(checkpoint.through_sequence, 7);
    assert_eq!(checkpoint.mode, CompactionMode::ProviderNative);
    assert_eq!(checkpoint.lineage, Some(lineage()));
    assert_eq!(checkpoint.replacement.len(), 2);
    assert!(matches!(
        checkpoint.replacement[1].payload,
        ModelContextPayload::ProviderOpaque(_)
    ));
}

#[test]
fn keeps_text_only_compaction_provider_neutral() {
    let compacted = CompactedItem {
        message: "portable summary".to_string(),
        replacement_history: None,
        window_number: Some(3),
        first_window_id: Some("window-1".to_string()),
        previous_window_id: Some("window-2".to_string()),
        window_id: Some("window-3".to_string()),
    };

    let event = expect_event(
        adapter()
            .adapt_rollout_item(
                metadata("semantic-compaction", 9),
                &RolloutItem::Compacted(compacted),
            )
            .expect("adapt semantic compaction"),
    );
    let ContextEventPayload::Compaction(checkpoint) = event.payload else {
        panic!("expected checkpoint");
    };
    assert_eq!(checkpoint.mode, CompactionMode::Semantic);
    assert_eq!(checkpoint.lineage, None);
    let ModelContextPayload::Message(summary) = &checkpoint.replacement[0].payload else {
        panic!("expected semantic summary");
    };
    assert_eq!(
        summary.content,
        [ContentPart::Text {
            text: "portable summary".to_string(),
        }]
    );
}

#[test]
fn preserves_unknown_future_response_items_only_when_raw_bytes_are_available() {
    let raw = br#"{"type":"future_continuation","token":"do-not-drop"}"#;
    let item: ResponseItem = serde_json::from_slice(raw).expect("future item");
    assert_eq!(item, ResponseItem::Other);
    assert_eq!(
        adapter().adapt_response_item(metadata("event-9", 9), &item, None),
        Err(CodexAdapterError::RawPayloadRequired {
            kind: "codex.unknown_response_item",
        })
    );

    let event = expect_event(
        adapter()
            .adapt_response_item(metadata("event-9", 9), &item, Some(raw))
            .expect("adapt future item"),
    );
    let ContextEventPayload::ProviderOpaque(opaque) = event.payload else {
        panic!("expected opaque future item");
    };
    assert_eq!(opaque.payload.as_bytes(), raw);
}

#[test]
fn classifies_request_controls_instead_of_silently_dropping_them() {
    assert_eq!(
        adapter()
            .adapt_response_item(
                metadata("control", 10),
                &ResponseItem::CompactionTrigger {},
                None,
            )
            .expect("adapt request control"),
        AdaptedRolloutItem::Ignored(IgnoredRolloutItem::RequestControl)
    );
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

fn metadata(event_id: &str, sequence: u64) -> EventMetadata {
    EventMetadata {
        event_id: event_id.to_string(),
        conversation_id: "conversation-1".to_string(),
        turn_id: Some("turn-1".to_string()),
        sequence,
    }
}

fn expect_event(adapted: AdaptedRolloutItem) -> ContextEvent {
    let AdaptedRolloutItem::Event(event) = adapted else {
        panic!("expected context event");
    };
    *event
}

fn expect_tool(adapted: AdaptedRolloutItem) -> codex_context_engine::ToolRecord {
    let event = expect_event(adapted);
    let ContextEventPayload::Tool(tool) = event.payload else {
        panic!("expected tool record");
    };
    tool
}
