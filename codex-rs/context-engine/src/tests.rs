use std::collections::BTreeSet;

use pretty_assertions::assert_eq;
use serde::Deserialize;

use super::*;

const FIXTURES: &str = include_str!("../tests/fixtures/context_compatibility.json");

#[derive(Debug, Deserialize)]
struct FixtureSet {
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    target: ProviderCapabilities,
    events: Vec<ContextEvent>,
    #[serde(default)]
    tools: Vec<ToolDefinition>,
    fork_request: Option<ForkRequest>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    transcript_event_ids: Vec<String>,
    model_item_ids: Vec<String>,
    #[serde(default)]
    excluded_opaque_event_ids: Vec<String>,
    #[serde(default)]
    active_tool_names: Vec<String>,
    fork_transcript_event_ids: Option<Vec<String>>,
    fork_model_item_ids: Option<Vec<String>>,
}

fn fixtures() -> FixtureSet {
    serde_json::from_str(FIXTURES).expect("context compatibility fixtures")
}

#[test]
fn fixtures_cover_the_extraction_acceptance_matrix() {
    let names: BTreeSet<_> = fixtures()
        .scenarios
        .into_iter()
        .map(|scenario| scenario.name)
        .collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "automatic_compaction".to_string(),
            "encrypted_reasoning".to_string(),
            "fork_resume".to_string(),
            "hosted_web_search".to_string(),
            "image_input_and_view_image".to_string(),
            "local_dynamic_tools".to_string(),
            "model_switch".to_string(),
            "text_continuation".to_string(),
        ])
    );
}

#[test]
fn fixture_projections_and_tools_match_the_contract() {
    for scenario in fixtures().scenarios {
        let projection = project_context(&scenario.events, &scenario.target.lineage)
            .unwrap_or_else(|error| panic!("{}: {error}", scenario.name));
        assert_eq!(
            event_ids(&projection.transcript),
            scenario.expected.transcript_event_ids,
            "{} transcript",
            scenario.name
        );
        assert_eq!(
            item_ids(&projection.model_context),
            scenario.expected.model_item_ids,
            "{} model context",
            scenario.name
        );
        assert_eq!(
            projection.excluded_opaque_event_ids, scenario.expected.excluded_opaque_event_ids,
            "{} opaque exclusions",
            scenario.name
        );
        validate_model_input(&scenario.target, &projection.model_context)
            .unwrap_or_else(|error| panic!("{}: {error}", scenario.name));
        assert_eq!(
            finalize_tools(&scenario.target, &scenario.tools)
                .into_iter()
                .map(|tool| tool.name)
                .collect::<Vec<_>>(),
            scenario.expected.active_tool_names,
            "{} active tools",
            scenario.name
        );

        if let Some(request) = scenario.fork_request {
            let fork = prepare_fork(&scenario.events, &request, &scenario.target.lineage)
                .unwrap_or_else(|error| panic!("{}: {error}", scenario.name));
            assert_eq!(
                event_ids(&fork.transcript),
                scenario
                    .expected
                    .fork_transcript_event_ids
                    .unwrap_or_default()
            );
            assert_eq!(
                item_ids(&fork.model_context),
                scenario.expected.fork_model_item_ids.unwrap_or_default()
            );
        }
    }
}

#[test]
fn opaque_payload_is_exact_and_redacted_from_debug_output() {
    let scenario = fixtures()
        .scenarios
        .into_iter()
        .find(|scenario| scenario.name == "encrypted_reasoning")
        .expect("encrypted reasoning fixture");
    let ContextEventPayload::ProviderOpaque(opaque) = &scenario.events[1].payload else {
        panic!("expected provider opaque event");
    };
    assert_eq!(opaque.payload.as_bytes(), b"fake-encrypted-reasoning");
    assert!(!format!("{:?}", opaque.payload).contains("fake-encrypted"));

    let round_trip: ContextEvent = serde_json::from_str(
        &serde_json::to_string(&scenario.events[1]).expect("serialize opaque event"),
    )
    .expect("deserialize opaque event");
    assert_eq!(round_trip, scenario.events[1]);
}

#[test]
fn compaction_changes_only_the_model_projection() {
    let scenario = fixtures()
        .scenarios
        .into_iter()
        .find(|scenario| scenario.name == "automatic_compaction")
        .expect("compaction fixture");
    let projection = project_context(&scenario.events, &scenario.target.lineage)
        .expect("project compacted context");
    assert_eq!(projection.transcript.len(), 5);
    assert_eq!(
        item_ids(&projection.model_context),
        ["summary-window-1", "compact-6"]
    );
    assert_eq!(projection.checkpoint_id.as_deref(), Some("checkpoint-1"));
}

#[test]
fn switching_lineage_excludes_but_does_not_delete_opaque_state() {
    let scenario = fixtures()
        .scenarios
        .into_iter()
        .find(|scenario| scenario.name == "model_switch")
        .expect("model switch fixture");
    let switched = project_context(&scenario.events, &scenario.target.lineage)
        .expect("project switched context");
    assert_eq!(switched.excluded_opaque_event_ids, ["switch-2"]);

    let ContextEventPayload::ProviderOpaque(opaque) = &scenario.events[1].payload else {
        panic!("expected preserved opaque event");
    };
    let original = project_context(&scenario.events, &opaque.lineage)
        .expect("re-project original provider lineage");
    assert_eq!(
        item_ids(&original.model_context),
        ["switch-1", "switch-2", "switch-3"]
    );
}

#[test]
fn image_input_requires_a_model_capability() {
    let mut scenario = fixtures()
        .scenarios
        .into_iter()
        .find(|scenario| scenario.name == "image_input_and_view_image")
        .expect("image fixture");
    let projection =
        project_context(&scenario.events, &scenario.target.lineage).expect("project image context");
    scenario
        .target
        .supported
        .remove(&ProviderCapability::ImageInput);
    assert_eq!(
        validate_model_input(&scenario.target, &projection.model_context),
        Err(CapabilityError::Unsupported {
            model: scenario.target.model,
            capability: ProviderCapability::ImageInput,
        })
    );
}

fn event_ids(events: &[ContextEvent]) -> Vec<String> {
    events.iter().map(|event| event.id.clone()).collect()
}

fn item_ids(items: &[ModelContextItem]) -> Vec<String> {
    items.iter().map(|item| item.id.clone()).collect()
}
