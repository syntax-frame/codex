use crate::models::ImageDetail;
use crate::models::ResponseItem;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde::de::Error as _;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::collections::HashSet;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema, TS)]
#[serde(tag = "type", rename_all = "camelCase")]
#[ts(tag = "type", export_to = "v2/")]
pub enum DynamicToolSpec {
    Function(DynamicToolFunctionSpec),
    Namespace(DynamicToolNamespaceSpec),
    #[schemars(skip)]
    #[ts(skip)]
    ArgumentPolicy(DynamicToolArgumentPolicySpec),
}

/// Controls whether a dynamic tool's model-produced arguments may cross
/// observability or persistence boundaries.
///
/// `Transient` arguments are delivered only to the live client-side handler.
/// Core persists and logs a content-free projection while retaining the tool
/// name, call id, status, and result provenance.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DynamicToolArgumentHandling {
    #[default]
    Persistent,
    Transient,
}

impl DynamicToolArgumentHandling {
    pub fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent)
    }

    pub fn redacts_arguments(self) -> bool {
        matches!(self, Self::Transient)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct DynamicToolFunctionSpec {
    pub name: String,
    pub description: String,
    pub input_schema: JsonValue,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub defer_loading: bool,
    #[serde(
        default,
        skip_serializing_if = "DynamicToolArgumentHandling::is_persistent"
    )]
    #[schemars(skip)]
    #[ts(skip)]
    pub argument_handling: DynamicToolArgumentHandling,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct DynamicToolNamespaceSpec {
    pub name: String,
    pub description: String,
    pub tools: Vec<DynamicToolNamespaceTool>,
}

/// A privacy-only policy carried beside dynamic tool schemas.
///
/// This does not register or advertise a tool. It lets a client keep learned,
/// stale, or malformed calls content-free even when the corresponding tool is
/// disabled and therefore absent from the catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DynamicToolArgumentPolicySpec {
    pub argument_handling: DynamicToolArgumentHandling,
    pub tools: Vec<DynamicToolArgumentIdentity>,
    /// Privacy-only policies are authority-bearing: unlike a callable dynamic
    /// tool schema, they can project stale or malformed calls that are not in
    /// the current catalog. Only a trusted host bridge may construct one.
    ///
    /// The marker is deliberately absent from the wire format. Deserialized
    /// client input is therefore always untrusted, even if it reproduces the
    /// rest of this structure byte-for-byte.
    #[serde(skip)]
    trusted: bool,
}

pub const MAX_TRANSIENT_ARGUMENT_IDENTITIES: usize = 32;

impl DynamicToolArgumentPolicySpec {
    pub fn trusted_transient(
        tools: Vec<DynamicToolArgumentIdentity>,
    ) -> Result<Self, &'static str> {
        if tools.is_empty() {
            return Err("trusted dynamic tool argument policy must not be empty");
        }
        if tools.len() > MAX_TRANSIENT_ARGUMENT_IDENTITIES {
            return Err("trusted dynamic tool argument policy exceeds the identity limit");
        }
        let unique = tools.iter().collect::<HashSet<_>>();
        if unique.len() != tools.len() {
            return Err("trusted dynamic tool argument policy contains duplicate identities");
        }
        Ok(Self {
            argument_handling: DynamicToolArgumentHandling::Transient,
            tools,
            trusted: true,
        })
    }

    pub fn is_trusted(&self) -> bool {
        self.trusted
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct DynamicToolArgumentIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub name: String,
    /// When true, the name remains protected if a stale or hostile call adds
    /// or changes its namespace.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub match_any_namespace: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub match_case_insensitive: bool,
}

/// Turn-local lookup used by every Core persistence and observability boundary.
#[derive(Clone, Debug, Default)]
pub struct DynamicToolArgumentPolicy {
    transient_tools: HashSet<DynamicToolArgumentIdentity>,
}

impl DynamicToolArgumentPolicy {
    pub fn from_dynamic_tools(dynamic_tools: &[DynamicToolSpec]) -> Self {
        let mut transient_tools = HashSet::new();
        for dynamic_tool in dynamic_tools {
            match dynamic_tool {
                DynamicToolSpec::ArgumentPolicy(policy)
                    if policy.is_trusted() && policy.argument_handling.redacts_arguments() =>
                {
                    transient_tools.extend(
                        policy
                            .tools
                            .iter()
                            .take(MAX_TRANSIENT_ARGUMENT_IDENTITIES)
                            .cloned(),
                    );
                }
                DynamicToolSpec::Function(_)
                | DynamicToolSpec::Namespace(_)
                | DynamicToolSpec::ArgumentPolicy(_) => {}
            }
        }
        Self { transient_tools }
    }

    pub fn is_empty(&self) -> bool {
        self.transient_tools.is_empty()
    }

    pub fn handling_for(&self, namespace: Option<&str>, name: &str) -> DynamicToolArgumentHandling {
        // Function names are protocol identifiers, not user content. Treat
        // surrounding whitespace as malformed spelling of the same protected
        // identity so an invalid call fails routing without regaining durable
        // argument persistence.
        let name = name.trim();
        let namespace = namespace.map(str::trim);
        if self.transient_tools.iter().any(|identity| {
            let name_matches = if identity.match_case_insensitive {
                identity.name.eq_ignore_ascii_case(name)
            } else {
                identity.name == name
            };
            let namespace_matches = if identity.match_any_namespace {
                true
            } else if identity.match_case_insensitive {
                match (identity.namespace.as_deref(), namespace) {
                    (Some(expected), Some(actual)) => expected.eq_ignore_ascii_case(actual),
                    (None, None) => true,
                    _ => false,
                }
            } else {
                identity.namespace.as_deref() == namespace
            };
            name_matches && namespace_matches
        }) {
            DynamicToolArgumentHandling::Transient
        } else {
            DynamicToolArgumentHandling::Persistent
        }
    }

    /// Removes whole argument blobs structurally. The contents are never
    /// inspected, so aliases, nesting, and encodings cannot bypass projection.
    pub fn redact_json(&self, value: &mut JsonValue) {
        match value {
            JsonValue::Array(values) => {
                for value in values {
                    self.redact_json(value);
                }
            }
            JsonValue::Object(object) => {
                let names = ["name", "tool"]
                    .into_iter()
                    .filter_map(|key| object.get(key).and_then(JsonValue::as_str));
                let namespace = object.get("namespace").and_then(JsonValue::as_str);
                if names
                    .into_iter()
                    .any(|name| self.handling_for(namespace, name).redacts_arguments())
                {
                    if let Some(arguments) = object.get_mut("arguments") {
                        *arguments = match arguments {
                            JsonValue::String(_) => JsonValue::String("{}".to_string()),
                            _ => JsonValue::Object(Default::default()),
                        };
                    }
                    if let Some(input) = object.get_mut("input") {
                        *input = match input {
                            JsonValue::String(_) => JsonValue::String(String::new()),
                            _ => JsonValue::Object(Default::default()),
                        };
                    }
                }
                for value in object.values_mut() {
                    self.redact_json(value);
                }
            }
            _ => {}
        }
    }

    pub fn redact_response_item(&self, item: &ResponseItem) -> ResponseItem {
        let mut projected = item.clone();
        match &mut projected {
            ResponseItem::FunctionCall {
                name,
                namespace,
                arguments,
                ..
            } if self
                .handling_for(namespace.as_deref(), name)
                .redacts_arguments() =>
            {
                arguments.clear();
                arguments.push_str("{}");
            }
            ResponseItem::CustomToolCall {
                name,
                namespace,
                input,
                ..
            } if self
                .handling_for(namespace.as_deref(), name)
                .redacts_arguments() =>
            {
                input.clear();
            }
            _ => {}
        }
        projected
    }

    /// Applies the structural projection to any serializable protocol envelope.
    ///
    /// This is the last-line persistence guard for nested rollout, event,
    /// compaction, and trace shapes. Projection is identity-based and replaces
    /// the entire argument blob; it never attempts to classify its contents.
    pub fn redact_serializable<T>(&self, value: &T) -> Result<T, serde_json::Error>
    where
        T: Serialize + DeserializeOwned,
    {
        let mut json = serde_json::to_value(value)?;
        self.redact_json(&mut json);
        serde_json::from_value(json)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema, TS)]
#[serde(tag = "type", rename_all = "camelCase")]
#[ts(tag = "type", export_to = "v2/")]
pub enum DynamicToolNamespaceTool {
    Function(DynamicToolFunctionSpec),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct DynamicToolCallRequest {
    pub call_id: String,
    pub turn_id: String,
    #[serde(default)]
    pub started_at_ms: i64,
    #[serde(default)]
    pub namespace: Option<String>,
    pub tool: String,
    pub arguments: JsonValue,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub arguments_transient: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct DynamicToolResponse {
    pub content_items: Vec<DynamicToolCallOutputContentItem>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema, TS)]
#[serde(tag = "type", rename_all = "camelCase")]
#[ts(tag = "type")]
pub enum DynamicToolCallOutputContentItem {
    #[serde(rename_all = "camelCase")]
    InputText { text: String },
    #[serde(rename_all = "camelCase")]
    InputImage {
        image_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<ImageDetail>,
    },
    #[serde(rename_all = "camelCase")]
    InputAudio { audio_url: String },
}

/// Former flat `SessionMeta` shape, including the old `exposeToContext` flag.
/// Kept so new builds can resume sessions written before explicit namespaces.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyDynamicToolSpec {
    namespace: Option<String>,
    name: String,
    description: String,
    input_schema: JsonValue,
    defer_loading: Option<bool>,
    expose_to_context: Option<bool>,
    argument_handling: Option<DynamicToolArgumentHandling>,
}

pub fn normalize_dynamic_tool_specs(
    values: Vec<JsonValue>,
) -> Result<Vec<DynamicToolSpec>, serde_json::Error> {
    let has_legacy_fields = |value: &JsonValue| {
        value.get("namespace").is_some()
            || value.get("exposeToContext").is_some()
            || value.get("type").is_none()
    };
    let has_legacy_format = values.iter().any(|value| {
        has_legacy_fields(value)
            || (value.get("type").and_then(JsonValue::as_str) == Some("namespace")
                && value
                    .get("tools")
                    .and_then(JsonValue::as_array)
                    .is_some_and(|tools| tools.iter().any(&has_legacy_fields)))
    });
    let has_canonical_format = values.iter().any(|value| value.get("type").is_some());
    if has_legacy_format && has_canonical_format {
        return Err(serde_json::Error::custom(
            "dynamic tools must use either canonical or legacy format consistently",
        ));
    }
    if !has_legacy_format {
        return values.into_iter().map(serde_json::from_value).collect();
    }

    let tools = values
        .into_iter()
        .map(|value| {
            let tool: LegacyDynamicToolSpec = serde_json::from_value(value)?;
            let function = DynamicToolFunctionSpec {
                name: tool.name,
                description: tool.description,
                input_schema: tool.input_schema,
                defer_loading: tool.defer_loading.unwrap_or_else(|| {
                    tool.expose_to_context
                        .map(|visible| !visible)
                        .unwrap_or(false)
                }),
                argument_handling: tool.argument_handling.unwrap_or_default(),
            };
            Ok((tool.namespace, function))
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()?;
    Ok(group_dynamic_tools_by_namespace(tools))
}

pub fn group_dynamic_tools_by_namespace(
    tools: Vec<(Option<String>, DynamicToolFunctionSpec)>,
) -> Vec<DynamicToolSpec> {
    let mut grouped_tools = Vec::with_capacity(tools.len());
    let mut namespace_indices = HashMap::<String, usize>::new();
    for (namespace, function) in tools {
        let Some(namespace) = namespace else {
            grouped_tools.push(DynamicToolSpec::Function(function));
            continue;
        };
        let function = DynamicToolNamespaceTool::Function(function);
        if let Some(index) = namespace_indices.get(&namespace).copied() {
            let DynamicToolSpec::Namespace(namespace) = &mut grouped_tools[index] else {
                unreachable!("namespace index must point to a namespace");
            };
            namespace.tools.push(function);
            continue;
        }
        namespace_indices.insert(namespace.clone(), grouped_tools.len());
        grouped_tools.push(DynamicToolSpec::Namespace(DynamicToolNamespaceSpec {
            name: namespace,
            description: String::new(),
            tools: vec![function],
        }));
    }
    grouped_tools
}

pub fn deserialize_dynamic_tool_specs<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<DynamicToolSpec>>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(values) = Option::<Vec<JsonValue>>::deserialize(deserializer)? else {
        return Ok(None);
    };
    normalize_dynamic_tool_specs(values)
        .map(Some)
        .map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    const SENTINEL: &str = "RAW_BROWSER_ARGUMENT_SENTINEL";

    fn trusted_policy() -> DynamicToolArgumentPolicy {
        DynamicToolArgumentPolicy::from_dynamic_tools(&[DynamicToolSpec::ArgumentPolicy(
            DynamicToolArgumentPolicySpec::trusted_transient(vec![
                DynamicToolArgumentIdentity {
                    namespace: None,
                    name: "agentapp_browser_act".to_string(),
                    match_any_namespace: true,
                    match_case_insensitive: true,
                },
                DynamicToolArgumentIdentity {
                    namespace: None,
                    name: "browser.act".to_string(),
                    match_any_namespace: true,
                    match_case_insensitive: true,
                },
                DynamicToolArgumentIdentity {
                    namespace: Some("browser".to_string()),
                    name: "act".to_string(),
                    match_any_namespace: false,
                    match_case_insensitive: true,
                },
            ])
            .expect("trusted test policy"),
        )])
    }

    #[test]
    fn trusted_policy_projects_whole_function_and_custom_argument_blobs() {
        let policy = trusted_policy();
        let function = ResponseItem::FunctionCall {
            id: None,
            name: "AGENTAPP_BROWSER_ACT".to_string(),
            namespace: None,
            arguments: format!(r#"{{"password":"{SENTINEL}","encoded":"UkFXX0JST1dTRVI="}}"#),
            call_id: "call-function".to_string(),
            internal_chat_message_metadata_passthrough: None,
        };
        let custom = ResponseItem::CustomToolCall {
            id: None,
            status: None,
            call_id: "call-custom".to_string(),
            name: "act".to_string(),
            namespace: Some("BROWSER".to_string()),
            input: SENTINEL.to_string(),
            internal_chat_message_metadata_passthrough: None,
        };

        let ResponseItem::FunctionCall { arguments, .. } = policy.redact_response_item(&function)
        else {
            panic!("function call");
        };
        assert_eq!(arguments, "{}");
        let ResponseItem::CustomToolCall { input, .. } = policy.redact_response_item(&custom)
        else {
            panic!("custom tool call");
        };
        assert_eq!(input, "");
    }

    #[test]
    fn recursive_projection_checks_name_and_tool_independently() {
        let policy = trusted_policy();
        let mut value = json!({
            "nested": [{
                "name": "benign",
                "tool": "browser.act",
                "arguments": {
                    "aliases": {
                        "pwd": SENTINEL,
                        "otp": "004201",
                        "token": "a.b.c"
                    }
                },
                "input": SENTINEL
            }]
        });

        policy.redact_json(&mut value);

        assert_eq!(value["nested"][0]["arguments"], json!({}));
        assert_eq!(value["nested"][0]["input"], json!(""));
        assert!(!value.to_string().contains(SENTINEL));
    }

    #[test]
    fn reserved_root_browser_identity_is_projected_across_namespaces() {
        let policy = trusted_policy();
        assert_eq!(
            policy.handling_for(Some("mcp_server"), "agentapp_browser_act"),
            DynamicToolArgumentHandling::Transient
        );
        assert_eq!(
            policy.handling_for(Some(""), "AGENTAPP_BROWSER_ACT"),
            DynamicToolArgumentHandling::Transient
        );
    }

    #[test]
    fn malformed_whitespace_does_not_restore_argument_persistence() {
        let policy = trusted_policy();
        assert_eq!(
            policy.handling_for(Some(" browser\t"), " act \n"),
            DynamicToolArgumentHandling::Transient
        );
        assert_eq!(
            policy.handling_for(None, "\tagentapp_browser_act "),
            DynamicToolArgumentHandling::Transient
        );
    }

    #[test]
    fn serialized_policy_never_restores_trusted_authority() {
        let spec = DynamicToolSpec::ArgumentPolicy(
            DynamicToolArgumentPolicySpec::trusted_transient(vec![DynamicToolArgumentIdentity {
                namespace: None,
                name: "agentapp_browser_act".to_string(),
                match_any_namespace: false,
                match_case_insensitive: false,
            }])
            .expect("trusted policy"),
        );
        let encoded = serde_json::to_string(&spec).expect("serialize policy");
        let decoded: DynamicToolSpec = serde_json::from_str(&encoded).expect("deserialize policy");
        let DynamicToolSpec::ArgumentPolicy(decoded_policy) = &decoded else {
            panic!("argument policy");
        };

        assert!(!decoded_policy.is_trusted());
        assert!(DynamicToolArgumentPolicy::from_dynamic_tools(&[decoded]).is_empty());
    }

    #[test]
    fn canonical_policy_identity_list_does_not_trigger_legacy_format_detection() {
        let specs = [
            DynamicToolSpec::Function(DynamicToolFunctionSpec {
                name: "agentapp_browser_act".to_string(),
                description: "Act without accepting secrets.".to_string(),
                input_schema: json!({"type": "object"}),
                defer_loading: false,
                argument_handling: DynamicToolArgumentHandling::Transient,
            }),
            DynamicToolSpec::ArgumentPolicy(
                DynamicToolArgumentPolicySpec::trusted_transient(vec![
                    DynamicToolArgumentIdentity {
                        namespace: None,
                        name: "agentapp_browser_act".to_string(),
                        match_any_namespace: true,
                        match_case_insensitive: true,
                    },
                ])
                .expect("trusted policy"),
            ),
        ];
        let values = specs
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .expect("serialize specs");

        let decoded = normalize_dynamic_tool_specs(values).expect("canonical specs");

        assert_eq!(decoded.len(), 2);
        let DynamicToolSpec::ArgumentPolicy(policy) = &decoded[1] else {
            panic!("argument policy");
        };
        assert!(!policy.is_trusted());
    }

    #[test]
    fn trusted_policy_rejects_duplicates_and_oversized_identity_sets() {
        let identity = DynamicToolArgumentIdentity {
            namespace: None,
            name: "agentapp_browser_act".to_string(),
            match_any_namespace: false,
            match_case_insensitive: false,
        };
        assert!(
            DynamicToolArgumentPolicySpec::trusted_transient(vec![
                identity.clone(),
                identity.clone()
            ])
            .is_err()
        );
        assert!(
            DynamicToolArgumentPolicySpec::trusted_transient(vec![
                identity;
                MAX_TRANSIENT_ARGUMENT_IDENTITIES
                    + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn public_dynamic_tool_schemas_omit_privacy_authority() {
        let json_schema =
            serde_json::to_string(&schemars::schema_for!(DynamicToolSpec)).expect("JSON schema");
        assert!(json_schema.contains("function"));
        assert!(json_schema.contains("namespace"));
        assert!(!json_schema.contains("argumentHandling"));
        assert!(!json_schema.contains("argumentPolicy"));

        let typescript = DynamicToolSpec::export_to_string().expect("TypeScript schema");
        assert!(typescript.contains("DynamicToolFunctionSpec"));
        assert!(typescript.contains("DynamicToolNamespaceSpec"));
        assert!(!typescript.contains("argumentHandling"));
        assert!(!typescript.contains("ArgumentPolicy"));
    }
}
