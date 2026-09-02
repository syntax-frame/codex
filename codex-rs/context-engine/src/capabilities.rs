use std::collections::BTreeSet;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::AttachmentKind;
use crate::ContentPart;
use crate::ModelContextItem;
use crate::ModelContextPayload;
use crate::ProviderLineage;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapability {
    ImageInput,
    NativeCompaction,
    OpaqueReasoning,
    HostedWebSearch,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    pub lineage: ProviderLineage,
    pub model: String,
    pub max_context_tokens: u64,
    pub supported: BTreeSet<ProviderCapability>,
}

impl ProviderCapabilities {
    pub fn supports(&self, capability: &ProviderCapability) -> bool {
        self.supported.contains(capability)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub execution: ToolExecutionKind,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToolExecutionKind {
    LocalDynamic,
    ProviderHosted { capability: ProviderCapability },
}

pub fn finalize_tools(
    capabilities: &ProviderCapabilities,
    requested: &[ToolDefinition],
) -> Vec<ToolDefinition> {
    requested
        .iter()
        .filter(|tool| match &tool.execution {
            ToolExecutionKind::LocalDynamic => true,
            ToolExecutionKind::ProviderHosted { capability } => capabilities.supports(capability),
        })
        .cloned()
        .collect()
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CapabilityError {
    #[error("model {model} does not support {capability:?}")]
    Unsupported {
        model: String,
        capability: ProviderCapability,
    },
}

pub fn validate_model_input(
    capabilities: &ProviderCapabilities,
    items: &[ModelContextItem],
) -> Result<(), CapabilityError> {
    let has_image = items.iter().any(|item| {
        let ModelContextPayload::Message(message) = &item.payload else {
            return false;
        };
        message.content.iter().any(|part| {
            matches!(
                part,
                ContentPart::Attachment {
                    kind: AttachmentKind::Image,
                    ..
                }
            )
        })
    });

    if has_image && !capabilities.supports(&ProviderCapability::ImageInput) {
        return Err(CapabilityError::Unsupported {
            model: capabilities.model.clone(),
            capability: ProviderCapability::ImageInput,
        });
    }

    Ok(())
}
