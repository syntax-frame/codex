//! Provider-neutral contracts for durable transcripts and bounded model context.
//!
//! This crate is deliberately not wired into `codex-core` yet. It defines the
//! compatibility boundary that the current implementation must satisfy before
//! persistence or compaction responsibilities move out of CodexCore.

mod capabilities;
mod context;
mod store;

pub use capabilities::CapabilityError;
pub use capabilities::ProviderCapabilities;
pub use capabilities::ProviderCapability;
pub use capabilities::ToolDefinition;
pub use capabilities::ToolExecutionKind;
pub use capabilities::finalize_tools;
pub use capabilities::validate_model_input;
pub use context::AttachmentKind;
pub use context::CompactionMode;
pub use context::ContentPart;
pub use context::ContextCheckpoint;
pub use context::ContextContractError;
pub use context::ContextEvent;
pub use context::ContextEventPayload;
pub use context::ContextProjection;
pub use context::ForkRequest;
pub use context::ForkSeed;
pub use context::Message;
pub use context::MessageDelivery;
pub use context::MessagePhase;
pub use context::MessageRole;
pub use context::MessageRoute;
pub use context::MessageVisibility;
pub use context::ModelContextItem;
pub use context::ModelContextPayload;
pub use context::OpaquePayload;
pub use context::ProviderLineage;
pub use context::ProviderOpaqueItem;
pub use context::ToolPhase;
pub use context::ToolRecord;
pub use context::prepare_fork;
pub use context::project_context;
pub use context::validate_events;
pub use store::AppendEventsRequest;
pub use store::CommitCompactionRequest;
pub use store::ContextStore;
pub use store::ForkCommitRequest;
pub use store::LoadEventsRequest;
pub use store::StoredEvents;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
