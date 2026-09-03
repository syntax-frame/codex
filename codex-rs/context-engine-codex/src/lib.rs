//! Adapter from Codex rollout protocol records to the provider-neutral context contract.
//!
//! This crate is intentionally not connected to `codex-core` yet. It gives the
//! existing runtime an explicit, testable translation boundary before storage
//! or compaction ownership moves.

mod adapter;
mod attachment;
mod codec;
mod error;
mod outbound;
mod parity;
mod types;

pub use adapter::CodexContextAdapter;
pub use attachment::AttachmentMaterializer;
pub use attachment::AttachmentResolver;
pub use attachment::MaterializedAttachment;
pub use attachment::ResolvedAttachment;
pub use error::CodexAdapterError;
pub use parity::CodexInputParityFailure;
pub use parity::CodexInputParityReport;
pub use parity::CodexInputParityStage;
pub use types::AdaptedRolloutItem;
pub use types::EventMetadata;
pub use types::IgnoredRolloutItem;
pub use types::PreparedCodexInputItem;

#[cfg(test)]
mod outbound_tests;

#[cfg(test)]
mod tests;
