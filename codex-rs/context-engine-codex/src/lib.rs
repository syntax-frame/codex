//! Adapter from Codex rollout protocol records to the provider-neutral context contract.
//!
//! This crate is intentionally not connected to `codex-core` yet. It gives the
//! existing runtime an explicit, testable translation boundary before storage
//! or compaction ownership moves.

mod adapter;
mod attachment;
mod codec;
mod error;
mod types;

pub use adapter::CodexContextAdapter;
pub use attachment::AttachmentResolver;
pub use attachment::ResolvedAttachment;
pub use error::CodexAdapterError;
pub use types::AdaptedRolloutItem;
pub use types::EventMetadata;
pub use types::IgnoredRolloutItem;

#[cfg(test)]
mod tests;
