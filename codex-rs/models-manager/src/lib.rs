pub(crate) mod cache;
pub mod collaboration_mode_presets;
pub(crate) mod config;
pub mod manager;
pub mod model_info;
pub mod model_presets;
pub mod test_support;

pub use codex_protocol::auth::AuthMode;
pub use config::ModelsManagerConfig;

/// Load the bundled model catalog shipped with `codex-models-manager`.
pub fn bundled_models_response()
-> std::result::Result<codex_protocol::openai_models::ModelsResponse, serde_json::Error> {
    serde_json::from_str(include_str!("../models.json"))
}

// Reviewed compatibility with the Codex /models contract, independent of this
// maintained fork's Cargo package version. The supported metadata includes
// Responses Lite, tool-mode selectors, and Max/Ultra reasoning levels. Hosts
// retain their feature-gated tool handling, including iOS's direct-tool fallback
// when the Code Mode runtime is unavailable.
// This does not claim that the fork includes the entire upstream 0.153 release.
// Advance only after reviewing catalog metadata and validating turn behavior.
const MODELS_CATALOG_COMPATIBILITY_VERSION: &str = "0.153.0";

/// Return the supported Codex /models compatibility version.
///
/// The backend uses this value to gate model availability. Cache eligibility
/// must use the same version so a fresh older catalog cannot hide new models.
pub fn client_version_to_whole() -> String {
    MODELS_CATALOG_COMPATIBILITY_VERSION.to_string()
}
