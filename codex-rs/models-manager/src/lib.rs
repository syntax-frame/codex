pub(crate) mod cache;
pub mod collaboration_mode_presets;
pub(crate) mod config;
pub mod manager;
pub mod model_info;
pub mod model_presets;
pub mod test_support;

use codex_protocol::CODEX_API_COMPATIBILITY_VERSION;
pub use codex_protocol::auth::AuthMode;
pub use config::ModelsManagerConfig;

/// Load the bundled model catalog shipped with `codex-models-manager`.
pub fn bundled_models_response()
-> std::result::Result<codex_protocol::openai_models::ModelsResponse, serde_json::Error> {
    serde_json::from_str(include_str!("../models.json"))
}

/// Return the supported Codex /models compatibility version.
///
/// The backend uses this value to gate model availability. Cache eligibility
/// must use the same version so a fresh older catalog cannot hide new models.
pub fn client_version_to_whole() -> String {
    CODEX_API_COMPATIBILITY_VERSION.to_string()
}
