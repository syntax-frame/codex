use std::collections::HashMap;
use std::hash::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Instant;

use codex_core::CodexThread;
use codex_exec_server::SshAuthentication;
use codex_exec_server::SshTmuxMode;
use codex_model_provider_info::WireApi;
use codex_protocol::ThreadId;

use super::ProviderAuthConfig;
use super::ServerMode;

const WARM_THREAD_CACHE_LIMIT: usize = 12;

pub(super) struct WarmThreadEntry {
    pub(super) fingerprint: u64,
    pub(super) thread_id: ThreadId,
    pub(super) thread: Arc<CodexThread>,
    pub(super) session_model: String,
    pub(super) rollout_path: PathBuf,
    pub(super) credential_guard: Option<Arc<tempfile::TempDir>>,
    pub(super) last_used: Instant,
}

fn warm_thread_cache() -> &'static Mutex<HashMap<PathBuf, WarmThreadEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, WarmThreadEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn warm_thread_fingerprint(
    provider_config: &ProviderAuthConfig,
    model: &str,
    reasoning_effort: &str,
    service_tier: &str,
    workspace: &str,
    dynamic_tools_json: &str,
    server_mode: Option<&ServerMode>,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    match provider_config {
        ProviderAuthConfig::ChatgptOAuth {
            access_token,
            id_token,
            account_id,
        } => {
            "oauth".hash(&mut hasher);
            access_token.hash(&mut hasher);
            id_token.hash(&mut hasher);
            account_id.hash(&mut hasher);
        }
        ProviderAuthConfig::ApiKey {
            base_url,
            api_key,
            wire_api,
        } => {
            "api_key".hash(&mut hasher);
            base_url.hash(&mut hasher);
            api_key.hash(&mut hasher);
            match wire_api {
                WireApi::Responses => "responses",
                WireApi::ChatCompletions => "chat_completions",
            }
            .hash(&mut hasher);
        }
    }
    model.hash(&mut hasher);
    reasoning_effort.hash(&mut hasher);
    service_tier.hash(&mut hasher);
    workspace.hash(&mut hasher);
    dynamic_tools_json.hash(&mut hasher);
    match server_mode {
        Some(server) => {
            "server".hash(&mut hasher);
            server.connection_key.hash(&mut hasher);
            server.session_key.hash(&mut hasher);
            server.host.hash(&mut hasher);
            server.port.hash(&mut hasher);
            server.user.hash(&mut hasher);
            server.host_fingerprint.hash(&mut hasher);
            match server.tmux_mode {
                SshTmuxMode::Required => "tmux_required",
                SshTmuxMode::Preferred => "tmux_preferred",
                SshTmuxMode::Disabled => "tmux_disabled",
            }
            .hash(&mut hasher);
            match &server.authentication {
                SshAuthentication::Password(password) => {
                    "password".hash(&mut hasher);
                    password.hash(&mut hasher);
                }
                SshAuthentication::PrivateKeyPath(path) => {
                    "private_key".hash(&mut hasher);
                    match std::fs::read(path) {
                        Ok(bytes) => bytes.hash(&mut hasher),
                        Err(_) => path.hash(&mut hasher),
                    }
                }
            }
        }
        None => "local".hash(&mut hasher),
    }
    hasher.finish()
}

pub(super) fn take_warm_thread(
    codex_home: &Path,
    fingerprint: u64,
    rollout_path: Option<&Path>,
) -> (Option<WarmThreadEntry>, Option<WarmThreadEntry>) {
    let Ok(mut cache) = warm_thread_cache().lock() else {
        tracing::warn!("warm iOS thread cache was poisoned");
        return (None, None);
    };
    let Some(entry) = cache.remove(codex_home) else {
        return (None, None);
    };
    if entry.fingerprint == fingerprint && rollout_path == Some(entry.rollout_path.as_path()) {
        (Some(entry), None)
    } else {
        (None, Some(entry))
    }
}

pub(super) fn cache_warm_thread(
    codex_home: PathBuf,
    mut entry: WarmThreadEntry,
) -> Vec<WarmThreadEntry> {
    entry.last_used = Instant::now();
    let Ok(mut cache) = warm_thread_cache().lock() else {
        tracing::warn!("warm iOS thread cache was poisoned");
        return vec![entry];
    };
    let mut retired = cache
        .insert(codex_home, entry)
        .into_iter()
        .collect::<Vec<_>>();
    while cache.len() > WARM_THREAD_CACHE_LIMIT {
        let Some(oldest_path) = cache
            .iter()
            .min_by_key(|(_, candidate)| candidate.last_used)
            .map(|(path, _)| path.clone())
        else {
            break;
        };
        if let Some(entry) = cache.remove(&oldest_path) {
            retired.push(entry);
        }
    }
    retired
}

pub(super) async fn retire_warm_thread(entry: WarmThreadEntry) {
    if let Err(error) = entry.thread.prepare_for_host_detach().await {
        tracing::warn!(error_type = %std::any::type_name_of_val(&error), "warm iOS thread detach failed");
    }
    if let Err(error) = entry.thread.shutdown_and_wait().await {
        tracing::warn!(error_type = %std::any::type_name_of_val(&error), "warm iOS thread shutdown failed");
    }
}

pub(super) fn retire_warm_threads_in_background(entries: Vec<WarmThreadEntry>) {
    for entry in entries {
        tokio::spawn(retire_warm_thread(entry));
    }
}
