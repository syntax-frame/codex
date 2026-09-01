//! Durable, content-free admission receipts for AgentApp-owned turns.
//!
//! Only the immutable ticket hash, semantic request digest, and exact
//! generation-specific execution digest are persisted. The execution digest
//! binds the actual model input and model-context selector without preventing
//! the one verified retry from moving to a fresh context. The receipt
//! deliberately never records a prompt, provider error, upload path,
//! credential, or model output.

use std::fmt;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

const RECEIPT_VERSION: u32 = 2;
const QUERY_CONTRACT_VERSION: u32 = 1;
const DIGEST_LENGTH: usize = 64;
const MAX_TICKET_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdmissionState {
    Preparing,
    PersistedQueued,
    RejectedBeforeAdmission,
    ToolOrSideEffectPossible,
    ModelRequestPossible,
    Admitted,
    Terminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionRequest {
    agent_inbox_ticket_id: String,
    ticket_digest: String,
    semantic_request_prompt: String,
    semantic_request_digest: String,
    execution_request_digest: String,
    receipt_root: PathBuf,
    generation: u32,
}

impl AdmissionRequest {
    pub(crate) fn new(
        agent_inbox_ticket_id: String,
        semantic_request_digest: String,
        execution_request_digest: String,
        receipt_root: String,
        generation: u32,
    ) -> Result<Self, AdmissionError> {
        if agent_inbox_ticket_id.is_empty()
            || agent_inbox_ticket_id.len() > MAX_TICKET_BYTES
            || generation > 1
            || !is_canonical_digest(&semantic_request_digest)
            || !is_canonical_digest(&execution_request_digest)
        {
            return Err(AdmissionError::InvalidRequest);
        }
        let receipt_root = PathBuf::from(receipt_root);
        if !receipt_root.is_absolute() {
            return Err(AdmissionError::InvalidRequest);
        }
        let ticket_digest = format!("{:x}", Sha256::digest(agent_inbox_ticket_id.as_bytes()));
        Ok(Self {
            agent_inbox_ticket_id,
            ticket_digest,
            semantic_request_prompt: String::new(),
            semantic_request_digest,
            execution_request_digest,
            receipt_root,
            generation,
        })
    }

    pub(crate) fn with_semantic_request_prompt(mut self, prompt: String) -> Self {
        self.semantic_request_prompt = prompt;
        self
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TurnAdmission {
    receipt: Receipt,
    agent_inbox_ticket_id: String,
    semantic_request_prompt: String,
    runtime_state: RuntimeState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeState {
    PreAdmission,
    ToolOrSideEffectPossible,
    ModelRequestPossible,
    Admitted,
    Finalized,
}

impl TurnAdmission {
    pub(crate) fn begin(request: AdmissionRequest) -> Result<Self, AdmissionError> {
        let agent_inbox_ticket_id = request.agent_inbox_ticket_id.clone();
        let semantic_request_prompt = request.semantic_request_prompt.clone();
        let receipt = Receipt::begin(request)?;
        Ok(Self {
            receipt,
            agent_inbox_ticket_id,
            semantic_request_prompt,
            runtime_state: RuntimeState::PreAdmission,
        })
    }

    pub(crate) fn semantic_request_prompt(&self) -> &str {
        &self.semantic_request_prompt
    }

    pub(crate) fn agent_inbox_ticket_id(&self) -> &str {
        &self.agent_inbox_ticket_id
    }

    pub(crate) fn semantic_request_digest(&self) -> &str {
        &self.receipt.semantic_request_digest
    }

    pub(crate) fn execution_request_digest(&self) -> &str {
        &self.receipt.execution_request_digest
    }

    pub(crate) fn is_pre_admission(&self) -> bool {
        self.runtime_state == RuntimeState::PreAdmission
    }

    pub(crate) fn is_finalized(&self) -> bool {
        self.runtime_state == RuntimeState::Finalized
    }

    pub(crate) fn mark_rejected_before_admission(&mut self) -> Result<(), AdmissionError> {
        if self.runtime_state != RuntimeState::PreAdmission {
            return Err(AdmissionError::UnexpectedTransition);
        }
        self.receipt.transition(
            AdmissionState::PersistedQueued,
            AdmissionState::RejectedBeforeAdmission,
        )?;
        self.runtime_state = RuntimeState::Finalized;
        Ok(())
    }

    pub(crate) fn mark_model_request_possible(&mut self) -> Result<(), AdmissionError> {
        let expected = match self.runtime_state {
            RuntimeState::PreAdmission => AdmissionState::PersistedQueued,
            RuntimeState::ToolOrSideEffectPossible => AdmissionState::ToolOrSideEffectPossible,
            _ => return Err(AdmissionError::UnexpectedTransition),
        };
        self.receipt
            .transition(expected, AdmissionState::ModelRequestPossible)?;
        self.runtime_state = RuntimeState::ModelRequestPossible;
        Ok(())
    }

    pub(crate) fn mark_tool_or_side_effect_possible(&mut self) -> Result<(), AdmissionError> {
        if self.runtime_state != RuntimeState::PreAdmission {
            return Err(AdmissionError::UnexpectedTransition);
        }
        self.receipt.transition(
            AdmissionState::PersistedQueued,
            AdmissionState::ToolOrSideEffectPossible,
        )?;
        self.runtime_state = RuntimeState::ToolOrSideEffectPossible;
        Ok(())
    }

    pub(crate) fn mark_admitted(&mut self) -> Result<(), AdmissionError> {
        if self.runtime_state != RuntimeState::ModelRequestPossible {
            return Err(AdmissionError::UnexpectedTransition);
        }
        self.receipt.transition(
            AdmissionState::ModelRequestPossible,
            AdmissionState::Admitted,
        )?;
        self.runtime_state = RuntimeState::Admitted;
        Ok(())
    }

    pub(crate) fn mark_terminal(&mut self) -> Result<(), AdmissionError> {
        let expected = match self.runtime_state {
            RuntimeState::PreAdmission => AdmissionState::PersistedQueued,
            RuntimeState::ToolOrSideEffectPossible => AdmissionState::ToolOrSideEffectPossible,
            RuntimeState::ModelRequestPossible => AdmissionState::ModelRequestPossible,
            RuntimeState::Admitted => AdmissionState::Admitted,
            RuntimeState::Finalized => return Ok(()),
        };
        self.receipt
            .transition(expected, AdmissionState::Terminal)?;
        self.runtime_state = RuntimeState::Finalized;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionError {
    InvalidRequest,
    Unavailable,
    Ambiguous,
    NotEligible,
    UnexpectedTransition,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidRequest => "AgentApp turn admission request is invalid.",
            Self::Unavailable => "AgentApp turn admission storage is unavailable.",
            Self::Ambiguous => "AgentApp turn admission is ambiguous.",
            Self::NotEligible => "AgentApp turn admission is not eligible.",
            Self::UnexpectedTransition => "AgentApp turn admission state changed unexpectedly.",
        };
        formatter.write_str(message)
    }
}

#[derive(Serialize)]
pub(crate) struct AdmissionReceiptQuery {
    contract_version: u32,
    receipt_version: u32,
    state: &'static str,
    generation: u32,
    digest_match: bool,
    authorizes_generation_one_start: bool,
}

impl AdmissionReceiptQuery {
    pub(crate) fn unavailable(state: &'static str) -> Self {
        Self {
            contract_version: QUERY_CONTRACT_VERSION,
            receipt_version: 0,
            state,
            generation: 0,
            digest_match: false,
            authorizes_generation_one_start: false,
        }
    }
}

pub(crate) fn query(request: &AdmissionRequest) -> AdmissionReceiptQuery {
    if matches!(
        fs::symlink_metadata(&request.receipt_root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        return AdmissionReceiptQuery::unavailable("missing");
    }
    let Ok(paths) = ReceiptPaths::from_existing(request) else {
        return AdmissionReceiptQuery::unavailable("unavailable");
    };
    let result = with_lock(&paths, || read_record(&paths, request));
    match result {
        Ok(Some(record)) => AdmissionReceiptQuery {
            contract_version: QUERY_CONTRACT_VERSION,
            receipt_version: record.version,
            state: record.state.as_str(),
            generation: record.generation,
            digest_match: record.semantic_request_digest == request.semantic_request_digest
                && record.execution_request_digest == request.execution_request_digest
                && record.generation == request.generation,
            authorizes_generation_one_start: record.version == RECEIPT_VERSION
                && record.state == AdmissionState::RejectedBeforeAdmission
                && record.generation == 0
                && request.generation == 1
                && record.semantic_request_digest == request.semantic_request_digest,
        },
        Ok(None) => AdmissionReceiptQuery::unavailable("missing"),
        Err(AdmissionError::Ambiguous) => AdmissionReceiptQuery::unavailable("ambiguous"),
        Err(_) => AdmissionReceiptQuery::unavailable("unavailable"),
    }
}

#[derive(Clone, Debug)]
struct Receipt {
    paths: ReceiptPaths,
    ticket_digest: String,
    semantic_request_digest: String,
    execution_request_digest: String,
    generation: u32,
}

impl Receipt {
    fn begin(request: AdmissionRequest) -> Result<Self, AdmissionError> {
        let paths = ReceiptPaths::new(&request)?;
        with_lock(&paths, || {
            let existing = read_record(&paths, &request)?;
            let record = match existing {
                None if request.generation == 0 => {
                    ReceiptRecord::new(&request, AdmissionState::Preparing, /*generation*/ 0)
                }
                Some(existing)
                    if request.generation == 1
                        && existing.generation == 0
                        && existing.state == AdmissionState::RejectedBeforeAdmission
                        && existing.semantic_request_digest == request.semantic_request_digest =>
                {
                    ReceiptRecord::new(&request, AdmissionState::Preparing, /*generation*/ 1)
                }
                None | Some(_) => return Err(AdmissionError::NotEligible),
            };
            write_record(&paths, &record)?;
            let queued = ReceiptRecord {
                state: AdmissionState::PersistedQueued,
                ..record
            };
            write_record(&paths, &queued)
        })?;
        Ok(Self {
            paths,
            ticket_digest: request.ticket_digest,
            semantic_request_digest: request.semantic_request_digest,
            execution_request_digest: request.execution_request_digest,
            generation: request.generation,
        })
    }

    fn transition(
        &self,
        expected: AdmissionState,
        next: AdmissionState,
    ) -> Result<(), AdmissionError> {
        with_lock(&self.paths, || {
            let request = AdmissionRequest {
                agent_inbox_ticket_id: String::new(),
                ticket_digest: self.ticket_digest.clone(),
                semantic_request_prompt: String::new(),
                semantic_request_digest: self.semantic_request_digest.clone(),
                execution_request_digest: self.execution_request_digest.clone(),
                receipt_root: self.paths.root.clone(),
                generation: self.generation,
            };
            let record = read_record(&self.paths, &request)?.ok_or(AdmissionError::Ambiguous)?;
            if record.generation != self.generation
                || record.state != expected
                || record.semantic_request_digest != self.semantic_request_digest
                || record.execution_request_digest != self.execution_request_digest
            {
                return Err(AdmissionError::UnexpectedTransition);
            }
            write_record(
                &self.paths,
                &ReceiptRecord {
                    state: next,
                    ..record
                },
            )
        })
    }
}

#[derive(Clone, Debug)]
struct ReceiptPaths {
    root: PathBuf,
    receipt: PathBuf,
    temporary: PathBuf,
    lock: PathBuf,
}

impl ReceiptPaths {
    fn new(request: &AdmissionRequest) -> Result<Self, AdmissionError> {
        fs::create_dir_all(&request.receipt_root).map_err(|_| AdmissionError::Unavailable)?;
        Self::from_existing(request)
    }

    fn from_existing(request: &AdmissionRequest) -> Result<Self, AdmissionError> {
        let metadata =
            fs::symlink_metadata(&request.receipt_root).map_err(|_| AdmissionError::Unavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AdmissionError::Unavailable);
        }
        let root =
            fs::canonicalize(&request.receipt_root).map_err(|_| AdmissionError::Unavailable)?;
        let prefix = format!(
            ".agentapp-turn-admission-v{RECEIPT_VERSION}-{}",
            request.ticket_digest
        );
        Ok(Self {
            receipt: root.join(format!("{prefix}.json")),
            temporary: root.join(format!("{prefix}.json.tmp")),
            lock: root.join(format!("{prefix}.lock")),
            root,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptRecord {
    version: u32,
    generation: u32,
    ticket_digest: String,
    semantic_request_digest: String,
    execution_request_digest: String,
    state: AdmissionState,
}

impl ReceiptRecord {
    fn new(request: &AdmissionRequest, state: AdmissionState, generation: u32) -> Self {
        Self {
            version: RECEIPT_VERSION,
            generation,
            ticket_digest: request.ticket_digest.clone(),
            semantic_request_digest: request.semantic_request_digest.clone(),
            execution_request_digest: request.execution_request_digest.clone(),
            state,
        }
    }
}

struct ReceiptLock(File);

impl Drop for ReceiptLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn with_lock<T>(
    paths: &ReceiptPaths,
    operation: impl FnOnce() -> Result<T, AdmissionError>,
) -> Result<T, AdmissionError> {
    if matches!(fs::symlink_metadata(&paths.lock), Ok(metadata) if metadata.file_type().is_symlink())
    {
        return Err(AdmissionError::Unavailable);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&paths.lock)
        .map_err(|_| AdmissionError::Unavailable)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(AdmissionError::Unavailable);
    }
    let _lock = ReceiptLock(file);
    operation()
}

fn read_record(
    paths: &ReceiptPaths,
    request: &AdmissionRequest,
) -> Result<Option<ReceiptRecord>, AdmissionError> {
    if fs::symlink_metadata(&paths.temporary).is_ok() {
        return Err(AdmissionError::Ambiguous);
    }
    let metadata = match fs::symlink_metadata(&paths.receipt) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AdmissionError::Unavailable),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AdmissionError::Ambiguous);
    }
    let bytes = fs::read(&paths.receipt).map_err(|_| AdmissionError::Unavailable)?;
    let record: ReceiptRecord =
        serde_json::from_slice(&bytes).map_err(|_| AdmissionError::Ambiguous)?;
    if record.version != RECEIPT_VERSION
        || record.generation > 1
        || !is_canonical_digest(&record.ticket_digest)
        || !is_canonical_digest(&record.semantic_request_digest)
        || !is_canonical_digest(&record.execution_request_digest)
        || record.ticket_digest != request.ticket_digest
    {
        return Err(AdmissionError::Ambiguous);
    }
    Ok(Some(record))
}

fn write_record(paths: &ReceiptPaths, record: &ReceiptRecord) -> Result<(), AdmissionError> {
    if fs::symlink_metadata(&paths.temporary).is_ok() {
        return Err(AdmissionError::Ambiguous);
    }
    let bytes = serde_json::to_vec(record).map_err(|_| AdmissionError::Unavailable)?;
    let mut temporary = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&paths.temporary)
        .map_err(|_| AdmissionError::Unavailable)?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.sync_all())
        .map_err(|_| AdmissionError::Unavailable)?;
    fs::rename(&paths.temporary, &paths.receipt).map_err(|_| AdmissionError::Unavailable)?;
    File::open(&paths.root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AdmissionError::Unavailable)
}

fn is_canonical_digest(value: &str) -> bool {
    value.len() == DIGEST_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl AdmissionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::PersistedQueued => "persisted_queued",
            Self::RejectedBeforeAdmission => "rejected_before_admission",
            Self::ToolOrSideEffectPossible => "tool_or_side_effect_possible",
            Self::ModelRequestPossible => "model_request_possible",
            Self::Admitted => "admitted",
            Self::Terminal => "terminal",
        }
    }
}

#[cfg(test)]
#[path = "admission_receipt_tests.rs"]
mod tests;
