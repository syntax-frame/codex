use crate::ContextEvent;
use crate::ForkRequest;
use crate::ForkSeed;

#[derive(Debug, Clone, PartialEq)]
pub struct AppendEventsRequest {
    pub conversation_id: String,
    pub expected_next_sequence: u64,
    pub events: Vec<ContextEvent>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LoadEventsRequest {
    pub conversation_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredEvents {
    pub conversation_id: String,
    pub events: Vec<ContextEvent>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommitCompactionRequest {
    pub conversation_id: String,
    pub expected_last_sequence: u64,
    /// The immutable journal event whose payload is the new checkpoint.
    /// Supplying its identity makes an interrupted commit idempotent.
    pub checkpoint_event: ContextEvent,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ForkCommitRequest {
    pub request: ForkRequest,
    pub seed: ForkSeed,
}

/// Durable storage boundary for the context engine.
///
/// Implementations append immutable events. `commit_compaction` must publish a
/// checkpoint atomically against `expected_last_sequence`; it must never erase
/// transcript events. `commit_fork` must create the target and its lineage in
/// one transaction so a crash cannot expose a transcript-only fork.
pub trait ContextStore: Send + Sync {
    type Error: Send + Sync + 'static;

    fn append_events(
        &self,
        request: AppendEventsRequest,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    fn load_events(
        &self,
        request: LoadEventsRequest,
    ) -> impl std::future::Future<Output = Result<StoredEvents, Self::Error>> + Send;

    fn commit_compaction(
        &self,
        request: CommitCompactionRequest,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    fn commit_fork(
        &self,
        request: ForkCommitRequest,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
}
