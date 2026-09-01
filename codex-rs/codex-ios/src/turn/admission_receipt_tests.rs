use std::sync::Arc;
use std::sync::Barrier;

use super::AdmissionError;
use super::AdmissionRequest;
use super::AdmissionState;
use super::ReceiptPaths;
use super::ReceiptRecord;
use super::TurnAdmission;
use super::query;
use super::write_record;

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn request(
    root: &std::path::Path,
    ticket: &str,
    digest_byte: char,
    generation: u32,
) -> AdmissionRequest {
    AdmissionRequest::new(
        ticket.to_string(),
        digest(digest_byte),
        digest('f'),
        root.to_string_lossy().into_owned(),
        generation,
    )
    .expect("valid request")
}

#[test]
fn atomically_persists_and_reopens_a_queued_receipt() {
    let root = tempfile::tempdir().expect("receipt root");
    let request = request(root.path(), "ticket-a", 'a', 0);

    let admission = TurnAdmission::begin(request.clone()).expect("admit original");
    assert!(admission.is_pre_admission());

    assert_eq!(
        serde_json::to_value(query(&request)).expect("query JSON"),
        serde_json::json!({
            "contract_version": 1,
            "receipt_version": 2,
            "state": "persisted_queued",
            "generation": 0,
            "digest_match": true,
            "authorizes_generation_one_start": false,
        })
    );
}

#[test]
fn crash_in_preparing_is_ambiguous_and_never_retryable() {
    let root = tempfile::tempdir().expect("receipt root");
    let original = request(root.path(), "ticket-a", 'a', 0);
    let paths = ReceiptPaths::new(&original).expect("paths");
    write_record(
        &paths,
        &ReceiptRecord::new(&original, AdmissionState::Preparing, /*generation*/ 0),
    )
    .expect("persist preparing crash state");

    assert_eq!(
        TurnAdmission::begin(request(root.path(), "ticket-a", 'a', 1)).expect_err("retry denied"),
        AdmissionError::NotEligible
    );
}

#[test]
fn retry_requires_the_same_semantic_digest() {
    let root = tempfile::tempdir().expect("receipt root");
    let original = request(root.path(), "ticket-a", 'a', 0);
    let mut admission = TurnAdmission::begin(original).expect("admit original");
    admission
        .mark_rejected_before_admission()
        .expect("durable rejection");
    let mismatched = request(root.path(), "ticket-a", 'b', 1);

    assert_eq!(
        TurnAdmission::begin(mismatched.clone()).expect_err("mismatch denied"),
        AdmissionError::NotEligible
    );
    assert_eq!(
        serde_json::to_value(query(&mismatched)).expect("query JSON"),
        serde_json::json!({
            "contract_version": 1,
            "receipt_version": 2,
            "state": "rejected_before_admission",
            "generation": 0,
            "digest_match": false,
            "authorizes_generation_one_start": false,
        })
    );
}

#[test]
fn generation_is_bounded_and_one_retry_is_consumed_once() {
    let root = tempfile::tempdir().expect("receipt root");
    assert_eq!(
        AdmissionRequest::new(
            "ticket-a".to_string(),
            digest('a'),
            digest('f'),
            root.path().to_string_lossy().into_owned(),
            2,
        )
        .expect_err("generation two rejected"),
        AdmissionError::InvalidRequest
    );

    let original = request(root.path(), "ticket-a", 'a', 0);
    let mut admission = TurnAdmission::begin(original).expect("admit original");
    admission
        .mark_rejected_before_admission()
        .expect("durable rejection");
    let retry = request(root.path(), "ticket-a", 'a', 1);
    assert_eq!(
        serde_json::to_value(query(&retry)).expect("query JSON"),
        serde_json::json!({
            "contract_version": 1,
            "receipt_version": 2,
            "state": "rejected_before_admission",
            "generation": 0,
            "digest_match": false,
            "authorizes_generation_one_start": true,
        })
    );
    let _retry = TurnAdmission::begin(retry.clone()).expect("admit sole retry");

    assert_eq!(
        TurnAdmission::begin(retry).expect_err("duplicate retry denied"),
        AdmissionError::NotEligible
    );
}

#[test]
fn sole_retry_binds_its_own_exact_execution_digest() {
    let root = tempfile::tempdir().expect("receipt root");
    let original = request(root.path(), "ticket-a", 'a', 0);
    let mut admission = TurnAdmission::begin(original).expect("admit original");
    admission
        .mark_rejected_before_admission()
        .expect("durable rejection");
    let retry = AdmissionRequest::new(
        "ticket-a".to_string(),
        digest('a'),
        digest('e'),
        root.path().to_string_lossy().into_owned(),
        1,
    )
    .expect("valid retry");
    let _retry = TurnAdmission::begin(retry.clone()).expect("admit retry");

    assert_eq!(
        serde_json::to_value(query(&retry)).expect("query JSON"),
        serde_json::json!({
            "contract_version": 1,
            "receipt_version": 2,
            "state": "persisted_queued",
            "generation": 1,
            "digest_match": true,
            "authorizes_generation_one_start": false,
        })
    );
}

#[test]
fn same_ticket_concurrency_admits_only_one_original() {
    let root = Arc::new(tempfile::tempdir().expect("receipt root"));
    let barrier = Arc::new(Barrier::new(8));
    // All workers must exist before any joins, or the barrier can deadlock.
    #[allow(clippy::needless_collect)]
    let workers = (0..8)
        .map(|_| {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                TurnAdmission::begin(request(root.path(), "ticket-a", 'a', 0)).is_ok()
            })
        })
        .collect::<Vec<_>>();
    let admitted = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .filter(|admitted| *admitted)
        .count();

    assert_eq!(admitted, 1);
}

#[test]
fn transitions_preserve_the_only_retryable_pre_admission_state() {
    let root = tempfile::tempdir().expect("receipt root");
    let request = request(root.path(), "ticket-a", 'a', 0);
    let mut admission = TurnAdmission::begin(request.clone()).expect("admit original");

    assert_eq!(
        admission.mark_admitted().expect_err("admit ordering"),
        AdmissionError::UnexpectedTransition
    );
    admission
        .mark_model_request_possible()
        .expect("persist before model request");
    assert_eq!(
        admission
            .mark_rejected_before_admission()
            .expect_err("cannot reopen after model request"),
        AdmissionError::UnexpectedTransition
    );
    admission.mark_admitted().expect("mark admitted");
    admission.mark_terminal().expect("mark terminal");
    assert!(admission.is_finalized());
    assert_eq!(
        serde_json::to_value(query(&request)).expect("query JSON"),
        serde_json::json!({
            "contract_version": 1,
            "receipt_version": 2,
            "state": "terminal",
            "generation": 0,
            "digest_match": true,
            "authorizes_generation_one_start": false,
        })
    );
}

#[test]
fn remote_or_tool_side_effect_boundary_is_never_retryable() {
    let root = tempfile::tempdir().expect("receipt root");
    let request = request(root.path(), "ticket-a", 'a', 0);
    let mut admission = TurnAdmission::begin(request.clone()).expect("admit original");

    admission
        .mark_tool_or_side_effect_possible()
        .expect("persist side-effect boundary");
    assert_eq!(
        admission
            .mark_rejected_before_admission()
            .expect_err("side effects cannot reopen retry"),
        AdmissionError::UnexpectedTransition
    );
    assert_eq!(
        serde_json::to_value(query(&request)).expect("query JSON"),
        serde_json::json!({
            "contract_version": 1,
            "receipt_version": 2,
            "state": "tool_or_side_effect_possible",
            "generation": 0,
            "digest_match": true,
            "authorizes_generation_one_start": false,
        })
    );

    admission
        .mark_model_request_possible()
        .expect("advance to model boundary");
    admission.mark_admitted().expect("mark admitted");
    admission.mark_terminal().expect("mark terminal");
}

#[test]
fn malformed_or_incomplete_atomic_writes_fail_closed() {
    let root = tempfile::tempdir().expect("receipt root");
    let request = request(root.path(), "ticket-a", 'a', 0);
    let paths = ReceiptPaths::new(&request).expect("paths");
    std::fs::write(&paths.temporary, b"partial receipt").expect("simulate interrupted write");

    assert_eq!(
        TurnAdmission::begin(request.clone()).expect_err("ambiguous receipt denied"),
        AdmissionError::Ambiguous
    );
    assert_eq!(
        serde_json::to_value(query(&request)).expect("query JSON"),
        serde_json::json!({
            "contract_version": 1,
            "receipt_version": 0,
            "state": "ambiguous",
            "generation": 0,
            "digest_match": false,
            "authorizes_generation_one_start": false,
        })
    );
}
