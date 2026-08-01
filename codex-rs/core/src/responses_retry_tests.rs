use super::ResponsesStreamRequest;
use super::fallback_warning_message;
use super::log_retry;
use crate::session::tests::make_session_and_context;
use codex_protocol::error::CodexErr;
use std::time::Duration;
use tracing_test::internal::MockWriter;

#[tokio::test]
async fn sampling_retry_logs_stream_error_context() {
    let (_session, turn_context) = make_session_and_context().await;
    let buffer: &'static std::sync::Mutex<Vec<u8>> =
        Box::leak(Box::new(std::sync::Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(MockWriter::new(buffer))
        .finish();
    let _subscriber_guard = tracing::subscriber::set_default(subscriber);

    log_retry(
        ResponsesStreamRequest::Sampling,
        &turn_context,
        &CodexErr::Stream(
            "websocket closed by server before response.completed".to_string(),
            None,
        ),
        /*retries*/ 2,
        /*max_retries*/ 5,
        Duration::from_secs(1),
        /*protect_arguments*/ false,
    );

    let logs = String::from_utf8(
        buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    )
    .expect("retry log should be valid utf-8");
    assert!(logs.contains("stream disconnected - retrying sampling request"));
    assert!(logs.contains(&format!("turn_id={}", turn_context.sub_id)));
    assert!(logs.contains("retries=2"));
    assert!(logs.contains("max_retries=5"));
    assert!(logs.contains(
        "sampling_error=stream disconnected before completion: websocket closed by server before response.completed"
    ));
}

#[tokio::test]
async fn protected_retry_and_fallback_diagnostics_never_include_provider_text() {
    const SENTINEL: &str = "RAW_BROWSER_ARGUMENT_SENTINEL";
    let (_session, turn_context) = make_session_and_context().await;
    let buffer: &'static std::sync::Mutex<Vec<u8>> =
        Box::leak(Box::new(std::sync::Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(MockWriter::new(buffer))
        .finish();
    let _subscriber_guard = tracing::subscriber::set_default(subscriber);
    let error = CodexErr::Stream(format!("provider reflected {SENTINEL}"), None);

    for request in [
        ResponsesStreamRequest::Sampling,
        ResponsesStreamRequest::RemoteCompactionV2,
    ] {
        log_retry(
            request,
            &turn_context,
            &error,
            /*retries*/ 2,
            /*max_retries*/ 5,
            Duration::from_secs(1),
            /*protect_arguments*/ true,
        );
    }

    let warning = fallback_warning_message(&error, /*protect_arguments*/ true);
    let logs = String::from_utf8(
        buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    )
    .expect("protected retry log should be valid utf-8");
    assert!(!logs.contains(SENTINEL));
    assert!(!warning.contains(SENTINEL));
    assert!(logs.contains("protected stream disconnected"));
    assert!(logs.contains("protected remote compaction v2 stream failed"));
    assert!(warning.contains("protected turn"));
}
