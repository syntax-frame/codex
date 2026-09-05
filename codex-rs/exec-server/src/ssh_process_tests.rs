use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use pretty_assertions::assert_eq;
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::watch;

use super::ChannelCommand;
use super::ExecProcessImpl;
use super::PROCESS_EVENT_CHANNEL_CAPACITY;
use super::RETAINED_OUTPUT_BYTES_PER_PROCESS;
use super::SSH_SIGNAL_ACK_TIMEOUT;
use super::SSH_TERMINATE_ACK_TIMEOUT;
use super::SSH_WRITE_ACK_TIMEOUT;
use super::SharedState;
use super::SshProcess;
use super::complete_queued_write;
use crate::ExecServerError;
use crate::ProcessId;
use crate::ProcessSignalOutcome;
use crate::ProcessSignalRejectionReason;
use crate::process::ExecProcessEventLog;
use crate::protocol::ProcessSignal;
use crate::protocol::WriteResponse;
use crate::protocol::WriteStatus;

fn process_with_command_pump() -> (Arc<SshProcess>, mpsc::Receiver<ChannelCommand>) {
    let (cmd_tx, cmd_rx) = mpsc::channel(1);
    let (wake_tx, _wake_rx) = watch::channel(0);
    (
        Arc::new(SshProcess {
            process_id: ProcessId::from("process"),
            events: ExecProcessEventLog::new(
                PROCESS_EVENT_CHANNEL_CAPACITY,
                RETAINED_OUTPUT_BYTES_PER_PROCESS,
            ),
            wake_tx,
            output_notify: Arc::new(Notify::new()),
            state: Arc::new(StdMutex::new(SharedState::default())),
            cmd_tx,
        }),
        cmd_rx,
    )
}

fn assert_unknown_write_timeout(error: ExecServerError) {
    let ExecServerError::Protocol(message) = error else {
        panic!("expected an unknown-outcome protocol error");
    };
    assert_eq!(
        message,
        "ssh stdin write acknowledgement timed out; remote outcome is unknown"
    );
}

#[tokio::test]
async fn write_waits_for_remote_acknowledgement() {
    let (process, mut commands) = process_with_command_pump();
    let writing = tokio::spawn(async move {
        ExecProcessImpl::write_with_id(
            process.as_ref(),
            b"input".to_vec(),
            Some("write-receipt".to_string()),
        )
        .await
    });
    let Some(ChannelCommand::Write {
        data,
        write_id,
        ack,
    }) = commands.recv().await
    else {
        panic!("expected queued write");
    };
    assert_eq!(
        (data, write_id),
        (b"input".to_vec(), Some("write-receipt".to_string()))
    );
    assert!(!writing.is_finished());
    complete_queued_write(ack, async { Ok(()) }).await;
    assert_eq!(
        writing
            .await
            .expect("write task")
            .expect("acknowledged write"),
        WriteResponse {
            status: WriteStatus::Accepted
        }
    );
}

#[tokio::test(start_paused = true)]
async fn write_timeout_discards_unconsumed_input_before_late_pump_delivery() {
    let (process, mut commands) = process_with_command_pump();
    let writing =
        tokio::spawn(
            async move { ExecProcessImpl::write(process.as_ref(), b"input".to_vec()).await },
        );
    tokio::task::yield_now().await;
    assert_eq!(commands.len(), 1);
    tokio::time::advance(SSH_WRITE_ACK_TIMEOUT + Duration::from_secs(1)).await;
    assert_unknown_write_timeout(
        writing
            .await
            .expect("write task")
            .expect_err("write must time out"),
    );

    let Some(ChannelCommand::Write { ack, .. }) = commands.recv().await else {
        panic!("expected timed-out queued write");
    };
    assert!(ack.is_closed());
    let mut delivered = false;
    complete_queued_write(ack, async {
        delivered = true;
        Ok(())
    })
    .await;
    assert!(
        !delivered,
        "production pump gate must not poll expired input"
    );
    assert!(
        commands.recv().await.is_none(),
        "write must not be replayed"
    );
}

#[tokio::test(start_paused = true)]
async fn write_timeout_includes_full_command_queue() {
    let (process, mut commands) = process_with_command_pump();
    let (ack, _receiver) = oneshot::channel();
    process
        .cmd_tx
        .send(ChannelCommand::Terminate { ack })
        .await
        .expect("fill queue");
    let writing =
        tokio::spawn(
            async move { ExecProcessImpl::write(process.as_ref(), b"input".to_vec()).await },
        );
    tokio::task::yield_now().await;
    tokio::time::advance(SSH_WRITE_ACK_TIMEOUT + Duration::from_secs(1)).await;
    assert_unknown_write_timeout(
        writing
            .await
            .expect("write task")
            .expect_err("full queue must time out"),
    );
    assert!(matches!(
        commands.recv().await,
        Some(ChannelCommand::Terminate { .. })
    ));
    assert!(
        commands.recv().await.is_none(),
        "expired write must never enter the queue"
    );
}

#[tokio::test(start_paused = true)]
async fn write_timeout_preserves_unknown_outcome_after_delivery_begins() {
    let (process, mut commands) = process_with_command_pump();
    let writing =
        tokio::spawn(
            async move { ExecProcessImpl::write(process.as_ref(), b"input".to_vec()).await },
        );
    let Some(ChannelCommand::Write { ack, .. }) = commands.recv().await else {
        panic!("expected queued write");
    };
    let (started, started_rx) = oneshot::channel();
    let (finish, finish_rx) = oneshot::channel();
    let delivery = tokio::spawn(complete_queued_write(ack, async move {
        started.send(()).expect("signal delivery began");
        finish_rx.await.expect("finish delivery");
        Ok(())
    }));
    started_rx.await.expect("delivery began");
    tokio::time::advance(SSH_WRITE_ACK_TIMEOUT + Duration::from_secs(1)).await;
    assert_unknown_write_timeout(
        writing
            .await
            .expect("write task")
            .expect_err("in-flight write must time out"),
    );
    finish.send(()).expect("allow late remote acknowledgement");
    delivery.await.expect("delivery task");
    assert!(
        commands.recv().await.is_none(),
        "uncertain input must not be replayed"
    );
}

#[tokio::test]
async fn signal_waits_for_remote_acknowledgement() {
    let (process, mut commands) = process_with_command_pump();
    let signalling = tokio::spawn(async move {
        ExecProcessImpl::signal(process.as_ref(), ProcessSignal::Interrupt).await
    });

    let Some(ChannelCommand::Signal { ack, .. }) = commands.recv().await else {
        panic!("expected acknowledged signal");
    };
    assert!(!signalling.is_finished());
    ack.send(Ok(ProcessSignalOutcome::Accepted))
        .expect("deliver acknowledgement");

    assert_eq!(
        signalling
            .await
            .expect("signal task")
            .expect("acknowledged signal"),
        ProcessSignalOutcome::Accepted
    );
}

#[tokio::test]
async fn signal_preserves_typed_pre_delivery_rejection() {
    let (process, mut commands) = process_with_command_pump();
    let signalling = tokio::spawn(async move {
        ExecProcessImpl::signal(process.as_ref(), ProcessSignal::Interrupt).await
    });

    let Some(ChannelCommand::Signal { ack, .. }) = commands.recv().await else {
        panic!("expected acknowledged signal");
    };
    ack.send(Ok(ProcessSignalOutcome::RejectedBeforeDelivery(
        ProcessSignalRejectionReason::OwnershipMismatch,
    )))
    .expect("deliver rejection");

    assert_eq!(
        signalling
            .await
            .expect("signal task")
            .expect("typed rejection"),
        ProcessSignalOutcome::RejectedBeforeDelivery(
            ProcessSignalRejectionReason::OwnershipMismatch
        )
    );
}

#[tokio::test]
async fn signal_propagates_remote_failure() {
    let (process, mut commands) = process_with_command_pump();
    let signalling = tokio::spawn(async move {
        ExecProcessImpl::signal(process.as_ref(), ProcessSignal::Interrupt).await
    });

    let Some(ChannelCommand::Signal { ack, .. }) = commands.recv().await else {
        panic!("expected acknowledged signal");
    };
    ack.send(Err("remote interrupt failed".to_string()))
        .expect("deliver failure");

    let error = signalling
        .await
        .expect("signal task")
        .expect_err("signal must fail");
    assert!(error.to_string().contains("remote interrupt failed"));
}

#[tokio::test(start_paused = true)]
async fn signal_times_out_without_remote_acknowledgement() {
    let (process, mut commands) = process_with_command_pump();
    let signalling = tokio::spawn(async move {
        ExecProcessImpl::signal(process.as_ref(), ProcessSignal::Interrupt).await
    });

    let Some(ChannelCommand::Signal { ack: _ack, .. }) = commands.recv().await else {
        panic!("expected acknowledged signal");
    };
    tokio::time::advance(std::time::Duration::from_secs(31)).await;

    let error = signalling
        .await
        .expect("signal task")
        .expect_err("signal must time out");
    assert!(error.to_string().contains("timed out"));
}

#[tokio::test]
async fn terminate_waits_for_remote_acknowledgement() {
    let (process, mut commands) = process_with_command_pump();
    let termination =
        tokio::spawn(async move { ExecProcessImpl::terminate(process.as_ref()).await });

    let Some(ChannelCommand::Terminate { ack }) = commands.recv().await else {
        panic!("expected acknowledged termination");
    };
    assert!(!termination.is_finished());
    ack.send(Ok(())).expect("deliver acknowledgement");

    termination
        .await
        .expect("termination task")
        .expect("acknowledged termination");
}

#[tokio::test(start_paused = true)]
async fn signal_timeout_includes_full_command_queue() {
    let (process, mut commands) = process_with_command_pump();
    let (ack, _receiver) = oneshot::channel();
    process
        .cmd_tx
        .send(ChannelCommand::Terminate { ack })
        .await
        .expect("fill queue");
    let signalling = tokio::spawn(async move {
        ExecProcessImpl::signal(process.as_ref(), ProcessSignal::Interrupt).await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(SSH_SIGNAL_ACK_TIMEOUT + Duration::from_secs(1)).await;
    let ExecServerError::Protocol(message) = signalling
        .await
        .expect("signal task")
        .expect_err("full queue must time out")
    else {
        panic!("expected signal timeout protocol error");
    };
    assert_eq!(message, "ssh signal acknowledgement timed out");
    assert!(matches!(
        commands.recv().await,
        Some(ChannelCommand::Terminate { .. })
    ));
    assert!(
        commands.recv().await.is_none(),
        "expired signal must not enter the queue"
    );
}

#[tokio::test(start_paused = true)]
async fn terminate_timeout_includes_full_command_queue() {
    let (process, mut commands) = process_with_command_pump();
    let (ack, _receiver) = oneshot::channel();
    process
        .cmd_tx
        .send(ChannelCommand::Write {
            data: b"earlier input".to_vec(),
            write_id: None,
            ack,
        })
        .await
        .expect("fill queue");
    let termination =
        tokio::spawn(async move { ExecProcessImpl::terminate(process.as_ref()).await });
    tokio::task::yield_now().await;
    tokio::time::advance(SSH_TERMINATE_ACK_TIMEOUT + Duration::from_secs(1)).await;
    let ExecServerError::Protocol(message) = termination
        .await
        .expect("termination task")
        .expect_err("full queue must time out")
    else {
        panic!("expected termination timeout protocol error");
    };
    assert_eq!(
        message,
        "ssh terminate failed: timed out awaiting remote acknowledgement"
    );
    assert!(matches!(
        commands.recv().await,
        Some(ChannelCommand::Write { .. })
    ));
    assert!(
        commands.recv().await.is_none(),
        "expired termination must not enter the queue"
    );
}

#[tokio::test]
async fn terminate_propagates_remote_failure() {
    let (process, mut commands) = process_with_command_pump();
    let termination =
        tokio::spawn(async move { ExecProcessImpl::terminate(process.as_ref()).await });

    let Some(ChannelCommand::Terminate { ack }) = commands.recv().await else {
        panic!("expected acknowledged termination");
    };
    ack.send(Err("remote kill failed".to_string()))
        .expect("deliver failure");

    let error = termination
        .await
        .expect("termination task")
        .expect_err("termination must fail");
    assert!(error.to_string().contains("remote kill failed"));
}

#[tokio::test(start_paused = true)]
async fn terminate_times_out_without_remote_acknowledgement() {
    let (process, mut commands) = process_with_command_pump();
    let termination =
        tokio::spawn(async move { ExecProcessImpl::terminate(process.as_ref()).await });

    let Some(ChannelCommand::Terminate { ack: _ack }) = commands.recv().await else {
        panic!("expected acknowledged termination");
    };
    tokio::time::advance(std::time::Duration::from_secs(31)).await;

    let error = termination
        .await
        .expect("termination task")
        .expect_err("termination must time out");
    assert!(error.to_string().contains("timed out"));
}
