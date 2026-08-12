use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::sync::watch;

use super::ChannelCommand;
use super::ExecProcessImpl;
use super::PROCESS_EVENT_CHANNEL_CAPACITY;
use super::RETAINED_OUTPUT_BYTES_PER_PROCESS;
use super::SharedState;
use super::SshProcess;
use crate::ProcessId;
use crate::process::ExecProcessEventLog;
use crate::protocol::ProcessSignal;

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
    ack.send(Ok(())).expect("deliver acknowledgement");

    signalling
        .await
        .expect("signal task")
        .expect("acknowledged signal");
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
