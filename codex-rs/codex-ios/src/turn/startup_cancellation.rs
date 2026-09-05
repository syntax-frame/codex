use std::os::raw::c_void;

use tokio::sync::Mutex;
use tokio::sync::MutexGuard;

use super::EventCallback;
use super::KIND_TURN_ABORTED;
use super::TurnAdmission;
use super::TurnBridge;
use super::active_turn_registry;
use super::emit;
use super::startup_interrupt_requested;

/// Cancels only the context-lock waiter, before this call owns a native thread.
/// Dropping a thread-construction future would abandon reconciliation work, so
/// later startup stages observe interruption at completed-operation boundaries.
pub(super) async fn acquire_startup_context_lock(
    turn_handle: u64,
    turn_lock: &Mutex<()>,
) -> Result<Option<MutexGuard<'_, ()>>, String> {
    let mut interrupted = {
        let registry = active_turn_registry()
            .lock()
            .map_err(|_| "active turn registry poisoned".to_string())?;
        match registry.get(&turn_handle) {
            Some(TurnBridge::Starting {
                interrupt_signal, ..
            }) => interrupt_signal.subscribe(),
            Some(TurnBridge::Active { .. }) => {
                return Err("turn handle was already activated".to_string());
            }
            None => return Err("unknown or finished turn handle".to_string()),
        }
    };
    tokio::select! {
        biased;
        result = interrupted.wait_for(|requested| *requested) => {
            result.map_err(|_| "turn handle was removed during startup".to_string())?;
            Ok(None)
        }
        guard = turn_lock.lock() => Ok(Some(guard)),
    }
}

/// Finalizes a stopped startup only when no operation is still in flight.
pub(super) fn abort_interrupted_startup(
    turn_handle: u64,
    admission: &mut Option<TurnAdmission>,
    callback: EventCallback,
    ctx: *mut c_void,
) -> Result<bool, String> {
    if !startup_interrupt_requested(turn_handle)? {
        return Ok(false);
    }
    if let Some(admission) = admission.as_mut() {
        admission
            .mark_terminal()
            .map_err(|error| error.to_string())?;
    }
    emit(callback, ctx, KIND_TURN_ABORTED, "");
    Ok(true)
}
