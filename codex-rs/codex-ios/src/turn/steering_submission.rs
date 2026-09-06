use std::os::raw::c_int;

use codex_core::SteerInputError;

/// These typed errors leave Session's input queue unchanged. In particular,
/// turnReady can precede creation of its active task after UserInput is queued.
/// Keep that unavailable result distinct from the FFI's unknown panic outcome.
pub(super) fn rejected_input_code(error: SteerInputError) -> c_int {
    match error {
        SteerInputError::NoActiveTurn(_)
        | SteerInputError::ExpectedTurnMismatch { .. }
        | SteerInputError::ActiveTurnNotSteerable { .. } => 6,
        SteerInputError::EmptyInput => 2,
    }
}
