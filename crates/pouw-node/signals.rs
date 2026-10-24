//! Shutdown on a signal. The signal thread blocks until the process gets one of
//! [`SHUTDOWN_SIGNALS`], then sends [`Control::Shutdown`] to the node loop, which is the
//! only way [`crate::node::run`] returns `Ok`. `main` registers the handlers with
//! `Signals::new(SHUTDOWN_SIGNALS)` before any other thread starts, so no signal arrives while the default action is
//! still in place.
//!
//! `signal-hook` is a blocking, runtime-free library with two dependencies already in
//! the tree (`libc`, `signal-hook-registry`), which fits a thread that only waits.

use std::os::raw::c_int;

use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use tokio::sync::mpsc;
use tracing::info;

use crate::node::{ComponentFault, Control, to_control};

/// The signals that stop the node.
pub const SHUTDOWN_SIGNALS: [c_int; 2] = [SIGINT, SIGTERM];

/// The signal thread: waits for the first signal and tells the loop to shut down. The
/// control channel has room for it ([`crate::node::CONTROL_CAPACITY`]).
pub fn run(mut signals: Signals, control: &mpsc::Sender<Control>) -> Result<(), ComponentFault> {
    if let Some(signal) = signals.forever().next() {
        info!(signal, "shutdown requested");
        to_control(control, Control::Shutdown)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use signal_hook::{consts::SIGUSR1, low_level};

    use super::*;
    use crate::node;

    #[test]
    fn the_first_signal_becomes_a_shutdown_event() {
        let signals = Signals::new([SIGUSR1]).unwrap();
        let (control, mut inbox) = mpsc::channel(node::CONTROL_CAPACITY);
        low_level::raise(SIGUSR1).unwrap();
        run(signals, &control).unwrap();
        assert!(matches!(inbox.try_recv(), Ok(Control::Shutdown)));
        assert!(inbox.try_recv().is_err());
    }
}
