use std::{
    sync::mpsc::{self, RecvTimeoutError},
    time::Duration,
};

#[derive(Clone, Debug, PartialEq)]
pub enum TestKind {
    /// Test will pass if a success has been notified in the test duration
    ExpectSuccess,
    /// Test will pass if no failure has been notified in the test duration
    ExpectNoFailure,
}

#[derive(Clone, Debug)] // mpsc channels are clone-able to be shared between threads
pub struct StatusNotifier {
    kind: TestKind,
    tx: mpsc::SyncSender<()>,
}

impl StatusNotifier {
    pub fn notify_success(&self) {
        if self.kind == TestKind::ExpectSuccess {
            // A full or disconnected receiver is expected: the callback can
            // outlive the function that started the trace
            let _ = self.tx.try_send(());
        }
    }

    #[allow(dead_code)]
    pub fn notify_failure(&self) {
        if self.kind == TestKind::ExpectNoFailure {
            // See notify_success: send errors are expected here
            let _ = self.tx.try_send(());
        }
    }
}

#[derive(Debug)]
pub struct Status {
    notifier: StatusNotifier,
    rx: mpsc::Receiver<()>,
}

impl Status {
    pub fn new(kind: TestKind) -> Self {
        let (tx, rx) = mpsc::sync_channel(1);
        Self {
            notifier: StatusNotifier { kind, tx },
            rx,
        }
    }

    pub fn notifier(&self) -> StatusNotifier {
        self.notifier.clone()
    }

    pub fn assert_passed(&self) {
        let timeout = Duration::from_secs(10);

        match self.notifier.kind {
            TestKind::ExpectSuccess => match self.rx.recv_timeout(timeout) {
                Ok(()) => {},
                Err(RecvTimeoutError::Timeout) => {
                    panic!("Test did not pass within the allowed timeout");
                },
                _ => panic!("Should not happen, the sending end has not hung up."),
            },

            TestKind::ExpectNoFailure => match self.rx.recv_timeout(timeout) {
                Ok(()) => {
                    panic!("Test failed within the allowed timeout");
                },
                Err(RecvTimeoutError::Timeout) => {},
                _ => panic!("Should not happen, the sending end has not hung up."),
            },
        }
    }
}
