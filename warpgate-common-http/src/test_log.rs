//! Captures what the code under test writes to the log, for tests that assert
//! on log lines.

use std::fmt::Write;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// Every field of every event, as `name=value` pairs.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<String>>);

impl Visit for Captured {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if let Ok(mut out) = self.0.lock() {
            let _ = write!(out, "{}={:?} ", field.name(), value);
        }
    }
}

impl Subscriber for Captured {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        event.record(&mut self.clone());
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// Everything `f` logs on this thread.
pub fn logged(f: impl FnOnce()) -> String {
    let captured = Captured::default();
    tracing::subscriber::with_default(captured.clone(), f);
    captured
        .0
        .lock()
        .map(|out| out.clone())
        .unwrap_or_default()
}
