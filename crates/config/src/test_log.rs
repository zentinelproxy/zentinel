//! Reads the warnings a piece of code logs, for tests.
//!
//! The parsers report what they load through `tracing`, so a test that wants
//! to know "was this said when the file was loaded" has to listen. The config
//! crate has no subscriber of its own, so this one is small: it keeps the text
//! of every `WARN` event emitted on the calling thread.

use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

#[derive(Default)]
struct MessageOf(String);

impl Visit for MessageOf {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

struct Collector(Arc<Mutex<Vec<String>>>);

impl Subscriber for Collector {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= Level::WARN
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if *event.metadata().level() == Level::WARN {
            let mut message = MessageOf::default();
            event.record(&mut message);
            self.0
                .lock()
                .expect("the warning list is only locked to push")
                .push(message.0);
        }
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// Runs `run` and returns what it produced with the text of every warning it
/// logged on this thread.
pub(crate) fn warnings_logged_by<T>(run: impl FnOnce() -> T) -> (T, Vec<String>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let result = tracing::subscriber::with_default(Collector(Arc::clone(&seen)), run);
    let warnings = seen
        .lock()
        .expect("the warning list is only locked to push")
        .clone();
    (result, warnings)
}
