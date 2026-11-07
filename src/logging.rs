//! logging: tracing init (daily rolling file + stdout + mirror into the web event log).

use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

/// Forwards every tracing event into the global web event log so the UI log
/// shows everything (scan rounds, WPS attempts, crack progress, ...).
struct MirrorLayer;

struct MsgVisitor(String);

impl tracing::field::Visit for MsgVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        } else {
            self.0.push_str(&format!(" {}={:?}", field.name(), value));
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        } else {
            self.0.push_str(&format!(" {}={}", field.name(), value));
        }
    }
}

impl<S> tracing_subscriber::Layer<S> for MirrorLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut v = MsgVisitor(String::new());
        event.record(&mut v);
        let time = chrono::Local::now().format("%H:%M:%S");
        crate::events::global()
            .push(format!("[{}] {} {}", time, event.metadata().level(), v.0));
    }
}

/// Initialise tracing with a daily-rolling file layer + stdout layer + web mirror.
/// Panics only if the background writer thread cannot spawn (process is broken anyway).
pub fn init(logs_dir: &Path) -> WorkerGuard {
    let _ = std::fs::create_dir_all(logs_dir);
    let file_appender = tracing_appender::rolling::daily(logs_dir, "wifi-toolkit.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_writer)
        .with_ansi(false)
        .with_target(false);

    let stdout_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stdout_layer)
        .with(MirrorLayer)
        .init();

    guard
}
