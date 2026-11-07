//! logging: tracing init (daily rolling file + stdout).

use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::prelude::*;

/// Initialise tracing with a daily-rolling file layer + stdout layer.
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
        .init();

    guard
}
