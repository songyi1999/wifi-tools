//! Global event log shared by the web UI, worker tasks and the tracing mirror.
//! A single ring buffer with monotonically increasing sequence ids so the
//! frontend can poll incrementally with `?since=<id>`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

pub struct EventLog {
    buf: Mutex<VecDeque<(u64, String)>>,
    seq: AtomicU64,
    cap: usize,
}

impl EventLog {
    pub fn new() -> Self {
        Self {
            buf: Mutex::new(VecDeque::new()),
            seq: AtomicU64::new(0),
            cap: 3000,
        }
    }

    pub fn push(&self, msg: impl Into<String>) {
        let id = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let mut buf = self.buf.lock().unwrap();
        buf.push_back((id, msg.into()));
        while buf.len() > self.cap {
            buf.pop_front();
        }
    }

    /// Events with id > since, plus the current last id.
    pub fn since(&self, since: u64) -> (u64, Vec<String>) {
        let buf = self.buf.lock().unwrap();
        let events: Vec<String> = buf
            .iter()
            .filter(|(id, _)| *id > since)
            .map(|(_, m)| m.clone())
            .collect();
        let last = buf.back().map(|(id, _)| *id).unwrap_or(since);
        (last, events)
    }
}

static GLOBAL: OnceLock<EventLog> = OnceLock::new();

pub fn global() -> &'static EventLog {
    GLOBAL.get_or_init(EventLog::new)
}
