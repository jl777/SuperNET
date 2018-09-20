//! Human-readable logging and statuses.

#[cfg(test)]
mod test {
    use super::LogState;

    #[test]
    fn test_status() {
        let log = LogState::in_memory();

        log.with_dashboard (&mut |dashboard| assert_eq! (dashboard.len(), 0));

        let mut handle = log.status_handle();
        for n in 1..=3 {
            handle.status (&[&"tag1", &"tag2"], &format! ("line {}", n));

            log.with_dashboard (&mut |dashboard| {
                assert_eq! (dashboard.len(), 1);
                let status = unwrap! (dashboard[0].lock());
                assert! (status.tags.iter().any (|tag| tag.key == "tag1"));
                assert! (status.tags.iter().any (|tag| tag.key == "tag2"));
                assert_eq! (status.tags.len(), 2);
                assert_eq! (status.line, format! ("line {}", n));
            });
        }
        drop (handle);

        log.with_dashboard (&mut |dashboard| assert_eq! (dashboard.len(), 0));  // The status was dumped into the log.
        log.with_tail (&mut |tail| {
            assert_eq! (tail.len(), 1);
            assert_eq! (tail[0].line, "line 3");
            assert! (tail[0].trail.iter().any (|status| status.line == "line 2"));
            assert! (tail[0].trail.iter().any (|status| status.line == "line 1"));

            assert! (tail[0].tags.iter().any (|tag| tag.key == "tag1"));
            assert! (tail[0].tags.iter().any (|tag| tag.key == "tag2"));
            assert_eq! (tail[0].tags.len(), 2);
        })
    }
}

use std::collections::VecDeque;
use std::mem::swap;
use std::sync::{Arc, Mutex};

pub trait TagParam<'a> {
    fn key (&self) -> String;
    fn val (&self) -> Option<String>;
}

impl<'a> TagParam<'a> for &'a str {
    fn key (&self) -> String {String::from (&self[..])}
    fn val (&self) -> Option<String> {None}
}

pub struct Tag {
    pub key: String,
    pub val: Option<String>
}

/// The status entry kept in the dashboard.
pub struct Status {
    pub tags: Vec<Tag>,
    pub line: String,
    // Might contain the previous versions of the status.
    pub trail: Vec<Status>
}

#[derive(Default)]
pub struct LogEntry {
    pub tags: Vec<Tag>,
    pub line: String,
    /// If the log entry represents a finished `Status` then `trail` might contain the previous versions of that `Status`.
    pub trail: Vec<Status>
}

impl LogEntry {
    fn print (&self) {
        pintln! (
            // TODO: JSON-escape the keys and values when necessary.
            '[' for t in &self.tags {(t.key)} separated {' '} "] "
            (self.line)
            for tr in self.trail.iter().rev() {
                "\n    " (tr.line)
            }
        )
    }
}

/// Tracks the status of an ongoing operation, allowing us to inform the user of the status updates.
/// 
/// Dropping the handle tells us that the operation was "finished" and that we can dump the final status into the log.
pub struct StatusHandle<'a> {
    log: &'a LogState,
    status: Option<Arc<Mutex<Status>>>
}

impl<'a> StatusHandle<'a> {
    /// Creates the status or rewrites it.
    pub fn status<'b> (&mut self, tags: &[&TagParam], line: &str) {
        let mut stack_status = Status {
            tags: tags.iter().map (|t| Tag {key: t.key(), val: t.val()}) .collect(),
            line: line.into(),
            trail: Vec::new()
        };
        if let Some (ref status) = self.status {
            let mut shared_status = unwrap! (status.lock(), "Can't lock the status");
            swap (&mut stack_status, &mut shared_status);
            swap (&mut stack_status.trail, &mut shared_status.trail);  // Move the existing `trail` back to the `shared_status`.
            shared_status.trail.push (stack_status);
        } else {
            let status = Arc::new (Mutex::new (stack_status));
            self.status = Some (status.clone());
            self.log.started (status);
        }
    }

    /// Adds new text into the status line.
    pub fn append (&self, suffix: &str) {
        if let Some (ref status) = self.status {
            let mut status = unwrap! (status.lock(), "Can't lock the status");
            status.line.push_str (suffix)
        }
    }
}

impl<'a> Drop for StatusHandle<'a> {
    fn drop (&mut self) {
        if let Some (ref status) = self.status {
            self.log.finished (status)
        }
    }
}

/// The shared log state of a MarketMaker instance.  
/// Carried around by the MarketMaker state, `MmCtx`.  
/// Keeps track of the log file and the status dashboard.
pub struct LogState {
    dashboard: Mutex<Vec<Arc<Mutex<Status>>>>,
    /// Keeps recent log entries in memory in case we need them for debugging.  
    /// Should allow us to examine the log from withing the unit tests, core dumps and live debugging sessions.
    tail: Mutex<VecDeque<LogEntry>>
}

impl LogState {
    /// Log into memory, for unit testing.
    pub fn in_memory() -> LogState {
        LogState {
            dashboard: Mutex::new (Vec::new()),
            tail: Mutex::new (VecDeque::with_capacity (64))
        }
    }

    /// The operation is considered "in progress" while the `StatusHandle` exists.
    /// 
    /// When the `StatusHandle` is dropped the operation is considered "finished" (possibly with a failure)
    /// and the status summary is dumped into the log.
    pub fn status_handle (&self) -> StatusHandle {
        StatusHandle {
            log: self,
            status: None
        }
    }

    /// Invoked when the `StatusHandle` gets the first status.
    fn started (&self, status: Arc<Mutex<Status>>) {
        match self.dashboard.lock() {
            Ok (mut dashboard) => dashboard.push (status),
            Err (err) => eprintln! ("log] Can't lock the dashboard: {}", err)
        }
    }

    /// Invoked when the `StatusHandle` is dropped, marking the status as finished.
    fn finished (&self, status: &Arc<Mutex<Status>>) {
        match self.dashboard.lock() {
            Ok (mut dashboard) => {
                if let Some (idx) = dashboard.iter().position (|e| Arc::ptr_eq (e, status)) {
                    dashboard.swap_remove (idx);
                } else {
                    eprintln! ("log] Warning, a finished StatusHandle was missing from the dashboard.");
                }
            },
            Err (err) => eprintln! ("log] Can't lock the dashboard: {}", err)
        }
        let mut status = match status.lock() {
            Ok (status) => status,
            Err (err) => {
                eprintln! ("log] Can't lock the status: {}", err);
                return
            }
        };
        match self.tail.lock() {
            Ok (mut tail) => {
                if tail.len() == tail.capacity() {let _ = tail.pop_front();}
                let mut log = LogEntry::default();
                swap (&mut log.tags, &mut status.tags);
                swap (&mut log.line, &mut status.line);
                swap (&mut log.trail, &mut status.trail);
                log.print();
                tail.push_back (log);
            },
            Err (err) => eprintln! ("log] Can't lock the tail: {}", err)
        }
    }

    /// Read-only access to the status dashboard.
    pub fn with_dashboard (&self, cb: &mut FnMut (&[Arc<Mutex<Status>>])) {
        let dashboard = unwrap! (self.dashboard.lock(), "Can't lock the dashboard");
        cb (&dashboard[..])
    }

    pub fn with_tail (&self, cb: &mut FnMut (&VecDeque<LogEntry>)) {
        let tail = unwrap! (self.tail.lock(), "Can't lock the tail");
        cb (&*tail)
    }

   /// Creates the status.
   pub fn status<'b> (&self, tags: &[&TagParam], line: &str) -> StatusHandle {
        let mut status = self.status_handle();
        status.status (tags, line);
        status
    }
}