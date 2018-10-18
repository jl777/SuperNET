//! Human-readable logging and statuses.

// TODO: As we discussed with Artem, skip a status update if it is equal to the previous update.
// TODO: Sort the tags while converting `&[&TagParam]` to `Vec<Tag>`.

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

use chrono::{Local, TimeZone};
use gstuff::now_ms;
use serde_json::{Value as Json};
use std::collections::VecDeque;
use std::default::Default;
use std::fs;
use std::fmt::{self, Write as WriteFmt};
use std::io::{Seek, SeekFrom, Write};
use std::mem::swap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

pub trait TagParam<'a> {
    fn key (&self) -> String;
    fn val (&self) -> Option<String>;
}

impl<'a> TagParam<'a> for &'a str {
    fn key (&self) -> String {String::from (&self[..])}
    fn val (&self) -> Option<String> {None}
}

impl<'a> TagParam<'a> for (&'a str, &'a str) {
    fn key (&self) -> String {String::from (self.0)}
    fn val (&self) -> Option<String> {Some (String::from (self.1))}
}

impl<'a> TagParam<'a> for (String, &'a str) {
    fn key (&self) -> String { self.0.clone() }
    fn val (&self) -> Option<String> {Some (String::from (self.1))}
}

impl<'a> TagParam<'a> for (&'a str, i32) {
    fn key (&self) -> String {String::from (self.0)}
    fn val (&self) -> Option<String> {Some (fomat! ((self.1)))}
}

#[derive(Clone, Eq, PartialEq)]
pub struct Tag {
    pub key: String,
    pub val: Option<String>
}

impl Tag {
    /// Returns the tag's value or the empty string if there is no value.
    pub fn val_s (&self) -> &str {
        match self.val {
            Some (ref s) => &s[..],
            None => ""
        }
    }
}

impl fmt::Debug for Tag {
    fn fmt (&self, ft: &mut fmt::Formatter) -> fmt::Result {
        ft.write_str (&self.key) ?;
        if let Some (ref val) = self.val {
            ft.write_str ("=") ?;
            ft.write_str (val) ?;
        }
        Ok(())
    }
}

/// The status entry kept in the dashboard.
#[derive(Clone)]
pub struct Status {
    pub tags: Vec<Tag>,
    pub line: String,
    // Might contain the previous versions of the status.
    pub trail: Vec<Status>
}

#[derive(Clone)]
pub struct LogEntry {
    pub time: u64,
    pub emotion: String,
    pub tags: Vec<Tag>,
    pub line: String,
    /// If the log entry represents a finished `Status` then `trail` might contain the previous versions of that `Status`.
    pub trail: Vec<Status>
}

impl Default for LogEntry {
    fn default() -> Self {
        LogEntry {
            time: now_ms(),
            emotion: Default::default(),
            tags: Default::default(),
            line: Default::default(),
            trail: Default::default(),
        }
    }
}

impl LogEntry {
    fn format (&self, buf: &mut String) -> Result<(), fmt::Error> {
        use fmt::Write;

        let time = Local.timestamp_millis (self.time as i64);

        witeln! (buf,
            if self.emotion.is_empty() {'·'} else {(self.emotion)}
            ' '
            (time.format ("%Y-%m-%d %H:%M:%S"))
            ' '
            // TODO: JSON-escape the keys and values when necessary.
            '[' for t in &self.tags {(t.key) if let Some (ref v) = t.val {'=' (v)}} separated {' '} "] "
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
            {
                let mut shared_status = unwrap! (status.lock(), "Can't lock the status");
                swap (&mut stack_status, &mut shared_status);
                swap (&mut stack_status.trail, &mut shared_status.trail);  // Move the existing `trail` back to the `shared_status`.
                shared_status.trail.push (stack_status);
            }
            self.log.updated (status);
        } else {
            let status = Arc::new (Mutex::new (stack_status));
            self.status = Some (status.clone());
            self.log.started (status);
        }
    }

    /// Adds new text into the status line.
    pub fn append (&self, suffix: &str) {
        if let Some (ref status) = self.status {
            {
                let mut status = unwrap! (status.lock(), "Can't lock the status");
                status.line.push_str (suffix)
            }
            self.log.updated (status);
        }
    }

    /// Detach the handle from the status, allowing the status to remain in the dashboard when the handle is dropped.
    /// 
    /// The code should later manually finish the status (finding it with `LogState::find_status`).
    pub fn detach (&mut self) -> &mut Self {
        self.status = None;
        self
    }
}

impl<'a> Drop for StatusHandle<'a> {
    fn drop (&mut self) {
        if let Some (ref status) = self.status {
            self.log.finished (status)
        }
    }
}

/// Generates a MM dashboard file path from the MM log file path.
pub fn dashboard_path (log_path: &Path) -> Result<PathBuf, String> {
    let log_path = try_s! (log_path.to_str().ok_or ("Non-unicode log_path?"));
    Ok (format! ("{}.dashboard", log_path) .into())
}

/// The shared log state of a MarketMaker instance.  
/// Carried around by the MarketMaker state, `MmCtx`.  
/// Keeps track of the log file and the status dashboard.
pub struct LogState {
    dashboard: Mutex<Vec<Arc<Mutex<Status>>>>,
    /// Keeps recent log entries in memory in case we need them for debugging.  
    /// Should allow us to examine the log from withing the unit tests, core dumps and live debugging sessions.
    tail: Mutex<VecDeque<LogEntry>>,
    /// Log to stdout if `None`.
    log_file: Option<Mutex<fs::File>>,
    /// Dashboard is dumped here, allowing us to easily observe it from a command-line or the tests.  
    /// No dumping if `None`.
    dashboard_file: Option<Mutex<fs::File>>
}

impl LogState {
    /// Log into memory, for unit testing.
    pub fn in_memory() -> LogState {
        LogState {
            dashboard: Mutex::new (Vec::new()),
            tail: Mutex::new (VecDeque::with_capacity (64)),
            log_file: None,
            dashboard_file: None
        }
    }

    /// Initialize according to the MM command-line configuration.
    pub fn mm (conf: &Json) -> LogState {
        let (log_file, dashboard_file) = match conf["log"] {
            Json::Null => (None, None),
            Json::String (ref path) => {
                let log_file = unwrap! (
                    fs::OpenOptions::new().append (true) .create (true) .open (path),
                    "Can't open log file {}", path
                );

                let dashboard_path = unwrap! (dashboard_path (Path::new (&path)));
                let dashboard_file = unwrap! (
                    fs::OpenOptions::new().write (true) .create (true) .open (&dashboard_path),
                    "Can't open dashboard file {:?}", dashboard_path
                );

                (Some (Mutex::new (log_file)), Some (Mutex::new (dashboard_file)))
            },
            ref x => panic! ("The 'log' is not a string: {:?}", x)
        };
        LogState {
            dashboard: Mutex::new (Vec::new()),
            tail: Mutex::new (VecDeque::with_capacity (64)),
            log_file,
            dashboard_file
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

    fn dump_dashboard (&self, dashboard: MutexGuard<Vec<Arc<Mutex<Status>>>>) {
        if dashboard.len() == 0 {return}
        let df = match self.dashboard_file {Some (ref df) => df, None => return};
        let mut buf = String::with_capacity (dashboard.len() * 256);
        let mut locked = Vec::new();
        for status in dashboard.iter() {
            if let Ok (status) = status.try_lock() {
                let _ = writeln! (&mut buf, "{:?} {}", status.tags, status.line);
            } else {
                locked.push (status.clone())
            }
        }
        drop (dashboard);  // Unlock the dashboard.
        for status in locked {
            if let Ok (status) = status.lock() {
                let _ = writeln! (&mut buf, "{:?} {}", status.tags, status.line);
            } else {
                eprintln! ("dump_dashboard] Can't lock a status")
            }
        }

        let mut df = match df.lock() {Ok (lock) => lock, Err (err) => {eprintln! ("dump_dashboard] Can't lock the file: {}", err); return}};
        if let Err (err) = df.seek (SeekFrom::Start (0)) {eprintln! ("dump_dashboard] Can't seek the file: {}", err); return}
        if let Err (err) = df.write_all (buf.as_bytes()) {eprintln! ("dump_dashboard] Can't write the file: {}", err); return}
        if let Err (err) = df.set_len (buf.len() as u64) {eprintln! ("dump_dashboard] Can't truncate the file: {}", err); return}
    }

    /// Invoked when the `StatusHandle` gets the first status.
    fn started (&self, status: Arc<Mutex<Status>>) {
        match self.dashboard.lock() {
            Ok (mut dashboard) => {
                dashboard.push (status);
                self.dump_dashboard (dashboard)
            },
            Err (err) => eprintln! ("log] Can't lock the dashboard: {}", err)
        }
    }

    /// Invoked when the `StatusHandle` updates the status.
    fn updated (&self, _status: &Arc<Mutex<Status>>) {
        match self.dashboard.lock() {
            Ok (dashboard) => self.dump_dashboard (dashboard),
            Err (err) => eprintln! ("log] Can't lock the dashboard: {}", err)
        }
    }

    /// Invoked when the `StatusHandle` is dropped, marking the status as finished.
    fn finished (&self, status: &Arc<Mutex<Status>>) {
        match self.dashboard.lock() {
            Ok (mut dashboard) => {
                if let Some (idx) = dashboard.iter().position (|e| Arc::ptr_eq (e, status)) {
                    dashboard.swap_remove (idx);
                    self.dump_dashboard (dashboard)
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
        let chunk = match self.tail.lock() {
            Ok (mut tail) => {
                if tail.len() == tail.capacity() {let _ = tail.pop_front();}
                let mut log = LogEntry::default();
                swap (&mut log.tags, &mut status.tags);
                swap (&mut log.line, &mut status.line);
                swap (&mut log.trail, &mut status.trail);
                let mut chunk = String::with_capacity (256);
                if let Err (err) = log.format (&mut chunk) {
                    eprintln! ("log] Error formatting log entry: {}", err);
                }
                tail.push_back (log);
                Some (chunk)
            },
            Err (err) => {
                eprintln! ("log] Can't lock the tail: {}", err);
                None
            }
        };
        if let Some (chunk) = chunk {self.chunk2log (chunk)}
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

    /// Creates the status or rewrites it if the tags match.
    pub fn status<'b> (&self, tags: &[&TagParam], line: &str) -> StatusHandle {
        let mut status = self.claim_status (tags) .unwrap_or (self.status_handle());
        status.status (tags, line);
        status
    }

    /// Search dashboard for status matching the tags.
    /// 
    /// Note that returned status handle represent an ownership of the status and on the `drop` will mark the status as finished.
    pub fn claim_status (&self, tags: &[&TagParam]) -> Option<StatusHandle> {
        let mut found = Vec::new();
        let mut locked = Vec::new();
        let tags: Vec<Tag> = tags.iter().map (|t| Tag {key: t.key(), val: t.val()}) .collect();
        let dashboard = unwrap! (self.dashboard.lock(), "Can't lock the dashboard");
        for status_arc in &*dashboard {
            if let Ok (ref status) = status_arc.try_lock() {
                if status.tags == tags {found.push (StatusHandle {
                    log: self,
                    status: Some (status_arc.clone())
                })}
            } else {
                locked.push (status_arc.clone())
            }
        }
        drop (dashboard);  // Unlock the dashboard before lock-waiting on statuses, avoiding a chance of deadlock.
        for status_arc in locked {
            let matches = unwrap! (status_arc.lock(), "Can't lock a status") .tags == tags;
            if matches {found.push (StatusHandle {
                log: self,
                status: Some (status_arc)
            })}
        }
        if found.len() > 1 {eprintln! ("log] Dashboard tags not unique!")}
        found.pop()
    }

    /// Returns `true` if there are recent log entries exactly matching the tags.
    pub fn tail_any (&self, tags: &[&TagParam]) -> bool {
        let tags: Vec<Tag> = tags.iter().map (|t| Tag {key: t.key(), val: t.val()}) .collect();
        let tail = match self.tail.lock() {Ok (l) => l, _ => return false};
        for en in tail.iter() {
            if en.tags == tags {
                return true
            }
        }
        return false
    }

    /// Creates a new human-readable log entry.
    /// 
    /// This is a bit different from the `println!` logging
    /// (https://www.reddit.com/r/rust/comments/9hpk65/which_tools_are_you_using_to_debug_rust_projects/e6dkciz/)
    /// as the information here is intended for the end users
    /// (and to be shared through the GUI),
    /// explaining what's going on with MM.
    /// 
    /// * `emotion` - We might use a unicode smiley here
    ///   (https://unicode.org/emoji/charts/full-emoji-list.html)
    ///   to emotionally color the event (the good, the bad and the ugly)
    ///   or enrich it with infographics.
    /// * `tags` - Parsable part of the log,
    ///   representing subsystems and sharing concrete values.
    ///   GUI might use it to get some useful information from the log.
    /// * `line` - The human-readable description of the event,
    ///   we have no intention to make it parsable.
    pub fn log (&self, emotion: &str, tags: &[&TagParam], line: &str) {
        let entry = LogEntry {
            time: now_ms(),
            emotion: emotion.into(),
            tags: tags.iter().map (|t| Tag {key: t.key(), val: t.val()}) .collect(),
            line: line.into(),
            trail: Vec::new()
        };

        let mut chunk = String::with_capacity (256);
        if let Err (err) = entry.format (&mut chunk) {
            eprintln! ("log] Error formatting log entry: {}", err);
            return
        }

        match self.tail.lock() {
            Ok (mut tail) => {
                if tail.len() == tail.capacity() {let _ = tail.pop_front();}
                tail.push_back (entry)
            },
            Err (err) => eprintln! ("log] Can't lock the tail: {}", err)
        }

        self.chunk2log (chunk)
    }

    fn chunk2log (&self, chunk: String) {
        // As of now we're logging from both the C and the Rust code and mixing the `println!` with the file writing to boot.
        // On Windows these writes aren't atomic unfortunately.
        // Duplicating the logging output here is a temporary workaround.
        // 
        // To properly fix this we'll likely need a thread-local log access, in order to replace the `println!` with proper file writes.
        // (Stdout redirection is not an option because multiple MM instances might be in flight).
        // 
        // A simpler temporary fix might be to have a version of `printf` and `println!`
        // primitives that uses a global Rust lock.
        if cfg! (windows) {print! ("⸗{}", chunk)}

        match self.log_file {
            Some (ref f) => match f.lock() {
                Ok (mut f) => {
                    if let Err (err) = f.write (chunk.as_bytes()) {
                        eprintln! ("log] Can't write to the log: {}", err);
                        println! ("{}", chunk);
                    }
                },
                Err (err) => {
                    eprintln! ("log] Can't lock the log: {}", err);
                    println! ("{}", chunk)
                }
            },
            None => println! ("{}", chunk)
        }
    }

    /// Writes into the *raw* portion of the log, the one not shared with the UI.
    pub fn rawln (&self, mut line: String) {
        line.push ('\n');
        self.chunk2log (line);
    }
}

impl Drop for LogState {
    fn drop (&mut self) {
        let dashboard_copy = {
            let dashboard = match self.dashboard.lock() {
                Ok (d) => d,
                Err (err) => {eprintln! ("LogState::drop] Can't lock `dashboard`: {}", err); return}
            };
            dashboard.clone()
        };
        if dashboard_copy.len() > 0 {
            println! ("--- LogState] Remaining status entries. ---");
            for status in &*dashboard_copy {self.finished (status)}
        } else {
            println! ("LogState] Bye!");
        }
    }
}