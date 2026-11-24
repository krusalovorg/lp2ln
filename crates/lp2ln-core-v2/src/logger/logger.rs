use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};

use chrono::Local;
use colored::*;

const FILE_LOG_CAPACITY: usize = 1024;
const MAX_FILE_LOG_BYTES: usize = 4096;

struct FileLogRecord {
    path: Arc<PathBuf>,
    line: Box<str>,
}

static FILE_LOG_PATH: Mutex<Option<Arc<PathBuf>>> = Mutex::new(None);
static FILE_LOG_TX: OnceLock<Option<mpsc::SyncSender<FileLogRecord>>> = OnceLock::new();
static DROPPED_FILE_LOGS: AtomicU64 = AtomicU64::new(0);

static SHOW_DEBUG: AtomicBool = AtomicBool::new(true);
static SHOW_INFO: AtomicBool = AtomicBool::new(true);
static SHOW_WARNING: AtomicBool = AtomicBool::new(true);
static SHOW_ERROR: AtomicBool = AtomicBool::new(true);

#[derive(Clone, Debug)]
pub struct LoggerOptions {
    pub log_dir: Option<PathBuf>,
    pub file_enabled: bool,
    pub show_debug: bool,
    pub show_info: bool,
    pub show_warning: bool,
    pub show_error: bool,
}

impl Default for LoggerOptions {
    fn default() -> Self {
        Self {
            log_dir: Some(PathBuf::from("logs")),
            file_enabled: true,
            show_debug: true,
            show_info: true,
            show_warning: true,
            show_error: true,
        }
    }
}

impl LoggerOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn log_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.log_dir = Some(dir.into());
        self
    }

    pub fn file_enabled(mut self, enabled: bool) -> Self {
        self.file_enabled = enabled;
        self
    }

    pub fn show_debug(mut self, enabled: bool) -> Self {
        self.show_debug = enabled;
        self
    }

    pub fn show_info(mut self, enabled: bool) -> Self {
        self.show_info = enabled;
        self
    }

    pub fn show_warning(mut self, enabled: bool) -> Self {
        self.show_warning = enabled;
        self
    }

    pub fn show_error(mut self, enabled: bool) -> Self {
        self.show_error = enabled;
        self
    }
}

pub fn init(options: &LoggerOptions) {
    SHOW_DEBUG.store(options.show_debug, Ordering::SeqCst);
    SHOW_INFO.store(options.show_info, Ordering::SeqCst);
    SHOW_WARNING.store(options.show_warning, Ordering::SeqCst);
    SHOW_ERROR.store(options.show_error, Ordering::SeqCst);
    let mut path = FILE_LOG_PATH.lock().unwrap();
    *path = options.file_enabled.then(|| {
        let log_dir = options
            .log_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("logs"));
        let file_name = format!("{}.log", Local::now().format("%Y-%m-%d"));
        Arc::new(log_dir.join(file_name))
    });
}

/// File log records rejected due to capacity or a disconnected writer.
pub fn dropped_file_logs() -> u64 {
    DROPPED_FILE_LOGS.load(Ordering::Relaxed)
}

fn queue_file_write(mut message: String) {
    let Some(path) = FILE_LOG_PATH.lock().unwrap().clone() else {
        return;
    };
    message.truncate(message.floor_char_boundary(MAX_FILE_LOG_BYTES));
    let record = FileLogRecord {
        path,
        line: message.into_boxed_str(),
    };
    let tx = FILE_LOG_TX.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel(FILE_LOG_CAPACITY);
        std::thread::Builder::new()
            .name("lp2ln-file-log".into())
            .spawn(move || write_file_logs(rx))
            .ok()
            .map(|_| tx)
    });
    if tx.as_ref().is_none_or(|tx| tx.try_send(record).is_err()) {
        DROPPED_FILE_LOGS.fetch_add(1, Ordering::Relaxed);
    }
}

fn write_file_logs(rx: mpsc::Receiver<FileLogRecord>) {
    let mut current: Option<(Arc<PathBuf>, Option<File>)> = None;
    for record in rx {
        if current
            .as_ref()
            .is_none_or(|(path, _)| path != &record.path)
        {
            let open = || -> std::io::Result<File> {
                if let Some(parent) = record.path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(record.path.as_ref())
            };
            let file = match open() {
                Ok(file) => Some(file),
                Err(err) => {
                    eprintln!("[LP2LN] Could not open log file: {err}");
                    None
                }
            };
            current = Some((record.path, file));
        }
        if let Some((_, Some(file))) = &mut current {
            let _ = writeln!(file, "{}", record.line);
        }
    }
}

fn get_timestamp() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn set_log_dir(dir: Option<&str>) {
    let opts = match dir {
        Some(d) => LoggerOptions::default().log_dir(d),
        None => LoggerOptions::default(),
    };
    init(&opts);
}

pub fn is_debug_enabled() -> bool {
    SHOW_DEBUG.load(Ordering::SeqCst)
}
pub fn is_info_enabled() -> bool {
    SHOW_INFO.load(Ordering::SeqCst)
}
pub fn is_warning_enabled() -> bool {
    SHOW_WARNING.load(Ordering::SeqCst)
}
pub fn is_error_enabled() -> bool {
    SHOW_ERROR.load(Ordering::SeqCst)
}

/// English I/O summary (avoids localized OS `Display`), plus `os error` code when present.
pub fn format_io_error(io: &std::io::Error) -> String {
    let label = match io.kind() {
        ErrorKind::ConnectionRefused => "connection refused",
        ErrorKind::ConnectionReset => "connection reset",
        ErrorKind::ConnectionAborted => "connection aborted",
        ErrorKind::TimedOut => "timed out",
        ErrorKind::HostUnreachable => "host unreachable",
        ErrorKind::NetworkUnreachable => "network unreachable",
        ErrorKind::AddrNotAvailable => "address not available",
        ErrorKind::AddrInUse => "address in use",
        ErrorKind::NotConnected => "not connected",
        ErrorKind::BrokenPipe => "broken pipe",
        ErrorKind::UnexpectedEof => "unexpected end of stream",
        ErrorKind::Interrupted => "interrupted",
        ErrorKind::PermissionDenied => "permission denied",
        ErrorKind::WouldBlock => "would block",
        ErrorKind::AlreadyExists => "already exists",
        ErrorKind::NotFound => "not found",
        _ => "other I/O error",
    };
    match io.raw_os_error() {
        Some(code) if label == "other I/O error" => format!("{:?} (os error {code})", io.kind()),
        Some(code) => format!("{label} (os error {code})"),
        None if label == "other I/O error" => format!("{:?}", io.kind()),
        None => label.to_string(),
    }
}

/// Prefer the first `std::io::Error` in an `anyhow` chain (e.g. after `.context(...)`).
pub fn describe_anyhow_io_error(err: &anyhow::Error) -> String {
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return format_io_error(io);
        }
    }
    err.to_string()
}

pub fn debug(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [DEBUG] {}", timestamp, message);
    if SHOW_DEBUG.load(Ordering::SeqCst) {
        println!("{}", log_message.blue().bold());
    }
    queue_file_write(log_message);
}

pub fn info(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] {}", timestamp, message);
    if SHOW_INFO.load(Ordering::SeqCst) {
        println!("{}", log_message);
    }
    queue_file_write(log_message);
}

pub fn warning(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [WARNING] {}", timestamp, message);
    if SHOW_WARNING.load(Ordering::SeqCst) {
        println!("{}", log_message.yellow().bold());
    }
    queue_file_write(log_message);
}

pub fn error(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [ERROR] {}", timestamp, message);
    if SHOW_ERROR.load(Ordering::SeqCst) {
        println!("{}", log_message.red().bold());
    }
    queue_file_write(log_message);
}

pub fn session(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [SESSION] {}", timestamp, message);
    if SHOW_INFO.load(Ordering::SeqCst) {
        println!("{}", log_message.cyan());
    }
    queue_file_write(log_message);
}

pub fn processor(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [PROCESSOR] {}", timestamp, message);
    if SHOW_INFO.load(Ordering::SeqCst) {
        println!("{}", log_message.magenta());
    }
    queue_file_write(log_message);
}

/// Expected peer / TCP session teardown (colored on stderr).
pub fn net_disconnect(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [NET] {}", timestamp, message);
    if SHOW_INFO.load(Ordering::SeqCst) {
        println!("{}", log_message.cyan().bold());
    }
    queue_file_write(log_message);
}

/// Failed outbound dial / reachability (colored on stderr).
pub fn net_dial(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [DIAL] {}", timestamp, message);
    if SHOW_DEBUG.load(Ordering::SeqCst) {
        println!("{}", log_message.yellow().bold());
    }
    queue_file_write(log_message);
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::logger::debug(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::logger::info(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::logger::warning(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::logger::error(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! session {
    ($($arg:tt)*) => {
        $crate::logger::session(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! processor {
    ($($arg:tt)*) => {
        $crate::logger::processor(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! net_disconnect {
    ($($arg:tt)*) => {
        $crate::logger::net_disconnect(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! net_dial {
    ($($arg:tt)*) => {
        $crate::logger::net_dial(&format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_writer_runs_without_a_tokio_runtime() {
        let dir = std::env::temp_dir().join(format!("lp2ln-test-{}", uuid::Uuid::new_v4()));
        let path = Arc::new(dir.join("net.log"));
        let (tx, rx) = mpsc::sync_channel(1);
        tx.try_send(FileLogRecord {
            path: path.clone(),
            line: "first".into(),
        })
        .unwrap();
        assert!(matches!(
            tx.try_send(FileLogRecord {
                path: path.clone(),
                line: "overflow".into()
            }),
            Err(mpsc::TrySendError::Full(_))
        ));
        drop(tx);
        write_file_logs(rx);
        assert_eq!(std::fs::read_to_string(path.as_ref()).unwrap(), "first\n");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
