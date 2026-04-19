use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Local;
use colored::*;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

lazy_static::lazy_static! {
    static ref LOG_FILE: std::sync::Arc<Mutex<Option<tokio::fs::File>>> =
        std::sync::Arc::new(Mutex::new(None));
}

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

    if !options.file_enabled {
        return;
    }

    let log_dir = options
        .log_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("logs"));
    let file_name = format!("{}.log", Local::now().format("%Y-%m-%d"));
    let path = log_dir.join(&file_name);

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let path = path.clone();
    tokio::spawn(async move {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .expect("Failed to open log file");

        let mut guard = LOG_FILE.lock().await;
        *guard = Some(file);
    });
}

fn get_timestamp() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

async fn write_to_file(message: String) {
    let mut guard = LOG_FILE.lock().await;
    if let Some(file) = &mut *guard {
        let _ = file.write_all(format!("{}\n", message).as_bytes()).await;
        let _ = file.flush().await;
    }
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
    tokio::spawn(write_to_file(log_message));
}

pub fn info(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] {}", timestamp, message);
    if SHOW_INFO.load(Ordering::SeqCst) {
        println!("{}", log_message);
    }
    tokio::spawn(write_to_file(log_message));
}

pub fn warning(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [WARNING] {}", timestamp, message);
    if SHOW_WARNING.load(Ordering::SeqCst) {
        println!("{}", log_message.yellow().bold());
    }
    tokio::spawn(write_to_file(log_message));
}

pub fn error(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [ERROR] {}", timestamp, message);
    if SHOW_ERROR.load(Ordering::SeqCst) {
        println!("{}", log_message.red().bold());
    }
    tokio::spawn(write_to_file(log_message));
}

pub fn session(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [SESSION] {}", timestamp, message);
    if SHOW_INFO.load(Ordering::SeqCst) {
        println!("{}", log_message.cyan());
    }
    tokio::spawn(write_to_file(log_message));
}

pub fn processor(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [PROCESSOR] {}", timestamp, message);
    if SHOW_INFO.load(Ordering::SeqCst) {
        println!("{}", log_message.magenta());
    }
    tokio::spawn(write_to_file(log_message));
}

/// Expected peer / TCP session teardown (colored on stderr).
pub fn net_disconnect(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [NET] {}", timestamp, message);
    if SHOW_INFO.load(Ordering::SeqCst) {
        println!("{}", log_message.cyan().bold());
    }
    tokio::spawn(write_to_file(log_message));
}

/// Failed outbound dial / reachability (colored on stderr).
pub fn net_dial(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [DIAL] {}", timestamp, message);
    if SHOW_INFO.load(Ordering::SeqCst) {
        println!("{}", log_message.yellow().bold());
    }
    tokio::spawn(write_to_file(log_message));
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
