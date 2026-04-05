use colored::*;
use chrono::Local;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use std::path::PathBuf;

static mut SHOW_DEBUG: bool = true;
static mut SHOW_INFO: bool = true;
static mut SHOW_WARNING: bool = true;
static mut SHOW_ERROR: bool = true;

lazy_static::lazy_static! {
    static ref LOG_FILE: Arc<Mutex<Option<tokio::fs::File>>> = Arc::new(Mutex::new(None));
}

fn get_log_filename() -> String {
    let now = Local::now();
    format!("logs/log_{}.log", now.format("%Y-%m-%d_%H-%M-%S"))
}

pub fn set_log_file(path: Option<&str>) {
    let path = match path {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(get_log_filename())
    };
    
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    
    let file = tokio::spawn(async move {
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

async fn write_to_file(message: String) {
    let mut guard = LOG_FILE.lock().await;
    if let Some(file) = &mut *guard {
        let _ = file.write_all(format!("{}\n", message).as_bytes()).await;
    }
}

pub fn set_debug(enabled: bool) {
    unsafe { SHOW_DEBUG = enabled; }
}

pub fn set_info(enabled: bool) {
    unsafe { SHOW_INFO = enabled; }
}

pub fn set_warning(enabled: bool) {
    unsafe { SHOW_WARNING = enabled; }
}

pub fn set_error(enabled: bool) {
    unsafe { SHOW_ERROR = enabled; }
}

pub fn is_debug_enabled() -> bool {
    unsafe { SHOW_DEBUG }
}

pub fn is_info_enabled() -> bool {
    unsafe { SHOW_INFO }
}

pub fn is_warning_enabled() -> bool {
    unsafe { SHOW_WARNING }
}

pub fn is_error_enabled() -> bool {
    unsafe { SHOW_ERROR }
}

fn get_timestamp() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn debug(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [DEBUG] {}", timestamp, message);
    unsafe {
        if SHOW_DEBUG {
            println!("{}", log_message.blue().bold());
        }
    }
    tokio::spawn(write_to_file(log_message));
}

pub fn info(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] {}", timestamp, message);
    unsafe {
        if SHOW_INFO {
            println!("{}", log_message);
        }
    }
    tokio::spawn(write_to_file(log_message));
}

pub fn warning(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [WARNING] {}", timestamp, message);
    unsafe {
        if SHOW_WARNING {
            println!("{}", log_message.yellow().bold());
        }
    }
    tokio::spawn(write_to_file(log_message));
}

pub fn error(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [ERROR] {}", timestamp, message);
    unsafe {
        if SHOW_ERROR {
            println!("{}", log_message.red().bold());
        }
    }
    tokio::spawn(write_to_file(log_message));
}

pub fn peer(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [PEER] {}", timestamp, message);
    unsafe {
        if SHOW_INFO {
            println!("{}", log_message.cyan());
        }
    }
    tokio::spawn(write_to_file(log_message));
}

pub fn turn(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [TURN] {}", timestamp, message);
    unsafe {
        if SHOW_INFO {
            println!("{}", log_message.green());
        }
    }
    tokio::spawn(write_to_file(log_message));
}

pub fn storage(message: &str) {
    let timestamp = get_timestamp();
    let log_message = format!("[{}] [STORAGE] {}", timestamp, message);
    unsafe {
        if SHOW_INFO {
            println!("{}", log_message.magenta());
        }
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
macro_rules! peer {
    ($($arg:tt)*) => {
        $crate::logger::peer(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! turn {
    ($($arg:tt)*) => {
        $crate::logger::turn(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! storage {
    ($($arg:tt)*) => {
        $crate::logger::storage(&format!($($arg)*))
    };
} 