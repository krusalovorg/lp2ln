use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::net::IpAddr;
use hyper::Request;
use hyper::body::Incoming;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub max_request_size: usize,
    pub max_uri_length: usize,
    pub max_headers_count: usize,
    pub max_query_params: usize,
    pub block_duration: Duration,
    pub max_requests_per_minute: u32,
    pub allowed_mime_types: HashSet<String>,
    pub allowed_ips: HashSet<IpAddr>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        let mut allowed_mime_types = HashSet::new();
        allowed_mime_types.insert("application/json".to_string());
        allowed_mime_types.insert("text/plain".to_string());
        allowed_mime_types.insert("application/octet-stream".to_string());

        Self {
            max_request_size: 1024 * 1024, // 1MB
            max_uri_length: 2048,
            max_headers_count: 50,
            max_query_params: 10,
            block_duration: Duration::from_secs(3600), // 1 hour
            max_requests_per_minute: 100,
            allowed_mime_types,
            allowed_ips: HashSet::new(),
        }
    }
}

#[derive(Debug)]
pub struct SecurityManager {
    config: Arc<SecurityConfig>,
    blocked_ips: Arc<DashMap<String, Instant>>,
    request_counts: Arc<DashMap<String, (u32, Instant)>>,
    suspicious_patterns: Vec<String>,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config: Arc::new(config),
            blocked_ips: Arc::new(DashMap::new()),
            request_counts: Arc::new(DashMap::new()),
            suspicious_patterns: vec![
                // Команды выполнения
                "wget".to_string(), "curl".to_string(), "tftp".to_string(), "ftpget".to_string(), "chmod 777".to_string(),
                "sh ".to_string(), "bash ".to_string(), "exec".to_string(), "system".to_string(), "eval".to_string(),
                // Подозрительные пути
                "/tmp".to_string(), "/var/run".to_string(), "/mnt".to_string(), "/root".to_string(),
                // Подозрительные действия
                "rm -rf".to_string(), "chmod".to_string(), "wget".to_string(), "curl".to_string(),
                // WordPress сканирование
                "wp-admin".to_string(), "wordpress".to_string(), "setup-config.php".to_string(),
                "wp-includes".to_string(), "wp-content".to_string(), "wp-login.php".to_string(),
                "wlwmanifest.xml".to_string(), "xmlrpc.php".to_string(), "wp-json".to_string(),
                "wp-cron.php".to_string(), "wp-settings.php".to_string(), "wp-load.php".to_string(),
                "wp-config.php".to_string(), "wp-blog-header.php".to_string(),
                // Другие подозрительные паттерны
                "___S_O_S_T_R_E_A_MAX___".to_string(), "device.rsp".to_string(),
                // Дополнительные паттерны сканирования
                ".env".to_string(), "config.php".to_string(), "phpinfo.php".to_string(),
                "info.php".to_string(), "test.php".to_string(), "admin.php".to_string(),
                "administrator".to_string(), "login.php".to_string(), "wp-".to_string(),
                // Паттерны бэкапов
                "archive.tar".to_string(), "backup".to_string(), ".bak".to_string(),
                ".old".to_string(), ".tmp".to_string(), ".temp".to_string(),
                ".swp".to_string(), ".swo".to_string(), ".log".to_string(),
                // Подозрительные заголовки
                "x-requested-with".to_string(), "x-forwarded-for".to_string(),
                "x-real-ip".to_string(), "x-forwarded-proto".to_string(),
            ],
        }
    }

    pub fn check_request(&self, req: &Request<Incoming>, client_ip: &str) -> Result<(), SecurityError> {
        // Проверка IP
        if self.is_ip_blocked(client_ip) {
            return Err(SecurityError::IpBlocked);
        }

        // Проверка rate limiting
        if !self.check_rate_limit(client_ip) {
            return Err(SecurityError::RateLimitExceeded);
        }

        // Проверка размера запроса
        if req.headers().get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .map_or(false, |size| size > self.config.max_request_size) {
            return Err(SecurityError::RequestTooLarge);
        }

        // Проверка URI
        if req.uri().to_string().len() > self.config.max_uri_length {
            return Err(SecurityError::UriTooLong);
        }

        // Проверка количества заголовков
        if req.headers().len() > self.config.max_headers_count {
            return Err(SecurityError::TooManyHeaders);
        }

        // Проверка query параметров
        if let Some(query) = req.uri().query() {
            if query.split('&').count() > self.config.max_query_params {
                return Err(SecurityError::TooManyQueryParams);
            }
        }

        // Проверка на подозрительные паттерны
        if self.is_suspicious_request(req) {
            self.block_ip(client_ip.to_string());
            return Err(SecurityError::SuspiciousRequest);
        }

        Ok(())
    }

    fn is_suspicious_request(&self, req: &Request<Incoming>) -> bool {
        let uri = req.uri().to_string();
        let query = req.uri().query().unwrap_or("");
        
        // Проверка на WordPress сканирование
        if uri.contains("wp-") || uri.contains("wordpress") || uri.contains("wp-includes") {
            return true;
        }
        
        // Проверка URI и query параметров
        if self.suspicious_patterns.iter().any(|pattern| {
            uri.to_lowercase().contains(&pattern.to_lowercase()) ||
            query.to_lowercase().contains(&pattern.to_lowercase())
        }) {
            return true;
        }

        // Проверка заголовков
        for (_, value) in req.headers() {
            if let Ok(value_str) = value.to_str() {
                if self.suspicious_patterns.iter().any(|pattern| {
                    value_str.to_lowercase().contains(&pattern.to_lowercase())
                }) {
                    return true;
                }
            }
        }

        false
    }

    pub fn block_ip(&self, ip: String) {
        self.blocked_ips.insert(ip, Instant::now());
    }

    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        if let Some(blocked_time) = self.blocked_ips.get(ip) {
            if blocked_time.elapsed() < self.config.block_duration {
                return true;
            }
            self.blocked_ips.remove(ip);
        }
        false
    }

    fn check_rate_limit(&self, ip: &str) -> bool {
        let now = Instant::now();
        let mut entry = self.request_counts.entry(ip.to_string()).or_insert((0, now));
        
        if entry.1.elapsed() > Duration::from_secs(60) {
            *entry = (1, now);
            return true;
        }

        if entry.0 >= self.config.max_requests_per_minute {
            return false;
        }

        entry.0 += 1;
        true
    }
}

#[derive(Debug)]
pub enum SecurityError {
    IpBlocked,
    RateLimitExceeded,
    RequestTooLarge,
    UriTooLong,
    TooManyHeaders,
    TooManyQueryParams,
    SuspiciousRequest,
} 