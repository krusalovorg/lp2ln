use std::time::{Duration, Instant};
use dashmap::DashMap;

#[derive(Clone, Debug)]
pub struct CachedFile {
    pub content: Vec<u8>,
    pub mime_type: String,
    pub expires_at: Instant,
}

#[derive(Debug)]
pub struct FileCache {
    cache: DashMap<String, CachedFile>,
}

impl FileCache {
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

    pub fn cache_file(&self, file_hash: String, content: Vec<u8>, mime_type: String) {
        let cached_file = CachedFile {
            content,
            mime_type,
            expires_at: Instant::now() + Duration::from_secs(300), // 5 minutes
        };
        self.cache.insert(file_hash, cached_file);
    }

    pub fn get_cached_file(&self, file_hash: &str) -> Option<(Vec<u8>, String)> {
        if let Some(cached) = self.cache.get(file_hash) {
            if cached.expires_at > Instant::now() {
                return Some((cached.content.clone(), cached.mime_type.clone()));
            } else {
                self.cache.remove(file_hash);
            }
        }
        None
    }
} 