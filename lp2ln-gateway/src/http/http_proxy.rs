use p2p_server::config::Config;
use p2p_server::db::P2PDatabase;
use p2p_server::packets::{
    FileRequest, FragmentSearchRequest, Protocol, TransportData, TransportPacket,
};
use bytes::Bytes;
use dashmap::DashMap;
use flate2::read::{GzDecoder, GzEncoder};
use flate2::Compression;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::tokio::TokioIo;
use std::io::{Read};
use std::time::{Duration, Instant};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use p2p_server::logger;
use std::collections::HashSet;

use crate::http::security::{SecurityManager, SecurityConfig};

#[derive(Clone, Debug)]
struct CachedFile {
    content: Vec<u8>,
    mime_type: String,
    expires_at: Instant,
}

#[derive(Clone, Debug)]
pub struct HttpProxy {
    db: Arc<P2PDatabase>,
    proxy_tx: mpsc::Sender<TransportPacket>,
    pending_responses: Arc<DashMap<String, oneshot::Sender<TransportPacket>>>,
    fragment_cache: Arc<DashMap<String, String>>,
    file_cache: Arc<DashMap<String, CachedFile>>,
    path_blobs: String,
    security_manager: Arc<SecurityManager>,
}

impl HttpProxy {
    pub fn new(
        db: Arc<P2PDatabase>,
        proxy_tx: mpsc::Sender<TransportPacket>,
        path_blobs: String,
    ) -> Self {
        let security_config = SecurityConfig {
            allowed_ips: HashSet::new(), // Добавьте разрешенные IP
            ..Default::default()
        };
        
        Self {
            db,
            proxy_tx,
            pending_responses: Arc::new(DashMap::new()),
            fragment_cache: Arc::new(DashMap::new()),
            file_cache: Arc::new(DashMap::new()),
            path_blobs,
            security_manager: Arc::new(SecurityManager::new(security_config)),
        }
    }

    pub async fn set_response(&self, request_id: String, response: TransportPacket) {
        logger::info(&format!("[HTTP Proxy] Set response for request: {}", request_id));
        if let Some((_, sender)) = self.pending_responses.remove(&request_id) {
            let _ = sender.send(response);
        }
    }

    pub async fn start(self: Arc<Self>) {
        let config = Config::from_file("config.toml");
        let mut port = config.proxy_port;
        let mut listener = None;

        while listener.is_none() {
            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            match TcpListener::bind(addr).await {
                Ok(l) => {
                    listener = Some(l);
                    logger::info(&format!("[HTTP Proxy] Listening on http://{}", addr));
                }
                Err(_) => {
                    logger::warning(&format!("[HTTP Proxy] Port {} is busy, trying {}", port, port + 1));
                    port += 1;
                }
            }
        }

        let listener = listener.unwrap();

        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let peer_ip = format!(
                "{}:{}",
                stream.peer_addr().unwrap().ip().to_string(),
                stream.peer_addr().unwrap().port()
            );
            logger::info(&format!("[HTTP Proxy] Peer IP: {}", peer_ip));
            let proxy = self.clone();

            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let proxy = proxy.clone();
                    let peer_ip = peer_ip.clone();
                    logger::info(&format!("[HTTP Proxy] [thread] Peer IP: {}", peer_ip));
                    async move { proxy.handle(req, peer_ip).await }
                });

                if let Err(err) = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    logger::error(&format!("[HTTP Proxy] Connection error: {:?}", err));
                }
            });
        }
    }

    fn extract_peer_id(req: &Request<Incoming>) -> Option<String> {
        logger::debug("[HTTP Proxy] Starting peer ID extraction");

        if let Some(host) = req.headers().get("host") {
            if let Ok(host_str) = host.to_str() {
                logger::debug(&format!("[HTTP Proxy] Checking host header: {}", host_str));
                if host_str.chars().all(|c| c.is_ascii_hexdigit()) {
                    logger::debug(&format!("[HTTP Proxy] Found valid peer ID in host: {}", host_str));
                    return Some(host_str.to_string());
                }
            }
        }

        let path = req.uri().path();
        logger::debug(&format!("[HTTP Proxy] Checking URI path: {}", path));

        for segment in path.split('/') {
            if !segment.is_empty() && segment.chars().all(|c| c.is_ascii_hexdigit()) {
                logger::debug(&format!("[HTTP Proxy] Found valid peer ID in URI path: {}", segment));
                return Some(segment.to_string());
            }
        }

        if let Some(query) = req.uri().query() {
            logger::debug(&format!("[HTTP Proxy] Checking query parameters: {}", query));
            for param in query.split('&') {
                let parts: Vec<&str> = param.split('=').collect();
                if parts.len() == 2 {
                    let value = parts[1];
                    if value.chars().all(|c| c.is_ascii_hexdigit()) {
                        logger::debug(&format!("[HTTP Proxy] Found valid peer ID in query: {}", value));
                        return Some(value.to_string());
                    }
                }
            }
        }

        logger::debug("[HTTP Proxy] No valid peer ID found in request");
        None
    }

    async fn get_hash_file_from_request(&self, req: &Request<Incoming>, client_ip: &str) -> String {
        logger::debug(&format!("[HTTP Proxy] Starting peer ID extraction for client IP: {}", client_ip));
        let mut peer_id = None;

        if peer_id.is_none() {
            if let Some(extracted) = Self::extract_peer_id(req) {
                logger::debug(&format!("[HTTP Proxy] Successfully extracted peer ID from request: {}", extracted));
                peer_id = Some(extracted);
            } else {
                logger::debug("[HTTP Proxy] No peer ID found in request, checking client mapping");
            }
        }

        let peer_id = peer_id.unwrap_or_else(|| {
            logger::debug("[HTTP Proxy] No peer ID found, using empty string");
            "".to_string()
        });

        peer_id
    }

    async fn handle(
        &self,
        req: Request<Incoming>,
        client_ip: String,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        // Проверяем безопасность запроса
        if let Err(e) = self.security_manager.check_request(&req, &client_ip) {
            logger::error(&format!(
                "[HTTP Proxy] [SECURITY] Request blocked: {:?} from IP: {}",
                e, client_ip
            ));
            
            return Ok(Response::builder()
                .status(hyper::StatusCode::FORBIDDEN)
                .body(full(format!("Request blocked: {:?}", e)))
                .unwrap());
        }

        logger::info(&format!("[HTTP Proxy] Request Method: {}", req.method()));
        logger::info(&format!("[HTTP Proxy] Request URI: {}", req.uri()));
        logger::info("[HTTP Proxy] Request Headers:");
        for (name, value) in req.headers() {
            logger::info(&format!("  {}: {}", name, value.to_str().unwrap_or("(invalid)")));
        }

        let hash_file = self.get_hash_file_from_request(&req, &client_ip).await;
        logger::info(&format!("[HTTP Proxy] Hash File: {}", hash_file));

        let mut request_str = String::new();
        request_str.push_str(&format!("{} {} HTTP/1.1\r\n", req.method(), req.uri()));

        for (name, value) in req.headers() {
            request_str.push_str(&format!(
                "{}: {}\r\n",
                name,
                value.to_str().unwrap_or("(invalid)")
            ));
        }

        request_str.push_str("\r\n");

        let whole_body = req.collect().await?.to_bytes();
        if !whole_body.is_empty() {
            request_str.push_str(&String::from_utf8_lossy(&whole_body));
        }

        let request_id = Uuid::new_v4().to_string();
        let mut this_peer_storage_file = false;
        let mut file_hash = None;
        let mut peer_id = None;
        let mut mime = None;

        let is_hash = hash_file.len() == 64 && hash_file.chars().all(|c| c.is_ascii_hexdigit());

        if !is_hash {
            logger::error("[HTTP Proxy] [ERROR] Invalid hash format or length. Expected 64 characters hex string");
            return Ok(Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(full(
                    "Invalid hash format. Expected 64 characters hex string",
                ))
                .unwrap());
        }

        logger::debug("[HTTP Proxy] [DEBUG] Searching for fragments by hash");

        if let Some(cached_owner) = self.fragment_cache.get(&hash_file) {
            logger::debug(&format!("[HTTP Proxy] [DEBUG] Found cached owner for hash: {}", cached_owner.clone()));
            peer_id = Some(cached_owner.clone());
            this_peer_storage_file = *cached_owner == *self.db.get_or_create_peer_id().unwrap();
            if this_peer_storage_file {
                if let Ok(fragments) = self.db.search_fragment_in_virtual_storage(&hash_file, None)
                {
                    if let Some(fragment) = fragments.first() {
                        file_hash = Some(fragment.file_hash.clone());
                        mime = Some(fragment.mime.clone());
                    }
                }
            }
        } else {
            logger::debug("[HTTP Proxy] [DEBUG] No cached owner found, searching in storage");
            if let Ok(fragments) = self.db.search_fragment_in_virtual_storage(&hash_file, None) {
                if let Some(fragment) = fragments.first() {
                    logger::debug("[HTTP Proxy] [DEBUG] Found fragment in local storage");
                    peer_id = Some(fragment.storage_peer_key.clone());
                    this_peer_storage_file =
                        fragment.storage_peer_key == self.db.get_or_create_peer_id().unwrap();
                    file_hash = Some(fragment.file_hash.clone());
                    mime = Some(fragment.mime.clone());
                } else {
                    logger::debug(
                        "[HTTP Proxy] [DEBUG] No fragment found locally, sending search request"
                    );
                    let search_packet = TransportPacket {
                        act: "search_fragments".to_string(),
                        to: None,
                        data: Some(TransportData::FragmentSearchRequest(
                            FragmentSearchRequest {
                                query: hash_file.clone(),
                                request_id: request_id.clone(),
                            },
                        )),
                        protocol: Protocol::TURN,
                        peer_key: self.db.get_or_create_peer_id().unwrap(),
                        uuid: request_id.clone(),
                        nodes: vec![],
            signature: None,
                    };

                    let (search_tx, search_rx) = oneshot::channel();
                    self.pending_responses.insert(request_id.clone(), search_tx);

                    logger::debug("[HTTP Proxy] [DEBUG] Sending search packet");
                    self.proxy_tx.send(search_packet).await.unwrap();
                    logger::debug("[HTTP Proxy] [DEBUG] Search packet sent, waiting for response");

                    if let Ok(search_response) =
                        tokio::time::timeout(tokio::time::Duration::from_secs(5), search_rx).await
                    {
                        logger::debug("[HTTP Proxy] [DEBUG] Got search response");
                        if let Ok(response_data) = search_response {
                            logger::debug(&format!("[HTTP Proxy] Search response: {:?}", response_data));
                            if let Some(TransportData::FragmentSearchResponse(response)) =
                                response_data.data
                            {
                                for fragment in response.fragments {
                                    if fragment.file_hash == hash_file {
                                        logger::debug("[HTTP Proxy] [DEBUG] Found matching fragment in search response");
                                        self.fragment_cache.insert(
                                            hash_file.clone(),
                                            fragment.storage_peer_key.clone(),
                                        );
                                        peer_id = Some(fragment.storage_peer_key.clone());
                                        break;
                                    }
                                }
                            }
                        }
                    } else {
                        logger::debug("[HTTP Proxy] [DEBUG] Search response timeout");
                    }
                }
            }
        }

        let file_hash_clone = file_hash.clone();
        if file_hash.is_some() {
            let file_hash_str = file_hash.unwrap();
            logger::info(&format!("[HTTP PROXY] Processing file request for hash: {}", file_hash_str));

            if let Some((cached_content, cached_mime)) = self.get_cached_file(&file_hash_str) {
                logger::info(&format!("[HTTP PROXY] Serving file from cache: {}", file_hash_str));

                let mut decoder = GzDecoder::new(&cached_content[..]);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed).unwrap();

                return Ok(Response::builder()
                    .status(hyper::StatusCode::OK)
                    .header("Content-Type", cached_mime)
                    .header("Cache-Control", "no-cache")
                    .body(Full::new(Bytes::from(decompressed)).boxed())
                    .unwrap());
            }

            if this_peer_storage_file {
                logger::info("[HTTP PROXY] File is stored locally, serving from disk");
                let file_hash_str = file_hash_clone.unwrap();

                let file_path = format!("{}/{}", self.path_blobs, file_hash_str);
                logger::info(&format!("[HTTP PROXY] File path: {}", file_path));

                if !std::path::Path::new(&file_path).exists() {
                    logger::info(&format!("[HTTP PROXY] File not found at path: {}", file_path));
                    return Ok(Response::builder()
                        .status(hyper::StatusCode::NOT_FOUND)
                        .body(full("File not found"))
                        .unwrap());
                }

                let file_content = std::fs::read(&file_path).unwrap();
                let mime_type = mime.unwrap_or("application/octet-stream".to_string());

                let mut encoder = GzEncoder::new(&file_content[..], Compression::best());
                let mut compressed = Vec::new();
                encoder.read_to_end(&mut compressed).unwrap();

                logger::info(&format!("[HTTP PROXY] Caching file with hash: {}", file_hash_str));
                self.cache_file(file_hash_str.clone(), compressed.clone(), mime_type.clone());

                return Ok(Response::builder()
                    .status(hyper::StatusCode::OK)
                    .header("Content-Type", mime_type)
                    .header("Content-Encoding", "gzip")
                    .header("Cache-Control", "no-cache")
                    .body(Full::new(Bytes::from(compressed)).boxed())
                    .unwrap());
            }
        }

        logger::debug("[HTTP Proxy] [DEBUG] Preparing to send file request packet");
        let (tx, rx) = oneshot::channel();
        self.pending_responses.insert(request_id.clone(), tx);

        let packet = TransportPacket {
            act: "http_proxy_request".to_string(),
            to: peer_id.clone(),
            data: Some(TransportData::FileRequest(FileRequest {
                file_hash: hash_file.clone(),
                request_id: request_id.clone(),
                from_peer_id: self.db.get_or_create_peer_id().unwrap(),
                end_peer_id: peer_id.clone().unwrap_or_default(),
            })),
            protocol: Protocol::TURN,
            peer_key: self.db.get_or_create_peer_id().unwrap(),
            uuid: request_id.clone(),
            nodes: vec![],
            signature: None,
        };

        logger::debug("[HTTP Proxy] [DEBUG] Sending file request packet");
        self.proxy_tx.send(packet).await.unwrap();
        logger::debug("[HTTP Proxy] [DEBUG] File request packet sent, waiting for response");

        match tokio::time::timeout(tokio::time::Duration::from_secs(30), rx).await {
            Ok(Ok(packet)) => {
                logger::debug("[HTTP Proxy] [DEBUG] Got file response packet");
                if let Some(TransportData::ProxyMessage(msg)) = packet.data {
                    let file_content = msg.text;
                    let mime_type = msg.mime.clone();
                    let nonce = msg.nonce;

                    let decrypted = match self.db.decrypt_message(
                        &file_content,
                        nonce,
                        &peer_id.unwrap_or_default(),
                    ) {
                        Ok(d) => d,
                        Err(_) => {
                            return Ok(Response::builder()
                                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                                .body(full("Failed to decrypt file content"))
                                .unwrap());
                        }
                    };

                    let mut decoder = GzDecoder::new(&decrypted[..]);
                    let mut decompressed = Vec::new();
                    if decoder.read_to_end(&mut decompressed).is_err() {
                        decompressed = decrypted.clone();
                    }

                    let response_builder = Response::builder()
                        .status(hyper::StatusCode::OK)
                        .header("Content-Type", &mime_type)
                        .header("Content-Length", decompressed.len().to_string())
                        .header("Cache-Control", "no-cache")
                        .header("X-Content-Type-Options", "nosniff");

                    if file_hash_clone.is_some() {
                        self.cache_file(
                            file_hash_clone.unwrap(),
                            decrypted.clone(),
                            mime_type.clone(),
                        );
                    }

                    Ok(response_builder
                        .body(Full::new(Bytes::from(decompressed)).boxed())
                        .unwrap())
                } else {
                    logger::error("[HTTP Proxy] Received invalid packet data");
                    return Ok(Response::builder()
                        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(full("Invalid packet data"))
                        .unwrap());
                }
            }
            _ => Ok(Response::builder()
                .status(hyper::StatusCode::GATEWAY_TIMEOUT)
                .body(full("Proxy timeout"))
                .unwrap()),
        }
    }

    fn cache_file(&self, file_hash: String, content: Vec<u8>, mime_type: String) {
        logger::info(&format!("[HTTP PROXY] Caching file with hash: {}", file_hash));
        let cached_file = CachedFile {
            content,
            mime_type,
            expires_at: Instant::now() + Duration::from_secs(60), //300
        };

        let cache = self.file_cache.clone();
        let file_hash_clone = file_hash.clone();

        tokio::spawn(async move {
            cache.insert(file_hash_clone, cached_file);
            logger::info(&format!("[HTTP PROXY] File cached successfully: {}", file_hash));
        });
    }

    fn get_cached_file(&self, file_hash: &str) -> Option<(Vec<u8>, String)> {
        logger::debug(&format!("[HTTP PROXY] Checking cache for file: {}", file_hash));
        match self.file_cache.get(file_hash) {
            Some(cached) => {
                if cached.expires_at > Instant::now() {
                    logger::debug(&format!("[HTTP PROXY] Cache hit for file: {}", file_hash));
                    return Some((cached.content.clone(), cached.mime_type.clone()));
                } else {
                    logger::debug(&format!("[HTTP PROXY] Cache expired for file: {}", file_hash));
                    let file_hash = file_hash.to_string();
                    let cache = self.file_cache.clone();

                    tokio::spawn(async move {
                        if cache.remove_if(&file_hash, |_, _| true).is_some() {
                            logger::debug(&format!("[HTTP PROXY] Cache removed for file: {}", file_hash));
                        } else {
                            logger::error(&format!("[HTTP PROXY] Failed to remove cache for file: {}", file_hash));
                        }
                    });
                }
            }
            None => {
                logger::debug(&format!("[HTTP PROXY] Cache miss for file: {}", file_hash));
            }
        }
        None
    }
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, Infallible> {
    Full::new(chunk.into()).map_err(|_| unreachable!()).boxed()
}
