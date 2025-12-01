use crate::connection::Connection;
use crate::crypto::crypto::generate_uuid;
use crate::crypto::token::get_metadata_from_token;
use crate::db::P2PDatabase;
use crate::manager::connection_manager::ConnectionManager;
use crate::packets::{
    ContractExecutionRequest, EncryptedData, FragmentMetadata, FragmentMetadataSync,
    GetFragmentsMetadata, Message, PeerFileAccessChange, PeerFileDelete, PeerFileGet, PeerFileMove,
    PeerFileUpdate, PeerSearchRequest, PeerUploadFile, PeerWaitConnection, Protocol,
    SearchPathNode, StorageReservationRequest, StorageValidTokenRequest, TransportData,
    TransportPacket,
};
use crate::tunnel::Tunnel;
use colored::Colorize;
use hex;
use mime_guess;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::AsyncReadExt;

use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;
use std::path::Path;

#[derive(Debug)]
pub enum UploadError {
    FileNotFound(String),
    NoTokensAvailable,
    InsufficientSpace { required: u64, available: u64 },
    DatabaseError(String),
    IoError(String),
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UploadError::FileNotFound(path) => write!(f, "Файл не найден: {}", path),
            UploadError::NoTokensAvailable => write!(f, "Нет доступных токенов для загрузки. Используйте команду reserve для получения нового токена."),
            UploadError::InsufficientSpace { required, available } => write!(
                f,
                "Недостаточно места для загрузки файла. Требуется: {} байт, Доступно: {} байт. Используйте команду reserve для получения дополнительного места.",
                required, available
            ),
            UploadError::DatabaseError(e) => write!(f, "Ошибка базы данных: {}", e),
            UploadError::IoError(e) => write!(f, "Ошибка ввода/вывода: {}", e),
        }
    }
}

impl std::error::Error for UploadError {}

#[derive(Clone)]
pub struct PeerAPI {
    connection: Arc<Connection>,
    pub db: Arc<P2PDatabase>,
    manager: Arc<ConnectionManager>,
}

impl PeerAPI {
    pub fn new(connection: Arc<Connection>, db: &P2PDatabase, manager: &ConnectionManager) -> Self {
        PeerAPI {
            connection,
            db: Arc::new(db.clone()),
            manager: Arc::new(manager.clone()),
        }
    }

    pub async fn get_file(&self, identifier: String) -> Result<(), String> {
        let my_peer_id = self.db.get_or_create_peer_id().unwrap();
        let files = self.db.get_my_fragments().unwrap();

        let file = files
            .iter()
            .find(|f| f.filename == identifier || f.file_hash == identifier);

        if file.is_none() {
            return Err(format!("Файл не найден: {}", identifier));
        }
        let file = file.unwrap();
        let token = file.token.clone();
        let uuid_peer = file.storage_peer_key.clone();

        let packet = TransportPacket {
            act: "get_file".to_string(),
            to: Some(uuid_peer),
            data: Some(TransportData::PeerFileGet(PeerFileGet {
                token: Some(token),
                peer_id: my_peer_id.clone(),
                file_hash: file.file_hash.clone(),
            })),
            protocol: Protocol::TURN,
            peer_key: my_peer_id,
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.connection.send_packet(packet).await
    }

    fn clean_file_path(path: &str, root_dir: &str) -> String {
        let path = Path::new(path);
        let root = Path::new(root_dir);

        if let Ok(relative) = path.strip_prefix(root) {
            relative.to_string_lossy().replace('\\', "/")
        } else {
            path.file_name()
                .unwrap_or_else(|| path.as_os_str())
                .to_string_lossy()
                .to_string()
        }
    }

    pub async fn upload_file(
        &self,
        file_path: String,
        encrypt: bool,
        public: bool,
        auto_decompress: bool,
        root_dir: &str,
        is_contract: bool,
    ) -> Result<(), UploadError> {
        println!("Uploading file: {}", file_path);
        let file_size = tokio::fs::metadata(&file_path)
            .await
            .map_err(|e| UploadError::FileNotFound(e.to_string()))?
            .len();

        println!("File size: {}", file_size);

        let (owner_peer_id, token_info) = self
            .db
            .get_best_token(file_size)
            .map_err(|e| UploadError::DatabaseError(e.to_string()))?
            .ok_or(UploadError::NoTokensAvailable)?;

        let used_space = self
            .db
            .get_token_used_space(&owner_peer_id)
            .map_err(|e| UploadError::DatabaseError(e.to_string()))?;

        if used_space + file_size > token_info.free_space && !public {
            return Err(UploadError::InsufficientSpace {
                required: file_size,
                available: if used_space > token_info.free_space {
                    0
                } else {
                    token_info.free_space - used_space
                },
            });
        }

        println!("Owner peer id: {}", owner_peer_id);
        println!("Token info: {}", token_info.token);
        println!("Used space: {} / {}", used_space, token_info.free_space);

        let metadata = get_metadata_from_token(token_info.token.clone()).await;

        let token_provider = metadata.unwrap().storage_provider;

        if !self
            .manager
            .have_connection_with_peer(token_provider.clone())
            .await
        {
            self.connect_to_peer(token_provider.clone())
                .await
                .map_err(|e| UploadError::IoError(format!("Failed to connect to peer: {}", e)))?;

            let mut attempts = 0;
            let max_attempts = 4;

            while attempts < max_attempts {
                if self
                    .manager
                    .have_connection_with_peer(token_provider.clone())
                    .await
                {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                attempts += 1;
            }

            if attempts >= max_attempts {
                println!("Failed to establish connection with peer, send file use turn protocol");
            }
        }

        // ⏬ Сжатие файла
        let contents = tokio::fs::read(&file_path)
            .await
            .map_err(|e| UploadError::IoError(e.to_string()))?;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&contents)
            .map_err(|e| UploadError::IoError(e.to_string()))?;
        let compressed_contents = encoder
            .finish()
            .map_err(|e| UploadError::IoError(e.to_string()))?;

        println!("Compressed size: {}", compressed_contents.len());

        let (final_content, encrypted) = if encrypt {
            // ⏬ Шифрование файла
            let encrypted_contents = self
                .db
                .encrypt_data(&compressed_contents)
                .map_err(|e| UploadError::DatabaseError(e.to_string()))?;

            let content = serde_json::to_string(&EncryptedData {
                nonce: encrypted_contents.1,
                content: encrypted_contents.0,
            })
            .unwrap();
            (content.into_bytes(), true)
        } else {
            (compressed_contents, false)
        };

        let my_peer_id = self
            .db
            .get_or_create_peer_id()
            .map_err(|e| UploadError::DatabaseError(e.to_string()))?;

        let file_hash = hex::encode(Sha256::digest(&final_content));
        let mime = mime_guess::from_path(file_path.clone()).first_or_text_plain();

        let packet = TransportPacket {
            act: "save_file".to_string(),
            to: Some(token_provider),
            data: Some(TransportData::PeerUploadFile(PeerUploadFile {
                filename: Self::clean_file_path(&file_path, root_dir),
                contents: final_content,
                peer_id: my_peer_id.clone(),
                token: token_info.token,
                file_hash: file_hash,
                mime: mime.to_string(),
                public,
                encrypted,
                compressed: true,
                auto_decompress,
                is_contract,
            })),
            protocol: Protocol::TURN,
            peer_key: my_peer_id,
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        let _ = self.manager.auto_send_packet(packet).await;

        self.db
            .update_token_used_space(&owner_peer_id, used_space + file_size)
            .map_err(|e| UploadError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn upload_contract(&self, contract_path: String) -> Result<(), UploadError> {
        self.upload_file(contract_path, false, true, true, "", true)
            .await
    }

    pub async fn upload_file_default(&self, file_path: String) -> Result<(), UploadError> {
        self.upload_file(file_path, true, false, false, "", false)
            .await
    }

    pub async fn send_message(&self, peer_id: String, message: String) -> Result<(), String> {
        let packet = TransportPacket {
            act: "message".to_string(),
            to: Some(peer_id),
            data: Some(TransportData::Message(Message {
                text: message,
                nonce: None,
            })),
            protocol: Protocol::TURN,
            peer_key: self.db.get_or_create_peer_id().unwrap(),
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.manager.auto_send_packet(packet).await
    }

    pub async fn connect_to_peer(&self, peer_id: String) -> Result<(), String> {
        let tunnel = Tunnel::new().await;
        let tunnel_ip = tunnel.public_ip.clone();
        let tunnel_port = tunnel.public_port.clone();
        self.manager.add_tunnel(peer_id.to_string(), tunnel).await;
        let mut packet = TransportPacket {
            act: "wait_connection".to_string(),
            to: None,
            data: Some(TransportData::PeerWaitConnection(PeerWaitConnection {
                connect_peer_id: peer_id,
                public_port: tunnel_port,
                public_ip: tunnel_ip,
                initiator_key: self.db.get_or_create_peer_id().unwrap(),
            })),
            protocol: Protocol::STUN,
            peer_key: self.db.get_or_create_peer_id().unwrap(),
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.connection.send_packet(packet).await
    }

    pub async fn request_peer_list(&self) -> Result<(), String> {
        let packet = TransportPacket {
            act: "peer_list".to_string(),
            to: None,
            data: None,
            protocol: Protocol::SIGNAL,
            peer_key: self.db.get_or_create_peer_id().unwrap(),
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };
        println!("{}", format!("[Peer] Sending peer list to signal server"));
        self.manager.auto_send_packet(packet).await
    }

    pub async fn reserve_storage(&self, size_in_bytes: u64) -> Result<(), String> {
        let packet = TransportPacket {
            act: "reserve_storage".to_string(),
            to: None,
            data: Some(TransportData::StorageReservationRequest(
                StorageReservationRequest {
                    peer_id: self.db.get_or_create_peer_id().unwrap(),
                    size_in_bytes,
                },
            )),
            protocol: Protocol::SIGNAL,
            peer_key: self.db.get_or_create_peer_id().unwrap(),
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.connection.send_packet(packet).await
    }

    pub async fn valid_token(&self, token: String) -> Result<(), String> {
        let metadata = get_metadata_from_token(token.clone().to_string()).await;

        if let Ok(metadata) = metadata {
            let packet = TransportPacket {
                act: "valid_token".to_string(),
                to: Some(metadata.storage_provider),
                data: Some(TransportData::StorageValidTokenRequest(
                    StorageValidTokenRequest {
                        token: token.clone(),
                        peer_id: self.db.get_or_create_peer_id().unwrap(),
                    },
                )),
                protocol: Protocol::SIGNAL,
                peer_key: self.db.get_or_create_peer_id().unwrap(),
                uuid: generate_uuid(),
                nodes: vec![],
            signature: None,
            };

            self.connection.send_packet(packet).await
        } else {
            Err("Invalid token".to_string())
        }
    }

    pub async fn search_peer(&self, peer_id: String) -> Result<(), String> {
        let packet = TransportPacket {
            act: "search_peer".to_string(),
            to: None,
            data: Some(TransportData::PeerSearchRequest(PeerSearchRequest {
                peer_id: self.db.get_or_create_peer_id().unwrap(),
                search_id: peer_id,
                max_hops: 3,
                path: vec![SearchPathNode {
                    uuid: self.db.get_or_create_peer_id().unwrap(),
                    public_ip: self.connection.ip.clone(),
                    public_port: self.connection.port.clone(),
                }],
            })),
            protocol: Protocol::SIGNAL,
            peer_key: self.db.get_or_create_peer_id().unwrap(),
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.connection.send_packet(packet).await
    }

    pub async fn change_file_public_access(
        &self,
        file_hash: String,
        public: bool,
    ) -> Result<(), String> {
        let my_peer_id = self.db.get_or_create_peer_id().unwrap();
        let files = self.db.get_my_fragments().unwrap();

        let file = files.iter().find(|f| f.file_hash == file_hash);

        if file.is_none() {
            return Err(format!("Файл не найден: {}", file_hash));
        }
        let file = file.unwrap();
        let uuid_peer = file.storage_peer_key.clone();

        let packet = TransportPacket {
            act: "change_file_access".to_string(),
            to: Some(uuid_peer),
            data: Some(TransportData::PeerFileAccessChange(PeerFileAccessChange {
                file_hash,
                public,
                token: file.token.clone(),
                peer_id: my_peer_id.clone(),
            })),
            protocol: Protocol::TURN,
            peer_key: my_peer_id,
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.connection.send_packet(packet).await
    }

    pub async fn delete_file(&self, file_hash: String) -> Result<(), String> {
        let my_peer_id = self.db.get_or_create_peer_id().unwrap();
        let files = self.db.get_my_fragments().unwrap();

        let file = files.iter().find(|f| f.file_hash == file_hash);

        if file.is_none() {
            return Err(format!("Файл не найден: {}", file_hash));
        }
        let file = file.unwrap();
        let uuid_peer = file.storage_peer_key.clone();

        let packet = TransportPacket {
            act: "delete_file".to_string(),
            to: Some(uuid_peer),
            data: Some(TransportData::PeerFileDelete(PeerFileDelete {
                file_hash,
                token: file.token.clone(),
                peer_id: my_peer_id.clone(),
            })),
            protocol: Protocol::TURN,
            peer_key: my_peer_id,
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.connection.send_packet(packet).await
    }

    pub async fn move_file(&self, file_hash: String, new_path: String) -> Result<(), String> {
        let my_peer_id = self.db.get_or_create_peer_id().unwrap();
        let files = self.db.get_my_fragments().unwrap();

        let file = files.iter().find(|f| f.file_hash == file_hash);

        if file.is_none() {
            return Err(format!("Файл не найден: {}", file_hash));
        }
        let file = file.unwrap();
        let uuid_peer = file.storage_peer_key.clone();

        // Получаем имя файла из текущего пути
        let current_filename = std::path::Path::new(&file.filename)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&file.filename);

        // Формируем новый путь с сохранением имени файла
        let new_path = if new_path.ends_with('/') || new_path.ends_with('\\') {
            format!("{}{}", new_path, current_filename)
        } else {
            format!("{}/{}", new_path, current_filename)
        };

        let packet = TransportPacket {
            act: "move_file".to_string(),
            to: Some(uuid_peer),
            data: Some(TransportData::PeerFileMove(PeerFileMove {
                file_hash: file_hash.clone(),
                new_path: new_path.clone(),
                token: file.token.clone(),
                peer_id: my_peer_id.clone(),
            })),
            protocol: Protocol::TURN,
            peer_key: my_peer_id,
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.connection.send_packet(packet).await?;

        self.db
            .update_fragment_path(&file_hash, &new_path)
            .map_err(|e| format!("Ошибка при обновлении метаданных: {}", e))?;

        Ok(())
    }

    fn collect_files_recursively(
        &self,
        dir_path: &std::path::Path,
        files: &mut Vec<String>,
    ) -> Result<(), UploadError> {
        for entry in std::fs::read_dir(dir_path).map_err(|e| UploadError::IoError(e.to_string()))? {
            let entry = entry.map_err(|e| UploadError::IoError(e.to_string()))?;
            let path = entry.path();

            if path.is_file() {
                files.push(path.to_string_lossy().to_string());
            } else if path.is_dir() {
                self.collect_files_recursively(&path, files)?;
            }
        }
        Ok(())
    }

    pub async fn upload_directory(
        &self,
        dir_path: String,
        encrypt: bool,
        public: bool,
        auto_decompress: bool,
    ) -> Result<(), UploadError> {
        let path = std::path::Path::new(&dir_path);
        if !path.is_dir() {
            return Err(UploadError::FileNotFound(
                "Указанный путь не является директорией".to_string(),
            ));
        }

        let mut files = Vec::new();
        self.collect_files_recursively(path, &mut files)?;

        if files.is_empty() {
            return Err(UploadError::FileNotFound("Директория пуста".to_string()));
        }

        println!(
            "{}",
            format!("Найдено файлов для загрузки: {}", files.len()).cyan()
        );

        for (i, file) in files.iter().enumerate() {
            println!(
                "{}",
                format!("Загрузка файла {}/{}: {}", i + 1, files.len(), file).yellow()
            );
            if let Err(e) = self
                .upload_file(
                    file.clone(),
                    encrypt,
                    public,
                    auto_decompress,
                    &dir_path,
                    false,
                )
                .await
            {
                println!(
                    "{}",
                    format!("Ошибка при загрузке файла {}: {}", file, e).red()
                );
            } else {
                println!("{}", format!("Файл {} успешно загружен", file).green());
            }
        }

        Ok(())
    }

    pub async fn get_fragments_metadata(&self, token_hash: String) -> Result<(), String> {
        let my_peer_id = self.db.get_or_create_peer_id().unwrap();
        let packet = TransportPacket {
            act: "get_fragments_metadata".to_string(),
            to: None,
            data: Some(TransportData::GetFragmentsMetadata(GetFragmentsMetadata {
                token_hash,
            })),
            protocol: Protocol::SIGNAL,
            peer_key: my_peer_id,
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.connection.send_packet(packet).await
    }

    pub async fn sync_fragment_metadata(&self) -> Result<(), String> {
        let my_peer_id = self.db.get_or_create_peer_id().unwrap();
        let fragments = self
            .db
            .get_my_fragments()
            .map_err(|e| format!("Ошибка при получении фрагментов: {}", e))?;

        let metadata_fragments: Vec<FragmentMetadata> = fragments
            .into_iter()
            .map(|f| FragmentMetadata {
                file_hash: f.file_hash,
                mime: f.mime,
                public: f.public,
                encrypted: f.encrypted,
                compressed: f.compressed,
                auto_decompress: f.auto_decompress,
                owner_key: f.owner_key,
                storage_peer_key: f.storage_peer_key,
                size: f.size,
                is_contract: f.is_contract,
            })
            .collect();

        let sync_data = FragmentMetadataSync {
            fragments: metadata_fragments,
            peer_id: my_peer_id.clone(),
        };

        let packet = TransportPacket {
            act: "sync_fragments".to_string(),
            to: None,
            data: Some(TransportData::FragmentMetadataSync(sync_data)),
            protocol: Protocol::SIGNAL,
            peer_key: my_peer_id,
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        println!(
            "{}",
            "[Peer] Отправка метаданных фрагментов на сигнальную ноду".cyan()
        );
        self.connection.send_packet(packet).await
    }

    pub async fn update_file(
        &self,
        file_hash: String,
        new_file_path: String,
        encrypt: bool,
        public: bool,
        auto_decompress: bool,
    ) -> Result<(), String> {
        println!("Обновление файла: {}", new_file_path);
        let file_size = tokio::fs::metadata(&new_file_path)
            .await
            .map_err(|e| format!("Ошибка при получении метаданных файла: {}", e))?
            .len();

        println!("Размер файла: {}", file_size);

        // Получаем информацию о текущем файле
        let fragments = self
            .db
            .get_my_fragments()
            .map_err(|e| format!("Ошибка при получении фрагментов: {}", e))?;

        let fragment = fragments
            .iter()
            .find(|f| f.file_hash == file_hash)
            .ok_or_else(|| format!("Файл с хешем {} не найден", file_hash))?;

        let token_info = self
            .db
            .get_token(&fragment.storage_peer_key)
            .map_err(|e| format!("Ошибка при получении токена: {}", e))?
            .ok_or_else(|| "Токен не найден".to_string())?;

        let used_space = self
            .db
            .get_token_used_space(&fragment.storage_peer_key)
            .map_err(|e| format!("Ошибка при получении использованного места: {}", e))?;

        if used_space + file_size > token_info.free_space && !public {
            return Err(format!(
                "Недостаточно места. Требуется: {}, Доступно: {}",
                file_size,
                token_info.free_space - used_space
            ));
        }

        // Читаем содержимое нового файла
        let mut file = tokio::fs::File::open(&new_file_path)
            .await
            .map_err(|e| format!("Ошибка при открытии файла: {}", e))?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .await
            .map_err(|e| format!("Ошибка при чтении файла: {}", e))?;

        // Сжимаем содержимое
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&contents)
            .map_err(|e| format!("Ошибка при сжатии файла: {}", e))?;
        let compressed_contents = encoder
            .finish()
            .map_err(|e| format!("Ошибка при завершении сжатия: {}", e))?;

        // Шифруем содержимое если нужно
        let (final_content, encrypted) = if encrypt {
            let encrypted_contents = self
                .db
                .encrypt_data(&compressed_contents)
                .map_err(|e| format!("Ошибка при шифровании: {}", e))?;

            let content = serde_json::to_string(&EncryptedData {
                nonce: encrypted_contents.1,
                content: encrypted_contents.0,
            })
            .map_err(|e| format!("Ошибка при сериализации: {}", e))?;
            (content.into_bytes(), true)
        } else {
            (compressed_contents, false)
        };

        let my_peer_id = self
            .db
            .get_or_create_peer_id()
            .map_err(|e| format!("Ошибка при получении peer_id: {}", e))?;

        let mime = mime_guess::from_path(new_file_path.clone()).first_or_text_plain();

        let packet = TransportPacket {
            act: "update_file".to_string(),
            to: Some(fragment.storage_peer_key.clone()),
            data: Some(TransportData::PeerFileUpdate(PeerFileUpdate {
                peer_id: my_peer_id.clone(),
                file_hash: file_hash.clone(),
                filename: fragment.filename.clone(),
                contents: final_content,
                token: token_info.token,
                mime: mime.to_string(),
                public,
                encrypted,
                compressed: true,
                auto_decompress,
            })),
            protocol: Protocol::TURN,
            peer_key: my_peer_id,
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.connection.send_packet(packet).await?;

        // Обновляем информацию об использованном месте
        self.db
            .update_token_used_space(&fragment.storage_peer_key, used_space + file_size)
            .map_err(|e| format!("Ошибка при обновлении использованного места: {}", e))?;

        Ok(())
    }

    pub async fn call_contract(
        &self,
        contract_hash: String,
        function_name: String,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        let packet = TransportPacket {
            act: "request_contract".to_string(),
            to: None,
            data: Some(TransportData::ContractExecutionRequest(
                ContractExecutionRequest {
                    contract_hash: contract_hash.clone(),
                    function_name,
                    payload,
                    peer_id: self.db.get_or_create_peer_id().unwrap(),
                },
            )),
            protocol: Protocol::SIGNAL,
            peer_key: self.db.get_or_create_peer_id().unwrap(),
            uuid: generate_uuid(),
            nodes: vec![],
            signature: None,
        };

        self.manager.auto_send_packet(packet).await
    }
}
