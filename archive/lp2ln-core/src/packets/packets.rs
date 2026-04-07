use crate::db::Storage;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PeerInfo {
    pub is_signal_server: bool,
    pub total_space: u64,
    pub free_space: u64,
    pub stored_files: Vec<String>,
    pub public_key: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PeerWaitConnection {
    pub connect_peer_id: String,
    pub public_ip: String,
    pub public_port: u16,
    pub initiator_key: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PeerFileSaved {
    pub filename: String,
    pub token: String,
    pub token_hash: Option<String>,
    pub storage_peer_key: String,
    pub owner_key: String,
    pub hash_file: String,
    pub encrypted: bool,
    pub compressed: bool,
    pub auto_decompress: bool,
    pub public: bool,
    pub size: u64,
    pub mime: String,
    pub is_contract: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PeerFileGet {
    pub peer_id: String,
    pub file_hash: String,
    pub token: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PeerUploadFile {
    pub peer_id: String,
    pub file_hash: String,
    pub filename: String,
    pub contents: Vec<u8>,
    pub token: String,
    pub mime: String,
    pub public: bool,
    pub encrypted: bool,
    pub compressed: bool,
    pub auto_decompress: bool,
    pub is_contract: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SyncPeerInfo {
    pub uuid: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SyncPeerInfoData {
    pub peers: Vec<SyncPeerInfo>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub enum Protocol {
    TURN,
    STUN,
    SIGNAL,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub enum Status {
    ERROR,
    SUCCESS,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Message {
    pub text: String,
    pub nonce: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ProxyMessage {
    pub text: Vec<u8>,
    pub nonce: [u8; 12],
    pub from_peer_id: String,
    pub end_peer_id: String,
    pub request_id: String,
    pub mime: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct FileData {
    pub filename: String,
    pub contents: Vec<u8>,
    pub peer_id: String,
    pub hash_file: String,
    pub encrypted: bool,
    pub mime: String,
    pub compressed: bool,
    pub public: bool,
    pub auto_decompress: bool,
}


#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct StunSyncPubAddr {
    pub public_addr: String
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct StorageValidTokenRequest {
    pub token: String,
    pub peer_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct StorageValidTokenResponse {
    pub peer_id: String,
    pub status: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct StorageReservationRequest {
    pub peer_id: String,
    pub size_in_bytes: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct StorageToken {
    pub file_size: u64,                  // Размер файла
    pub storage_provider: String,      // Паблик-ключ (или крипто-адрес) хранителя
    pub timestamp: u64,                  // Unix-время создания токена
    pub signature: Vec<u8>,              // Подпись хранителя, подтверждающая согласие
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct StorageReservationResponse {
    pub peer_id: String,
    pub token: String,  // base64 encoded StorageToken
    pub size_in_bytes: u64,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct PeerSearchRequest {
    pub search_id: String, // id поиска
    pub peer_id: String, // id пира инициатора поиска
    pub max_hops: u32, // максимальное количество прыжков
    pub path: Vec<SearchPathNode>, // путь поиска от инициатора до текущего узла
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct SearchPathNode {
    pub uuid: String,        // UUID узла
    pub public_ip: String, // Публичный адрес узла
    pub public_port: i64,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct PeerSearchResponse {
    pub search_id: String,     // id поиска
    pub peer_id: String,       // id пира инициатора поиска
    pub found_peer_id: String, // id пира найденного
    pub public_ip: String,   // публичный адрес ноды пира
    pub public_port: i64,
    pub hops: u32,            // количество прыжков
    pub path: Vec<SearchPathNode>, // путь поиска от инициатора до нашедшего пира
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SignalServerInfo {
    pub public_key: String,
    pub public_ip: String,
    pub port: i64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PeerFileMove {
    pub file_hash: String,
    pub peer_id: String,
    pub token: String,
    pub new_path: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct GetFragmentsMetadata {
    pub token_hash: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FragmentSearchRequest {
    pub query: String,
    pub request_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FragmentSearchResponse {
    pub fragments: Vec<Storage>,
    pub request_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PeerFileUpdate {
    pub peer_id: String,
    pub file_hash: String,
    pub filename: String,
    pub contents: Vec<u8>,
    pub token: String,
    pub mime: String,
    pub public: bool,
    pub encrypted: bool,
    pub compressed: bool,
    pub auto_decompress: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct FileRequest {
    pub file_hash: String,
    pub request_id: String,
    pub from_peer_id: String,
    pub end_peer_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContractExecutionRequest {
    pub contract_hash: String,
    pub function_name: String,
    pub payload: Vec<u8>,
    pub peer_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContractExecutionResponse {
    pub contract_hash: String,
    pub result: Vec<u8>,
    pub peer_id: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub enum TransportData {
    Message(Message),
    ProxyMessage(ProxyMessage),
    FileRequest(FileRequest),
    PeerInfo(PeerInfo),
    PeerWaitConnection(PeerWaitConnection),
    PeerFileGet(PeerFileGet),
    PeerUploadFile(PeerUploadFile),
    SyncPeerInfoData(SyncPeerInfoData),
    StorageReservationRequest(StorageReservationRequest),
    StorageReservationResponse(StorageReservationResponse),
    StorageValidTokenRequest(StorageValidTokenRequest),
    StorageValidTokenResponse(StorageValidTokenResponse),
    PeerFileSaved(PeerFileSaved),
    StunSyncPubAddr(StunSyncPubAddr),
    FileData(FileData),
    PeerSearchRequest(PeerSearchRequest),
    PeerSearchResponse(PeerSearchResponse),
    SignalServerInfo(SignalServerInfo),
    PeerFileAccessChange(PeerFileAccessChange),
    PeerFileDelete(PeerFileDelete),
    PeerFileMove(PeerFileMove),
    FragmentMetadataSync(FragmentMetadataSync),
    GetFragmentsMetadata(GetFragmentsMetadata),
    FragmentSearchRequest(FragmentSearchRequest),
    FragmentSearchResponse(FragmentSearchResponse),
    PeerFileUpdate(PeerFileUpdate),
    ContractExecutionRequest(ContractExecutionRequest),
    ContractExecutionResponse(ContractExecutionResponse),
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct TransportPacket {
    pub act: String,         //info, answer, wait_connection,
    pub to: Option<String>,  //кому отправляем данный пакет
    pub data: Option<TransportData>,
    pub protocol: Protocol,     // TURN, STUN, SIGNAL
    pub peer_key: String,
    pub uuid: String,
    pub nodes: Vec<SearchPathNode>, // ноды через которых прошел пакет
    pub signature: Option<String>,  // подпись пакета
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct EncryptedData {
    pub content: Vec<u8>,
    pub nonce: [u8; 12],
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PeerFileAccessChange {
    pub file_hash: String,
    pub public: bool,
    pub peer_id: String,
    pub token: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PeerFileDelete {
    pub file_hash: String,
    pub peer_id: String,
    pub token: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct FragmentMetadata {
    pub file_hash: String,
    pub mime: String,
    pub public: bool,
    pub encrypted: bool,
    pub compressed: bool,
    pub auto_decompress: bool,
    pub owner_key: String,
    pub storage_peer_key: String,
    pub size: u64,
    pub is_contract: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct FragmentMetadataSync {
    pub fragments: Vec<FragmentMetadata>,
    pub peer_id: String,
}

impl std::fmt::Display for TransportPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TransportPacket {{ act: {}, to: {:?}, protocol: {:?}, uuid: {}, signature: {:?} }}",
            self.act, self.to, self.protocol, format!("{:?}...{:?}", &self.uuid[0..5], &self.uuid[30..]), self.signature
        )
    }
}