use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Packet {
    pub signature: Option<String>,
    pub data: Vec<u8>,
    pub nodes: Vec<String>,
    pub sender: String,
    pub receiver: String,
    pub max_hops: u8,
    /// Корреляция запрос/ответ: роутер назначает уникальный id;
    /// ответы должны повторять id входящего запроса.
    #[serde(default)]
    pub request_id: Option<u64>,
    /// App Plane protocol identifier; None = legacy/control traffic.
    #[serde(default)]
    pub protocol_id: Option<u16>,
    /// Идентификатор потока чанков (один на всё сообщение).
    #[serde(default)]
    pub chunk_stream_id: Option<u64>,
    /// Порядковый номер чанка (0-based).
    #[serde(default)]
    pub chunk_index: Option<u32>,
    /// Общее количество чанков в потоке.
    #[serde(default)]
    pub total_chunks: Option<u32>,
}

impl Packet {
    pub fn wire_size_estimate(&self) -> u64 {
        let sig = self.signature.as_ref().map(|s| s.len()).unwrap_or(0);
        let nodes: usize = self.nodes.iter().map(|s| s.len()).sum();
        let rid = self.request_id.map(|_| 8).unwrap_or(0);
        (sig + self.data.len()
            + self.nodes.len() * 4
            + nodes
            + self.sender.len()
            + self.receiver.len()
            + self.max_hops as usize
            + rid) as u64
    }

    pub fn is_chunk(&self) -> bool {
        self.chunk_stream_id.is_some() && self.chunk_index.is_some() && self.total_chunks.is_some()
    }

    /// Разбивает данные на чанки и возвращает вектор пакетов с одинаковыми
    /// `sender`, `receiver`, `nodes` и общим `chunk_stream_id`.
    /// Каждый пакет содержит кусок данных и порядковый номер чанка.
    ///
    /// Пример отправки:
    /// ```ignore
    /// let data = vec![0u8; 100_000];
    /// let chunks = Packet::chunk_packets(
    ///     &data,
    ///     4096,
    ///     stream_id,
    ///     "sender".into(),
    ///     "receiver".into(),
    ///     vec![],
    /// );
    /// for p in chunks {
    ///     router.send_to_peer(peer_id, p, None).await?;
    /// }
    /// ```
    pub fn chunk_packets(
        data: &[u8],
        chunk_size: usize,
        chunk_stream_id: u64,
        sender: impl Into<String>,
        receiver: impl Into<String>,
        nodes: Vec<String>,
        max_hops: Option<u8>,
    ) -> Vec<Packet> {
        let sender = sender.into();
        let receiver = receiver.into();
        let total = data.len().max(1).div_ceil(chunk_size);
        let total_chunks = total as u32;
        (0..total)
            .map(|i| {
                let start = i * chunk_size;
                let end = (start + chunk_size).min(data.len());
                let chunk_data = data[start..end].to_vec();
                Packet {
                    signature: None,
                    data: chunk_data,
                    nodes: nodes.clone(),
                    sender: sender.clone(),
                    receiver: receiver.clone(),
                    max_hops: max_hops.unwrap_or(8),
                    request_id: Some(chunk_stream_id),
                    chunk_stream_id: Some(chunk_stream_id),
                    chunk_index: Some(i as u32),
                    total_chunks: Some(total_chunks),
                    protocol_id: None,
                }
            })
            .collect()
    }
}
