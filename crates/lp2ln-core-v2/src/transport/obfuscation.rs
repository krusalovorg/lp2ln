use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, sleep};

const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObfuscationMode {
    Plain,
    MimicHttp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObfuscationConfig {
    pub mode: ObfuscationMode,
    pub fake_hosts: Vec<String>,
    pub fake_paths: Vec<String>,
    pub padding_min: usize,
    pub padding_max: usize,
    pub min_chunk_size: usize,
    pub max_chunk_size: usize,
    pub min_chunk_delay_ms: u64,
    pub max_chunk_delay_ms: u64,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            mode: ObfuscationMode::Plain,
            fake_hosts: vec![
                "www.google.com".to_string(),
                "www.cloudflare.com".to_string(),
                "yandex.ru".to_string(),
            ],
            fake_paths: vec![
                "/api/v1/ping".to_string(),
                "/v2/status".to_string(),
                "/cdn-cgi/trace".to_string(),
            ],
            padding_min: 64,
            padding_max: 512,
            min_chunk_size: 128,
            max_chunk_size: 1400,
            min_chunk_delay_ms: 0,
            max_chunk_delay_ms: 12,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Obfuscator {
    config: ObfuscationConfig,
}

impl Default for Obfuscator {
    fn default() -> Self {
        Self {
            config: ObfuscationConfig::default(),
        }
    }
}

impl Obfuscator {
    pub fn from_config(config: ObfuscationConfig) -> Self {
        Self { config }
    }

    pub fn plain() -> Self {
        Self::from_config(ObfuscationConfig::default())
    }

    pub fn config(&self) -> &ObfuscationConfig {
        &self.config
    }

    pub fn is_enabled(&self) -> bool {
        self.config.mode != ObfuscationMode::Plain
    }

    pub fn encode_datagram(&self, payload: &[u8]) -> Result<Vec<u8>> {
        match self.config.mode {
            ObfuscationMode::Plain => Ok(payload.to_vec()),
            ObfuscationMode::MimicHttp => self.encode_http_mimic_datagram(payload),
        }
    }

    pub fn decode_datagram(&self, datagram: &[u8]) -> Result<Vec<u8>> {
        match self.config.mode {
            ObfuscationMode::Plain => Ok(datagram.to_vec()),
            ObfuscationMode::MimicHttp => self.decode_http_mimic_datagram(datagram),
        }
    }

    pub async fn write_frame<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
        payload: &[u8],
    ) -> Result<()> {
        match self.config.mode {
            ObfuscationMode::Plain => write_length_prefixed_frame(writer, payload).await,
            ObfuscationMode::MimicHttp => self.write_http_mimic_frame(writer, payload).await,
        }
    }

    pub async fn read_frame<R: AsyncReadExt + Unpin>(&self, reader: &mut R) -> Result<Vec<u8>> {
        match self.config.mode {
            ObfuscationMode::Plain => read_length_prefixed_frame(reader).await,
            ObfuscationMode::MimicHttp => self.read_http_mimic_frame(reader).await,
        }
    }

    async fn write_http_mimic_frame<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
        payload: &[u8],
    ) -> Result<()> {
        let frame = self.encode_http_mimic_datagram(payload)?;
        let split_at = find_http_header_end(&frame)
            .ok_or_else(|| anyhow::anyhow!("HTTP-mimic frame missing header/body separator"))?;
        let (headers, body) = frame.split_at(split_at);

        write_chunked(writer, headers, &self.config).await?;
        write_chunked(writer, body, &self.config).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn read_http_mimic_frame<R: AsyncReadExt + Unpin>(&self, reader: &mut R) -> Result<Vec<u8>> {
        let header_bytes = read_http_headers(reader).await?;
        let header_text = std::str::from_utf8(&header_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 HTTP headers: {}", e))?;
        let (content_length, padding_len) = parse_http_lengths(header_text)?;

        if content_length > MAX_HTTP_BODY_BYTES {
            return Err(anyhow::anyhow!(
                "HTTP-mimic body too large: {} bytes",
                content_length
            ));
        }
        if padding_len > content_length {
            return Err(anyhow::anyhow!(
                "Invalid HTTP-mimic payload: padding {} > length {}",
                padding_len,
                content_length
            ));
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                anyhow::anyhow!("Connection closed while reading HTTP-mimic body")
            } else {
                anyhow::anyhow!("Failed to read HTTP-mimic body: {}", e)
            }
        })?;
        body.truncate(content_length - padding_len);
        Ok(body)
    }

    fn encode_http_mimic_datagram(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand::rng();
        let pad_len = bounded_usize(self.config.padding_min, self.config.padding_max);
        let mut body = Vec::with_capacity(payload.len() + pad_len);
        body.extend_from_slice(payload);
        if pad_len > 0 {
            body.extend((0..pad_len).map(|_| rng.random::<u8>()));
        }
        let host = pick_or_default(&self.config.fake_hosts, "www.cloudflare.com");
        let path = pick_or_default(&self.config.fake_paths, "/api/v1/ping");
        let req = build_http_request(&host, &path, body.len(), pad_len);
        let mut out = req.into_bytes();
        out.extend_from_slice(&body);
        Ok(out)
    }

    fn decode_http_mimic_datagram(&self, datagram: &[u8]) -> Result<Vec<u8>> {
        let split_at = find_http_header_end(datagram)
            .ok_or_else(|| anyhow::anyhow!("HTTP-mimic datagram missing header terminator"))?;
        let (headers, body) = datagram.split_at(split_at);
        let headers = std::str::from_utf8(headers)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 HTTP headers in datagram: {}", e))?;
        let (content_length, padding_len) = parse_http_lengths(headers)?;
        if content_length > body.len() {
            return Err(anyhow::anyhow!(
                "Invalid HTTP-mimic datagram content length: {} > body {}",
                content_length,
                body.len()
            ));
        }
        if padding_len > content_length {
            return Err(anyhow::anyhow!(
                "Invalid HTTP-mimic datagram padding: {} > {}",
                padding_len,
                content_length
            ));
        }
        Ok(body[..content_length - padding_len].to_vec())
    }
}

fn build_http_request(host: &str, path: &str, content_len: usize, padding_len: usize) -> String {
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nX-Padding-Len: {}\r\n\r\n",
        path, host, content_len, padding_len
    )
}

async fn write_chunked<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    cfg: &ObfuscationConfig,
) -> Result<()> {
    let min_chunk = cfg.min_chunk_size.max(1);
    let max_chunk = cfg.max_chunk_size.max(min_chunk);
    let mut offset = 0usize;

    while offset < data.len() {
        let requested = bounded_usize(min_chunk, max_chunk);
        let end = (offset + requested).min(data.len());
        writer.write_all(&data[offset..end]).await?;
        offset = end;
        maybe_sleep(cfg.min_chunk_delay_ms, cfg.max_chunk_delay_ms).await;
    }
    Ok(())
}

async fn maybe_sleep(min_delay_ms: u64, max_delay_ms: u64) {
    if max_delay_ms == 0 {
        return;
    }
    let delay = bounded_u64(min_delay_ms, max_delay_ms);
    if delay > 0 {
        sleep(Duration::from_millis(delay)).await;
    }
}

fn parse_http_lengths(headers: &str) -> Result<(usize, usize)> {
    let mut content_len = None;
    let mut pad_len = 0usize;

    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            content_len = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|e| anyhow::anyhow!("Invalid Content-Length value: {}", e))?,
            );
            continue;
        }
        if let Some(value) = lower.strip_prefix("x-padding-len:") {
            pad_len = value
                .trim()
                .parse::<usize>()
                .map_err(|e| anyhow::anyhow!("Invalid X-Padding-Len value: {}", e))?;
        }
    }

    let content_len =
        content_len.ok_or_else(|| anyhow::anyhow!("Missing Content-Length in HTTP-mimic frame"))?;
    Ok((content_len, pad_len))
}

async fn read_http_headers<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::<u8>::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                anyhow::anyhow!("Connection closed while reading HTTP-mimic headers")
            } else {
                anyhow::anyhow!("Failed to read HTTP-mimic headers: {}", e)
            }
        })?;
        buf.push(byte[0]);
        if buf.len() > MAX_HTTP_HEADER_BYTES {
            return Err(anyhow::anyhow!("HTTP-mimic headers exceed max size"));
        }
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }
}

fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

async fn write_length_prefixed_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await.map_err(|e| {
        anyhow::anyhow!("Failed to write plain frame length: {}", e)
    })?;
    writer.write_all(data).await.map_err(|e| {
        anyhow::anyhow!("Failed to write plain frame data: {}", e)
    })?;
    writer.flush().await.map_err(|e| {
        anyhow::anyhow!("Failed to flush plain frame writer: {}", e)
    })?;
    Ok(())
}

async fn read_length_prefixed_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            anyhow::anyhow!("Connection closed by peer")
        } else {
            anyhow::anyhow!("Failed to read plain frame length: {}", e)
        }
    })?;
    let packet_len = u32::from_be_bytes(len_bytes) as usize;
    if packet_len > MAX_HTTP_BODY_BYTES {
        return Err(anyhow::anyhow!("Packet size too large: {} bytes", packet_len));
    }
    let mut packet_bytes = vec![0u8; packet_len];
    reader.read_exact(&mut packet_bytes).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            anyhow::anyhow!("Connection closed by peer")
        } else {
            anyhow::anyhow!("Failed to read plain frame data: {}", e)
        }
    })?;
    Ok(packet_bytes)
}

fn pick_or_default(values: &[String], fallback: &str) -> String {
    if values.is_empty() {
        return fallback.to_string();
    }
    let idx = rand::rng().random_range(0..values.len());
    values[idx].clone()
}

fn bounded_usize(min: usize, max: usize) -> usize {
    if max <= min {
        min
    } else {
        rand::rng().random_range(min..=max)
    }
}

fn bounded_u64(min: u64, max: u64) -> u64 {
    if max <= min {
        min
    } else {
        rand::rng().random_range(min..=max)
    }
}
