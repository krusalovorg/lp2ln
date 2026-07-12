use crate::packet::Packet;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn encode_packet(packet: Packet) -> Result<Vec<u8>> {
    postcard::to_allocvec(&packet).map_err(|e| anyhow::anyhow!("Failed to encode packet: {}", e))
}

pub fn decode_packet(bytes: Vec<u8>) -> Result<Packet> {
    postcard::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("Failed to decode packet: {}", e))
}

pub async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    let len_bytes = len.to_be_bytes();

    writer
        .write_all(&len_bytes)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to write frame length: {}", e))?;

    writer
        .write_all(data)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to write frame data: {}", e))?;

    writer
        .flush()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to flush writer: {}", e))?;

    Ok(())
}

pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            anyhow::anyhow!("Connection closed by peer")
        } else {
            anyhow::anyhow!("Failed to read frame length: {}", e)
        }
    })?;

    let packet_len = u32::from_be_bytes(len_bytes) as usize;

    if packet_len > 10 * 1024 * 1024 {
        return Err(anyhow::anyhow!(
            "Packet size too large: {} bytes",
            packet_len
        ));
    }

    let mut packet_bytes = vec![0u8; packet_len];
    reader.read_exact(&mut packet_bytes).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            anyhow::anyhow!("Connection closed by peer")
        } else {
            anyhow::anyhow!("Failed to read frame data: {}", e)
        }
    })?;

    Ok(packet_bytes)
}
