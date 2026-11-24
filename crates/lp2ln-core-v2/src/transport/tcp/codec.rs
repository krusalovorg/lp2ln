use crate::packet::Packet;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

pub fn encode_packet(packet: Packet) -> Result<Vec<u8>> {
    postcard::to_allocvec(&packet).map_err(|e| anyhow::anyhow!("Failed to encode packet: {}", e))
}

pub fn decode_packet(bytes: Vec<u8>) -> Result<Packet> {
    decode_packet_slice(&bytes)
}

pub(crate) fn decode_packet_slice(bytes: &[u8]) -> Result<Packet> {
    // Preflight the fields preceding the hop list without allocating. Each
    // hop owns a String and vector entry, so bound record amplification.
    let (signature, remaining) = postcard::take_from_bytes::<Option<&str>>(bytes)?;
    anyhow::ensure!(
        signature.is_none_or(|value| value.len() <= 256),
        "legacy signature field too large"
    );
    let (_, remaining) = postcard::take_from_bytes::<&[u8]>(remaining)?;
    let (nodes, mut remaining) = postcard::take_from_bytes::<usize>(remaining)?;
    anyhow::ensure!(
        nodes <= u8::MAX as usize,
        "legacy frame hop list exceeds 255 entries"
    );
    for _ in 0..nodes + 2 {
        let (identity, rest) = postcard::take_from_bytes::<&str>(remaining)?;
        anyhow::ensure!(identity.len() <= 256, "legacy identity field too large");
        remaining = rest;
    }
    postcard::from_bytes(bytes).map_err(|e| anyhow::anyhow!("Failed to decode packet: {}", e))
}

/// At decode the wire and owned packet overlap. Afterwards, legacy AEAD
/// can hold ciphertext and plaintext together. The retained charge shrinks.
pub(crate) fn decode_reservation(frame: usize) -> usize {
    frame.saturating_mul(3).saturating_add(24 * 1024)
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
    let len = read_frame_len(reader, MAX_FRAME_BYTES).await?;
    read_frame_body(reader, len).await
}

pub(crate) async fn read_frame_len<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    max: usize,
) -> Result<usize> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            anyhow::anyhow!("Connection closed by peer")
        } else {
            anyhow::anyhow!("Failed to read frame length: {}", e)
        }
    })?;

    let packet_len = u32::from_be_bytes(len_bytes) as usize;

    if packet_len > max {
        return Err(anyhow::anyhow!(
            "Packet size too large: {} bytes",
            packet_len
        ));
    }

    Ok(packet_len)
}

pub(crate) async fn read_frame_body<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    packet_len: usize,
) -> Result<Vec<u8>> {
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
