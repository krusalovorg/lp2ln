use std::mem::size_of;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

const FRAME_COUNT: usize = 1024;
pub(super) const STREAM_QUEUE_BYTES: usize = 16 * 1024 * 1024;
pub(super) const DATAGRAM_QUEUE_BYTES: usize = 8 * 1024 * 1024;

/// Failure to admit bytes to a standard transport's writer. An admitted
/// frame still needs a protocol-level acknowledgement to confirm delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterAdmissionError {
    FrameTooLarge,
    Closed,
}

impl std::fmt::Display for WriterAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FrameTooLarge => "frame exceeds session writer limit",
            Self::Closed => "session writer closed",
        })
    }
}

impl std::error::Error for WriterAdmissionError {}

pub(super) struct QueuedFrame {
    pub data: Vec<u8>,
    _charge: OwnedSemaphorePermit,
}

pub(super) struct WriterQueue {
    tx: mpsc::Sender<QueuedFrame>,
    bytes: Arc<Semaphore>,
    max_bytes: usize,
    max_frame: usize,
}

impl WriterQueue {
    pub(super) fn channel(
        max_bytes: usize,
        max_frame: usize,
    ) -> (Self, mpsc::Receiver<QueuedFrame>) {
        let (tx, rx) = mpsc::channel(FRAME_COUNT);
        (
            Self {
                tx,
                bytes: Arc::new(Semaphore::new(max_bytes)),
                max_bytes,
                max_frame,
            },
            rx,
        )
    }

    pub(super) async fn send(&self, data: Vec<u8>) -> Result<u64> {
        let charge = data.capacity().saturating_add(size_of::<QueuedFrame>());
        if data.len() > self.max_frame || charge > self.max_bytes {
            return Err(WriterAdmissionError::FrameTooLarge.into());
        }
        let length = data.len() as u64;
        let permit = tokio::select! {
            _ = self.tx.closed() => return Err(WriterAdmissionError::Closed.into()),
            permit = self.bytes.clone().acquire_many_owned(charge as u32) => permit.map_err(|_| WriterAdmissionError::Closed)?,
        };
        let slot = self
            .tx
            .reserve()
            .await
            .map_err(|_| WriterAdmissionError::Closed)?;
        #[cfg(feature = "packet-trace")]
        crate::packet_trace::record_wire(&data, crate::packet_trace::Stage::WriterAdmitted);
        slot.send(QueuedFrame {
            data,
            _charge: permit,
        });
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn byte_budget_stays_charged_until_write_finishes() {
        let (writer, mut reader) = WriterQueue::channel(128, 100);
        writer.send(vec![0; 72]).await.unwrap();
        let in_flight = reader.recv().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), writer.send(vec![0; 72]))
                .await
                .is_err()
        );
        drop(in_flight);
        writer.send(vec![0; 72]).await.unwrap();
        assert_eq!(reader.recv().await.unwrap().data.len(), 72);
        let too_large = writer.send(vec![0; 256]).await.unwrap_err();
        assert_eq!(
            too_large.downcast_ref(),
            Some(&WriterAdmissionError::FrameTooLarge)
        );
        drop(reader);
        let closed = writer.send(vec![0; 72]).await.unwrap_err();
        assert_eq!(closed.downcast_ref(), Some(&WriterAdmissionError::Closed));
    }
}
