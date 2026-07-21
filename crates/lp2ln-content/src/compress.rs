//! Per-chunk compression framing (used when `FileManifest.codec == CODEC_FRAMED_LZ4`).
//!
//! Framed plaintext chunk = `[flag: 1 byte][payload]`:
//! - `FLAG_RAW`  — payload is the original bytes (chunk didn't compress);
//! - `FLAG_LZ4`  — payload is lz4 with prepended size (`lz4_flex` format).
//!
//! Framing happens **before** encryption — ciphertext is incompressible.
//! Incompressible chunks (media, archives) are stored raw so the only
//! overhead is the 1-byte flag.
//!
//! ponytail: lz4 for speed; swap to zstd if ratio ever matters more than CPU.

use crate::error::ContentError;

pub const FLAG_RAW: u8 = 0;
pub const FLAG_LZ4: u8 = 1;

/// Frame a plaintext chunk, compressing only when it actually helps.
pub fn compress_frame(plain: &[u8]) -> Vec<u8> {
    let lz = lz4_flex::compress_prepend_size(plain);
    if lz.len() + 1 < plain.len() + 1 {
        let mut out = Vec::with_capacity(lz.len() + 1);
        out.push(FLAG_LZ4);
        out.extend_from_slice(&lz);
        out
    } else {
        let mut out = Vec::with_capacity(plain.len() + 1);
        out.push(FLAG_RAW);
        out.extend_from_slice(plain);
        out
    }
}

/// Inverse of [`compress_frame`]. Input is untrusted — returns `Err`, never panics.
pub fn decompress_frame(framed: &[u8]) -> Result<Vec<u8>, ContentError> {
    match framed.split_first() {
        Some((&FLAG_RAW, rest)) => Ok(rest.to_vec()),
        Some((&FLAG_LZ4, rest)) => lz4_flex::decompress_size_prepended(rest)
            .map_err(|e| ContentError::Other(format!("lz4 decompress: {e}"))),
        Some((flag, _)) => Err(ContentError::Other(format!("unknown chunk frame flag {flag}"))),
        None => Err(ContentError::Other("empty chunk frame".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressible_roundtrip() {
        let plain = vec![b'a'; 100_000];
        let framed = compress_frame(&plain);
        assert_eq!(framed[0], FLAG_LZ4);
        assert!(framed.len() < plain.len() / 10);
        assert_eq!(decompress_frame(&framed).unwrap(), plain);
    }

    #[test]
    fn incompressible_stored_raw() {
        use rand::RngCore;
        let mut plain = vec![0u8; 4096];
        rand::rng().fill_bytes(&mut plain);
        let framed = compress_frame(&plain);
        assert_eq!(framed[0], FLAG_RAW);
        assert_eq!(framed.len(), plain.len() + 1);
        assert_eq!(decompress_frame(&framed).unwrap(), plain);
    }

    #[test]
    fn empty_and_garbage_frames_fail_safely() {
        assert!(decompress_frame(&[]).is_err());
        assert!(decompress_frame(&[7, 1, 2]).is_err());
        // Truncated lz4 payload must error, not panic.
        assert!(decompress_frame(&[FLAG_LZ4, 0xff, 0xff]).is_err());
        // Empty payloads are valid.
        assert_eq!(decompress_frame(&compress_frame(&[])).unwrap(), Vec::<u8>::new());
    }
}
