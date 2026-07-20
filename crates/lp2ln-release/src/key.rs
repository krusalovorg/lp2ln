use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use k256::elliptic_curve::rand_core::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("invalid key hex: {0}")]
    BadKeyHex(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("serialization error: {0}")]
    Codec(#[from] postcard::Error),
}

pub struct ReleaseSigningKey(SigningKey);

impl ReleaseSigningKey {
    pub fn generate() -> Self {
        Self(SigningKey::random(&mut OsRng))
    }

    pub fn from_hex(s: &str) -> Result<Self, ReleaseError> {
        let bytes = hex::decode(s).map_err(|_| ReleaseError::BadKeyHex(s.into()))?;
        SigningKey::from_slice(&bytes)
            .map(Self)
            .map_err(|_| ReleaseError::BadKeyHex(s.into()))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    pub fn verify_key(&self) -> ReleaseVerifyKey {
        ReleaseVerifyKey(*self.0.verifying_key())
    }

    /// Signs `body` with SHA-256 prehash (k256 `sha256` feature).
    pub fn sign(&self, body: &[u8]) -> Vec<u8> {
        let sig: Signature = self.0.sign(body);
        sig.to_der().as_bytes().to_vec()
    }
}

pub struct ReleaseVerifyKey(VerifyingKey);

impl ReleaseVerifyKey {
    pub fn from_hex(s: &str) -> Result<Self, ReleaseError> {
        let bytes = hex::decode(s).map_err(|_| ReleaseError::BadKeyHex(s.into()))?;
        VerifyingKey::from_sec1_bytes(&bytes)
            .map(Self)
            .map_err(|_| ReleaseError::BadKeyHex(s.into()))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0.to_encoded_point(true).as_bytes())
    }

    pub fn verify(&self, body: &[u8], sig_der: &[u8]) -> Result<(), ReleaseError> {
        let sig = Signature::from_der(sig_der).map_err(|_| ReleaseError::BadSignature)?;
        self.0.verify(body, &sig).map_err(|_| ReleaseError::BadSignature)
    }
}
