use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use k256::elliptic_curve::generic_array::GenericArray;

#[derive(Clone)]
pub struct NodeKeypair {
    signing_key: SigningKey,
    peer_id: String,
}

impl NodeKeypair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let peer_id = Self::public_key_to_peer_id(&signing_key.verifying_key());
        Self { signing_key, peer_id }
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&*self.signing_key.to_bytes())
    }

    pub fn from_hex(private_key_hex: &str) -> Result<Self, String> {
        let bytes = hex::decode(private_key_hex).map_err(|e| e.to_string())?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Private key must be 32 bytes".to_string())?;
        let signing_key = SigningKey::from_bytes(GenericArray::from_slice(&arr))
            .map_err(|e| e.to_string())?;
        let peer_id = Self::public_key_to_peer_id(&signing_key.verifying_key());
        Ok(Self { signing_key, peer_id })
    }

    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let peer_id = Self::public_key_to_peer_id(&signing_key.verifying_key());
        Self { signing_key, peer_id }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn public_key_to_peer_id(verifying_key: &k256::ecdsa::VerifyingKey) -> String {
        let point = verifying_key.to_encoded_point(true);
        hex::encode(point.as_bytes())
    }
}
