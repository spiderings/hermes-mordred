use crate::error::OpError;
use sha2::{Digest, Sha256};

// BCRYPT_ECDH_PUBLIC_P256_MAGIC followed by cbKey, both little-endian DWORDs.
const PUBLIC_HEADER: [u8; 8] = [0x45, 0x43, 0x4b, 0x31, 32, 0, 0, 0];

pub fn decode_tag(tag_hex: &str) -> Result<Vec<u8>, OpError> {
    if tag_hex.is_empty() || tag_hex.len() > 512 || tag_hex.len() % 2 != 0 {
        return Err(OpError::request(
            "tag must contain 1 to 256 bytes of even hex",
        ));
    }
    hex::decode(tag_hex).map_err(|_| OpError::request("invalid tag hex"))
}

pub fn key_name(tag_hex: &str) -> Result<String, OpError> {
    let tag = decode_tag(tag_hex)?;
    Ok(format!(
        "mordred-hermes:{}",
        hex::encode(Sha256::digest(tag))
    ))
}

/// TRUNCATE is little-endian; Mordred's ECDH boundary is exactly 32 big-endian bytes.
pub fn raw_to_be32(raw: &[u8]) -> Result<[u8; 32], OpError> {
    let mut result: [u8; 32] = raw
        .try_into()
        .map_err(|_| OpError::request("invalid raw P-256 secret length"))?;
    result.reverse();
    Ok(result)
}

pub fn cng_public_to_sec1(blob: &[u8]) -> Result<Vec<u8>, OpError> {
    if blob.len() != 72 || blob[..8] != PUBLIC_HEADER {
        return Err(OpError::request("invalid CNG P-256 public blob"));
    }
    let mut public = Vec::with_capacity(65);
    public.push(4);
    public.extend_from_slice(&blob[8..]);
    Ok(public)
}

/// Shape conversion only. CNG import must additionally reject off-curve peers.
pub fn sec1_to_cng_public(peer: &[u8]) -> Result<Vec<u8>, OpError> {
    if peer.len() != 65 || peer[0] != 4 {
        return Err(OpError::request(
            "peer must be an uncompressed P-256 public key",
        ));
    }
    let mut blob = Vec::with_capacity(72);
    blob.extend_from_slice(&PUBLIC_HEADER);
    blob.extend_from_slice(&peer[1..]);
    Ok(blob)
}
