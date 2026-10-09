use crate::error::{OpError, Reason};

pub trait KeyOps {
    fn generate(&mut self, tag_hex: &str) -> Result<Vec<u8>, OpError>;
    fn public_key(&mut self, tag_hex: &str) -> Result<Vec<u8>, OpError>;
    fn ecdh(&mut self, tag_hex: &str, peer_sec1: &[u8]) -> Result<[u8; 32], OpError>;
    fn delete(&mut self, tag_hex: &str) -> Result<(), OpError>;
    fn probe(&mut self) -> Result<(), OpError>;
}

/// No emulation or software custody on hosts without the native implementation.
pub struct UnavailableOps;
fn unavailable() -> OpError {
    OpError::native(
        0x80090029,
        Reason::Unavailable,
        "Windows hardware provider unavailable",
    )
}
impl KeyOps for UnavailableOps {
    fn generate(&mut self, _: &str) -> Result<Vec<u8>, OpError> {
        Err(unavailable())
    }
    fn public_key(&mut self, _: &str) -> Result<Vec<u8>, OpError> {
        Err(unavailable())
    }
    fn ecdh(&mut self, _: &str, _: &[u8]) -> Result<[u8; 32], OpError> {
        Err(unavailable())
    }
    fn delete(&mut self, _: &str) -> Result<(), OpError> {
        Err(unavailable())
    }
    fn probe(&mut self) -> Result<(), OpError> {
        Err(unavailable())
    }
}
