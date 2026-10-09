//! User-scoped P-256 custody in the explicit Microsoft Platform Crypto Provider.
//! No password capture, impersonation, software provider or private-key export.
use crate::{
    codec::{cng_public_to_sec1, key_name, raw_to_be32, sec1_to_cng_public},
    error::{check, validate_provider_flags, OpError, Reason},
    handles::{Key, PendingKey, Provider, Secret},
    key_lock::KeyLock,
    ops::KeyOps,
};
use std::ptr;
use windows_sys::{core::PCWSTR, Win32::Security::Cryptography::*};
use zeroize::Zeroizing;

pub struct CngOps;

fn unavailable(message: &'static str) -> OpError {
    OpError::native(0x80090029, Reason::Unavailable, message)
}

fn wide_name(tag: &str) -> Result<Vec<u16>, OpError> {
    Ok(key_name(tag)?.encode_utf16().chain(Some(0)).collect())
}

fn property_dword(handle: usize, property: PCWSTR) -> Result<u32, OpError> {
    let mut bytes = [0u8; 4];
    let mut count = 0;
    // Handle and property are owned/static; CNG receives exactly the writable byte count.
    check(
        unsafe { NCryptGetProperty(handle, property, bytes.as_mut_ptr(), 4, &mut count, 0) },
        "CNG property query failed",
    )?;
    if count != 4 {
        return Err(unavailable("invalid CNG property length"));
    }
    Ok(u32::from_le_bytes(bytes))
}

fn provider() -> Result<Provider, OpError> {
    let mut raw = 0;
    check(
        unsafe { NCryptOpenStorageProvider(&mut raw, MS_PLATFORM_CRYPTO_PROVIDER, 0) },
        "Windows Platform Crypto Provider unavailable",
    )?;
    let provider = unsafe { Provider::from_raw(raw)? };
    validate_provider_flags(property_dword(provider.raw(), NCRYPT_IMPL_TYPE_PROPERTY)?)?;
    Ok(provider)
}

fn nonexportable(key: &Key) -> Result<(), OpError> {
    if property_dword(key.raw(), NCRYPT_EXPORT_POLICY_PROPERTY)? != 0 {
        return Err(unavailable("key export policy is not non-exportable"));
    }
    Ok(())
}

fn create(provider: &Provider, name: &[u16]) -> Result<PendingKey, OpError> {
    let mut raw = 0;
    // Zero flags: user scope, no overwrite, no software/VBS fallback.
    check(
        unsafe {
            NCryptCreatePersistedKey(
                provider.raw(),
                &mut raw,
                BCRYPT_ECDH_P256_ALGORITHM,
                name.as_ptr(),
                0,
                0,
            )
        },
        "key creation failed",
    )?;
    let key = PendingKey::new(unsafe { Key::from_raw(raw)? });
    // The tested TPM refuses an explicit KeyAgreement usage property. Its default
    // usage supports real ECDH; validate operations rather than changing that property.
    check(
        unsafe { NCryptFinalizeKey(key.key().raw(), NCRYPT_SILENT_FLAG) },
        "key finalization failed",
    )?;
    nonexportable(key.key())?;
    Ok(key)
}

fn open(provider: &Provider, name: &[u16]) -> Result<Key, OpError> {
    let mut raw = 0;
    check(
        unsafe {
            NCryptOpenKey(
                provider.raw(),
                &mut raw,
                name.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            )
        },
        "key not accessible to current logon token; it may be absent or inaccessible",
    )?;
    let key = unsafe { Key::from_raw(raw)? };
    nonexportable(&key)?;
    Ok(key)
}

fn public(key: &Key) -> Result<Vec<u8>, OpError> {
    let mut count = 0;
    check(
        unsafe {
            NCryptExportKey(
                key.raw(),
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                ptr::null_mut(),
                0,
                &mut count,
                NCRYPT_SILENT_FLAG,
            )
        },
        "public key size query failed",
    )?;
    if count != 72 {
        return Err(unavailable("unexpected P-256 public key size"));
    }
    let mut blob = [0u8; 72];
    check(
        unsafe {
            NCryptExportKey(
                key.raw(),
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                blob.as_mut_ptr(),
                72,
                &mut count,
                NCRYPT_SILENT_FLAG,
            )
        },
        "public key export failed",
    )?;
    if count != 72 {
        return Err(unavailable("incomplete P-256 public key"));
    }
    cng_public_to_sec1(&blob)
}

fn exchange(provider: &Provider, key: &Key, peer: &[u8]) -> Result<[u8; 32], OpError> {
    let blob = sec1_to_cng_public(peer)?;
    let mut raw_peer = 0;
    check(
        unsafe {
            NCryptImportKey(
                provider.raw(),
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                ptr::null(),
                &mut raw_peer,
                blob.as_ptr(),
                72,
                0,
            )
        },
        "P-256 peer import failed",
    )?;
    let peer = unsafe { Key::from_raw(raw_peer)? };
    let mut raw_secret = 0;
    check(
        unsafe {
            NCryptSecretAgreement(key.raw(), peer.raw(), &mut raw_secret, NCRYPT_SILENT_FLAG)
        },
        "hardware ECDH failed",
    )?;
    let secret = unsafe { Secret::from_raw(raw_secret)? };
    let mut count = 0;
    check(
        unsafe {
            NCryptDeriveKey(
                secret.raw(),
                BCRYPT_KDF_RAW_SECRET,
                ptr::null(),
                ptr::null_mut(),
                0,
                &mut count,
                0,
            )
        },
        "raw ECDH size query failed",
    )?;
    if count != 32 {
        return Err(unavailable("unexpected raw ECDH size"));
    }
    let mut raw = Zeroizing::new([0u8; 32]);
    check(
        unsafe {
            NCryptDeriveKey(
                secret.raw(),
                BCRYPT_KDF_RAW_SECRET,
                ptr::null(),
                raw.as_mut_ptr(),
                32,
                &mut count,
                0,
            )
        },
        "raw ECDH derivation failed",
    )?;
    if count != 32 {
        return Err(unavailable("incomplete raw ECDH secret"));
    }
    raw_to_be32(raw.as_ref())
}

impl KeyOps for CngOps {
    fn generate(&mut self, tag: &str) -> Result<Vec<u8>, OpError> {
        let _lock = KeyLock::acquire(tag)?;
        let name = wide_name(tag)?;
        let provider = provider()?;
        let pending = create(&provider, &name)?;
        let public = public(pending.key())?;
        // Only successful generation commits a persisted key. Drop frees the handle.
        let _committed = pending.commit();
        Ok(public)
    }
    fn public_key(&mut self, tag: &str) -> Result<Vec<u8>, OpError> {
        let _lock = KeyLock::acquire(tag)?;
        let name = wide_name(tag)?;
        let provider = provider()?;
        let key = open(&provider, &name)?;
        public(&key)
    }
    fn ecdh(&mut self, tag: &str, peer: &[u8]) -> Result<[u8; 32], OpError> {
        sec1_to_cng_public(peer)?;
        let _lock = KeyLock::acquire(tag)?;
        let name = wide_name(tag)?;
        let provider = provider()?;
        let key = open(&provider, &name)?;
        // Validate the existing key's exact algorithm/representation as well.
        public(&key)?;
        exchange(&provider, &key, peer)
    }
    fn delete(&mut self, tag: &str) -> Result<(), OpError> {
        let _lock = KeyLock::acquire(tag)?;
        let name = wide_name(tag)?;
        let provider = provider()?;
        match open(&provider, &name) {
            Ok(key) => key.delete(),
            Err(mut error) if error.reason == Some(Reason::NotFound) => {
                // PCP returns BAD_KEYSET for both absence and a retained key
                // bound to another TPM. Enumeration also omits inaccessible keys,
                // and a fresh-key probe can succeed there: neither proves absence.
                // Preserve the cause and refuse to falsely acknowledge removal.
                error.reason = Some(Reason::Unavailable);
                error.message = "key absent or inaccessible; deletion was not performed";
                Err(error)
            }
            Err(error) => Err(error),
        }
    }
    fn probe(&mut self) -> Result<(), OpError> {
        let mut random = [0u8; 32];
        check(
            unsafe {
                BCryptGenRandom(
                    ptr::null_mut(),
                    random.as_mut_ptr(),
                    32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            },
            "probe randomness unavailable",
        )?;
        let mut tag = b"mordred-hermes.probe.".to_vec();
        tag.extend(random);
        let name = wide_name(&hex::encode(tag))?;
        let provider = provider()?;
        let pending = create(&provider, &name)?;
        let result = (|| {
            let public = public(pending.key())?;
            // Generator G corresponds to peer scalar 1: ECDH must equal our public X.
            let generator = hex::decode(concat!(
                "04",
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
            ))
            .expect("constant P-256 generator");
            let secret = Zeroizing::new(exchange(&provider, pending.key(), &generator)?);
            if secret.as_ref() != &public[1..33] {
                return Err(unavailable("hardware ECDH probe mismatch"));
            }
            Ok(())
        })();
        let cleanup = pending.delete();
        // A successful operation with failed cleanup is not a successful probe.
        result.and(cleanup)
    }
}
