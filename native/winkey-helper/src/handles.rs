//! CNG ownership: a successful delete consumes the key handle exactly once.
use crate::error::{check, OpError, Reason};
use std::marker::PhantomData;
use windows_sys::Win32::Security::Cryptography::{NCryptDeleteKey, NCryptFreeObject};

pub(crate) enum ProviderKind {}
pub(crate) enum KeyKind {}
pub(crate) enum SecretKind {}
pub(crate) type Provider = Handle<ProviderKind>;
pub(crate) type Key = Handle<KeyKind>;
pub(crate) type Secret = Handle<SecretKind>;

pub(crate) struct Handle<Kind> {
    raw: usize,
    kind: PhantomData<Kind>,
}
impl<Kind> Handle<Kind> {
    /// Caller transfers sole ownership of a handle returned by a successful CNG call.
    pub(crate) unsafe fn from_raw(raw: usize) -> Result<Self, OpError> {
        if raw == 0 {
            return Err(OpError::native(
                0x80090026,
                Reason::Unavailable,
                "CNG returned an empty handle",
            ));
        }
        Ok(Self {
            raw,
            kind: PhantomData,
        })
    }
    pub(crate) fn raw(&self) -> usize {
        self.raw
    }
}
impl<Kind> Drop for Handle<Kind> {
    fn drop(&mut self) {
        if self.raw != 0 {
            // Sole ownership; successful deletion sets raw to zero before Drop.
            unsafe {
                NCryptFreeObject(self.raw);
            }
        }
    }
}
impl Key {
    pub(crate) fn delete(mut self) -> Result<(), OpError> {
        // Platform Crypto Provider on actual NitroTPM rejects SILENT on deletion
        // with NTE_BAD_FLAGS; zero is its supported deletion flag set.
        // On failure CNG leaves ownership with us; Drop then frees the handle.
        check(
            unsafe { NCryptDeleteKey(self.raw, 0) },
            "key deletion failed",
        )?;
        self.raw = 0;
        Ok(())
    }
}

/// Roll back only a key that this operation successfully created, never a name lookup.
pub(crate) struct PendingKey(Option<Key>);
impl PendingKey {
    pub(crate) fn new(key: Key) -> Self {
        Self(Some(key))
    }
    pub(crate) fn key(&self) -> &Key {
        self.0.as_ref().expect("owned pending key")
    }
    pub(crate) fn commit(mut self) -> Key {
        self.0.take().expect("owned pending key")
    }
    pub(crate) fn delete(mut self) -> Result<(), OpError> {
        self.0.take().expect("owned pending key").delete()
    }
}
impl Drop for PendingKey {
    fn drop(&mut self) {
        if let Some(key) = self.0.take() {
            let _ = key.delete();
        }
    }
}
