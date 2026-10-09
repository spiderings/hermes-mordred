//! Serialize helper operations on one user's key across processes and sessions.
//! PCP's create/finalize pair was observed to allow two simultaneous creations
//! of the same name despite neither caller requesting overwrite.
use crate::{
    codec::key_name,
    error::{OpError, Reason},
};
use sha2::{Digest, Sha256};
use std::{marker::PhantomData, ptr, rc::Rc};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::{GetLengthSid, GetTokenInformation, IsValidSid, TokenUser, TOKEN_QUERY, TOKEN_USER},
    System::Threading::{
        CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex, WaitForSingleObject,
    },
};

fn failure(status: u32) -> OpError {
    OpError::native(
        status,
        Reason::Unavailable,
        "key operation lock unavailable",
    )
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// Mutex ownership is thread-affine, so the guard must never be Send or Sync.
pub(crate) struct KeyLock {
    handle: Handle,
    _thread: PhantomData<Rc<()>>,
}
impl KeyLock {
    pub(crate) fn acquire(tag: &str) -> Result<Self, OpError> {
        let key = key_name(tag)?;
        let mut raw = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(failure(unsafe { GetLastError() }));
        }
        let token = Handle(raw);
        // Aligned storage, bounded well above TOKEN_USER plus the maximum SID.
        let mut storage = [0usize; 128];
        let mut count = 0;
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                storage.as_mut_ptr().cast(),
                std::mem::size_of_val(&storage) as u32,
                &mut count,
            )
        } == 0
        {
            return Err(failure(unsafe { GetLastError() }));
        }
        if (count as usize) < std::mem::size_of::<TOKEN_USER>()
            || count as usize > std::mem::size_of_val(&storage)
        {
            return Err(failure(13));
        }
        let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
        if unsafe { IsValidSid(user.User.Sid) } == 0 {
            return Err(failure(13));
        }
        let sid_len = unsafe { GetLengthSid(user.User.Sid) } as usize;
        let sid = unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), sid_len) };
        let name = format!(
            "Global\\mordred-hermes-winkey-{}-{}",
            hex::encode(Sha256::digest(sid)),
            key
        );
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // Default token DACL restricts access. Global spans logon sessions; the
        // SID separates users. Squatting/access denial fails closed, never unlocked.
        let raw = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if raw.is_null() {
            return Err(failure(unsafe { GetLastError() }));
        }
        let handle = Handle(raw);
        match unsafe { WaitForSingleObject(handle.0, 30_000) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self {
                handle,
                _thread: PhantomData,
            }),
            WAIT_TIMEOUT => Err(failure(WAIT_TIMEOUT)),
            _ => Err(failure(unsafe { GetLastError() })),
        }
    }
}
impl Drop for KeyLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.handle.0);
        }
    }
}
