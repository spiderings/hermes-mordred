//! Explicit real-device tests, never a software-provider or CI emulation pass.
//! Run in an isolated credentialed Windows user with MORDRED_WINKEY_TEST=1:
//! cargo test --test live_cng -- --ignored --test-threads=1
#![cfg(windows)]

use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    ptr,
};
use windows_sys::Win32::Security::Cryptography::*;
use winkey_helper::codec::key_name;

fn gate() {
    assert_eq!(
        std::env::var("MORDRED_WINKEY_TEST").as_deref(),
        Ok("1"),
        "explicit actual-device gate required"
    );
}

fn tag() -> String {
    let mut bytes = b"mordred-hermes.live-test.".to_vec();
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    bytes.extend(random);
    hex::encode(bytes)
}

fn request(value: Value) -> (bool, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mordred-hermes-winkey"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(value.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.stderr.is_empty(),
        "native helper must use its structured error channel"
    );
    (
        out.status.success(),
        serde_json::from_slice(&out.stdout).unwrap(),
    )
}

fn success(value: Value) -> Value {
    let (ok, response) = request(value);
    assert!(ok, "{response}");
    response
}

struct OwnedKey {
    tag: String,
    public: String,
}
impl OwnedKey {
    fn create() -> Self {
        let tag = tag();
        let response = success(json!({"cmd":"generate","tag_hex":tag}));
        Self {
            tag,
            public: response["public_key_hex"].as_str().unwrap().into(),
        }
    }
}
impl Drop for OwnedKey {
    fn drop(&mut self) {
        let _ = request(json!({"cmd":"delete","tag_hex":self.tag}));
    }
}

#[test]
#[ignore = "requires actual Windows TPM and explicit MORDRED_WINKEY_TEST=1"]
fn live_creation_duplicate_reopen_ecdh_invalid_peer_and_deletion() {
    gate();
    let key = OwnedKey::create();
    let response = success(json!({"cmd":"public_key","tag_hex":key.tag}));
    assert_eq!(response["public_key_hex"], key.public);
    let (ok, duplicate) = request(json!({"cmd":"generate","tag_hex":key.tag}));
    assert!(!ok);
    assert_eq!(duplicate["error"]["reason"], "EXISTS");
    assert_eq!(
        success(json!({"cmd":"public_key","tag_hex":key.tag}))["public_key_hex"],
        key.public
    );

    let public = PublicKey::from_sec1_bytes(&hex::decode(&key.public).unwrap()).unwrap();
    let mut leading_zero = false;
    let mut comparisons = 0;
    for scalar in 1u32..=65535 {
        let mut bytes = [0u8; 32];
        bytes[28..].copy_from_slice(&scalar.to_be_bytes());
        let peer = SecretKey::from_slice(&bytes).unwrap();
        let expected = diffie_hellman(peer.to_nonzero_scalar(), public.as_affine());
        if scalar <= 8 || expected.raw_secret_bytes()[0] == 0 {
            let response = success(json!({"cmd":"ecdh","tag_hex":key.tag,
                "peer_pub_hex":hex::encode(peer.public_key().to_encoded_point(false).as_bytes())}));
            let actual = hex::decode(response["shared_hex"].as_str().unwrap()).unwrap();
            assert_eq!(actual.as_slice(), &expected.raw_secret_bytes()[..]);
            comparisons += 1;
        }
        if expected.raw_secret_bytes()[0] == 0 {
            leading_zero = true;
            break;
        }
    }
    assert!(leading_zero);
    assert!(comparisons >= 1);
    let (ok, _) = request(
        json!({"cmd":"ecdh","tag_hex":key.tag,"peer_pub_hex":format!("04{}","00".repeat(64))}),
    );
    assert!(!ok, "off-curve peer must not reach a secret");
    assert_eq!(
        success(json!({"cmd":"public_key","tag_hex":key.tag}))["public_key_hex"],
        key.public
    );
    success(json!({"cmd":"delete","tag_hex":key.tag}));
    let (ok, missing) = request(json!({"cmd":"public_key","tag_hex":key.tag}));
    assert!(!ok);
    assert_eq!(missing["error"]["reason"], "NOT_FOUND");
    let (ok, repeated) = request(json!({"cmd":"delete","tag_hex":key.tag}));
    assert!(!ok, "PCP cannot prove absence from an inaccessible keyset");
    assert_eq!(repeated["error"]["reason"], "UNAVAILABLE");
    assert_eq!(repeated["error"]["status"], missing["error"]["status"]);
    println!("independent ECDH comparisons={comparisons}; leading-zero case passed");
}

// Independent direct CNG observations: production must never attempt private export.
struct Handles(Vec<usize>);
impl Drop for Handles {
    fn drop(&mut self) {
        for h in self.0.iter().rev() {
            unsafe {
                NCryptFreeObject(*h);
            }
        }
    }
}

unsafe fn dword(handle: usize, property: windows_sys::core::PCWSTR) -> u32 {
    let mut value = [0u8; 4];
    let mut length = 0;
    assert_eq!(
        NCryptGetProperty(handle, property, value.as_mut_ptr(), 4, &mut length, 0),
        0
    );
    assert_eq!(length, 4);
    u32::from_le_bytes(value)
}

#[test]
#[ignore = "requires actual Windows TPM and explicit MORDRED_WINKEY_TEST=1"]
fn live_hardware_provider_nonexportable_key_policy() {
    gate();
    let key = OwnedKey::create();
    let mut handles = Handles(vec![]);
    let name: Vec<u16> = key_name(&key.tag)
        .unwrap()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // All pointers refer to live, correctly sized values; handles outlive each call.
    unsafe {
        let mut provider = 0;
        assert_eq!(
            NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0),
            0
        );
        handles.0.push(provider);
        let flags = dword(provider, NCRYPT_IMPL_TYPE_PROPERTY);
        assert_ne!(flags & NCRYPT_IMPL_HARDWARE_FLAG, 0);
        assert_eq!(flags & NCRYPT_IMPL_SOFTWARE_FLAG, 0);
        let mut native_key = 0;
        assert_eq!(
            NCryptOpenKey(provider, &mut native_key, name.as_ptr(), 0, 0),
            0
        );
        handles.0.push(native_key);
        assert_eq!(dword(native_key, NCRYPT_EXPORT_POLICY_PROPERTY), 0);
        let mut length = 0;
        assert_ne!(
            NCryptExportKey(
                native_key,
                0,
                BCRYPT_ECCPRIVATE_BLOB,
                ptr::null(),
                ptr::null_mut(),
                0,
                &mut length,
                0
            ),
            0,
            "private export sizing must be refused"
        );
    }
}

fn files(path: &Path, found: &mut BTreeSet<PathBuf>) {
    if !path.exists() {
        return;
    }
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            files(&entry.path(), found);
        } else {
            found.insert(entry.path());
        }
    }
}

#[test]
#[ignore = "requires isolated Windows TPM user and explicit MORDRED_WINKEY_TEST=1"]
fn live_concurrent_probes_cleanup_and_duplicate_creation() {
    gate();
    let store =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap()).join("Microsoft/Crypto/PCPKSP");
    let mut before = BTreeSet::new();
    files(&store, &mut before);
    let threads: Vec<_> = (0..4)
        .map(|_| std::thread::spawn(|| success(json!({"cmd":"probe"}))))
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    let mut after = BTreeSet::new();
    files(&store, &mut after);
    assert_eq!(before, after, "probe must not leave persistent key files");
    let tag = tag();
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let tag = tag.clone();
            std::thread::spawn(move || request(json!({"cmd":"generate","tag_hex":tag})))
        })
        .collect();
    let responses: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    // Guard any successful creation before assertions so failure cannot leak it.
    let owned = responses.iter().find(|(ok, _)| *ok).map(|(_, v)| OwnedKey {
        tag: tag.clone(),
        public: v["public_key_hex"].as_str().unwrap().into(),
    });
    assert_eq!(
        responses.iter().filter(|(ok, _)| *ok).count(),
        1,
        "concurrent creation responses: {responses:?}"
    );
    assert_eq!(
        responses.iter().find(|(ok, _)| !*ok).unwrap().1["error"]["reason"],
        "EXISTS"
    );
    let owned = owned.unwrap();
    assert_eq!(
        success(json!({"cmd":"public_key","tag_hex":tag}))["public_key_hex"],
        owned.public
    );
}
