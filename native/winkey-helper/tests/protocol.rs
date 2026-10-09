//! Breaks caught: bypassed input validation, wrong command routing, malformed
//! CNG representation, reversed/truncated secrets and lost neutral failures.
use std::io::{Cursor, Write};
use std::process::{Command, Stdio};
use winkey_helper::{
    codec::*,
    error::{OpError, Reason},
    ops::KeyOps,
    wire::*,
};

const GENERATOR: &str = concat!(
    "04",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
);

#[derive(Default)]
struct Fixture {
    calls: Vec<String>,
    failure: Option<Reason>,
}
impl Fixture {
    fn call(&mut self, command: &str, tag: &str) -> Result<(), OpError> {
        self.calls.push(format!("{command}:{tag}"));
        match self.failure {
            Some(reason) => Err(OpError::native(
                0x80090016,
                reason,
                "key inaccessible to current token",
            )),
            None => Ok(()),
        }
    }
}
impl KeyOps for Fixture {
    fn generate(&mut self, tag: &str) -> Result<Vec<u8>, OpError> {
        self.call("generate", tag)?;
        Ok(hex::decode(GENERATOR).unwrap())
    }
    fn public_key(&mut self, tag: &str) -> Result<Vec<u8>, OpError> {
        self.call("public_key", tag)?;
        Ok(hex::decode(GENERATOR).unwrap())
    }
    fn ecdh(&mut self, tag: &str, peer: &[u8]) -> Result<[u8; 32], OpError> {
        assert_eq!(hex::encode(peer), GENERATOR);
        self.call("ecdh", tag)?;
        Ok([0x5a; 32])
    }
    fn delete(&mut self, tag: &str) -> Result<(), OpError> {
        self.call("delete", tag)
    }
    fn probe(&mut self) -> Result<(), OpError> {
        self.call("probe", "")
    }
}
fn invoke(value: serde_json::Value, ops: &mut Fixture) -> serde_json::Value {
    serde_json::from_str(&dispatch(serde_json::from_value(value).unwrap(), ops).to_json()).unwrap()
}

#[test]
fn request_size_is_bounded() {
    let mut exact = br#"{"cmd":"probe"}"#.to_vec();
    exact.resize(4096, b' ');
    assert!(read_request(&exact[..]).is_ok());
    exact.push(b' ');
    assert!(read_request(&exact[..]).is_err());
    let mut long = Cursor::new(vec![b' '; 1024 * 1024]);
    assert!(read_request(&mut long).is_err());
    assert!(long.position() <= 4097, "must not consume unbounded stdin");
}

#[test]
fn tag_requires_even_hex() {
    for bad in ["", "0", "0g", " 00", "00\n", &"00".repeat(257)] {
        assert!(decode_tag(bad).is_err(), "accepted invalid tag");
    }
    assert_eq!(decode_tag("00aAFF").unwrap(), vec![0, 170, 255]);
    assert_eq!(decode_tag(&"ff".repeat(256)).unwrap().len(), 256);
}

#[test]
fn key_names_hash_decoded_bytes_and_are_case_stable() {
    assert_eq!(
        key_name("00").unwrap(),
        "mordred-hermes:6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    );
    assert_eq!(key_name("aB").unwrap(), key_name("Ab").unwrap());
    assert_ne!(key_name("00").unwrap(), key_name("0000").unwrap());
}

#[test]
fn raw_secret_is_reversed_not_trimmed() {
    let mut little = [0u8; 32];
    little[0] = 1;
    little[1] = 2;
    let big = raw_to_be32(&little).unwrap();
    assert_eq!(&big[..30], &[0; 30]);
    assert_eq!(&big[30..], &[2, 1]);
    for n in [0, 31, 33, 64] {
        assert!(raw_to_be32(&vec![0; n]).is_err());
    }
}

#[test]
fn sec1_rejects_bad_magic_length_curve() {
    let peer = hex::decode(GENERATOR).unwrap();
    let mut blob = vec![0x45, 0x43, 0x4b, 0x31, 32, 0, 0, 0];
    blob.extend_from_slice(&peer[1..]);
    assert_eq!(cng_public_to_sec1(&blob).unwrap(), peer);
    assert_eq!(sec1_to_cng_public(&peer).unwrap(), blob);
    for index in [0, 3, 4, 7] {
        let mut bad = blob.clone();
        bad[index] ^= 1;
        assert!(cng_public_to_sec1(&bad).is_err());
    }
    assert!(cng_public_to_sec1(&blob[..71]).is_err());
    blob.push(0);
    assert!(cng_public_to_sec1(&blob).is_err());
    let mut bad = peer.clone();
    bad[0] = 2;
    assert!(sec1_to_cng_public(&bad).is_err());
    assert!(sec1_to_cng_public(&peer[..64]).is_err());
}

#[test]
fn unknown_command_is_refused() {
    let mut ops = Fixture::default();
    let value = invoke(serde_json::json!({"cmd":"secret-payload"}), &mut ops);
    assert_eq!(value["error"]["domain"], "helper");
    assert!(!value.to_string().contains("secret-payload"));
    assert!(ops.calls.is_empty());
}

#[test]
fn invalid_requests_never_touch_native_keys() {
    for value in [
        serde_json::json!({"cmd":"generate","tag_hex":""}),
        serde_json::json!({"cmd":"public_key"}),
        serde_json::json!({"cmd":"delete","tag_hex":"xyz"}),
        serde_json::json!({"cmd":"ecdh","tag_hex":"00","peer_pub_hex":"04"}),
        serde_json::json!({"cmd":"ecdh","tag_hex":"00"}),
    ] {
        let mut ops = Fixture::default();
        let response = invoke(value, &mut ops);
        assert_eq!(response["error"]["domain"], "helper");
        assert!(ops.calls.is_empty());
    }
}

#[test]
fn dispatch_preserves_success_shapes_and_routes_every_command() {
    let mut ops = Fixture::default();
    for command in ["generate", "public_key", "ecdh", "delete", "probe"] {
        let value = invoke(
            serde_json::json!({"cmd":command,"tag_hex":"aA","label":"accepted","unattended":false,"peer_pub_hex":GENERATOR}),
            &mut ops,
        );
        let want = match command {
            "generate" | "public_key" => serde_json::json!({"public_key_hex":GENERATOR}),
            "ecdh" => serde_json::json!({"shared_hex":"5a".repeat(32)}),
            _ => serde_json::json!({"ok":true}),
        };
        assert_eq!(value, want);
    }
    assert_eq!(
        ops.calls,
        vec![
            "generate:aa",
            "public_key:aa",
            "ecdh:aa",
            "delete:aa",
            "probe:"
        ]
    );
}

#[test]
fn failure_json_uses_neutral_reason() {
    for (reason, want) in [
        (Reason::NotFound, "NOT_FOUND"),
        (Reason::Exists, "EXISTS"),
        (Reason::Unavailable, "UNAVAILABLE"),
        (Reason::AuthDenied, "AUTH_DENIED"),
    ] {
        let mut ops = Fixture {
            failure: Some(reason),
            ..Default::default()
        };
        let value = invoke(
            serde_json::json!({"cmd":"public_key","tag_hex":"00"}),
            &mut ops,
        );
        assert_eq!(value["error"]["reason"], want);
        assert_eq!(value["error"]["domain"], "cng");
        assert_eq!(value["error"]["status"], 0x80090016u32);
    }
}

#[test]
fn process_returns_one_json_failure_without_echoing_input() {
    for bytes in [
        b"secret-sentinel".to_vec(),
        vec![b'x'; 4097],
        b"{}".to_vec(),
        b"\xff".to_vec(),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mordred-hermes-winkey"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(!out.status.success());
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(value["error"]["domain"], "helper");
        assert!(!String::from_utf8_lossy(&out.stdout).contains("secret-sentinel"));
        assert!(out.stderr.is_empty());
    }
}
