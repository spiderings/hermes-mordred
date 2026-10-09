use crate::{
    codec::{decode_tag, sec1_to_cng_public},
    error::OpError,
    ops::KeyOps,
};
use serde::Deserialize;
use std::io::Read;
use zeroize::Zeroize;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub cmd: String,
    pub tag_hex: Option<String>,
    pub label: Option<String>,
    pub peer_pub_hex: Option<String>,
    pub unattended: Option<bool>,
}
pub struct Response(pub serde_json::Value);
impl Response {
    pub fn to_json(&self) -> String {
        self.0.to_string()
    }
    pub fn is_error(&self) -> bool {
        self.0.get("error").is_some()
    }

    pub fn from_error(error: OpError) -> Self {
        let mut body = serde_json::json!({
            "domain": if error.reason.is_some() { "cng" } else { "helper" },
            "status": error.status,
            "message": error.message,
        });
        if let Some(reason) = error.reason {
            body["reason"] = reason.as_str().into();
        }
        Self(serde_json::json!({"error":body}))
    }
}
// Responses can contain an ECDH secret. Wipe the owned hex buffer on all paths.
impl Drop for Response {
    fn drop(&mut self) {
        if let Some(serde_json::Value::String(secret)) = self.0.get_mut("shared_hex") {
            secret.zeroize();
        }
    }
}

pub fn read_request(input: impl Read) -> Result<Request, OpError> {
    let mut bytes = Vec::new();
    input
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| OpError::request("request read failed"))?;
    if bytes.len() > 4096 {
        return Err(OpError::request("request exceeds 4096 bytes"));
    }
    serde_json::from_slice(&bytes).map_err(|_| OpError::request("invalid request"))
}

pub fn dispatch(request: Request, ops: &mut dyn KeyOps) -> Response {
    match dispatch_inner(request, ops) {
        Ok(value) => Response(value),
        Err(error) => Response::from_error(error),
    }
}

fn dispatch_inner(request: Request, ops: &mut dyn KeyOps) -> Result<serde_json::Value, OpError> {
    if request.cmd == "probe" {
        ops.probe()?;
        return Ok(serde_json::json!({"ok":true}));
    }
    if !matches!(
        request.cmd.as_str(),
        "generate" | "public_key" | "ecdh" | "delete"
    ) {
        return Err(OpError::request("unknown command"));
    }
    let tag = hex::encode(decode_tag(
        request
            .tag_hex
            .as_deref()
            .ok_or_else(|| OpError::request("tag required"))?,
    )?);
    match request.cmd.as_str() {
        "generate" => Ok(serde_json::json!({"public_key_hex":hex::encode(ops.generate(&tag)?)})),
        "public_key" => {
            Ok(serde_json::json!({"public_key_hex":hex::encode(ops.public_key(&tag)?)}))
        }
        "delete" => {
            ops.delete(&tag)?;
            Ok(serde_json::json!({"ok":true}))
        }
        "ecdh" => {
            let peer = hex::decode(
                request
                    .peer_pub_hex
                    .as_deref()
                    .ok_or_else(|| OpError::request("peer required"))?,
            )
            .map_err(|_| OpError::request("invalid peer hex"))?;
            sec1_to_cng_public(&peer)?;
            let mut secret = ops.ecdh(&tag, &peer)?;
            let encoded = hex::encode(secret.as_slice());
            secret.zeroize();
            Ok(serde_json::json!({"shared_hex":encoded}))
        }
        _ => unreachable!("command validated above"),
    }
}
