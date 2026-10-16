#[path = "../../rust/src/sysalloc.rs"]
mod sysalloc;
#[path = "../../rust/src/varnish.rs"]
mod varnish;
use serde_json::{json, Value};
use std::ffi::{c_char, CString};
use std::time::{SystemTime, UNIX_EPOCH};
use varnish::*;

// HS256 JSON Web Tokens (RFC 7519) using native base64 and SHA-256.
// From VCL:
//   set req.http.X-JWT-Sub = riscv.call("jwt_verify", req.http.Authorization);
//   set req.http.X-Token = riscv.call("jwt_sign", "alice");
const SECRET_KEY: &[u8] = b"my-secret-key-for-varnish-CDN";
const TOKEN_LIFETIME: i64 = 3600;
const B64URL: u32 = BASE64_URL | BASE64_NOPAD;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
	let mut k = [0u8; 64];
	if key.len() > k.len() {
		k[..32].copy_from_slice(&sha256(key));
	} else {
		k[..key.len()].copy_from_slice(key);
	}

	let mut inner = Vec::with_capacity(k.len() + msg.len());
	inner.extend(k.iter().map(|b| b ^ 0x36));
	inner.extend_from_slice(msg);
	let inner_hash = sha256(&inner);

	let mut outer = [0u8; 64 + 32];
	for (o, b) in outer.iter_mut().zip(k.iter()) {
		*o = b ^ 0x5c;
	}
	outer[64..].copy_from_slice(&inner_hash);
	sha256(&outer)
}

fn equal_constant_time(a: &[u8], b: &[u8]) -> bool {
	a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

fn header_safe(text: &str) -> bool {
	!text.is_empty() && text.len() <= 256 && text.bytes().all(|c| c >= 0x20 && c != 0x7f)
}

fn unix_time() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn jwt_encode(claims: &Value) -> String {
	let mut token = base64_encode(br#"{"alg":"HS256","typ":"JWT"}"#, B64URL);
	token.push('.');
	token.push_str(&base64_encode(claims.to_string().as_bytes(), B64URL));
	let signature = hmac_sha256(SECRET_KEY, token.as_bytes());
	token.push('.');
	token.push_str(&base64_encode(&signature, B64URL));
	token
}

fn jwt_decode(token: &str, now: i64) -> Option<Value> {
	let (signing_input, signature) = token.rsplit_once('.')?;
	let (header, payload) = signing_input.split_once('.')?;
	if payload.contains('.') {
		return None;
	}

	// Authenticate before parsing anything the client sent
	let signature = base64_decode(signature.as_bytes(), B64URL)?;
	if !equal_constant_time(&signature, &hmac_sha256(SECRET_KEY, signing_input.as_bytes())) {
		return None;
	}

	let header: Value = serde_json::from_slice(&base64_decode(header.as_bytes(), B64URL)?).ok()?;
	if header.get("alg")?.as_str()? != "HS256" {
		return None;
	}

	let claims: Value = serde_json::from_slice(&base64_decode(payload.as_bytes(), B64URL)?).ok()?;
	if now as f64 >= claims.get("exp")?.as_f64()? {
		return None;
	}
	if let Some(nbf) = claims.get("nbf") {
		if (now as f64) < nbf.as_f64()? {
			return None;
		}
	}
	if !header_safe(claims.get("sub")?.as_str()?) {
		return None;
	}
	Some(claims)
}

fn c_string(text: &str) -> *const c_char {
	CString::new(text).map_or(std::ptr::null(), |s| s.into_raw())
}

// Returns the subject of a valid token, or NULL
extern "C" fn jwt_verify(arg: *const c_char, len: usize) -> *const c_char {
	let arg = unsafe { std::slice::from_raw_parts(arg as *const u8, len) };
	let Ok(token) = std::str::from_utf8(arg) else {
		return std::ptr::null();
	};
	let token = token.strip_prefix("Bearer ").unwrap_or(token);

	match jwt_decode(token, unix_time()) {
		Some(claims) => c_string(claims["sub"].as_str().unwrap_or_default()),
		None => std::ptr::null(),
	}
}

// Returns a token for the subject, valid for TOKEN_LIFETIME
extern "C" fn jwt_sign(arg: *const c_char, len: usize) -> *const c_char {
	let arg = unsafe { std::slice::from_raw_parts(arg as *const u8, len) };
	let subject = match std::str::from_utf8(arg) {
		Ok(subject) if header_safe(subject) => subject,
		_ => return std::ptr::null(),
	};

	let now = unix_time();
	c_string(&jwt_encode(&json!({
		"sub": subject,
		"iat": now,
		"exp": now + TOKEN_LIFETIME,
	})))
}

fn on_client_request(_a: u32, _b: u32) {}

pub fn main() {
	register_function("jwt_verify", jwt_verify);
	register_function("jwt_sign", jwt_sign);
	wait_for_requests(on_client_request);
}
