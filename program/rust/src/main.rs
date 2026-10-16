mod sysalloc;
mod varnish;
use base64;
use common_access_token::{Algorithm, KeyId, RegisteredClaims, TokenBuilder, VerificationOptions};
use common_access_token::current_timestamp;
use varnish::*;

// The secret key used for signing and verifying tokens
const SECRET_KEY: &[u8] = b"my-secret-key-for-varnish-CDN";

// A pulib C function that takes a C-string argument
// and returns a C-string response (indicating success or failure)
extern "C" fn verify_signature(signature_ptr: *const std::ffi::c_char, signature_len: usize) -> *const std::ffi::c_char {
	let signature_base64 = unsafe {
		std::slice::from_raw_parts(signature_ptr as *const u8, signature_len)
	};

	// The signagture is base64 encoded, decode it first
	let signature = decode_base64(signature_base64);

	// Decode and verify the token
	let decoded_token_result = common_access_token::Token::from_bytes(signature.as_slice());
	if decoded_token_result.is_err() {
		return std::ptr::null() as *const std::ffi::c_char;
	}
	let decoded_token = decoded_token_result.unwrap();

	// Verify the signature
	if decoded_token.verify(SECRET_KEY).is_err() {
		return std::ptr::null() as *const std::ffi::c_char;
	}

	// Verify the claims
	let options = VerificationOptions::new()
		.verify_exp(true)
		.expected_issuer("example-issuer");
	if decoded_token.verify_claims(&options).is_err() {
		return std::ptr::null() as *const std::ffi::c_char;
	}

	std::ffi::CString::new("Signature is valid").unwrap().into_raw()
}
extern "C" fn create_token(_ptr: *const std::ffi::c_char, _len: usize) -> *const std::ffi::c_char {
	// Create a token
	let now = current_timestamp();
	let token = TokenBuilder::new()
		.algorithm(Algorithm::HmacSha256)
		.protected_key_id(KeyId::string("example-key-id"))
		.registered_claims(
			RegisteredClaims::new()
				.with_issuer("example-issuer")
				.with_subject("example-subject")
				.with_audience("example-audience")
				.with_expiration(now + 3600) // 1 hour from now
		)
		.custom_string(100, "custom-value")
		.sign(SECRET_KEY)
		.expect("Failed to sign token");

	// Encode token to bytes
	let token_bytes = token.to_bytes().expect("Failed to encode token");

	// Return base64 encoded token
	let token_base64 = base64::encode(token_bytes);
	std::ffi::CString::new(token_base64).unwrap().into_raw()
}

fn on_client_request(_a: u32, _b: u32) {
	let url = get_url();
	add_req_header("X-Hello", &get_url());

	if url == "/verify" {
		forge_with_post(CachingDecision::Uncached, |_a: u32, _b: u32, data: &[u8]| {
			if data.len() == 0 {
				// We can return a response, but also through a function call (faster)
				backend_response(400, "text/plain", b"No token provided");
			}
			// Decode and verify the token
			let decoded_token = common_access_token::Token::from_bytes(data)
				.expect("Failed to decode token");

			// Verify the signature
			decoded_token.verify(SECRET_KEY).expect("Failed to verify signature");

			// Verify the claims
			let options = VerificationOptions::new()
				.verify_exp(true)
				.expected_issuer("example-issuer");
			decoded_token.verify_claims(&options).expect("Failed to verify claims");

			BackendResponse {
				status: 200,
				content_type: "text/plain",
				body: "Token is valid".as_bytes().to_vec(),
			}
		});
	}
	else if url.contains("/cat") {
		forge(CachingDecision::Uncached, |_a: u32, _b: u32| {
			let now = current_timestamp();

			// Create a token
			let token = TokenBuilder::new()
				.algorithm(Algorithm::HmacSha256)
				.protected_key_id(KeyId::string("example-key-id"))
				.registered_claims(
					RegisteredClaims::new()
						.with_issuer("example-issuer")
						.with_subject("example-subject")
						.with_audience("example-audience")
						.with_expiration(now + 3600) // 1 hour from now
				)
				.custom_string(100, "custom-value")
				.sign(SECRET_KEY)
				.expect("Failed to sign token");

			// Encode token to bytes
			let token_bytes = token.to_bytes().expect("Failed to encode token");

			// Decode and verify the token
			let decoded_token = common_access_token::Token::from_bytes(&token_bytes)
				.expect("Failed to decode token");

			// Verify the signature
			decoded_token.verify(SECRET_KEY).expect("Failed to verify signature");

			// Verify the claims
			let options = VerificationOptions::new()
				.verify_exp(true)
				.expected_issuer("example-issuer");

			decoded_token.verify_claims(&options).expect("Failed to verify claims");

			BackendResponse {
				status: 200,
				content_type: "application/cbor",
				body: token_bytes,
			}
		});
	}

	forge(CachingDecision::Cached, |_a: u32, _b: u32| {
		backend_response(200, "text/plain", b"Default response from Rust");
	});
}

fn on_deliver(_a: u32, _b: u32) {
	add_resp_header("X-Delivered-By", "Rust");
	add_full_resp_header(get_req_header("X-Hello").as_str());
}

fn token_ok(token: &str) -> bool {
	!token.is_empty() && token.len() <= 128 && token.bytes().all(|c|
		c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.')
}

fn push_uri(out: &mut Vec<u8>, uri: &[u8], token: &str) {
	out.extend_from_slice(uri);
	out.push(if uri.contains(&b'?') { b'&' } else { b'?' });
	out.extend_from_slice(b"token=");
	out.extend_from_slice(token.as_bytes());
}

fn find_uri_attribute(line: &[u8]) -> Option<(usize, usize)> {
	let start = line.windows(5).position(|w| w == b"URI=\"")? + 5;
	let len = line[start..].iter().position(|&c| c == b'"')?;
	Some((start, start + len))
}

fn manifest_tokens<'a>(token: &'a str, body: &'a mut [u8]) -> Option<DeliverResponse<'a>> {
	if !token_ok(token) {
		deliver_response(403, "text/plain", b"Invalid token");
	}
	let mut out = Vec::with_capacity(body.len() + body.len() / 4);
	for line in body.split_inclusive(|&c| c == b'\n') {
		let eol = line.iter().rev().take_while(|&&c| c == b'\n' || c == b'\r').count();
		let (text, ending) = line.split_at(line.len() - eol);
		if text.is_empty() {
		} else if text[0] != b'#' {
			push_uri(&mut out, text, token);
		} else if let Some((start, end)) = find_uri_attribute(text) {
			out.extend_from_slice(&text[..start]);
			push_uri(&mut out, &text[start..end], token);
			out.extend_from_slice(&text[end..]);
		} else {
			out.extend_from_slice(text);
		}
		out.extend_from_slice(ending);
	}
	Some(DeliverResponse {
		status: 200,
		content_type: "application/vnd.apple.mpegurl",
		body: out.into(),
	})
}

pub fn main() {
	println!("RISC-V Rust example program started");
	register_function("verify_signature", verify_signature);
	register_function("create_token", create_token);
	deliver_transform!("on_manifest", manifest_tokens);
	set_on_deliver(on_deliver);
	wait_for_requests(on_client_request);
}
