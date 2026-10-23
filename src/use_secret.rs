//! Domain-separated input for the use-secret HMAC endpoint.
//!
//! Callers supply a message. They do not choose the bytes that go under the
//! MAC, so this endpoint cannot sign audit lines, webhooks, or fingerprints.

/// Domain label mixed into every use-secret MAC.
pub const USE_SECRET_DOMAIN: &[u8] = b"ironcrypt-use-secret-v1";

/// Build the MAC input: domain || length-prefixed service, name, and body.
pub fn use_secret_message(service: &str, secret_name: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        USE_SECRET_DOMAIN.len() + 1 + 12 + service.len() + secret_name.len() + body.len(),
    );
    out.extend_from_slice(USE_SECRET_DOMAIN);
    out.push(0xff);
    push_len_prefixed(&mut out, service.as_bytes());
    push_len_prefixed(&mut out, secret_name.as_bytes());
    push_len_prefixed(&mut out, body);
    out
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let take = len as usize;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes[..take.min(bytes.len())]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_cannot_slide_into_the_body() {
        let a = use_secret_message("pay", "key", b"ab");
        let b = use_secret_message("paykey", "", b"ab");
        assert_ne!(a, b);
        let c = use_secret_message("pay", "key", b"ab");
        let d = use_secret_message("pay", "ke", b"yab");
        assert_ne!(c, d);
    }
}
