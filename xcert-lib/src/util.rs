//! Shared encoding utilities.

use base64::Engine;

/// Format bytes as colon-separated uppercase hex (e.g., "AB:CD:EF").
pub fn hex_colon_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Encode bytes as base64 with PEM-style 64-character line wrapping.
pub fn base64_wrap(data: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    encoded
        .as_bytes()
        .chunks(64)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .collect::<Vec<_>>()
        .join("\n")
}
