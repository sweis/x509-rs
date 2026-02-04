//! Shared encoding and matching utilities.

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

/// Map common OID dotted-decimal strings to their short name equivalents.
///
/// These match the names used by OpenSSL for distinguished name components.
pub fn oid_short_name(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN".into(),
        "2.5.4.4" => "SN".into(),
        "2.5.4.5" => "serialNumber".into(),
        "2.5.4.6" => "C".into(),
        "2.5.4.7" => "L".into(),
        "2.5.4.8" => "ST".into(),
        "2.5.4.9" => "street".into(),
        "2.5.4.10" => "O".into(),
        "2.5.4.11" => "OU".into(),
        "2.5.4.12" => "title".into(),
        "2.5.4.17" => "postalCode".into(),
        "2.5.4.42" => "GN".into(),
        "1.2.840.113549.1.9.1" => "emailAddress".into(),
        "0.9.2342.19200300.100.1.25" => "DC".into(),
        other => other.to_string(),
    }
}

/// RFC 6125 hostname matching with wildcard support.
///
/// Checks for exact match or wildcard match (e.g., `*.example.com` matches
/// `sub.example.com` but not `deep.sub.example.com` or `example.com`).
pub fn hostname_matches(pattern: &str, hostname: &str) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();

    if pattern_lower == *hostname {
        return true;
    }

    // Wildcard matching: *.example.com
    if let Some(suffix) = pattern_lower.strip_prefix("*.") {
        if let Some(rest) = hostname.strip_suffix(suffix) {
            // rest should be "label." (a single label followed by a dot)
            if let Some(label) = rest.strip_suffix('.') {
                if !label.is_empty() && !label.contains('.') {
                    return true;
                }
            }
        }
    }

    false
}
