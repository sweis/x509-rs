//! Shared encoding and matching utilities.

use crate::oid;
use base64::Engine;

/// Format bytes as colon-separated uppercase hex (e.g., "AB:CD:EF").
pub fn hex_colon_upper(bytes: &[u8]) -> String {
    use std::fmt::Write;
    if bytes.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(bytes.len() * 3 - 1);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = write!(out, "{:02X}", b);
    }
    out
}

/// Encode bytes as base64 with PEM-style 64-character line wrapping.
pub fn base64_wrap(data: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    // Base64 output is always valid ASCII, so we can chunk the string directly.
    let num_lines = encoded.len().div_ceil(64);
    let mut result = String::with_capacity(encoded.len() + num_lines);
    let mut pos = 0;
    while pos < encoded.len() {
        if pos > 0 {
            result.push('\n');
        }
        let end = (pos + 64).min(encoded.len());
        result.push_str(&encoded[pos..end]);
        pos = end;
    }
    result
}

/// Map common OID dotted-decimal strings to their short name equivalents.
///
/// These match the names used by OpenSSL for distinguished name components.
pub fn oid_short_name(oid: &str) -> String {
    match oid {
        oid::COMMON_NAME => "CN".into(),
        oid::SURNAME => "SN".into(),
        oid::SERIAL_NUMBER => "serialNumber".into(),
        oid::COUNTRY => "C".into(),
        oid::LOCALITY => "L".into(),
        oid::STATE_OR_PROVINCE => "ST".into(),
        oid::STREET_ADDRESS => "street".into(),
        oid::ORGANIZATION => "O".into(),
        oid::ORGANIZATIONAL_UNIT => "OU".into(),
        oid::TITLE => "title".into(),
        oid::POSTAL_CODE => "postalCode".into(),
        oid::GIVEN_NAME => "GN".into(),
        oid::EMAIL_ADDRESS => "emailAddress".into(),
        oid::DOMAIN_COMPONENT => "DC".into(),
        other => other.to_string(),
    }
}

/// Detect whether input bytes are PEM-encoded.
///
/// Returns `true` if the input starts with `-----BEGIN` (after stripping
/// leading whitespace).
pub fn is_pem(input: &[u8]) -> bool {
    input
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take(10)
        .eq(b"-----BEGIN".iter())
}

/// Format an IPv6 address in OpenSSL-compatible expanded uppercase hex.
///
/// Each 16-bit segment is printed without leading zeros, separated by colons.
/// Example: `"2606:2800:220:1:248:1893:25C8:1946"`.
///
/// This avoids `::` compression so the output matches OpenSSL's display format.
pub fn format_ipv6_expanded(addr: &std::net::Ipv6Addr) -> String {
    addr.segments()
        .iter()
        .map(|s| format!("{:X}", s))
        .collect::<Vec<_>>()
        .join(":")
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

// ---------------------------------------------------------------------------
// Shared certificate-name matching (used by both check and verify modules)
// ---------------------------------------------------------------------------

/// Match a hostname against a list of DNS SAN names with CN fallback.
///
/// Implements RFC 6125: SAN DNS names take priority; CN is only checked
/// when no SAN DNS entries exist.
pub fn verify_hostname_match(dns_names: &[String], cn: Option<&str>, hostname: &str) -> bool {
    let hostname_lower = hostname.to_ascii_lowercase();

    if !dns_names.is_empty() {
        return dns_names
            .iter()
            .any(|pattern| hostname_matches(pattern, &hostname_lower));
    }

    if let Some(cn) = cn {
        return hostname_matches(cn, &hostname_lower);
    }

    false
}

/// Match an email against a list of certificate email addresses.
///
/// Case-insensitive comparison per RFC 5280.
pub fn verify_email_match(emails: &[String], target: &str) -> bool {
    let target_lower = target.to_ascii_lowercase();
    emails
        .iter()
        .any(|e| e.to_ascii_lowercase() == target_lower)
}

/// Match an IP address against a list of SAN IP strings.
///
/// Both sides are normalized so that equivalent representations (e.g.,
/// `::1` vs `0:0:0:0:0:0:0:1`) compare equal.
pub fn verify_ip_match(san_ips: &[String], target: &str) -> bool {
    let normalized = normalize_ip(target);
    san_ips
        .iter()
        .any(|san_ip| normalize_ip(san_ip) == normalized)
}

/// Normalize an IP address string for comparison.
///
/// IPv4 addresses are formatted via `Ipv4Addr::to_string()`.
/// IPv6 addresses are formatted via [`format_ipv6_expanded`].
/// Other strings are lowercased.
pub fn normalize_ip(ip: &str) -> String {
    if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
        return addr.to_string();
    }
    if let Ok(addr) = ip.parse::<std::net::Ipv6Addr>() {
        return format_ipv6_expanded(&addr);
    }
    ip.to_ascii_lowercase()
}
