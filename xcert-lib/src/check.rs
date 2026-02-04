//! Certificate validity checks: expiry, hostname, email, IP matching.

use crate::fields::{CertificateInfo, SanEntry};
use std::time::{SystemTime, UNIX_EPOCH};

/// Check if the certificate expires within `seconds` from now.
///
/// Returns `true` if the certificate will still be valid after `seconds` have
/// elapsed. Returns `false` if it will have expired by then (or is already expired).
pub fn check_expiry(cert: &CertificateInfo, seconds: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let deadline = now.saturating_add(seconds);
    let not_after = cert.not_after.timestamp;

    if not_after < 0 {
        return false;
    }

    (not_after as u64) > deadline
}

/// Check if the certificate matches the given hostname.
///
/// Checks SAN DNS entries first; falls back to CN only if no SAN DNS entries exist.
/// Supports wildcard matching (e.g., `*.example.com` matches `sub.example.com`
/// but not `deep.sub.example.com` or `example.com`).
pub fn check_host(cert: &CertificateInfo, hostname: &str) -> bool {
    let hostname_lower = hostname.to_ascii_lowercase();

    let san_dns: Vec<&str> = cert
        .san_entries()
        .into_iter()
        .filter_map(|e| match e {
            SanEntry::Dns(name) => Some(name.as_str()),
            _ => None,
        })
        .collect();

    // If SAN DNS entries exist, use them exclusively (RFC 6125)
    if !san_dns.is_empty() {
        return san_dns
            .iter()
            .any(|pattern| hostname_matches(pattern, &hostname_lower));
    }

    // Fall back to CN if no SAN DNS entries
    for (key, value) in &cert.subject.components {
        if key == "CN" && hostname_matches(value, &hostname_lower) {
            return true;
        }
    }

    false
}

/// Check if the certificate matches the given email address.
///
/// Checks SAN email entries and subject emailAddress attribute.
pub fn check_email(cert: &CertificateInfo, email: &str) -> bool {
    let email_lower = email.to_ascii_lowercase();

    for e in cert.emails() {
        if e.to_ascii_lowercase() == email_lower {
            return true;
        }
    }

    false
}

/// Check if the certificate matches the given IP address.
///
/// Checks SAN IP address entries. Supports both IPv4 and IPv6.
pub fn check_ip(cert: &CertificateInfo, ip: &str) -> bool {
    let normalized = normalize_ip(ip);

    for entry in cert.san_entries() {
        if let SanEntry::Ip(san_ip) = entry {
            if normalize_ip(san_ip) == normalized {
                return true;
            }
        }
    }

    false
}

fn hostname_matches(pattern: &str, hostname: &str) -> bool {
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

fn normalize_ip(ip: &str) -> String {
    if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
        return addr.to_string();
    }
    if let Ok(addr) = ip.parse::<std::net::Ipv6Addr>() {
        let segments = addr.segments();
        return segments
            .iter()
            .map(|s| format!("{:x}", s))
            .collect::<Vec<_>>()
            .join(":");
    }
    ip.to_ascii_lowercase()
}
