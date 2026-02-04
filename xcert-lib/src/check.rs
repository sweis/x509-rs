//! Certificate validity checks: expiry, hostname, email, IP matching.

use crate::fields::{CertificateInfo, SanEntry};
use crate::util;
use std::time::{SystemTime, UNIX_EPOCH};

/// Check if the certificate expires within `seconds` from now.
///
/// Returns `true` if the certificate is currently valid (notBefore is in the
/// past) and will still be valid after `seconds` have elapsed. Returns `false`
/// if the certificate is not yet valid, already expired, or will expire within
/// the given window.
pub fn check_expiry(cert: &CertificateInfo, seconds: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check notBefore: certificate must already be valid.
    // Compare in signed arithmetic to correctly handle pre-epoch timestamps.
    let not_before = cert.not_before.timestamp;
    if not_before > (now as i64) {
        return false;
    }

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
    let dns_names: Vec<String> = cert
        .san_entries()
        .into_iter()
        .filter_map(|e| match e {
            SanEntry::Dns(name) => Some(name.clone()),
            _ => None,
        })
        .collect();

    let cn = cert
        .subject
        .components
        .iter()
        .find(|(k, _)| k == "CN")
        .map(|(_, v)| v.as_str());

    util::verify_hostname_match(&dns_names, cn, hostname)
}

/// Check if the certificate matches the given email address.
///
/// Checks SAN email entries and subject emailAddress attribute.
pub fn check_email(cert: &CertificateInfo, email: &str) -> bool {
    util::verify_email_match(&cert.emails(), email)
}

/// Check if the certificate matches the given IP address.
///
/// Checks SAN IP address entries. Supports both IPv4 and IPv6.
pub fn check_ip(cert: &CertificateInfo, ip: &str) -> bool {
    let san_ips: Vec<String> = cert
        .san_entries()
        .into_iter()
        .filter_map(|e| match e {
            SanEntry::Ip(ip_str) => Some(ip_str.clone()),
            _ => None,
        })
        .collect();

    util::verify_ip_match(&san_ips, ip)
}
