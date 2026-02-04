//! Certificate validity checks: expiry, hostname, email, IP matching.

use crate::fields::CertificateInfo;

/// Check if the certificate expires within `seconds` from now.
///
/// Returns `true` if the certificate will still be valid after `seconds` have
/// elapsed. Returns `false` if it will have expired by then (or is already expired).
pub fn check_expiry(cert: &CertificateInfo, seconds: u64) -> bool {
    let _ = (cert, seconds);
    false // stub
}

/// Check if the certificate matches the given hostname.
///
/// Checks SAN DNS entries first; falls back to CN only if no SAN DNS entries exist.
/// Supports wildcard matching (e.g., `*.example.com`).
pub fn check_host(cert: &CertificateInfo, hostname: &str) -> bool {
    let _ = (cert, hostname);
    false // stub
}

/// Check if the certificate matches the given email address.
///
/// Checks SAN email entries and subject emailAddress attribute.
pub fn check_email(cert: &CertificateInfo, email: &str) -> bool {
    let _ = (cert, email);
    false // stub
}

/// Check if the certificate matches the given IP address.
///
/// Checks SAN IP address entries. Supports both IPv4 and IPv6.
pub fn check_ip(cert: &CertificateInfo, ip: &str) -> bool {
    let _ = (cert, ip);
    false // stub
}
