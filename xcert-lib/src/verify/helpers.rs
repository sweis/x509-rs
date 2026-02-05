//! Small helper functions for certificate verification.
//!
//! Contains extraction and matching utilities for hostnames, emails,
//! IP addresses, and extension recognition.

use crate::oid;
use crate::util;
use x509_parser::prelude::*;

/// Check if a certificate is self-issued (subject == issuer).
///
/// RFC 5280 Section 6.1: Self-issued certificates are special — they do not
/// count toward chain depth, pathLenConstraint, or name constraints (except
/// the final certificate in the chain).
pub(crate) fn is_self_issued(cert: &X509Certificate) -> bool {
    cert.subject().as_raw() == cert.issuer().as_raw()
}

/// Verify that a hostname matches the leaf certificate's names.
///
/// Checks SAN DNS entries first. If `allow_cn_fallback` is true, falls back to
/// CN when no SAN DNS entries exist. In WebPKI mode CN fallback is disabled.
/// Supports wildcard matching per RFC 6125.
///
/// Delegates to [`util::verify_hostname_match`] (shared with `check_host`).
pub(crate) fn verify_hostname(
    cert: &X509Certificate,
    hostname: &str,
    allow_cn_fallback: bool,
) -> bool {
    let dns_names = extract_san_dns_names(cert);
    let cn = if allow_cn_fallback {
        extract_cn(cert)
    } else {
        None
    };
    util::verify_hostname_match(&dns_names, cn.as_deref(), hostname)
}

/// Extract DNS names from the Subject Alternative Name extension.
pub(crate) fn extract_san_dns_names(cert: &X509Certificate) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::DNSName(name) = gn {
                names.push(name.to_string());
            }
        }
    }
    names
}

/// Extract the Common Name from the certificate subject.
pub(crate) fn extract_cn(cert: &X509Certificate) -> Option<String> {
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type().to_id_string() == oid::COMMON_NAME {
                return attr.as_str().ok().map(|s| s.to_string());
            }
        }
    }
    None
}

/// Verify that an email matches the leaf certificate's SAN email entries or
/// subject emailAddress attribute.
///
/// Delegates to [`util::verify_email_match`] (shared with `check_email`).
pub(crate) fn verify_email(cert: &X509Certificate, email: &str) -> bool {
    let emails = extract_emails(cert);
    util::verify_email_match(&emails, email)
}

/// Extract email addresses from SAN and subject emailAddress attribute.
pub(crate) fn extract_emails(cert: &X509Certificate) -> Vec<String> {
    let mut emails = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::RFC822Name(email) = gn {
                emails.push(email.to_string());
            }
        }
    }
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type().to_id_string() == oid::EMAIL_ADDRESS {
                if let Ok(val) = attr.as_str() {
                    emails.push(val.to_string());
                }
            }
        }
    }
    emails
}

/// Verify that an IP address matches the leaf certificate's SAN IP entries.
///
/// Delegates to [`util::verify_ip_match`] (shared with `check_ip`).
pub(crate) fn verify_ip(cert: &X509Certificate, ip: &str) -> bool {
    let san_ips = extract_san_ips(cert);
    util::verify_ip_match(&san_ips, ip)
}

/// Extract IP address strings from the SAN extension.
pub(crate) fn extract_san_ips(cert: &X509Certificate) -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::IPAddress(ip_bytes) = gn {
                ips.push(crate::parser::format_ip_bytes(ip_bytes));
            }
        }
    }
    ips
}

/// Extract a short human-readable identifier from a certificate.
///
/// Tries in order: CN, O, OU. Returns the first non-empty value found,
/// or "Unknown" if none are present.
pub(crate) fn extract_short_name(cert: &X509Certificate) -> String {
    // Try CN first
    if let Some(cn) = extract_cn(cert) {
        return cn;
    }

    // Try O (Organization)
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type().to_id_string() == oid::ORGANIZATION {
                if let Ok(val) = attr.as_str() {
                    return val.to_string();
                }
            }
        }
    }

    // Try OU (Organizational Unit)
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type().to_id_string() == oid::ORGANIZATIONAL_UNIT {
                if let Ok(val) = attr.as_str() {
                    return val.to_string();
                }
            }
        }
    }

    "Unknown".to_string()
}

/// Extract the serial number from a certificate as a colon-separated hex string.
pub(crate) fn extract_serial_hex(cert: &X509Certificate) -> String {
    let serial_bytes = cert.serial.to_bytes_be();
    serial_bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Check if an extension OID is one we recognize and process.
/// RFC 5280 Section 4.2 requires that implementations reject certificates
/// containing unrecognized critical extensions.
pub(crate) fn is_known_extension(oid: &str) -> bool {
    matches!(
        oid,
        // RFC 5280 standard extensions
        oid::EXT_SUBJECT_KEY_ID
        | oid::EXT_KEY_USAGE
        | oid::EXT_SUBJECT_ALT_NAME
        | oid::EXT_ISSUER_ALT_NAME
        | oid::EXT_BASIC_CONSTRAINTS
        | oid::EXT_NAME_CONSTRAINTS
        | oid::EXT_CRL_DISTRIBUTION_POINTS
        | oid::EXT_CERTIFICATE_POLICIES
        | oid::EXT_POLICY_MAPPINGS
        | oid::EXT_AUTHORITY_KEY_ID
        | oid::EXT_POLICY_CONSTRAINTS
        | oid::EXT_EXTENDED_KEY_USAGE
        | oid::EXT_FRESHEST_CRL
        | oid::EXT_INHIBIT_ANY_POLICY
        // Common extensions in practice
        | oid::EXT_AUTHORITY_INFO_ACCESS
        | oid::EXT_SUBJECT_INFO_ACCESS
        | oid::EXT_TLS_FEATURE
        | oid::EXT_SCT_LIST
        | oid::EXT_CT_POISON
        // Netscape extensions (legacy, but still seen)
        | oid::EXT_NETSCAPE_CERT_TYPE
    )
}
