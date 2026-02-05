//! Name Constraints checking (RFC 5280 Section 4.2.1.10).
//!
//! Validates that certificate names comply with CA-imposed Name Constraints,
//! supporting DNS names, email addresses, and IP addresses.

use crate::oid;
use x509_parser::prelude::*;

/// Maximum work factor for Name Constraints checking (names × subtrees).
/// Protects against DoS from certificates with thousands of SANs or subtrees.
pub(crate) const MAX_NC_WORK_FACTOR: usize = 65_536;

/// Check that a certificate's names comply with a CA's Name Constraints.
///
/// Returns a list of error strings for any violations found.
pub(crate) fn check_name_constraints(
    nc: &x509_parser::extensions::NameConstraints,
    cert: &X509Certificate,
    subject: &str,
    child_depth: usize,
    ca_depth: usize,
) -> Vec<String> {
    let mut errors = Vec::new();

    // Collect all names from the certificate's SAN extension
    let mut dns_names: Vec<String> = Vec::new();
    let mut email_names: Vec<String> = Vec::new();
    let mut ip_addrs: Vec<Vec<u8>> = Vec::new();

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            match gn {
                GeneralName::DNSName(name) => {
                    dns_names.push(name.to_ascii_lowercase());
                }
                GeneralName::RFC822Name(email) => {
                    email_names.push(email.to_ascii_lowercase());
                }
                GeneralName::IPAddress(bytes) => {
                    ip_addrs.push(bytes.to_vec());
                }
                _ => {}
            }
        }
    }

    // Also check subject emailAddress (OID 1.2.840.113549.1.9.1)
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type().to_id_string() == oid::EMAIL_ADDRESS {
                if let Ok(val) = attr.as_str() {
                    email_names.push(val.to_ascii_lowercase());
                }
            }
        }
    }

    // DoS protection: limit the work factor of name constraint checking.
    let total_names = dns_names.len() + email_names.len() + ip_addrs.len();
    let excluded_count = nc.excluded_subtrees.as_ref().map_or(0, |s| s.len());
    let permitted_count = nc.permitted_subtrees.as_ref().map_or(0, |s| s.len());
    if total_names.saturating_mul(excluded_count + permitted_count) > MAX_NC_WORK_FACTOR {
        errors.push(format!(
            "certificate at depth {} ({}) name constraints check exceeds resource limits \
             ({} names × {} subtrees)",
            child_depth,
            subject,
            total_names,
            excluded_count + permitted_count
        ));
        return errors;
    }

    // Check excluded subtrees first (any match is a violation)
    if let Some(ref excluded) = nc.excluded_subtrees {
        for subtree in excluded {
            match &subtree.base {
                GeneralName::DNSName(constraint) => {
                    let c = constraint.to_ascii_lowercase();
                    for name in &dns_names {
                        if dns_name_matches_constraint(name, &c) {
                            errors.push(format!(
                                "certificate at depth {} ({}) DNS name '{}' \
                                 violates excluded Name Constraint '{}' \
                                 from CA at depth {}",
                                child_depth, subject, name, constraint, ca_depth
                            ));
                        }
                    }
                }
                GeneralName::RFC822Name(constraint) => {
                    let c = constraint.to_ascii_lowercase();
                    for email in &email_names {
                        if email_matches_constraint(email, &c) {
                            errors.push(format!(
                                "certificate at depth {} ({}) email '{}' \
                                 violates excluded Name Constraint '{}' \
                                 from CA at depth {}",
                                child_depth, subject, email, constraint, ca_depth
                            ));
                        }
                    }
                }
                GeneralName::IPAddress(constraint_bytes) => {
                    for ip_bytes in &ip_addrs {
                        if ip_matches_constraint(ip_bytes, constraint_bytes) {
                            let ip_str = crate::parser::format_ip_bytes(ip_bytes);
                            errors.push(format!(
                                "certificate at depth {} ({}) IP '{}' \
                                 violates excluded Name Constraint from CA at depth {}",
                                child_depth, subject, ip_str, ca_depth
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Check permitted subtrees (if present, names of the matching type must
    // fall within at least one permitted subtree)
    if let Some(ref permitted) = nc.permitted_subtrees {
        // Check DNS names: if any DNS constraint exists, all DNS names must match one
        let dns_constraints: Vec<String> = permitted
            .iter()
            .filter_map(|s| match &s.base {
                GeneralName::DNSName(c) => Some(c.to_ascii_lowercase()),
                _ => None,
            })
            .collect();

        if !dns_constraints.is_empty() {
            for name in &dns_names {
                let permitted_match = dns_constraints
                    .iter()
                    .any(|c| dns_name_matches_constraint(name, c));
                if !permitted_match {
                    errors.push(format!(
                        "certificate at depth {} ({}) DNS name '{}' \
                         is not within any permitted Name Constraint \
                         from CA at depth {}",
                        child_depth, subject, name, ca_depth
                    ));
                }
            }
        }

        // Check email names
        let email_constraints: Vec<String> = permitted
            .iter()
            .filter_map(|s| match &s.base {
                GeneralName::RFC822Name(c) => Some(c.to_ascii_lowercase()),
                _ => None,
            })
            .collect();

        if !email_constraints.is_empty() {
            for email in &email_names {
                let permitted_match = email_constraints
                    .iter()
                    .any(|c| email_matches_constraint(email, c));
                if !permitted_match {
                    errors.push(format!(
                        "certificate at depth {} ({}) email '{}' \
                         is not within any permitted Name Constraint \
                         from CA at depth {}",
                        child_depth, subject, email, ca_depth
                    ));
                }
            }
        }

        // Check IP addresses
        let ip_constraints: Vec<&[u8]> = permitted
            .iter()
            .filter_map(|s| match &s.base {
                GeneralName::IPAddress(bytes) => Some(*bytes),
                _ => None,
            })
            .collect();

        if !ip_constraints.is_empty() {
            for ip_bytes in &ip_addrs {
                let permitted_match = ip_constraints
                    .iter()
                    .any(|c| ip_matches_constraint(ip_bytes, c));
                if !permitted_match {
                    let ip_str = crate::parser::format_ip_bytes(ip_bytes);
                    errors.push(format!(
                        "certificate at depth {} ({}) IP '{}' \
                         is not within any permitted Name Constraint \
                         from CA at depth {}",
                        child_depth, subject, ip_str, ca_depth
                    ));
                }
            }
        }
    }

    errors
}

/// Check if a DNS name matches a Name Constraint.
///
/// RFC 5280: A constraint of ".example.com" matches "host.example.com" but
/// not "example.com". A constraint of "example.com" matches both
/// "example.com" and "host.example.com".
pub(crate) fn dns_name_matches_constraint(name: &str, constraint: &str) -> bool {
    if constraint.is_empty() {
        // Empty constraint matches everything
        return true;
    }
    if constraint.starts_with('.') {
        // ".example.com" matches any subdomain but not the domain itself
        name.ends_with(constraint)
    } else {
        // "example.com" matches exact or any subdomain (avoid format! allocation)
        name == constraint
            || (name.len() > constraint.len()
                && name.ends_with(constraint)
                && name.as_bytes().get(name.len() - constraint.len() - 1) == Some(&b'.'))
    }
}

/// Check if an email matches a Name Constraint.
///
/// RFC 5280: A constraint of "example.com" matches any email @example.com.
/// A constraint of ".example.com" matches email at any subdomain.
/// A specific email address is an exact match.
pub(crate) fn email_matches_constraint(email: &str, constraint: &str) -> bool {
    if constraint.is_empty() {
        return true;
    }
    if constraint.contains('@') {
        // Exact email match
        email == constraint
    } else if constraint.starts_with('.') {
        // Domain constraint: matches subdomains
        if let Some(pos) = email.find('@') {
            let domain = &email[pos + 1..];
            domain.ends_with(constraint)
        } else {
            false
        }
    } else {
        // Domain constraint: matches the domain exactly
        if let Some(pos) = email.find('@') {
            let domain = &email[pos + 1..];
            domain == constraint
        } else {
            false
        }
    }
}

/// Check if an IP address (as bytes from SAN) matches a constraint (IP + netmask).
///
/// IPv4 constraints are 8 bytes (4 address + 4 mask).
/// IPv6 constraints are 32 bytes (16 address + 16 mask).
pub(crate) fn ip_matches_constraint(ip_bytes: &[u8], constraint: &[u8]) -> bool {
    let addr_len = ip_bytes.len();
    // Constraint must be exactly 2x the address length (address + netmask)
    if constraint.len() != addr_len * 2 || (addr_len != 4 && addr_len != 16) {
        return false;
    }
    let (addr, mask) = constraint.split_at(addr_len);
    ip_bytes
        .iter()
        .zip(addr.iter())
        .zip(mask.iter())
        .all(|((ip, a), m)| (ip & m) == (a & m))
}
