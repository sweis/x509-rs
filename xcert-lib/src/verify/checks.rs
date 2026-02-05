//! Individual verification check functions.
//!
//! Contains helper functions for checking various aspects of certificate
//! chain validity: time, constraints, signatures, trust anchoring, etc.

use super::constraints::check_name_constraints;
use super::crl::check_crl_revocation;
use super::helpers::{
    extract_cn, extract_san_dns_names, is_known_extension, is_self_issued, verify_email,
    verify_hostname, verify_ip,
};
use super::{ChainCertInfo, TrustStore, VerifyOptions, VerifyPolicy};
use crate::oid;
use crate::XcertError;
use std::collections::HashSet;
use x509_parser::prelude::*;

/// Check validity dates for all certificates in the chain.
#[allow(clippy::indexing_slicing)] // subjects[i] is safe: same length as parsed
pub(crate) fn check_chain_time_validity(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    now_ts: i64,
    errors: &mut Vec<String>,
) {
    for (i, (_, x509)) in parsed.iter().enumerate() {
        let not_before = x509.validity().not_before.timestamp();
        let not_after = x509.validity().not_after.timestamp();
        if now_ts < not_before {
            errors.push(format!(
                "certificate at depth {} ({}) is not yet valid",
                i, subjects[i]
            ));
        }
        if now_ts > not_after {
            errors.push(format!(
                "certificate at depth {} ({}) has expired",
                i, subjects[i]
            ));
        }
    }
}

/// Check BasicConstraints for CA certificates (all except leaf at depth 0).
#[allow(clippy::indexing_slicing)] // subjects[i] is safe: same length as parsed
pub(crate) fn check_chain_basic_constraints(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    errors: &mut Vec<String>,
) {
    for (i, (_, x509)) in parsed.iter().enumerate().skip(1) {
        let bc = x509.basic_constraints().ok().flatten().map(|bc| bc.value);
        match bc {
            Some(constraints) => {
                if !constraints.ca {
                    errors.push(format!(
                        "certificate at depth {} ({}) is not a CA but is used as issuer",
                        i, subjects[i]
                    ));
                }
                if let Some(pathlen) = constraints.path_len_constraint {
                    // RFC 5280 Section 6.1.4(h): self-issued intermediates
                    // do not count toward pathLenConstraint.
                    let intermediates_below = parsed
                        .iter()
                        .enumerate()
                        .skip(1)
                        .take(i.saturating_sub(1))
                        .filter(|(_, (_, c))| !is_self_issued(c))
                        .count() as u32;
                    if intermediates_below > pathlen {
                        errors.push(format!(
                            "certificate at depth {} ({}) path length constraint violated \
                             (pathlen={}, intermediates below={})",
                            i, subjects[i], pathlen, intermediates_below
                        ));
                    }
                }
            }
            None => {
                let version = x509.version().0;
                if version >= 2 {
                    errors.push(format!(
                        "certificate at depth {} ({}) is not a CA but is used as issuer",
                        i, subjects[i]
                    ));
                }
            }
        }
    }
}

/// RFC 5280 Section 4.2: Reject certificates with unknown critical extensions.
#[allow(clippy::indexing_slicing)] // subjects[i] is safe: same length as parsed
pub(crate) fn check_chain_critical_extensions(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    errors: &mut Vec<String>,
) {
    for (i, (_, x509)) in parsed.iter().enumerate() {
        for ext in x509.extensions() {
            if ext.critical && !is_known_extension(ext.oid.to_id_string().as_str()) {
                errors.push(format!(
                    "certificate at depth {} ({}) has unrecognized critical extension {}",
                    i, subjects[i], ext.oid
                ));
            }
        }
    }
}

/// RFC 5280 Section 4.2: A certificate MUST NOT include more than one
/// instance of a particular extension.
#[allow(clippy::indexing_slicing)] // subjects[i] is safe: same length as parsed
pub(crate) fn check_chain_duplicate_extensions(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    errors: &mut Vec<String>,
) {
    for (i, (_, x509)) in parsed.iter().enumerate() {
        let mut seen = HashSet::new();
        for ext in x509.extensions() {
            if !seen.insert(ext.oid.to_id_string()) {
                errors.push(format!(
                    "certificate at depth {} ({}) has duplicate extension {}",
                    i, subjects[i], ext.oid
                ));
                break;
            }
        }
    }
}

/// RFC 5280 Section 4.2.1.10: Name Constraints MUST NOT appear in EE
/// certificates and MUST be critical when present.
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
pub(crate) fn check_chain_name_constraint_placement(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    errors: &mut Vec<String>,
) {
    for (i, (_, x509)) in parsed.iter().enumerate() {
        let is_leaf = i == 0;
        for ext in x509.extensions() {
            if ext.oid.to_id_string() == oid::EXT_NAME_CONSTRAINTS {
                if is_leaf {
                    errors.push(format!(
                        "certificate at depth {} ({}) is an end-entity but contains \
                         Name Constraints extension",
                        i, subjects[i]
                    ));
                } else if !ext.critical {
                    errors.push(format!(
                        "certificate at depth {} ({}) has Name Constraints extension \
                         that is not marked critical",
                        i, subjects[i]
                    ));
                }
            }
        }
    }
}

/// RFC 5280 Section 4.2.1.10: Check Name Constraints for CA certificates.
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
pub(crate) fn check_chain_name_constraints(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    errors: &mut Vec<String>,
) {
    for (ca_depth, (_, ca_cert)) in parsed.iter().enumerate().skip(1) {
        if let Ok(Some(nc_ext)) = ca_cert.name_constraints() {
            let nc = &nc_ext.value;
            for (child_depth, (_, child_cert)) in parsed.iter().enumerate() {
                if child_depth >= ca_depth {
                    break;
                }
                // RFC 5280 Section 6.1.4(b): Self-issued certificates are
                // exempt from name constraints, except for the leaf.
                if child_depth > 0 && is_self_issued(child_cert) {
                    continue;
                }
                let nc_errors = check_name_constraints(
                    nc,
                    child_cert,
                    &subjects[child_depth],
                    child_depth,
                    ca_depth,
                );
                errors.extend(nc_errors);
            }
        }
    }
}

/// RFC 5280 Section 4.2.1.3: CA certificates must have keyCertSign.
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
pub(crate) fn check_chain_key_cert_sign(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    errors: &mut Vec<String>,
) {
    for (i, (_, x509)) in parsed.iter().enumerate().skip(1) {
        if let Ok(Some(ku)) = x509.key_usage() {
            if !ku.value.key_cert_sign() {
                errors.push(format!(
                    "certificate at depth {} ({}) is a CA but Key Usage does not \
                     include keyCertSign",
                    i, subjects[i]
                ));
            }
        }
    }
}

/// RFC 5280 strict validation: AKI/SKI, serial number, SAN, AIA, Policy Constraints, EKU.
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
pub(crate) fn check_chain_rfc5280_strict(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    errors: &mut Vec<String>,
) {
    for (i, (_, x509)) in parsed.iter().enumerate() {
        let is_leaf = i == 0;
        let self_signed = x509.subject().as_raw() == x509.issuer().as_raw();

        // RFC 5280 Section 4.2.1.1: AKI MUST be present in all certificates
        // except self-signed root CAs. AKI MUST be non-critical.
        let aki_ext = x509
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == "2.5.29.35");
        if !self_signed && aki_ext.is_none() {
            errors.push(format!(
                "certificate at depth {} ({}) is missing Authority Key Identifier",
                i, subjects[i]
            ));
        }
        if let Some(ext) = aki_ext {
            if ext.critical {
                errors.push(format!(
                    "certificate at depth {} ({}) has Authority Key Identifier marked critical",
                    i, subjects[i]
                ));
            }
        }

        // RFC 5280 Section 4.2.1.2: SKI MUST appear in all CA certificates.
        // SKI MUST be non-critical.
        let ski_ext = x509
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == "2.5.29.14");
        if !is_leaf && ski_ext.is_none() {
            errors.push(format!(
                "certificate at depth {} ({}) is a CA but missing Subject Key Identifier",
                i, subjects[i]
            ));
        }
        if let Some(ext) = ski_ext {
            if ext.critical {
                errors.push(format!(
                    "certificate at depth {} ({}) has Subject Key Identifier marked critical",
                    i, subjects[i]
                ));
            }
        }

        // RFC 5280 Section 4.1.2.2: Serial number MUST NOT exceed 20 octets,
        // and MUST be positive (non-zero).
        let serial = x509.raw_serial();
        if serial.len() > 20 {
            errors.push(format!(
                "certificate at depth {} ({}) serial number exceeds 20 octets ({})",
                i,
                subjects[i],
                serial.len()
            ));
        }
        if serial.iter().all(|&b| b == 0) {
            errors.push(format!(
                "certificate at depth {} ({}) has zero serial number",
                i, subjects[i]
            ));
        }

        // RFC 5280 Section 4.2.1.6: SAN MUST be critical when subject is empty.
        let subject_empty = x509.subject().as_raw().len() <= 2;
        if subject_empty {
            let san_ext = x509
                .extensions()
                .iter()
                .find(|e| e.oid.to_id_string() == "2.5.29.17");
            match san_ext {
                Some(ext) if !ext.critical => {
                    errors.push(format!(
                        "certificate at depth {} ({}) has empty subject but SAN is not critical",
                        i, subjects[i]
                    ));
                }
                None if !is_leaf => {
                    errors.push(format!(
                        "certificate at depth {} ({}) is a CA with empty subject and no SAN",
                        i, subjects[i]
                    ));
                }
                _ => {}
            }
        }

        // RFC 5280 Section 4.2.2.1: AIA MUST be non-critical.
        for ext in x509.extensions() {
            if ext.oid.to_id_string() == "1.3.6.1.5.5.7.1.1" && ext.critical {
                errors.push(format!(
                    "certificate at depth {} ({}) has Authority Information Access marked critical",
                    i, subjects[i]
                ));
            }
        }

        // RFC 5280 Section 4.2.1.11: Policy Constraints MUST be critical.
        for ext in x509.extensions() {
            if ext.oid.to_id_string() == "2.5.29.36" && !ext.critical {
                errors.push(format!(
                    "certificate at depth {} ({}) has Policy Constraints not marked critical",
                    i, subjects[i]
                ));
            }
        }

        // Leaf-specific checks
        if is_leaf {
            // RFC 5280: EKU extension must not be empty.
            if let Ok(Some(eku)) = x509.extended_key_usage() {
                let v = &eku.value;
                let has_any = v.any
                    || v.server_auth
                    || v.client_auth
                    || v.code_signing
                    || v.email_protection
                    || v.time_stamping
                    || v.ocsp_signing
                    || !v.other.is_empty();
                if !has_any {
                    errors.push(format!(
                        "leaf certificate ({}) has empty Extended Key Usage extension",
                        subjects[i]
                    ));
                }
            }
        }
    }
}

/// Verify signatures along the chain (each cert signed by the next).
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
pub(crate) fn check_chain_signatures(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    errors: &mut Vec<String>,
) {
    for (i, (child, parent)) in parsed.iter().zip(parsed.iter().skip(1)).enumerate() {
        let (_, child_x509) = child;
        let (_, parent_x509) = parent;
        if let Err(e) = child_x509.verify_signature(Some(parent_x509.public_key())) {
            errors.push(format!(
                "signature verification failed ({} -> {}): {}",
                subjects[i],
                subjects[i + 1],
                e
            ));
        }
    }
}

/// Verify trust anchoring: find the root in the trust store.
///
/// Returns `Some(root_der)` if a trusted root was found, `None` otherwise.
#[allow(clippy::indexing_slicing)] // subjects/issuers have same length as parsed
pub(crate) fn verify_trust_anchoring(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    issuers: &[String],
    trust_store: &TrustStore,
    options: &VerifyOptions,
    chain_info: &mut Vec<ChainCertInfo>,
    errors: &mut Vec<String>,
) -> Result<Option<Vec<u8>>, XcertError> {
    let mut trust_anchored = false;
    let mut trusted_root_der: Option<Vec<u8>> = None;

    if options.partial_chain {
        for (der, _) in parsed {
            if trust_store.contains(der) {
                trust_anchored = true;
                break;
            }
        }
    }

    if !trust_anchored {
        let Some((last_der, last_x509)) = parsed.last() else {
            return Err(XcertError::VerifyError("empty certificate chain".into()));
        };
        let last_idx = parsed.len() - 1;

        let is_self_signed = last_x509.subject().as_raw() == last_x509.issuer().as_raw()
            && last_x509.verify_signature(None).is_ok();

        if is_self_signed {
            if trust_store.contains(last_der) {
                trusted_root_der = Some(last_der.to_vec());
            } else {
                errors.push(format!(
                    "root certificate ({}) is not in the trust store",
                    subjects[last_idx]
                ));
            }
        } else {
            let issuer_raw = last_x509.issuer().as_raw();
            if let Some(candidates) = trust_store.find_by_subject_raw(issuer_raw) {
                for root_der in candidates {
                    if let Ok((_, root_x509)) = X509Certificate::from_der(root_der) {
                        if last_x509
                            .verify_signature(Some(root_x509.public_key()))
                            .is_ok()
                        {
                            chain_info.push(ChainCertInfo {
                                depth: parsed.len(),
                                subject: crate::parser::build_dn(root_x509.subject()).to_oneline(),
                                issuer: crate::parser::build_dn(root_x509.issuer()).to_oneline(),
                            });
                            trusted_root_der = Some(root_der.clone());
                            trust_anchored = true;
                            break;
                        }
                    }
                }
            }

            if !trust_anchored {
                errors.push(format!(
                    "unable to find trusted root for issuer: {}",
                    issuers[last_idx]
                ));
            }
        }
    }

    Ok(trusted_root_der)
}

/// Validate the trusted root: time, critical extensions, Name Constraints.
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
pub(crate) fn check_trusted_root(
    root_der: &[u8],
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    options: &VerifyOptions,
    now_ts: i64,
    errors: &mut Vec<String>,
) {
    let Ok((_, root_x509)) = X509Certificate::from_der(root_der) else {
        return;
    };
    let root_subject = crate::parser::build_dn(root_x509.subject()).to_oneline();
    let root_depth = parsed.len();

    if options.check_time {
        let not_before = root_x509.validity().not_before.timestamp();
        let not_after = root_x509.validity().not_after.timestamp();
        if now_ts < not_before {
            errors.push(format!("trusted root ({}) is not yet valid", root_subject));
        }
        if now_ts > not_after {
            errors.push(format!("trusted root ({}) has expired", root_subject));
        }
    }

    for ext in root_x509.extensions() {
        let oid_str = ext.oid.to_id_string();
        if ext.critical && !is_known_extension(oid_str.as_str()) {
            errors.push(format!(
                "trusted root ({}) has unrecognized critical extension {}",
                root_subject, ext.oid
            ));
        }
    }

    // RFC 5280: Root CA must have BasicConstraints, and it must be critical.
    let root_bc = root_x509.basic_constraints().ok().flatten();
    match root_bc {
        Some(bc_ext) => {
            if !bc_ext.value.ca {
                errors.push(format!(
                    "trusted root ({}) BasicConstraints does not have CA:TRUE",
                    root_subject
                ));
            }
            let bc_critical = root_x509
                .extensions()
                .iter()
                .find(|e| e.oid.to_id_string() == "2.5.29.19")
                .is_some_and(|e| e.critical);
            if !bc_critical {
                errors.push(format!(
                    "trusted root ({}) has BasicConstraints not marked critical",
                    root_subject
                ));
            }
        }
        None => {
            errors.push(format!(
                "trusted root ({}) is missing BasicConstraints extension",
                root_subject
            ));
        }
    }

    // RFC 5280: Root must have SKI.
    let root_has_ski = root_x509
        .extensions()
        .iter()
        .any(|e| e.oid.to_id_string() == "2.5.29.14");
    if !root_has_ski {
        errors.push(format!(
            "trusted root ({}) is missing Subject Key Identifier",
            root_subject
        ));
    }

    // RFC 5280: Root serial number validation.
    let root_serial = root_x509.raw_serial();
    if root_serial.len() > 20 {
        errors.push(format!(
            "trusted root ({}) serial number exceeds 20 octets",
            root_subject
        ));
    }
    if root_serial.iter().all(|&b| b == 0) {
        errors.push(format!(
            "trusted root ({}) has zero serial number",
            root_subject
        ));
    }

    // RFC 5280: Root CA must have keyCertSign when KU is present.
    if let Ok(Some(ku)) = root_x509.key_usage() {
        if !ku.value.key_cert_sign() {
            errors.push(format!(
                "trusted root ({}) Key Usage does not include keyCertSign",
                root_subject
            ));
        }
    }

    // Name Constraints from trusted root.
    for ext in root_x509.extensions() {
        if ext.oid.to_id_string() == oid::EXT_NAME_CONSTRAINTS && !ext.critical {
            errors.push(format!(
                "trusted root ({}) has Name Constraints extension \
                 that is not marked critical",
                root_subject
            ));
        }
    }
    if let Ok(Some(nc_ext)) = root_x509.name_constraints() {
        let nc = &nc_ext.value;
        for (child_depth, (_, child_cert)) in parsed.iter().enumerate() {
            // RFC 5280: Self-issued intermediates are exempt from NC
            if child_depth > 0 && is_self_issued(child_cert) {
                continue;
            }
            let nc_errors = check_name_constraints(
                nc,
                child_cert,
                &subjects[child_depth],
                child_depth,
                root_depth,
            );
            errors.extend(nc_errors);
        }
    }
}

/// Check EKU purpose on the leaf certificate.
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
pub(crate) fn check_leaf_purpose(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    options: &VerifyOptions,
    errors: &mut Vec<String>,
) {
    let Some(ref required_oid) = options.purpose else {
        return;
    };
    let Some((_, leaf)) = parsed.first() else {
        return;
    };
    if let Ok(Some(eku)) = leaf.extended_key_usage() {
        let eku_val = &eku.value;
        let has_eku = eku_val.any
            || match required_oid.as_str() {
                oid::EKU_SERVER_AUTH => eku_val.server_auth,
                oid::EKU_CLIENT_AUTH => eku_val.client_auth,
                oid::EKU_CODE_SIGNING => eku_val.code_signing,
                oid::EKU_EMAIL_PROTECTION => eku_val.email_protection,
                oid::EKU_TIME_STAMPING => eku_val.time_stamping,
                oid::EKU_OCSP_SIGNING => eku_val.ocsp_signing,
                oid::EKU_ANY => true,
                _ => eku_val
                    .other
                    .iter()
                    .any(|oid| oid.to_id_string() == *required_oid),
            };
        if !has_eku {
            errors.push(format!(
                "leaf certificate ({}) does not have required EKU {}",
                subjects[0], required_oid
            ));
        }
    }
}

/// Check hostname against leaf certificate (if requested).
pub(crate) fn check_leaf_hostname(
    parsed: &[(&[u8], X509Certificate)],
    hostname: Option<&str>,
    options: &VerifyOptions,
    errors: &mut Vec<String>,
) {
    let Some(host) = hostname else { return };
    let ip_handled = options.verify_ip.as_deref() == Some(host);
    if ip_handled {
        return;
    }
    let Some((_, leaf)) = parsed.first() else {
        return;
    };
    let allow_cn = options.policy != VerifyPolicy::WebPki;
    if !verify_hostname(leaf, host, allow_cn) {
        let san_names = extract_san_dns_names(leaf);
        let cn = extract_cn(leaf);
        let mut names: Vec<String> = san_names;
        if let Some(cn_val) = cn {
            if names.is_empty() {
                names.push(cn_val);
            }
        }
        errors.push(format!(
            "hostname '{}' does not match certificate names: [{}]",
            host,
            names.join(", ")
        ));
    }
}

/// Check email against leaf certificate (if requested).
pub(crate) fn check_leaf_email(
    parsed: &[(&[u8], X509Certificate)],
    options: &VerifyOptions,
    errors: &mut Vec<String>,
) {
    let Some(ref email) = options.verify_email else {
        return;
    };
    let Some((_, leaf)) = parsed.first() else {
        return;
    };
    if !verify_email(leaf, email) {
        errors.push(format!("email '{}' does not match certificate", email));
    }
}

/// Check IP address against leaf certificate (if requested).
pub(crate) fn check_leaf_ip(
    parsed: &[(&[u8], X509Certificate)],
    options: &VerifyOptions,
    errors: &mut Vec<String>,
) {
    let Some(ref ip) = options.verify_ip else {
        return;
    };
    let Some((_, leaf)) = parsed.first() else {
        return;
    };
    if !verify_ip(leaf, ip) {
        errors.push(format!("IP address '{}' does not match certificate", ip));
    }
}

/// CRL strict validation: CRLNumber must be present and non-critical (RFC 5280 Section 5.2.3).
pub(crate) fn check_crl_strict(options: &VerifyOptions, errors: &mut Vec<String>) {
    if options.crl_ders.is_empty() || !(options.crl_check_leaf || options.crl_check_all) {
        return;
    }
    for crl_der in &options.crl_ders {
        if let Ok((_, crl)) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der)
        {
            let crl_number_ext = crl
                .extensions()
                .iter()
                .find(|e| e.oid.to_id_string() == "2.5.29.20");
            match crl_number_ext {
                Some(ext) if ext.critical => {
                    errors.push("CRL has CRL Number extension marked critical".to_string());
                }
                None => {
                    errors.push("CRL is missing CRL Number extension".to_string());
                }
                _ => {}
            }
        }
    }
}

/// CRL-based revocation checking.
#[allow(clippy::indexing_slicing)] // subjects/parsed have same length; range is bounded
pub(crate) fn check_crl_chain(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    options: &VerifyOptions,
    trusted_root_der: &Option<Vec<u8>>,
    now_ts: i64,
    errors: &mut Vec<String>,
) {
    if options.crl_ders.is_empty() || !(options.crl_check_leaf || options.crl_check_all) {
        return;
    }

    let check_range = if options.crl_check_all {
        0..parsed.len()
    } else {
        0..1
    };

    let trusted_root_parsed = trusted_root_der
        .as_deref()
        .and_then(|der| X509Certificate::from_der(der).ok().map(|(_, c)| c));

    for i in check_range {
        let (_, cert) = &parsed[i];
        let issuer = if i + 1 < parsed.len() {
            Some(&parsed[i + 1].1)
        } else if let Some(ref root) = trusted_root_parsed {
            Some(root)
        } else {
            Some(cert)
        };

        if let Some(reason) = check_crl_revocation(cert, &options.crl_ders, issuer, now_ts) {
            errors.push(format!(
                "certificate at depth {} ({}) has been revoked (reason: {})",
                i, subjects[i], reason
            ));
        }
    }
}
