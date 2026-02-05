//! WebPKI policy validation (CABF Baseline Requirements).
//!
//! Implements stricter validation rules for TLS server certificates
//! as specified by the CA/Browser Forum Baseline Requirements.

use x509_parser::prelude::*;

/// WebPKI-specific validation checks per CABF Baseline Requirements.
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
pub(crate) fn check_webpki_policy(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
    trusted_root_der: &Option<Vec<u8>>,
    errors: &mut Vec<String>,
) {
    for (i, (_, x509)) in parsed.iter().enumerate() {
        let is_leaf = i == 0;

        if is_leaf {
            // WebPKI: Leaf must have SAN
            let has_san = x509
                .extensions()
                .iter()
                .any(|e| e.oid.to_id_string() == "2.5.29.17");
            if !has_san {
                errors.push(format!(
                    "WebPKI: leaf certificate ({}) has no SAN extension",
                    subjects[i]
                ));
            }

            // WebPKI: Leaf must have EKU
            if x509.extended_key_usage().ok().flatten().is_none() {
                errors.push(format!(
                    "WebPKI: leaf certificate ({}) has no EKU extension",
                    subjects[i]
                ));
            }

            // WebPKI: anyExtendedKeyUsage not allowed, EKU must not be critical
            if let Ok(Some(eku)) = x509.extended_key_usage() {
                if eku.value.any {
                    errors.push(format!(
                        "WebPKI: leaf certificate ({}) has anyExtendedKeyUsage",
                        subjects[i]
                    ));
                }
                let eku_critical = x509
                    .extensions()
                    .iter()
                    .find(|e| e.oid.to_id_string() == "2.5.29.37")
                    .is_some_and(|e| e.critical);
                if eku_critical {
                    errors.push(format!(
                        "WebPKI: leaf certificate ({}) has critical EKU",
                        subjects[i]
                    ));
                }
            }

            // WebPKI: Leaf must not have BC:CA=true
            if let Some(bc) = x509.basic_constraints().ok().flatten() {
                if bc.value.ca {
                    errors.push(format!(
                        "WebPKI: leaf certificate ({}) has BasicConstraints CA:TRUE",
                        subjects[i]
                    ));
                }
            }

            // WebPKI: v1 certificates not allowed
            if x509.version().0 < 2 {
                errors.push(format!(
                    "WebPKI: leaf certificate ({}) is version {} (v3 required)",
                    subjects[i],
                    x509.version().0 + 1
                ));
            }

            // WebPKI: SAN should not be critical when subject is non-empty
            let subject_empty = x509.subject().as_raw().len() <= 2;
            if !subject_empty {
                let san_critical = x509
                    .extensions()
                    .iter()
                    .find(|e| e.oid.to_id_string() == "2.5.29.17")
                    .is_some_and(|e| e.critical);
                if san_critical {
                    errors.push(format!(
                        "WebPKI: leaf certificate ({}) has critical SAN with non-empty subject",
                        subjects[i]
                    ));
                }
            }

            // WebPKI: Weak crypto check
            if let Some(weakness) = check_weak_crypto(x509) {
                errors.push(format!(
                    "WebPKI: leaf certificate ({}) {}",
                    subjects[i], weakness
                ));
            }

            // WebPKI: Public suffix wildcard in SAN
            if let Ok(Some(san)) = x509.subject_alternative_name() {
                for gn in &san.value.general_names {
                    if let GeneralName::DNSName(name) = gn {
                        if let Some(base) = name.strip_prefix("*.") {
                            if is_public_suffix(base) {
                                errors.push(format!(
                                    "WebPKI: leaf certificate ({}) has wildcard on public suffix '{}'",
                                    subjects[i], name
                                ));
                            }
                        }
                    }
                }
            }

            // WebPKI: Malformed AIA
            for ext in x509.extensions() {
                if ext.oid.to_id_string() == "1.3.6.1.5.5.7.1.1"
                    && x509_parser::extensions::AuthorityInfoAccess::from_der(ext.value).is_err()
                {
                    errors.push(format!(
                        "WebPKI: leaf certificate ({}) has malformed AIA extension",
                        subjects[i]
                    ));
                }
            }
        }

        // WebPKI: NC with empty subtrees is malformed
        if !is_leaf {
            for ext in x509.extensions() {
                if ext.oid.to_id_string() == "2.5.29.30" {
                    if let Ok(Some(nc)) = x509.name_constraints() {
                        let permitted_empty = nc
                            .value
                            .permitted_subtrees
                            .as_ref()
                            .is_some_and(|s| s.is_empty());
                        let excluded_empty = nc
                            .value
                            .excluded_subtrees
                            .as_ref()
                            .is_some_and(|s| s.is_empty());
                        let both_absent = nc.value.permitted_subtrees.is_none()
                            && nc.value.excluded_subtrees.is_none();
                        if permitted_empty || excluded_empty || both_absent {
                            errors.push(format!(
                                "WebPKI: certificate at depth {} ({}) has empty or malformed Name Constraints",
                                i, subjects[i]
                            ));
                        }
                    }
                }
            }
        }
    }

    // WebPKI: Root certificate checks
    let root_certs_to_check: Vec<(&X509Certificate, String)> = {
        let mut roots = Vec::new();
        if let Some((_, last_cert)) = parsed.last() {
            if last_cert.subject().as_raw() == last_cert.issuer().as_raw() {
                roots.push((
                    last_cert,
                    crate::parser::build_dn(last_cert.subject()).to_oneline(),
                ));
            }
        }
        roots
    };

    for (root_x509, root_subject) in &root_certs_to_check {
        if root_x509.extended_key_usage().ok().flatten().is_some() {
            errors.push(format!("WebPKI: root ({}) has EKU extension", root_subject));
        }
        if let Some(weakness) = check_weak_crypto(root_x509) {
            errors.push(format!("WebPKI: root ({}) {}", root_subject, weakness));
        }
        webpki_check_root_aki(root_x509, root_subject, errors);
    }

    // Check trusted root from store (if not in chain)
    if let Some(ref root_der) = trusted_root_der {
        if let Ok((_, root_x509)) = X509Certificate::from_der(root_der) {
            let root_subject = crate::parser::build_dn(root_x509.subject()).to_oneline();
            let already_checked = parsed
                .last()
                .is_some_and(|(der, _)| *der == root_der.as_slice());
            if !already_checked {
                if root_x509.extended_key_usage().ok().flatten().is_some() {
                    errors.push(format!("WebPKI: root ({}) has EKU extension", root_subject));
                }
                if let Some(weakness) = check_weak_crypto(&root_x509) {
                    errors.push(format!("WebPKI: root ({}) {}", root_subject, weakness));
                }
                webpki_check_root_aki(&root_x509, &root_subject, errors);
            }
        }
    }
}

/// Check for weak or forbidden cryptographic algorithms (WebPKI / CABF BRs).
pub(crate) fn check_weak_crypto(cert: &X509Certificate) -> Option<String> {
    let pk = cert.public_key();
    let algo_oid = pk.algorithm.algorithm.to_id_string();

    match algo_oid.as_str() {
        // DSA is forbidden in WebPKI
        "1.2.840.10040.4.1" => Some("uses forbidden DSA key algorithm".into()),
        // RSA
        "1.2.840.113549.1.1.1" => {
            if let Ok(x509_parser::public_key::PublicKey::RSA(rsa)) = pk.parsed() {
                let mod_bytes = rsa.modulus;
                // Skip leading zero padding byte
                let effective = mod_bytes
                    .get(1..)
                    .filter(|_| mod_bytes.first() == Some(&0))
                    .unwrap_or(mod_bytes);
                let key_bits = effective.len() * 8;
                if key_bits < 2048 {
                    return Some(format!(
                        "has weak RSA key ({} bits, minimum 2048)",
                        key_bits
                    ));
                }
                if key_bits % 8 != 0 {
                    return Some(format!(
                        "has RSA key size not divisible by 8 ({} bits)",
                        key_bits
                    ));
                }
            }
            None
        }
        // EC
        "1.2.840.10045.2.1" => {
            if let Some(params) = &pk.algorithm.parameters {
                if let Ok(oid) = params.as_oid() {
                    let curve = oid.to_id_string();
                    // P-192 (secp192r1) is forbidden
                    if curve == "1.2.840.10045.3.1.1" {
                        return Some("uses forbidden P-192 elliptic curve".into());
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Simple public suffix check for wildcard SAN validation.
/// Returns true if the domain is a TLD (single label with no dots).
pub(crate) fn is_public_suffix(domain: &str) -> bool {
    !domain.contains('.')
}

/// WebPKI root AKI validation: if AKI is present on a self-signed root,
/// keyIdentifier must be present and must match SKI; authorityCertIssuer
/// and authorityCertSerialNumber must not be present.
pub(crate) fn webpki_check_root_aki(
    root_x509: &X509Certificate,
    root_subject: &str,
    errors: &mut Vec<String>,
) {
    let aki_ext = root_x509
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == "2.5.29.35");
    let ski_ext = root_x509
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == "2.5.29.14");

    if let Some(ext) = aki_ext {
        if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
            let has_key_id = aki.key_identifier.is_some();
            let has_cert_issuer = aki.authority_cert_issuer.is_some();
            let has_cert_serial = aki.authority_cert_serial.is_some();

            if !has_key_id {
                errors.push(format!(
                    "WebPKI: root ({}) AKI missing keyIdentifier",
                    root_subject
                ));
            }
            if has_cert_issuer {
                errors.push(format!(
                    "WebPKI: root ({}) AKI has authorityCertIssuer",
                    root_subject
                ));
            }
            if has_cert_serial {
                errors.push(format!(
                    "WebPKI: root ({}) AKI has authorityCertSerialNumber",
                    root_subject
                ));
            }
            // AKI keyIdentifier must match SKI
            if let (Some(aki_kid), Some(ski_raw)) = (&aki.key_identifier, ski_ext) {
                if let ParsedExtension::SubjectKeyIdentifier(ski_val) = ski_raw.parsed_extension() {
                    if aki_kid.0 != ski_val.0 {
                        errors.push(format!(
                            "WebPKI: root ({}) AKI keyIdentifier does not match SKI",
                            root_subject
                        ));
                    }
                }
            }
        }
    }
}
