//! Certificate chain verification against a trust store.
//!
//! Provides functionality to verify X.509 certificate chains by checking
//! signatures, validity dates, basic constraints, and trust anchoring
//! against the system's trusted CA certificates (the same store used by OpenSSL).
//!
//! The system trust store location is discovered via `openssl-probe` and
//! environment variables, matching OpenSSL's lookup behavior.

use crate::util;
use crate::XcertError;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

/// Maximum chain depth to prevent infinite loops during chain building.
const MAX_CHAIN_DEPTH: usize = 32;

/// Result of certificate chain verification.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationResult {
    /// Whether the entire chain verified successfully.
    pub is_valid: bool,
    /// Information about each certificate in the verified chain (leaf to root).
    pub chain: Vec<ChainCertInfo>,
    /// List of verification errors encountered (empty if `is_valid` is true).
    pub errors: Vec<String>,
}

impl std::fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_valid {
            write!(f, "OK")?;
            if !self.chain.is_empty() {
                write!(f, " (chain: ")?;
                for (i, info) in self.chain.iter().enumerate() {
                    if i > 0 {
                        write!(f, " -> ")?;
                    }
                    write!(f, "{}", info.subject)?;
                }
                write!(f, ")")?;
            }
        } else {
            write!(f, "FAIL")?;
            for err in &self.errors {
                write!(f, ": {}", err)?;
            }
        }
        Ok(())
    }
}

/// Information about a certificate in the verified chain.
#[derive(Debug, Clone, Serialize)]
pub struct ChainCertInfo {
    /// Position in chain (0 = leaf).
    pub depth: usize,
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
}

/// Options controlling verification behavior.
pub struct VerifyOptions {
    /// Whether to check certificate validity dates.
    /// Set to `false` to skip time checks (useful for testing expired certs).
    pub check_time: bool,
    /// Allow verification to succeed if any certificate in the chain (not just
    /// the root) is in the trust store. Matches OpenSSL's `-partial_chain` flag.
    pub partial_chain: bool,
    /// Required Extended Key Usage OID for the leaf certificate (e.g.,
    /// "1.3.6.1.5.5.7.3.1" for serverAuth). If set, verification fails when
    /// the leaf's EKU extension is present but does not include this OID.
    pub purpose: Option<String>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            check_time: true,
            partial_chain: false,
            purpose: None,
        }
    }
}

/// A set of trusted CA certificates.
///
/// By default, loads from the system trust store (the same certificates
/// used by OpenSSL). On Linux, this is typically `/etc/ssl/certs/ca-certificates.crt`.
///
/// The system trust store location is discovered using `openssl-probe` and
/// environment variables (`SSL_CERT_FILE`, `SSL_CERT_DIR`), matching
/// OpenSSL's lookup behavior.
pub struct TrustStore {
    /// Map from raw DER-encoded subject name to list of DER-encoded certificates.
    certs_by_subject: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    count: usize,
}

impl std::fmt::Debug for TrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustStore")
            .field("count", &self.count)
            .finish()
    }
}

impl TrustStore {
    /// Create an empty trust store.
    pub fn new() -> Self {
        TrustStore {
            certs_by_subject: HashMap::new(),
            count: 0,
        }
    }

    /// Load the system trust store.
    ///
    /// Uses `openssl-probe` and environment variables to find the CA bundle,
    /// matching the same locations OpenSSL searches:
    /// 1. `SSL_CERT_FILE` environment variable
    /// 2. Path discovered by `openssl-probe`
    /// 3. `/etc/ssl/certs/ca-certificates.crt` (Debian/Ubuntu)
    /// 4. `/etc/pki/tls/certs/ca-bundle.crt` (RHEL/CentOS/Fedora)
    /// 5. `/etc/ssl/ca-bundle.pem` (openSUSE)
    /// 6. `/etc/ssl/cert.pem` (macOS, Alpine)
    /// 7. `/etc/ssl/certs` directory (individual cert files)
    pub fn system() -> Result<Self, XcertError> {
        let mut store = TrustStore::new();

        // Use openssl-probe to discover the system trust store
        let probe = openssl_probe::probe();

        // Build candidate list: env var first, then openssl-probe, then known paths
        let mut bundle_paths: Vec<Option<String>> = vec![
            std::env::var("SSL_CERT_FILE").ok(),
        ];
        if let Some(probe_file) = probe.cert_file {
            bundle_paths.push(Some(probe_file.to_string_lossy().into_owned()));
        }
        bundle_paths.extend([
            Some("/etc/ssl/certs/ca-certificates.crt".into()),
            Some("/etc/pki/tls/certs/ca-bundle.crt".into()),
            Some("/etc/ssl/ca-bundle.pem".into()),
            Some("/etc/ssl/cert.pem".into()),
        ]);

        for path_opt in &bundle_paths {
            if let Some(path) = path_opt {
                if let Ok(data) = std::fs::read(path) {
                    let added = store.add_pem_bundle(&data)?;
                    if added > 0 {
                        return Ok(store);
                    }
                }
            }
        }

        // Try directory of individual certs
        let mut dir_paths: Vec<Option<String>> = vec![
            std::env::var("SSL_CERT_DIR").ok(),
        ];
        if let Some(probe_dir) = probe.cert_dir {
            dir_paths.push(Some(probe_dir.to_string_lossy().into_owned()));
        }
        dir_paths.push(Some("/etc/ssl/certs".into()));

        for dir_opt in &dir_paths {
            if let Some(dir) = dir_opt {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().map(|e| e == "pem" || e == "crt").unwrap_or(false) {
                            if let Ok(data) = std::fs::read(&path) {
                                let _ = store.add_pem_bundle(&data);
                            }
                        }
                    }
                    if !store.is_empty() {
                        return Ok(store);
                    }
                }
            }
        }

        if store.is_empty() {
            return Err(XcertError::VerifyError(
                "no system trust store found".into(),
            ));
        }

        Ok(store)
    }

    /// Create a trust store from a PEM bundle (e.g., a CA certificates file).
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, XcertError> {
        let mut store = TrustStore::new();
        store.add_pem_bundle(pem_data)?;
        Ok(store)
    }

    /// Create a trust store from a PEM file path.
    pub fn from_pem_file(path: &std::path::Path) -> Result<Self, XcertError> {
        let data = std::fs::read(path).map_err(|e| {
            XcertError::Io(std::io::Error::new(
                e.kind(),
                format!("{}: {}", path.display(), e),
            ))
        })?;
        Self::from_pem(&data)
    }

    /// Add a DER-encoded certificate to the trust store.
    pub fn add_der(&mut self, der: &[u8]) -> Result<(), XcertError> {
        let (_, x509) = X509Certificate::from_der(der)
            .map_err(|e| XcertError::DerError(format!("{}", e)))?;

        let subject_raw = x509.subject().as_raw().to_vec();
        self.certs_by_subject
            .entry(subject_raw)
            .or_default()
            .push(der.to_vec());
        self.count += 1;

        Ok(())
    }

    /// Add all certificates from a PEM bundle. Returns the number of
    /// certificates actually added (skipping those that fail to parse).
    pub fn add_pem_bundle(&mut self, pem_data: &[u8]) -> Result<usize, XcertError> {
        let certs = parse_pem_chain(pem_data)?;
        let mut added = 0;
        for cert_der in certs {
            // Skip certificates that fail to parse (some bundles have non-cert entries)
            if self.add_der(&cert_der).is_ok() {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Find trusted certificates whose subject matches the given issuer name.
    fn find_by_subject_raw(&self, subject_raw: &[u8]) -> Option<&Vec<Vec<u8>>> {
        self.certs_by_subject.get(subject_raw)
    }

    /// Number of certificates in the store.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if a DER-encoded certificate is in the trust store.
    ///
    /// Matches by subject and raw DER content.
    pub fn contains(&self, der: &[u8]) -> bool {
        if let Ok((_, x509)) = X509Certificate::from_der(der) {
            let subject_raw = x509.subject().as_raw().to_vec();
            if let Some(certs) = self.find_by_subject_raw(&subject_raw) {
                return certs.iter().any(|c| c == der);
            }
        }
        false
    }
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a PEM-encoded file containing one or more certificates into
/// individual DER-encoded certificates.
pub fn parse_pem_chain(input: &[u8]) -> Result<Vec<Vec<u8>>, XcertError> {
    let mut certs = Vec::new();

    // Use x509-parser's PEM iterator for robust multi-cert parsing
    for pem_result in Pem::iter_from_buffer(input) {
        match pem_result {
            Ok(pem) => {
                if pem.label == "CERTIFICATE" || pem.label == "TRUSTED CERTIFICATE" {
                    certs.push(pem.contents);
                }
            }
            Err(e) => {
                // If we already have some certs, stop at first error (trailing garbage)
                if !certs.is_empty() {
                    break;
                }
                return Err(XcertError::PemError(format!(
                    "failed to parse PEM: {}",
                    e
                )));
            }
        }
    }

    if certs.is_empty() {
        return Err(XcertError::PemError(
            "no certificates found in PEM input".into(),
        ));
    }

    Ok(certs)
}

/// Verify a certificate chain provided as a list of DER-encoded certificates.
///
/// The chain should be ordered leaf-first: `[leaf, intermediate..., (optional root)]`.
/// The trust store provides the root CA certificates used to anchor the chain.
///
/// Checks performed:
/// 1. Chain depth limit (max 32 certificates)
/// 2. Signature verification at each link in the chain
/// 3. Validity dates (not expired, not yet valid) for all certificates, unless
///    disabled via `options.check_time`
/// 4. Basic constraints (intermediate CAs must have `CA:TRUE` and satisfy
///    `pathLenConstraint`)
/// 5. Trust anchoring (the chain must terminate at a trusted root)
/// 6. Hostname matching against the leaf certificate (if `hostname` is provided)
pub fn verify_chain(
    chain_der: &[Vec<u8>],
    trust_store: &TrustStore,
    hostname: Option<&str>,
) -> Result<VerificationResult, XcertError> {
    verify_chain_with_options(chain_der, trust_store, hostname, &VerifyOptions::default())
}

/// Verify a certificate chain with configurable options.
///
/// Like [`verify_chain`], but accepts [`VerifyOptions`] to control behavior
/// such as skipping validity date checks.
pub fn verify_chain_with_options(
    chain_der: &[Vec<u8>],
    trust_store: &TrustStore,
    hostname: Option<&str>,
    options: &VerifyOptions,
) -> Result<VerificationResult, XcertError> {
    if chain_der.is_empty() {
        return Err(XcertError::VerifyError("empty certificate chain".into()));
    }

    if chain_der.len() > MAX_CHAIN_DEPTH {
        return Err(XcertError::VerifyError(format!(
            "certificate chain exceeds maximum depth of {}",
            MAX_CHAIN_DEPTH
        )));
    }

    let mut errors = Vec::new();
    let mut chain_info = Vec::new();

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Parse all certificates in the chain
    let parsed: Vec<(&[u8], X509Certificate)> = chain_der
        .iter()
        .enumerate()
        .map(|(i, der)| {
            X509Certificate::from_der(der)
                .map(|(_, x509)| (der.as_slice(), x509))
                .map_err(|e| {
                    XcertError::VerifyError(format!("failed to parse certificate at depth {}: {}", i, e))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Build chain info
    for (i, (_, x509)) in parsed.iter().enumerate() {
        chain_info.push(ChainCertInfo {
            depth: i,
            subject: crate::parser::build_dn(x509.subject()).to_oneline(),
            issuer: crate::parser::build_dn(x509.issuer()).to_oneline(),
        });
    }

    // Check validity dates for all certificates (unless disabled)
    if options.check_time {
        for (i, (_, x509)) in parsed.iter().enumerate() {
            let not_before = x509.validity().not_before.timestamp();
            let not_after = x509.validity().not_after.timestamp();
            let subject = crate::parser::build_dn(x509.subject()).to_oneline();

            if now_ts < not_before {
                errors.push(format!(
                    "certificate at depth {} ({}) is not yet valid",
                    i, subject
                ));
            }
            if now_ts > not_after {
                errors.push(format!(
                    "certificate at depth {} ({}) has expired",
                    i, subject
                ));
            }
        }
    }

    // Check basic constraints for CA certificates (all except leaf at depth 0)
    for (i, (_, x509)) in parsed.iter().enumerate().skip(1) {
        let subject = crate::parser::build_dn(x509.subject()).to_oneline();
        let bc = x509
            .basic_constraints()
            .ok()
            .flatten()
            .map(|bc| bc.value);

        match bc {
            Some(ref constraints) => {
                if !constraints.ca {
                    errors.push(format!(
                        "certificate at depth {} ({}) is not a CA but is used as issuer",
                        i, subject
                    ));
                }
                // Check pathLenConstraint: the number of intermediate CAs below
                // this CA must not exceed the constraint value. Depth i means
                // there are (i - 1) intermediates between the leaf and this CA.
                if let Some(pathlen) = constraints.path_len_constraint {
                    let intermediates_below = i.saturating_sub(1) as u32;
                    if intermediates_below > pathlen {
                        errors.push(format!(
                            "certificate at depth {} ({}) path length constraint violated \
                             (pathlen={}, intermediates below={})",
                            i, subject, pathlen, intermediates_below
                        ));
                    }
                }
            }
            None => {
                // No BasicConstraints extension. For v3 certificates this means
                // the certificate is not a CA. For v1/v2 certs we allow it for
                // compatibility (matching OpenSSL behavior).
                let version = x509.version().0;
                if version >= 2 {
                    errors.push(format!(
                        "certificate at depth {} ({}) is not a CA but is used as issuer",
                        i, subject
                    ));
                }
            }
        }
    }

    // RFC 5280 Section 4.2.1.3: CA certificates must have keyCertSign in
    // Key Usage when the extension is present.
    for (i, (_, x509)) in parsed.iter().enumerate().skip(1) {
        if let Ok(Some(ku)) = x509.key_usage() {
            if !ku.value.key_cert_sign() {
                let subject = crate::parser::build_dn(x509.subject()).to_oneline();
                errors.push(format!(
                    "certificate at depth {} ({}) is a CA but Key Usage does not include keyCertSign",
                    i, subject
                ));
            }
        }
    }

    // Verify signatures along the chain
    // Each cert should be signed by the next cert in the chain
    for i in 0..parsed.len().saturating_sub(1) {
        let (_, child) = &parsed[i];
        let (_, parent) = &parsed[i + 1];

        if let Err(e) = child.verify_signature(Some(parent.public_key())) {
            errors.push(format!(
                "signature verification failed at depth {} ({} -> {}): {}",
                i,
                crate::parser::build_dn(child.subject()).to_oneline(),
                crate::parser::build_dn(parent.subject()).to_oneline(),
                e
            ));
        }
    }

    // Verify trust anchoring.
    // With partial_chain, any certificate in the chain that is directly in the
    // trust store satisfies the anchoring requirement.
    let mut trust_anchored = false;

    if options.partial_chain {
        for (der, _) in &parsed {
            if trust_store.contains(der) {
                trust_anchored = true;
                break;
            }
        }
    }

    if !trust_anchored {
        let last = &parsed[parsed.len() - 1];
        let (last_der, last_x509) = last;
        let last_subject = crate::parser::build_dn(last_x509.subject()).to_oneline();

        // Check if the last cert in the chain is self-signed (i.e., it's a root)
        let is_self_signed = last_x509.subject().as_raw() == last_x509.issuer().as_raw()
            && last_x509.verify_signature(None).is_ok();

        if is_self_signed {
            // The chain includes the root - check if it's in the trust store
            if !trust_store.contains(last_der) {
                errors.push(format!(
                    "root certificate ({}) is not in the trust store",
                    last_subject
                ));
            }
        } else {
            // The chain doesn't include the root - find it in the trust store
            let issuer_raw = last_x509.issuer().as_raw();

            if let Some(candidates) = trust_store.find_by_subject_raw(issuer_raw) {
                for root_der in candidates {
                    if let Ok((_, root_x509)) = X509Certificate::from_der(root_der) {
                        if last_x509
                            .verify_signature(Some(root_x509.public_key()))
                            .is_ok()
                        {
                            // Add the trusted root to the chain info
                            chain_info.push(ChainCertInfo {
                                depth: parsed.len(),
                                subject: crate::parser::build_dn(root_x509.subject()).to_oneline(),
                                issuer: crate::parser::build_dn(root_x509.issuer()).to_oneline(),
                            });
                            trust_anchored = true;
                            break;
                        }
                    }
                }
            }

            if !trust_anchored {
                errors.push(format!(
                    "unable to find trusted root for issuer: {}",
                    crate::parser::build_dn(last_x509.issuer()).to_oneline()
                ));
            }
        }
    }

    // Check Extended Key Usage on the leaf certificate (if purpose is specified)
    if let Some(ref required_oid) = options.purpose {
        let (_, leaf) = &parsed[0];
        if let Ok(Some(eku)) = leaf.extended_key_usage() {
            let eku_val = &eku.value;
            // Map well-known OIDs to their boolean flags
            let has_eku = match required_oid.as_str() {
                "1.3.6.1.5.5.7.3.1" => eku_val.server_auth,
                "1.3.6.1.5.5.7.3.2" => eku_val.client_auth,
                "1.3.6.1.5.5.7.3.3" => eku_val.code_signing,
                "1.3.6.1.5.5.7.3.4" => eku_val.email_protection,
                "1.3.6.1.5.5.7.3.8" => eku_val.time_stamping,
                "1.3.6.1.5.5.7.3.9" => eku_val.ocsp_signing,
                "2.5.29.37.0" => eku_val.any,
                _ => {
                    // Check the 'other' OIDs list
                    eku_val
                        .other
                        .iter()
                        .any(|oid| format!("{}", oid) == *required_oid)
                }
            };
            if !has_eku {
                let leaf_subject = crate::parser::build_dn(leaf.subject()).to_oneline();
                errors.push(format!(
                    "leaf certificate ({}) does not have required EKU {}",
                    leaf_subject, required_oid
                ));
            }
        }
    }

    // Check hostname against leaf certificate (if requested)
    if let Some(host) = hostname {
        let (_, leaf) = &parsed[0];
        if !verify_hostname(leaf, host) {
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

    Ok(VerificationResult {
        is_valid: errors.is_empty(),
        chain: chain_info,
        errors,
    })
}

/// Convenience function: parse a PEM chain and verify it against a trust store.
pub fn verify_pem_chain(
    pem_data: &[u8],
    trust_store: &TrustStore,
    hostname: Option<&str>,
) -> Result<VerificationResult, XcertError> {
    let chain_der = parse_pem_chain(pem_data)?;
    verify_chain(&chain_der, trust_store, hostname)
}

/// Convenience function: parse a PEM chain and verify with options.
pub fn verify_pem_chain_with_options(
    pem_data: &[u8],
    trust_store: &TrustStore,
    hostname: Option<&str>,
    options: &VerifyOptions,
) -> Result<VerificationResult, XcertError> {
    let chain_der = parse_pem_chain(pem_data)?;
    verify_chain_with_options(&chain_der, trust_store, hostname, options)
}

/// Build a complete chain by combining a leaf certificate with untrusted
/// intermediate certificates and verify it.
///
/// This mirrors `openssl verify -untrusted intermediates.pem cert.pem`:
/// the leaf cert is provided separately, and intermediates are loaded from
/// a PEM file to be prepended to the chain in issuer order.
pub fn verify_with_untrusted(
    leaf_der: &[u8],
    untrusted_pem: &[u8],
    trust_store: &TrustStore,
    hostname: Option<&str>,
    options: &VerifyOptions,
) -> Result<VerificationResult, XcertError> {
    // Parse the intermediates
    let intermediate_der = parse_pem_chain(untrusted_pem)?;

    // Parse all intermediates so we can search them
    let mut intermediates: Vec<(Vec<u8>, X509Certificate)> = Vec::new();
    for der in &intermediate_der {
        if let Ok((_, cert)) = X509Certificate::from_der(der) {
            intermediates.push((der.clone(), cert));
        }
    }

    // Build the chain: start with leaf, then find intermediates by issuer
    let mut chain = vec![leaf_der.to_vec()];
    let (_, leaf) = X509Certificate::from_der(leaf_der)
        .map_err(|e| XcertError::ParseError(format!("failed to parse leaf certificate: {}", e)))?;

    let mut current_issuer_raw = leaf.issuer().as_raw().to_vec();
    let mut used = vec![false; intermediates.len()];

    for _ in 0..MAX_CHAIN_DEPTH {
        let mut found = false;
        for (idx, (der, cert)) in intermediates.iter().enumerate() {
            if used[idx] {
                continue;
            }
            if cert.subject().as_raw() == current_issuer_raw.as_slice() {
                chain.push(der.clone());
                current_issuer_raw = cert.issuer().as_raw().to_vec();
                used[idx] = true;
                found = true;
                break;
            }
        }
        if !found {
            break;
        }
    }

    verify_chain_with_options(&chain, trust_store, hostname, options)
}

/// Find the system CA bundle path (same location OpenSSL uses).
///
/// Uses `openssl-probe` to discover the platform's trust store.
/// Falls back to common well-known paths.
pub fn find_system_ca_bundle() -> Option<PathBuf> {
    let probe = openssl_probe::probe();
    if let Some(file) = probe.cert_file {
        let path = PathBuf::from(&file);
        if path.exists() {
            return Some(path);
        }
    }

    let candidates = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ];
    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Verify that a hostname matches the leaf certificate's names.
///
/// Checks SAN DNS entries first, falls back to CN if no SAN DNS entries exist.
/// Supports wildcard matching per RFC 6125.
fn verify_hostname(cert: &X509Certificate, hostname: &str) -> bool {
    let hostname_lower = hostname.to_ascii_lowercase();

    let san_dns = extract_san_dns_names(cert);

    if !san_dns.is_empty() {
        return san_dns
            .iter()
            .any(|pattern| util::hostname_matches(pattern, &hostname_lower));
    }

    // Fall back to CN
    if let Some(cn) = extract_cn(cert) {
        return util::hostname_matches(&cn, &hostname_lower);
    }

    false
}

/// Extract DNS names from the Subject Alternative Name extension.
fn extract_san_dns_names(cert: &X509Certificate) -> Vec<String> {
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
fn extract_cn(cert: &X509Certificate) -> Option<String> {
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            let oid = format!("{}", attr.attr_type());
            if oid == "2.5.4.3" {
                return attr.as_str().ok().map(|s| s.to_string());
            }
        }
    }
    None
}

