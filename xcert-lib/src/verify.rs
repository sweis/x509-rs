//! Certificate chain verification against a trust store.
//!
//! Provides functionality to verify X.509 certificate chains by checking
//! signatures, validity dates, basic constraints, and trust anchoring
//! against the system's trusted CA certificates (the same store used by OpenSSL).

use crate::XcertError;
use serde::Serialize;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

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

/// A set of trusted CA certificates.
///
/// By default, loads from the system trust store (the same certificates
/// used by OpenSSL). On Linux, this is typically `/etc/ssl/certs/ca-certificates.crt`.
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
    /// Searches the same locations as OpenSSL:
    /// 1. `SSL_CERT_FILE` environment variable
    /// 2. `/etc/ssl/certs/ca-certificates.crt` (Debian/Ubuntu)
    /// 3. `/etc/pki/tls/certs/ca-bundle.crt` (RHEL/CentOS/Fedora)
    /// 4. `/etc/ssl/cert.pem` (macOS, Alpine)
    /// 5. `/etc/ssl/certs` directory (individual cert files)
    pub fn system() -> Result<Self, XcertError> {
        let mut store = TrustStore::new();

        // Try bundle files first (most efficient)
        let bundle_paths = [
            std::env::var("SSL_CERT_FILE").ok(),
            Some("/etc/ssl/certs/ca-certificates.crt".into()),
            Some("/etc/pki/tls/certs/ca-bundle.crt".into()),
            Some("/etc/ssl/cert.pem".into()),
        ];

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
        let dir_paths = [
            std::env::var("SSL_CERT_DIR").ok(),
            Some("/etc/ssl/certs".into()),
        ];

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

    /// Add all certificates from a PEM bundle. Returns the number of certificates added.
    pub fn add_pem_bundle(&mut self, pem_data: &[u8]) -> Result<usize, XcertError> {
        let certs = parse_pem_chain(pem_data)?;
        let count = certs.len();
        for cert_der in certs {
            // Skip certificates that fail to parse (some bundles have non-cert entries)
            let _ = self.add_der(&cert_der);
        }
        Ok(count)
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
/// 1. Signature verification at each link in the chain
/// 2. Validity dates (not expired, not yet valid) for all certificates
/// 3. Basic constraints (intermediate and root CAs must have `CA:TRUE`)
/// 4. Trust anchoring (the chain must terminate at a trusted root)
/// 5. Hostname matching against the leaf certificate (if `hostname` is provided)
pub fn verify_chain(
    chain_der: &[Vec<u8>],
    trust_store: &TrustStore,
    hostname: Option<&str>,
) -> Result<VerificationResult, XcertError> {
    if chain_der.is_empty() {
        return Err(XcertError::VerifyError("empty certificate chain".into()));
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
            subject: format_x509_name(x509.subject()),
            issuer: format_x509_name(x509.issuer()),
        });
    }

    // Check validity dates for all certificates
    for (i, (_, x509)) in parsed.iter().enumerate() {
        let not_before = x509.validity().not_before.timestamp();
        let not_after = x509.validity().not_after.timestamp();
        let subject = format_x509_name(x509.subject());

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

    // Check basic constraints for CA certificates (all except leaf at depth 0)
    for (i, (_, x509)) in parsed.iter().enumerate().skip(1) {
        let is_ca = x509
            .basic_constraints()
            .ok()
            .flatten()
            .map(|bc| bc.value.ca)
            .unwrap_or(false);

        if !is_ca {
            errors.push(format!(
                "certificate at depth {} ({}) is not a CA but is used as issuer",
                i,
                format_x509_name(x509.subject())
            ));
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
                format_x509_name(child.subject()),
                format_x509_name(parent.subject()),
                e
            ));
        }
    }

    // Verify trust anchoring
    let last = &parsed[parsed.len() - 1];
    let (last_der, last_x509) = last;
    let last_subject = format_x509_name(last_x509.subject());

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
        let mut found_trusted_root = false;

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
                            subject: format_x509_name(root_x509.subject()),
                            issuer: format_x509_name(root_x509.issuer()),
                        });
                        found_trusted_root = true;
                        break;
                    }
                }
            }
        }

        if !found_trusted_root {
            errors.push(format!(
                "unable to find trusted root for issuer: {}",
                format_x509_name(last_x509.issuer())
            ));
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
            .any(|pattern| hostname_matches(pattern, &hostname_lower));
    }

    // Fall back to CN
    if let Some(cn) = extract_cn(cert) {
        return hostname_matches(&cn, &hostname_lower);
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

/// RFC 6125 hostname matching with wildcard support.
fn hostname_matches(pattern: &str, hostname: &str) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();

    if pattern_lower == *hostname {
        return true;
    }

    if let Some(suffix) = pattern_lower.strip_prefix("*.") {
        if let Some(rest) = hostname.strip_suffix(suffix) {
            if rest.ends_with('.') && !rest[..rest.len() - 1].contains('.') && rest.len() > 1 {
                return true;
            }
        }
    }

    false
}

/// Format an X509Name as a comma-separated one-line string.
fn format_x509_name(name: &X509Name) -> String {
    let mut parts = Vec::new();
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid_str = format!("{}", attr.attr_type());
            let key = oid_short_name(&oid_str);
            let value = attr.as_str().unwrap_or("<binary>");
            parts.push(format!("{}={}", key, value));
        }
    }
    parts.join(", ")
}

fn oid_short_name(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN".into(),
        "2.5.4.6" => "C".into(),
        "2.5.4.7" => "L".into(),
        "2.5.4.8" => "ST".into(),
        "2.5.4.10" => "O".into(),
        "2.5.4.11" => "OU".into(),
        other => other.to_string(),
    }
}
