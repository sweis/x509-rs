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
    /// Verify at a specific Unix timestamp instead of the current time.
    /// Matches OpenSSL's `-attime` flag.
    pub at_time: Option<i64>,
    /// Maximum chain depth. Defaults to 32.
    pub verify_depth: Option<usize>,
    /// Email to verify against the leaf certificate's SAN/subject.
    pub verify_email: Option<String>,
    /// IP address to verify against the leaf certificate's SAN.
    pub verify_ip: Option<String>,
    /// DER-encoded CRLs to check for revocation.
    pub crl_ders: Vec<Vec<u8>>,
    /// Check CRL for the leaf certificate only (`crl_check`).
    pub crl_check_leaf: bool,
    /// Check CRL for all certificates in the chain (`crl_check_all`).
    pub crl_check_all: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            check_time: true,
            partial_chain: false,
            purpose: None,
            at_time: None,
            verify_depth: None,
            verify_email: None,
            verify_ip: None,
            crl_ders: Vec::new(),
            crl_check_leaf: false,
            crl_check_all: false,
        }
    }
}

/// Resolve a named purpose string to its EKU OID.
///
/// Matches OpenSSL's `-purpose` named values.
pub fn resolve_purpose(name: &str) -> Option<&'static str> {
    match name {
        "sslserver" => Some("1.3.6.1.5.5.7.3.1"),
        "sslclient" => Some("1.3.6.1.5.5.7.3.2"),
        "smimesign" | "smimeencrypt" => Some("1.3.6.1.5.5.7.3.4"),
        "codesign" => Some("1.3.6.1.5.5.7.3.3"),
        "timestampsign" => Some("1.3.6.1.5.5.7.3.8"),
        "ocsphelper" => Some("1.3.6.1.5.5.7.3.9"),
        "any" => Some("2.5.29.37.0"),
        _ => None,
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
        let mut bundle_paths: Vec<Option<String>> = vec![std::env::var("SSL_CERT_FILE").ok()];
        if let Some(probe_file) = probe.cert_file {
            bundle_paths.push(Some(probe_file.to_string_lossy().into_owned()));
        }
        bundle_paths.extend([
            Some("/etc/ssl/certs/ca-certificates.crt".into()),
            Some("/etc/pki/tls/certs/ca-bundle.crt".into()),
            Some("/etc/ssl/ca-bundle.pem".into()),
            Some("/etc/ssl/cert.pem".into()),
        ]);

        for path in bundle_paths.iter().flatten() {
            if let Ok(data) = std::fs::read(path) {
                let added = store.add_pem_bundle(&data)?;
                if added > 0 {
                    return Ok(store);
                }
            }
        }

        // Try directory of individual certs
        let mut dir_paths: Vec<Option<String>> = vec![std::env::var("SSL_CERT_DIR").ok()];
        if let Some(probe_dir) = probe.cert_dir {
            dir_paths.push(Some(probe_dir.to_string_lossy().into_owned()));
        }
        dir_paths.push(Some("/etc/ssl/certs".into()));

        for dir in dir_paths.iter().flatten() {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path
                        .extension()
                        .map(|e| e == "pem" || e == "crt")
                        .unwrap_or(false)
                    {
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
        let (_, x509) =
            X509Certificate::from_der(der).map_err(|e| XcertError::DerError(format!("{}", e)))?;

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

    /// Load certificates from a directory of PEM files (like OpenSSL's -CApath).
    ///
    /// Reads all `.pem`, `.crt`, and `.0`-`.9` files in the directory.
    pub fn add_pem_directory(&mut self, dir: &std::path::Path) -> Result<usize, XcertError> {
        let mut total = 0;
        let entries = std::fs::read_dir(dir).map_err(|e| {
            XcertError::Io(std::io::Error::new(
                e.kind(),
                format!("{}: {}", dir.display(), e),
            ))
        })?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let is_cert_file = name.ends_with(".pem")
                    || name.ends_with(".crt")
                    || name.ends_with(".cer")
                    || name.chars().last().is_some_and(|c| c.is_ascii_digit());
                if is_cert_file {
                    if let Ok(data) = std::fs::read(&path) {
                        if let Ok(added) = self.add_pem_bundle(&data) {
                            total += added;
                        }
                    }
                }
            }
        }
        Ok(total)
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
                return Err(XcertError::PemError(format!("failed to parse PEM: {}", e)));
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
#[allow(clippy::indexing_slicing)]
pub fn verify_chain_with_options(
    chain_der: &[Vec<u8>],
    trust_store: &TrustStore,
    hostname: Option<&str>,
    options: &VerifyOptions,
) -> Result<VerificationResult, XcertError> {
    if chain_der.is_empty() {
        return Err(XcertError::VerifyError("empty certificate chain".into()));
    }

    let max_depth = options.verify_depth.unwrap_or(MAX_CHAIN_DEPTH);
    if chain_der.len() > max_depth {
        return Err(XcertError::VerifyError(format!(
            "certificate chain exceeds maximum depth of {}",
            max_depth
        )));
    }

    let mut errors = Vec::new();
    let mut chain_info = Vec::new();

    let now_ts = options.at_time.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    });

    // Parse all certificates in the chain
    let parsed: Vec<(&[u8], X509Certificate)> = chain_der
        .iter()
        .enumerate()
        .map(|(i, der)| {
            X509Certificate::from_der(der)
                .map(|(_, x509)| (der.as_slice(), x509))
                .map_err(|e| {
                    XcertError::VerifyError(format!(
                        "failed to parse certificate at depth {}: {}",
                        i, e
                    ))
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
        let bc = x509.basic_constraints().ok().flatten().map(|bc| bc.value);

        match bc {
            Some(constraints) => {
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

    // RFC 5280 Section 4.2.1.10: Check Name Constraints for CA certificates.
    // Each CA with Name Constraints restricts the names in all certificates
    // it issues (directly or transitively).
    for (ca_depth, (_, ca_cert)) in parsed.iter().enumerate().skip(1) {
        if let Ok(Some(nc_ext)) = ca_cert.name_constraints() {
            let nc = &nc_ext.value;
            // Check all certificates below this CA in the chain
            for (child_depth, (_, child_cert)) in parsed.iter().enumerate() {
                if child_depth >= ca_depth {
                    break;
                }
                let nc_errors = check_name_constraints(nc, child_cert, child_depth, ca_depth);
                errors.extend(nc_errors);
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
    for (child, parent) in parsed.iter().zip(parsed.iter().skip(1)) {
        let (_, child_x509) = child;
        let (_, parent_x509) = parent;

        if let Err(e) = child_x509.verify_signature(Some(parent_x509.public_key())) {
            errors.push(format!(
                "signature verification failed ({} -> {}): {}",
                crate::parser::build_dn(child_x509.subject()).to_oneline(),
                crate::parser::build_dn(parent_x509.subject()).to_oneline(),
                e
            ));
        }
    }

    // Verify trust anchoring.
    // With partial_chain, any certificate in the chain that is directly in the
    // trust store satisfies the anchoring requirement.
    let mut trust_anchored = false;
    let mut trusted_root_der: Option<Vec<u8>> = None;

    if options.partial_chain {
        for (der, _) in &parsed {
            if trust_store.contains(der) {
                trust_anchored = true;
                break;
            }
        }
    }

    if !trust_anchored {
        let Some((last_der, last_x509)) = parsed.last() else {
            // Unreachable: we checked chain_der.is_empty() at function entry
            return Err(XcertError::VerifyError("empty certificate chain".into()));
        };
        let last_subject = crate::parser::build_dn(last_x509.subject()).to_oneline();

        // Check if the last cert in the chain is self-signed (i.e., it's a root)
        let is_self_signed = last_x509.subject().as_raw() == last_x509.issuer().as_raw()
            && last_x509.verify_signature(None).is_ok();

        if is_self_signed {
            // The chain includes the root - check if it's in the trust store
            if trust_store.contains(last_der) {
                trusted_root_der = Some(last_der.to_vec());
            } else {
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
                    crate::parser::build_dn(last_x509.issuer()).to_oneline()
                ));
            }
        }
    }

    // Check Name Constraints from the trusted root against the entire chain.
    // This handles the case where the root is not in the chain itself but
    // was found in the trust store.
    if let Some(ref root_der) = trusted_root_der {
        if let Ok((_, root_x509)) = X509Certificate::from_der(root_der) {
            if let Ok(Some(nc_ext)) = root_x509.name_constraints() {
                let nc = &nc_ext.value;
                let root_depth = parsed.len(); // virtual depth of the trust store root
                for (child_depth, (_, child_cert)) in parsed.iter().enumerate() {
                    let nc_errors = check_name_constraints(nc, child_cert, child_depth, root_depth);
                    errors.extend(nc_errors);
                }
            }
        }
    }

    // Check Extended Key Usage on the leaf certificate (if purpose is specified)
    if let Some(ref required_oid) = options.purpose {
        let Some((_, leaf)) = parsed.first() else {
            return Err(XcertError::VerifyError("empty certificate chain".into()));
        };
        if let Ok(Some(eku)) = leaf.extended_key_usage() {
            let eku_val = &eku.value;
            // Map well-known OIDs to their boolean flags
            // RFC 5280 Section 4.2.1.12: anyExtendedKeyUsage satisfies
            // any specific purpose requirement.
            let has_eku = eku_val.any
                || match required_oid.as_str() {
                    "1.3.6.1.5.5.7.3.1" => eku_val.server_auth,
                    "1.3.6.1.5.5.7.3.2" => eku_val.client_auth,
                    "1.3.6.1.5.5.7.3.3" => eku_val.code_signing,
                    "1.3.6.1.5.5.7.3.4" => eku_val.email_protection,
                    "1.3.6.1.5.5.7.3.8" => eku_val.time_stamping,
                    "1.3.6.1.5.5.7.3.9" => eku_val.ocsp_signing,
                    "2.5.29.37.0" => true,
                    _ => eku_val
                        .other
                        .iter()
                        .any(|oid| format!("{}", oid) == *required_oid),
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
        let Some((_, leaf)) = parsed.first() else {
            return Err(XcertError::VerifyError("empty certificate chain".into()));
        };
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

    // Check email against leaf certificate SAN/subject (if requested)
    if let Some(ref email) = options.verify_email {
        let Some((_, leaf)) = parsed.first() else {
            return Err(XcertError::VerifyError("empty certificate chain".into()));
        };
        if !verify_email(leaf, email) {
            errors.push(format!("email '{}' does not match certificate", email));
        }
    }

    // Check IP address against leaf certificate SAN (if requested)
    if let Some(ref ip) = options.verify_ip {
        let Some((_, leaf)) = parsed.first() else {
            return Err(XcertError::VerifyError("empty certificate chain".into()));
        };
        if !verify_ip(leaf, ip) {
            errors.push(format!("IP address '{}' does not match certificate", ip));
        }
    }

    // CRL-based revocation checking
    if !options.crl_ders.is_empty() && (options.crl_check_leaf || options.crl_check_all) {
        let check_range = if options.crl_check_all {
            0..parsed.len()
        } else {
            // crl_check_leaf: only check the leaf (depth 0)
            0..1
        };

        // Pre-parse trusted root for CRL signature verification when
        // the root is not in the provided chain but was found in the trust store
        let trusted_root_parsed = trusted_root_der
            .as_deref()
            .and_then(|der| X509Certificate::from_der(der).ok().map(|(_, c)| c));

        for i in check_range {
            let (_, cert) = &parsed[i];
            // Find the issuer for CRL signature verification
            let issuer = if i + 1 < parsed.len() {
                Some(&parsed[i + 1].1)
            } else if let Some(ref root) = trusted_root_parsed {
                Some(root)
            } else {
                // Self-signed root: use itself as CRL issuer
                Some(cert)
            };

            if let Some(reason) = check_crl_revocation(cert, &options.crl_ders, issuer, now_ts) {
                let subject = crate::parser::build_dn(cert.subject()).to_oneline();
                errors.push(format!(
                    "certificate at depth {} ({}) has been revoked (reason: {})",
                    i, subject, reason
                ));
            }
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
#[allow(clippy::indexing_slicing)]
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
            if used.get(idx).copied().unwrap_or(true) {
                continue;
            }
            if cert.subject().as_raw() == current_issuer_raw.as_slice() {
                chain.push(der.clone());
                current_issuer_raw = cert.issuer().as_raw().to_vec();
                if let Some(flag) = used.get_mut(idx) {
                    *flag = true;
                }
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

/// Verify that an email matches the leaf certificate's SAN email entries or
/// subject emailAddress attribute.
fn verify_email(cert: &X509Certificate, email: &str) -> bool {
    let email_lower = email.to_ascii_lowercase();

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::RFC822Name(san_email) = gn {
                if san_email.to_ascii_lowercase() == email_lower {
                    return true;
                }
            }
        }
    }

    // Fall back to subject emailAddress (OID 1.2.840.113549.1.9.1)
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if format!("{}", attr.attr_type()) == "1.2.840.113549.1.9.1" {
                if let Ok(val) = attr.as_str() {
                    if val.to_ascii_lowercase() == email_lower {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Verify that an IP address matches the leaf certificate's SAN IP entries.
fn verify_ip(cert: &X509Certificate, ip: &str) -> bool {
    let normalized = crate::check::normalize_ip(ip);

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::IPAddress(ip_bytes) = gn {
                let san_ip = crate::parser::format_ip_bytes(ip_bytes);
                if crate::check::normalize_ip(&san_ip) == normalized {
                    return true;
                }
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Name Constraints checking (RFC 5280 Section 4.2.1.10)
// ---------------------------------------------------------------------------

/// Check that a certificate's names comply with a CA's Name Constraints.
///
/// Returns a list of error strings for any violations found.
fn check_name_constraints(
    nc: &x509_parser::extensions::NameConstraints,
    cert: &X509Certificate,
    child_depth: usize,
    ca_depth: usize,
) -> Vec<String> {
    let mut errors = Vec::new();
    let subject = crate::parser::build_dn(cert.subject()).to_oneline();

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
            if format!("{}", attr.attr_type()) == "1.2.840.113549.1.9.1" {
                if let Ok(val) = attr.as_str() {
                    email_names.push(val.to_ascii_lowercase());
                }
            }
        }
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
fn dns_name_matches_constraint(name: &str, constraint: &str) -> bool {
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
fn email_matches_constraint(email: &str, constraint: &str) -> bool {
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
fn ip_matches_constraint(ip_bytes: &[u8], constraint: &[u8]) -> bool {
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

// ---------------------------------------------------------------------------
// CRL-based revocation checking
// ---------------------------------------------------------------------------

/// Parse a PEM-encoded CRL file into DER-encoded CRL data.
pub fn parse_pem_crl(input: &[u8]) -> Result<Vec<Vec<u8>>, XcertError> {
    let mut crls = Vec::new();
    for pem_result in Pem::iter_from_buffer(input) {
        match pem_result {
            Ok(pem) => {
                if pem.label == "X509 CRL" {
                    crls.push(pem.contents);
                }
            }
            Err(e) => {
                if !crls.is_empty() {
                    break;
                }
                return Err(XcertError::PemError(format!(
                    "failed to parse CRL PEM: {}",
                    e
                )));
            }
        }
    }
    if crls.is_empty() {
        return Err(XcertError::PemError("no CRLs found in PEM input".into()));
    }
    Ok(crls)
}

/// Format a CRL revocation reason code as an RFC 5280-style string.
fn format_crl_reason(rc: &x509_parser::x509::ReasonCode) -> String {
    let debug = format!("{:?}", rc);
    if debug.contains("KeyCompromise") {
        "keyCompromise".into()
    } else if debug.contains("CACompromise") || debug.contains("CaCompromise") {
        "cACompromise".into()
    } else if debug.contains("AffiliationChanged") {
        "affiliationChanged".into()
    } else if debug.contains("Superseded") {
        "superseded".into()
    } else if debug.contains("CessationOfOperation") {
        "cessationOfOperation".into()
    } else if debug.contains("CertificateHold") {
        "certificateHold".into()
    } else if debug.contains("RemoveFromCRL") || debug.contains("RemoveFromCrl") {
        "removeFromCRL".into()
    } else if debug.contains("PrivilegeWithdrawn") {
        "privilegeWithdrawn".into()
    } else if debug.contains("AACompromise") || debug.contains("AaCompromise") {
        "aACompromise".into()
    } else {
        "unspecified".into()
    }
}

/// Check whether a certificate has been revoked according to the given CRLs.
///
/// `cert` is the parsed certificate to check.
/// `crl_ders` is a slice of DER-encoded CRL data.
/// `issuer_cert` is the issuer's certificate (used to verify the CRL signature).
/// `now_ts` is the current Unix timestamp for CRL validity checking.
///
/// Returns `Some(reason)` if revoked, `None` if not revoked.
pub fn check_crl_revocation(
    cert: &X509Certificate,
    crl_ders: &[Vec<u8>],
    issuer_cert: Option<&X509Certificate>,
    now_ts: i64,
) -> Option<String> {
    let serial = cert.raw_serial();

    for crl_der in crl_ders {
        let parsed = x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der);
        let (_, crl) = match parsed {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Verify CRL is from the right issuer
        if crl.issuer() != cert.issuer() {
            continue;
        }

        // RFC 5280 Section 6.3.3: Check CRL validity dates
        let this_update = crl.last_update().timestamp();
        if now_ts < this_update {
            continue; // CRL is not yet valid
        }
        if let Some(next_update) = crl.next_update() {
            if now_ts > next_update.timestamp() {
                continue; // CRL has expired
            }
        }

        // Verify CRL signature against the issuer's public key
        if let Some(issuer) = issuer_cert {
            if crl.verify_signature(issuer.public_key()).is_err() {
                continue;
            }
        }

        // Check if the certificate's serial number is in the revoked list
        for revoked in crl.iter_revoked_certificates() {
            if revoked.raw_serial() == serial {
                let reason = revoked
                    .reason_code()
                    .map(|rc| format_crl_reason(&rc.1))
                    .unwrap_or_else(|| "unspecified".to_string());
                return Some(reason);
            }
        }
    }

    None
}
