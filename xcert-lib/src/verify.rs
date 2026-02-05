//! Certificate chain verification against a trust store.
//!
//! Provides functionality to verify X.509 certificate chains by checking
//! signatures, validity dates, basic constraints, and trust anchoring
//! against the system's trusted CA certificates (the same store used by OpenSSL).
//!
//! The system trust store location is discovered via `openssl-probe` and
//! environment variables, matching OpenSSL's lookup behavior.

use crate::oid;
use crate::util;
use crate::XcertError;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

/// Maximum chain depth to prevent infinite loops during chain building.
const MAX_CHAIN_DEPTH: usize = 32;

/// Well-known CA bundle file paths, in order of preference.
const KNOWN_CA_BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/CentOS/Fedora
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/ssl/cert.pem",                  // macOS, Alpine
];

/// Well-known CA certificate directory paths.
const KNOWN_CA_DIR_PATHS: &[&str] = &["/etc/ssl/certs"];

/// Check if a file looks like a PEM certificate file for trust store loading.
///
/// Matches `.pem`, `.crt`, `.cer` extensions and OpenSSL hash-linked files
/// (`XXXXXXXX.N` where the extension is a single digit).
fn is_pem_cert_file(path: &std::path::Path) -> bool {
    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(e) => e,
        None => return false,
    };
    matches!(ext, "pem" | "crt" | "cer")
        || (ext.len() == 1 && ext.bytes().next().is_some_and(|b| b.is_ascii_digit()))
}

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
        "sslserver" => Some(oid::EKU_SERVER_AUTH),
        "sslclient" => Some(oid::EKU_CLIENT_AUTH),
        "smimesign" | "smimeencrypt" => Some(oid::EKU_EMAIL_PROTECTION),
        "codesign" => Some(oid::EKU_CODE_SIGNING),
        "timestampsign" => Some(oid::EKU_TIME_STAMPING),
        "ocsphelper" => Some(oid::EKU_OCSP_SIGNING),
        "any" => Some(oid::EKU_ANY),
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
    /// 3. Well-known bundle file paths ([`KNOWN_CA_BUNDLE_PATHS`])
    /// 4. `SSL_CERT_DIR` environment variable
    /// 5. Directory discovered by `openssl-probe`
    /// 6. Well-known certificate directories ([`KNOWN_CA_DIR_PATHS`])
    pub fn system() -> Result<Self, XcertError> {
        let mut store = TrustStore::new();

        // Try file-based CA bundle (delegates to find_system_ca_bundle for path
        // discovery, sharing the same path list and openssl-probe logic).
        if let Some(bundle_path) = find_system_ca_bundle() {
            if let Ok(data) = std::fs::read(&bundle_path) {
                let added = store.add_pem_bundle(&data)?;
                if added > 0 {
                    return Ok(store);
                }
            }
        }

        // Try directory of individual certs
        let probe = openssl_probe::probe();
        let mut dir_paths: Vec<Option<String>> = vec![std::env::var("SSL_CERT_DIR").ok()];
        for probe_dir in probe.cert_dir {
            dir_paths.push(Some(probe_dir.to_string_lossy().into_owned()));
        }
        for known in KNOWN_CA_DIR_PATHS {
            dir_paths.push(Some((*known).into()));
        }

        for dir in dir_paths.iter().flatten() {
            let dir_path = std::path::Path::new(dir);
            if let Ok(added) = store.add_pem_directory(dir_path) {
                if added > 0 {
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
    /// Reads all `.pem`, `.crt`, `.cer`, and OpenSSL hash-linked files in the
    /// directory. Hash-linked files follow the pattern `XXXXXXXX.N` where N is
    /// a single digit (e.g., `a1b2c3d4.0`).
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
                let is_cert = is_pem_cert_file(&path);
                if is_cert {
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

/// Check whether a list of DER-encoded certificates appears to form a chain
/// (each cert's issuer matches the next cert's subject) rather than an
/// unrelated bundle of independent certificates (e.g. a CA bundle).
///
/// Returns `true` if the certificates form a chain (or there's 0-1 certs).
/// Returns `false` if consecutive certificates lack issuer-subject linkage.
pub fn is_certificate_chain(certs_der: &[Vec<u8>]) -> bool {
    if certs_der.len() <= 1 {
        return true;
    }

    // Check if cert[0]'s issuer matches cert[1]'s subject
    let cert0 = match certs_der
        .first()
        .and_then(|der| X509Certificate::from_der(der).ok())
    {
        Some((_, cert)) => cert,
        None => return true, // can't parse; assume chain and let verification handle errors
    };
    let cert1 = match certs_der
        .get(1)
        .and_then(|der| X509Certificate::from_der(der).ok())
    {
        Some((_, cert)) => cert,
        None => return true,
    };

    cert0.issuer().as_raw() == cert1.subject().as_raw()
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
    let num_intermediates = chain_der.len().saturating_sub(1);
    if num_intermediates > max_depth {
        return Err(XcertError::VerifyError(format!(
            "certificate chain exceeds maximum depth of {} (has {} intermediates)",
            max_depth, num_intermediates
        )));
    }

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

    // Pre-compute subject and issuer strings for all certificates (#29).
    let subjects: Vec<String> = parsed
        .iter()
        .map(|(_, x509)| crate::parser::build_dn(x509.subject()).to_oneline())
        .collect();
    let issuers: Vec<String> = parsed
        .iter()
        .map(|(_, x509)| crate::parser::build_dn(x509.issuer()).to_oneline())
        .collect();

    let mut chain_info: Vec<ChainCertInfo> = subjects
        .iter()
        .zip(issuers.iter())
        .enumerate()
        .map(|(i, (subject, issuer))| ChainCertInfo {
            depth: i,
            subject: subject.clone(),
            issuer: issuer.clone(),
        })
        .collect();

    let mut errors = Vec::new();

    // Individual verification steps, each in its own helper function.
    if options.check_time {
        check_chain_time_validity(&parsed, &subjects, now_ts, &mut errors);
    }
    check_chain_basic_constraints(&parsed, &subjects, &mut errors);
    check_chain_critical_extensions(&parsed, &subjects, &mut errors);
    check_chain_duplicate_extensions(&parsed, &subjects, &mut errors);
    check_chain_name_constraint_placement(&parsed, &subjects, &mut errors);
    check_chain_name_constraints(&parsed, &mut errors);
    check_chain_key_cert_sign(&parsed, &subjects, &mut errors);
    check_chain_signatures(&parsed, &subjects, &mut errors);

    // Trust anchoring
    let trusted_root_der = verify_trust_anchoring(
        &parsed,
        &subjects,
        trust_store,
        options,
        &mut chain_info,
        &mut errors,
    )?;

    // Trusted root validation
    if let Some(ref root_der) = trusted_root_der {
        check_trusted_root(root_der, &parsed, options, now_ts, &mut errors);
    }

    // Leaf certificate checks
    check_leaf_purpose(&parsed, &subjects, options, &mut errors);
    check_leaf_hostname(&parsed, hostname, options, &mut errors);
    check_leaf_email(&parsed, options, &mut errors);
    check_leaf_ip(&parsed, options, &mut errors);

    // CRL revocation
    check_crl_chain(
        &parsed,
        &subjects,
        options,
        &trusted_root_der,
        now_ts,
        &mut errors,
    );

    Ok(VerificationResult {
        is_valid: errors.is_empty(),
        chain: chain_info,
        errors,
    })
}

// ---------------------------------------------------------------------------
// Helper functions for verify_chain_with_options (#35)
// ---------------------------------------------------------------------------

/// Check validity dates for all certificates in the chain.
#[allow(clippy::indexing_slicing)] // subjects[i] is safe: same length as parsed
fn check_chain_time_validity(
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
fn check_chain_basic_constraints(
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
                    let intermediates_below = i.saturating_sub(1) as u32;
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
fn check_chain_critical_extensions(
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
fn check_chain_duplicate_extensions(
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
fn check_chain_name_constraint_placement(
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
fn check_chain_name_constraints(parsed: &[(&[u8], X509Certificate)], errors: &mut Vec<String>) {
    for (ca_depth, (_, ca_cert)) in parsed.iter().enumerate().skip(1) {
        if let Ok(Some(nc_ext)) = ca_cert.name_constraints() {
            let nc = &nc_ext.value;
            for (child_depth, (_, child_cert)) in parsed.iter().enumerate() {
                if child_depth >= ca_depth {
                    break;
                }
                let nc_errors = check_name_constraints(nc, child_cert, child_depth, ca_depth);
                errors.extend(nc_errors);
            }
        }
    }
}

/// RFC 5280 Section 4.2.1.3: CA certificates must have keyCertSign.
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
fn check_chain_key_cert_sign(
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

/// Verify signatures along the chain (each cert signed by the next).
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
fn check_chain_signatures(
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
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
fn verify_trust_anchoring(
    parsed: &[(&[u8], X509Certificate)],
    subjects: &[String],
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
                let last_issuer = crate::parser::build_dn(last_x509.issuer()).to_oneline();
                errors.push(format!(
                    "unable to find trusted root for issuer: {}",
                    last_issuer
                ));
            }
        }
    }

    Ok(trusted_root_der)
}

/// Validate the trusted root: time, critical extensions, Name Constraints.
fn check_trusted_root(
    root_der: &[u8],
    parsed: &[(&[u8], X509Certificate)],
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
        if ext.critical && !is_known_extension(ext.oid.to_id_string().as_str()) {
            errors.push(format!(
                "trusted root ({}) has unrecognized critical extension {}",
                root_subject, ext.oid
            ));
        }
    }

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
            let nc_errors = check_name_constraints(nc, child_cert, child_depth, root_depth);
            errors.extend(nc_errors);
        }
    }
}

/// Check EKU purpose on the leaf certificate.
#[allow(clippy::indexing_slicing)] // subjects has same length as parsed
fn check_leaf_purpose(
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
fn check_leaf_hostname(
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

/// Check email against leaf certificate (if requested).
fn check_leaf_email(
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
fn check_leaf_ip(
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

/// CRL-based revocation checking.
#[allow(clippy::indexing_slicing)] // subjects/parsed have same length; range is bounded
fn check_crl_chain(
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
/// Checks, in order:
/// 1. `SSL_CERT_FILE` environment variable
/// 2. Path discovered by `openssl-probe`
/// 3. Well-known bundle file paths ([`KNOWN_CA_BUNDLE_PATHS`])
pub fn find_system_ca_bundle() -> Option<PathBuf> {
    // Check environment variable first (matches OpenSSL behavior)
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Some(p);
        }
    }

    let probe = openssl_probe::probe();
    if let Some(file) = probe.cert_file {
        let path = PathBuf::from(&file);
        if path.exists() {
            return Some(path);
        }
    }

    for candidate in KNOWN_CA_BUNDLE_PATHS {
        let p = PathBuf::from(candidate);
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
///
/// Delegates to [`util::verify_hostname_match`] (shared with `check_host`).
fn verify_hostname(cert: &X509Certificate, hostname: &str) -> bool {
    let dns_names = extract_san_dns_names(cert);
    let cn = extract_cn(cert);
    util::verify_hostname_match(&dns_names, cn.as_deref(), hostname)
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
fn verify_email(cert: &X509Certificate, email: &str) -> bool {
    let emails = extract_emails(cert);
    util::verify_email_match(&emails, email)
}

/// Extract email addresses from SAN and subject emailAddress attribute.
fn extract_emails(cert: &X509Certificate) -> Vec<String> {
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
fn verify_ip(cert: &X509Certificate, ip: &str) -> bool {
    let san_ips = extract_san_ips(cert);
    util::verify_ip_match(&san_ips, ip)
}

/// Extract IP address strings from the SAN extension.
fn extract_san_ips(cert: &X509Certificate) -> Vec<String> {
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

// ---------------------------------------------------------------------------
// Known extension OIDs (for unknown critical extension detection)
// ---------------------------------------------------------------------------

/// Check if an extension OID is one we recognize and process.
/// RFC 5280 Section 4.2 requires that implementations reject certificates
/// containing unrecognized critical extensions.
fn is_known_extension(oid: &str) -> bool {
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
            if attr.attr_type().to_id_string() == oid::EMAIL_ADDRESS {
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
///
/// Matches on the underlying numeric value of the `ReasonCode` newtype
/// (which wraps a `u8`), per RFC 5280 Section 5.3.1.
fn format_crl_reason(rc: &x509_parser::x509::ReasonCode) -> String {
    match rc.0 {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        // 7 is unused per RFC 5280
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aACompromise",
        _ => "unspecified",
    }
    .into()
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
