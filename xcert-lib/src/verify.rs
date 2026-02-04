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
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

/// Maximum chain depth to prevent infinite loops during chain building.
const MAX_CHAIN_DEPTH: usize = 32;

/// Maximum work factor for Name Constraints checking (names × subtrees).
/// Protects against DoS from certificates with thousands of SANs or subtrees.
const MAX_NC_WORK_FACTOR: usize = 65_536;

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

/// Verification policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifyPolicy {
    /// RFC 5280 baseline validation (default).
    #[default]
    Rfc5280,
    /// WebPKI / CA/Browser Forum Baseline Requirements validation.
    /// Adds stricter requirements on top of RFC 5280.
    WebPki,
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
    /// Verification policy mode. Defaults to RFC 5280.
    pub policy: VerifyPolicy,
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
            policy: VerifyPolicy::default(),
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
        for probe_dir in probe.cert_dir {
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

    // RFC 5280 Section 6.1: max_chain_depth counts non-self-issued
    // intermediates. Self-issued certificates (subject == issuer) do not
    // count toward the depth limit.
    let num_intermediates = parsed
        .iter()
        .enumerate()
        .skip(1) // skip leaf
        .filter(|(_, (_, cert))| !is_self_issued(cert))
        .count();
    if num_intermediates > max_depth {
        return Err(XcertError::VerifyError(format!(
            "certificate chain exceeds maximum depth of {} (has {} non-self-issued intermediates)",
            max_depth, num_intermediates
        )));
    }

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
                // Check pathLenConstraint: RFC 5280 Section 6.1.4(h) says
                // self-issued certificates do not count toward pathlen.
                if let Some(pathlen) = constraints.path_len_constraint {
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

    // RFC 5280 Section 4.2: Reject certificates with unknown critical extensions.
    // An implementation MUST reject a certificate if it encounters a critical
    // extension it does not recognize.
    for (i, (_, x509)) in parsed.iter().enumerate() {
        let subject = crate::parser::build_dn(x509.subject()).to_oneline();
        for ext in x509.extensions() {
            if ext.critical && !is_known_extension(ext.oid.to_id_string().as_str()) {
                errors.push(format!(
                    "certificate at depth {} ({}) has unrecognized critical extension {}",
                    i, subject, ext.oid
                ));
            }
        }
    }

    // RFC 5280 Section 4.2: A certificate MUST NOT include more than one
    // instance of a particular extension.
    for (i, (_, x509)) in parsed.iter().enumerate() {
        let mut seen = HashSet::new();
        for ext in x509.extensions() {
            if !seen.insert(ext.oid.to_id_string()) {
                let subject = crate::parser::build_dn(x509.subject()).to_oneline();
                errors.push(format!(
                    "certificate at depth {} ({}) has duplicate extension {}",
                    i, subject, ext.oid
                ));
                break; // one duplicate error per certificate is enough
            }
        }
    }

    // RFC 5280 Section 4.2.1.10: Name Constraints MUST NOT appear in EE
    // certificates and MUST be critical when present.
    for (i, (_, x509)) in parsed.iter().enumerate() {
        let is_leaf = i == 0;
        for ext in x509.extensions() {
            if ext.oid.to_id_string() == "2.5.29.30" {
                let subject = crate::parser::build_dn(x509.subject()).to_oneline();
                if is_leaf {
                    errors.push(format!(
                        "certificate at depth {} ({}) is an end-entity but contains \
                         Name Constraints extension",
                        i, subject
                    ));
                } else if !ext.critical {
                    errors.push(format!(
                        "certificate at depth {} ({}) has Name Constraints extension \
                         that is not marked critical",
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
                // RFC 5280 Section 6.1.4(b): Self-issued certificates are
                // exempt from name constraints, except for the leaf.
                if child_depth > 0 && is_self_issued(child_cert) {
                    continue;
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

    // RFC 5280 strict validation: AKI/SKI, serial number, SAN, AIA, PC, EKU.
    for (i, (_, x509)) in parsed.iter().enumerate() {
        let subject = crate::parser::build_dn(x509.subject()).to_oneline();
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
                i, subject
            ));
        }
        if let Some(ext) = aki_ext {
            if ext.critical {
                errors.push(format!(
                    "certificate at depth {} ({}) has Authority Key Identifier marked critical",
                    i, subject
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
                i, subject
            ));
        }
        if let Some(ext) = ski_ext {
            if ext.critical {
                errors.push(format!(
                    "certificate at depth {} ({}) has Subject Key Identifier marked critical",
                    i, subject
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
                subject,
                serial.len()
            ));
        }
        if serial.iter().all(|&b| b == 0) {
            errors.push(format!(
                "certificate at depth {} ({}) has zero serial number",
                i, subject
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
                        i, subject
                    ));
                }
                None if !is_leaf => {
                    errors.push(format!(
                        "certificate at depth {} ({}) is a CA with empty subject and no SAN",
                        i, subject
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
                    i, subject
                ));
            }
        }

        // RFC 5280 Section 4.2.1.11: Policy Constraints MUST be critical.
        for ext in x509.extensions() {
            if ext.oid.to_id_string() == "2.5.29.36" && !ext.critical {
                errors.push(format!(
                    "certificate at depth {} ({}) has Policy Constraints not marked critical",
                    i, subject
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
                        subject
                    ));
                }
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

    // Check the trusted root from the trust store: time validity, Name
    // Constraints, unknown critical extensions, and duplicate extensions.
    if let Some(ref root_der) = trusted_root_der {
        if let Ok((_, root_x509)) = X509Certificate::from_der(root_der) {
            let root_subject = crate::parser::build_dn(root_x509.subject()).to_oneline();
            let root_depth = parsed.len(); // virtual depth of the trust store root

            // RFC 5280: Check validity dates for the trusted root.
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

            // Check unknown critical extensions on the trusted root.
            for ext in root_x509.extensions() {
                if ext.critical && !is_known_extension(ext.oid.to_id_string().as_str()) {
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
                        .map_or(false, |e| e.critical);
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

            // Check Name Constraints from the trusted root against the chain.
            // Also enforce that NC MUST be critical (RFC 5280 Section 4.2.1.10).
            for ext in root_x509.extensions() {
                if ext.oid.to_id_string() == "2.5.29.30" && !ext.critical {
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
                        .any(|oid| oid.to_id_string() == *required_oid),
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

    // Check hostname against leaf certificate (if requested).
    // Skip hostname check when the hostname is an IP address that will be
    // verified via verify_ip instead (avoids false failure from DNS matching).
    if let Some(host) = hostname {
        let ip_handled = options.verify_ip.as_deref() == Some(host);
        if !ip_handled {
            let Some((_, leaf)) = parsed.first() else {
                return Err(XcertError::VerifyError("empty certificate chain".into()));
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

    // CRL strict validation: CRLNumber must be present and non-critical.
    // RFC 5280 Section 5.2.3: CRL Number MUST be included in all CRLs
    // and MUST be non-critical.
    if !options.crl_ders.is_empty() && (options.crl_check_leaf || options.crl_check_all) {
        for crl_der in &options.crl_ders {
            if let Ok((_, crl)) =
                x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der)
            {
                // CRLNumber OID is 2.5.29.20
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

    // WebPKI-specific validation (CABF Baseline Requirements)
    if options.policy == VerifyPolicy::WebPki {
        for (i, (_, x509)) in parsed.iter().enumerate() {
            let subject = crate::parser::build_dn(x509.subject()).to_oneline();
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
                        subject
                    ));
                }

                // WebPKI: Leaf must have EKU
                if x509.extended_key_usage().ok().flatten().is_none() {
                    errors.push(format!(
                        "WebPKI: leaf certificate ({}) has no EKU extension",
                        subject
                    ));
                }

                // WebPKI: anyExtendedKeyUsage not allowed, EKU must not be critical
                if let Ok(Some(eku)) = x509.extended_key_usage() {
                    if eku.value.any {
                        errors.push(format!(
                            "WebPKI: leaf certificate ({}) has anyExtendedKeyUsage",
                            subject
                        ));
                    }
                    let eku_critical = x509
                        .extensions()
                        .iter()
                        .find(|e| e.oid.to_id_string() == "2.5.29.37")
                        .map_or(false, |e| e.critical);
                    if eku_critical {
                        errors.push(format!(
                            "WebPKI: leaf certificate ({}) has critical EKU",
                            subject
                        ));
                    }
                }

                // WebPKI: Leaf must not have BC:CA=true
                if let Some(bc) = x509.basic_constraints().ok().flatten() {
                    if bc.value.ca {
                        errors.push(format!(
                            "WebPKI: leaf certificate ({}) has BasicConstraints CA:TRUE",
                            subject
                        ));
                    }
                }

                // WebPKI: v1 certificates not allowed
                if x509.version().0 < 2 {
                    errors.push(format!(
                        "WebPKI: leaf certificate ({}) is version {} (v3 required)",
                        subject,
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
                        .map_or(false, |e| e.critical);
                    if san_critical {
                        errors.push(format!(
                            "WebPKI: leaf certificate ({}) has critical SAN with non-empty subject",
                            subject
                        ));
                    }
                }

                // WebPKI: Weak crypto check
                if let Some(weakness) = check_weak_crypto(x509) {
                    errors.push(format!(
                        "WebPKI: leaf certificate ({}) {}",
                        subject, weakness
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
                                        subject, name
                                    ));
                                }
                            }
                        }
                    }
                }

                // WebPKI: Malformed AIA
                for ext in x509.extensions() {
                    if ext.oid.to_id_string() == "1.3.6.1.5.5.7.1.1" {
                        if x509_parser::extensions::AuthorityInfoAccess::from_der(ext.value)
                            .is_err()
                        {
                            errors.push(format!(
                                "WebPKI: leaf certificate ({}) has malformed AIA extension",
                                subject
                            ));
                        }
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
                                .map_or(false, |s| s.is_empty());
                            let excluded_empty = nc
                                .value
                                .excluded_subtrees
                                .as_ref()
                                .map_or(false, |s| s.is_empty());
                            let both_absent = nc.value.permitted_subtrees.is_none()
                                && nc.value.excluded_subtrees.is_none();
                            if permitted_empty || excluded_empty || both_absent {
                                errors.push(format!(
                                    "WebPKI: certificate at depth {} ({}) has empty or malformed Name Constraints",
                                    i, subject
                                ));
                            }
                        }
                    }
                }
            }
        }

        // WebPKI: Root certificate checks
        // Check both the trusted root from store and self-signed root in chain
        let root_certs_to_check: Vec<(&X509Certificate, String)> = {
            let mut roots = Vec::new();
            if let Some(ref root_der) = trusted_root_der {
                // We'll check the trusted root below in a separate block
                let _ = root_der;
            }
            // Check self-signed root in chain (last cert)
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
            // Root should not have EKU
            if root_x509.extended_key_usage().ok().flatten().is_some() {
                errors.push(format!("WebPKI: root ({}) has EKU extension", root_subject));
            }
            // Root weak crypto
            if let Some(weakness) = check_weak_crypto(root_x509) {
                errors.push(format!("WebPKI: root ({}) {}", root_subject, weakness));
            }
            // Root AKI validation
            webpki_check_root_aki(root_x509, root_subject, &mut errors);
        }

        // Check trusted root from store (if not in chain)
        if let Some(ref root_der) = trusted_root_der {
            if let Ok((_, root_x509)) = X509Certificate::from_der(root_der) {
                let root_subject = crate::parser::build_dn(root_x509.subject()).to_oneline();
                // Avoid double-checking if root is already the last cert in chain
                let already_checked = parsed
                    .last()
                    .map_or(false, |(der, _)| *der == root_der.as_slice());
                if !already_checked {
                    if root_x509.extended_key_usage().ok().flatten().is_some() {
                        errors.push(format!("WebPKI: root ({}) has EKU extension", root_subject));
                    }
                    if let Some(weakness) = check_weak_crypto(&root_x509) {
                        errors.push(format!("WebPKI: root ({}) {}", root_subject, weakness));
                    }
                    webpki_check_root_aki(&root_x509, &root_subject, &mut errors);
                }
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
    verify_pem_chain_with_options(pem_data, trust_store, hostname, &VerifyOptions::default())
}

/// Parse a PEM bundle, build the optimal chain via path building, and verify.
///
/// The first certificate in the PEM is the leaf. Remaining certificates form
/// the untrusted intermediate pool. A DFS path builder finds the shortest
/// chain from the leaf to a trust anchor.
pub fn verify_pem_chain_with_options(
    pem_data: &[u8],
    trust_store: &TrustStore,
    hostname: Option<&str>,
    options: &VerifyOptions,
) -> Result<VerificationResult, XcertError> {
    let all_ders = parse_pem_chain(pem_data)?;
    if all_ders.is_empty() {
        return Err(XcertError::VerifyError("empty certificate chain".into()));
    }

    // Path building: first cert is leaf, rest form the intermediate pool.
    let leaf_der = &all_ders[0];
    let intermediates: Vec<(Vec<u8>, X509Certificate)> = all_ders[1..]
        .iter()
        .filter_map(|der| {
            X509Certificate::from_der(der)
                .ok()
                .map(|(_, cert)| (der.clone(), cert))
        })
        .collect();

    let chain = build_chain_dfs(leaf_der, &intermediates, trust_store);
    verify_chain_with_options(&chain, trust_store, hostname, options)
}

/// Build a complete chain by combining a leaf certificate with untrusted
/// intermediate certificates and verify it.
///
/// This mirrors `openssl verify -untrusted intermediates.pem cert.pem`:
/// the leaf cert is provided separately, and intermediates are loaded from
/// a PEM file. Uses DFS path building to find the optimal chain.
pub fn verify_with_untrusted(
    leaf_der: &[u8],
    untrusted_pem: &[u8],
    trust_store: &TrustStore,
    hostname: Option<&str>,
    options: &VerifyOptions,
) -> Result<VerificationResult, XcertError> {
    let intermediate_der = parse_pem_chain(untrusted_pem)?;
    let intermediates: Vec<(Vec<u8>, X509Certificate)> = intermediate_der
        .iter()
        .filter_map(|der| {
            X509Certificate::from_der(der)
                .ok()
                .map(|(_, cert)| (der.clone(), cert))
        })
        .collect();

    let chain = build_chain_dfs(leaf_der, &intermediates, trust_store);
    verify_chain_with_options(&chain, trust_store, hostname, options)
}

/// Build a certificate chain from leaf to trust anchor using DFS with backtracking.
///
/// Given a leaf certificate and a pool of untrusted intermediates, finds a valid
/// chain that terminates at a trust anchor. Tries multiple paths via backtracking
/// when there are cross-signed or duplicate intermediates.
fn build_chain_dfs(
    leaf_der: &[u8],
    intermediates: &[(Vec<u8>, X509Certificate)],
    trust_store: &TrustStore,
) -> Vec<Vec<u8>> {
    let leaf = match X509Certificate::from_der(leaf_der) {
        Ok((_, cert)) => cert,
        Err(_) => return vec![leaf_der.to_vec()],
    };

    let mut best_chain = vec![leaf_der.to_vec()];
    let mut current_chain = vec![leaf_der.to_vec()];
    let mut used = vec![false; intermediates.len()];

    dfs_build(
        &leaf,
        &mut current_chain,
        &mut used,
        intermediates,
        trust_store,
        &mut best_chain,
    );

    best_chain
}

/// DFS recursive helper for chain building. Returns true if a valid chain
/// terminating at a trust anchor was found.
fn dfs_build(
    current: &X509Certificate,
    chain: &mut Vec<Vec<u8>>,
    used: &mut [bool],
    intermediates: &[(Vec<u8>, X509Certificate)],
    trust_store: &TrustStore,
    best: &mut Vec<Vec<u8>>,
) -> bool {
    let issuer_raw = current.issuer().as_raw();

    // Check if current cert is self-signed and in the trust store
    if current.subject().as_raw() == issuer_raw && current.verify_signature(None).is_ok() {
        if let Some(last) = chain.last() {
            if trust_store.contains(last) {
                *best = chain.clone();
                return true;
            }
        }
    }

    // Check if issuer is in the trust store (chain terminates here)
    if let Some(candidates) = trust_store.find_by_subject_raw(issuer_raw) {
        for root_der in candidates {
            if let Ok((_, root)) = X509Certificate::from_der(root_der) {
                if current.verify_signature(Some(root.public_key())).is_ok() {
                    *best = chain.clone();
                    return true;
                }
            }
        }
    }

    // Depth limit
    if chain.len() >= MAX_CHAIN_DEPTH {
        return false;
    }

    // Try each unused intermediate as the next link in the chain
    for (idx, (der, cert)) in intermediates.iter().enumerate() {
        if used[idx] {
            continue;
        }
        if cert.subject().as_raw() != issuer_raw {
            continue;
        }
        // Verify signature from current cert to candidate issuer
        if current.verify_signature(Some(cert.public_key())).is_err() {
            continue;
        }

        used[idx] = true;
        chain.push(der.clone());

        if dfs_build(cert, chain, used, intermediates, trust_store, best) {
            return true;
        }

        chain.pop();
        used[idx] = false;
    }

    false
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
/// Checks SAN DNS entries first. If `allow_cn_fallback` is true, falls back to
/// CN when no SAN DNS entries exist. In WebPKI mode CN fallback is disabled.
/// Supports wildcard matching per RFC 6125.
fn verify_hostname(cert: &X509Certificate, hostname: &str, allow_cn_fallback: bool) -> bool {
    let hostname_lower = hostname.to_ascii_lowercase();

    let san_dns = extract_san_dns_names(cert);

    if !san_dns.is_empty() {
        return san_dns
            .iter()
            .any(|pattern| util::hostname_matches(pattern, &hostname_lower));
    }

    // Fall back to CN (disabled in WebPKI mode)
    if allow_cn_fallback {
        if let Some(cn) = extract_cn(cert) {
            return util::hostname_matches(&cn, &hostname_lower);
        }
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
            if attr.attr_type().to_id_string() == "2.5.4.3" {
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
            if attr.attr_type().to_id_string() == "1.2.840.113549.1.9.1" {
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

/// Check if a certificate is self-issued (subject == issuer).
///
/// RFC 5280 Section 6.1: Self-issued certificates are special — they do not
/// count toward chain depth, pathLenConstraint, or name constraints (except
/// the final certificate in the chain).
fn is_self_issued(cert: &X509Certificate) -> bool {
    cert.subject().as_raw() == cert.issuer().as_raw()
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
        "2.5.29.14" // Subject Key Identifier
        | "2.5.29.15" // Key Usage
        | "2.5.29.17" // Subject Alternative Name
        | "2.5.29.18" // Issuer Alternative Name
        | "2.5.29.19" // Basic Constraints
        | "2.5.29.30" // Name Constraints
        | "2.5.29.31" // CRL Distribution Points
        | "2.5.29.32" // Certificate Policies
        | "2.5.29.33" // Policy Mappings
        | "2.5.29.35" // Authority Key Identifier
        | "2.5.29.36" // Policy Constraints
        | "2.5.29.37" // Extended Key Usage
        | "2.5.29.46" // Freshest CRL
        | "2.5.29.54" // Inhibit Any Policy
        // Common extensions in practice
        | "1.3.6.1.5.5.7.1.1"  // Authority Info Access (AIA)
        | "1.3.6.1.5.5.7.1.11" // Subject Info Access (SIA)
        | "1.3.6.1.5.5.7.1.12" // TLS Feature (OCSP Must-Staple)
        | "1.3.6.1.4.1.11129.2.4.2" // SCT List (Certificate Transparency)
        | "1.3.6.1.4.1.11129.2.4.3" // CT Poison (pre-certificate)
        // Netscape extensions (legacy, but still seen)
        | "2.16.840.1.113730.1.1" // Netscape Cert Type
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
            if attr.attr_type().to_id_string() == "1.2.840.113549.1.9.1" {
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
// WebPKI helper functions
// ---------------------------------------------------------------------------

/// Check for weak or forbidden cryptographic algorithms (WebPKI / CABF BRs).
fn check_weak_crypto(cert: &X509Certificate) -> Option<String> {
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
fn is_public_suffix(domain: &str) -> bool {
    !domain.contains('.')
}

/// WebPKI root AKI validation: if AKI is present on a self-signed root,
/// keyIdentifier must be present and must match SKI; authorityCertIssuer
/// and authorityCertSerialNumber must not be present.
fn webpki_check_root_aki(
    root_x509: &X509Certificate,
    root_subject: &str,
    errors: &mut Vec<String>,
) {
    // Find AKI extension and parse it
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
