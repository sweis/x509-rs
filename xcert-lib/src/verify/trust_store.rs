//! Trust store management for CA certificates.
//!
//! Provides [`TrustStore`] for loading and querying trusted CA certificates,
//! matching OpenSSL's trust store discovery behavior.

use crate::XcertError;
use std::collections::HashMap;
use std::path::PathBuf;
use x509_parser::prelude::*;

/// Well-known CA bundle file paths, in order of preference.
pub(crate) const KNOWN_CA_BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/CentOS/Fedora
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/ssl/cert.pem",                  // macOS, Alpine
];

/// Well-known CA certificate directory paths.
pub(crate) const KNOWN_CA_DIR_PATHS: &[&str] = &["/etc/ssl/certs"];

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
        let dir_candidates = std::env::var("SSL_CERT_DIR")
            .ok()
            .into_iter()
            .chain(
                probe
                    .cert_dir
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned()),
            )
            .chain(KNOWN_CA_DIR_PATHS.iter().map(|s| (*s).to_string()));

        for dir in dir_candidates {
            let dir_path = std::path::Path::new(&dir);
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
        let certs = super::parse_pem_chain(pem_data)?;
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
    pub(crate) fn find_by_subject_raw(&self, subject_raw: &[u8]) -> Option<&Vec<Vec<u8>>> {
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
