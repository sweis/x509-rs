//! Certificate data types and field extraction.

use serde::Serialize;

/// Digest algorithm for fingerprint computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha1,
}

/// A parsed X.509 certificate with extracted fields.
#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    /// Certificate version (1, 2, or 3).
    pub version: u32,
    /// Serial number as a colon-separated hex string.
    pub serial: String,
    /// Signature algorithm name.
    pub signature_algorithm: String,
    /// Issuer distinguished name.
    pub issuer: DistinguishedName,
    /// Subject distinguished name.
    pub subject: DistinguishedName,
    /// Validity start date.
    pub not_before: DateTime,
    /// Validity end date.
    pub not_after: DateTime,
    /// Public key information.
    pub public_key: PublicKeyInfo,
    /// X.509v3 extensions.
    pub extensions: Vec<Extension>,
    /// Raw signature bytes (hex-encoded).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub signature_hex: String,

    /// Raw DER bytes of the entire certificate (for fingerprint computation).
    #[serde(skip)]
    pub raw_der: Vec<u8>,
}

/// Distinguished name with ordered components.
#[derive(Debug, Clone, Serialize)]
pub struct DistinguishedName {
    /// Ordered list of (attribute_type, value) pairs.
    /// Attribute types use short names where known (e.g., "CN", "O", "C").
    pub components: Vec<(String, String)>,
}

impl DistinguishedName {
    /// Format as a comma-separated one-line string matching OpenSSL's default format.
    /// Example: "C = US, O = Org, CN = example.com"
    ///
    /// Values containing commas, equals signs, or backslashes are escaped
    /// to prevent ambiguous output.
    pub fn to_oneline(&self) -> String {
        let mut result = String::new();
        for (i, (k, v)) in self.components.iter().enumerate() {
            if i > 0 {
                result.push_str(", ");
            }
            result.push_str(k);
            result.push_str(" = ");
            for ch in v.chars() {
                match ch {
                    '\\' => result.push_str("\\\\"),
                    ',' => result.push_str("\\,"),
                    '=' => result.push_str("\\="),
                    _ => result.push(ch),
                }
            }
        }
        result
    }
}

impl std::fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_oneline())
    }
}

/// Public key information.
#[derive(Debug, Clone, Serialize)]
pub struct PublicKeyInfo {
    /// Algorithm name: "RSA", "EC", "Ed25519", etc.
    pub algorithm: String,
    /// Key size in bits (e.g., 2048 for RSA, 256 for P-256).
    pub key_size: Option<u32>,
    /// Named curve for EC keys (e.g., "P-256", "P-384").
    pub curve: Option<String>,
    /// RSA modulus as hex string (only for RSA keys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modulus: Option<String>,
    /// RSA exponent (only for RSA keys, typically 65537).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exponent: Option<u64>,
    /// PEM-encoded SubjectPublicKeyInfo.
    #[serde(skip)]
    pub pem: String,
}

/// A certificate extension.
#[derive(Debug, Clone, Serialize)]
pub struct Extension {
    /// OID as a dotted-decimal string.
    pub oid: String,
    /// Human-readable name (or OID string if unknown).
    pub name: String,
    /// Whether this extension is marked critical.
    pub critical: bool,
    /// Parsed extension value.
    pub value: ExtensionValue,
}

/// Strongly-typed extension values.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value")]
pub enum ExtensionValue {
    BasicConstraints {
        ca: bool,
        path_len: Option<u32>,
    },
    KeyUsage(Vec<String>),
    ExtendedKeyUsage(Vec<String>),
    SubjectAltName(Vec<SanEntry>),
    SubjectKeyIdentifier(String),
    AuthorityKeyIdentifier {
        key_id: Option<String>,
        issuer: Option<String>,
    },
    AuthorityInfoAccess(Vec<AiaEntry>),
    CrlDistributionPoints(Vec<String>),
    CertificatePolicies(Vec<String>),
    NsComment(String),
    /// Fallback for extensions we don't parse into a specific variant.
    Raw(String),
}

/// Subject Alternative Name entry.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value")]
pub enum SanEntry {
    Dns(String),
    Email(String),
    Ip(String),
    Uri(String),
    DirName(String),
    Other(String),
}

/// Authority Information Access entry.
#[derive(Debug, Clone, Serialize)]
pub struct AiaEntry {
    /// Access method: "OCSP" or "CA Issuers".
    pub method: String,
    /// Access location (usually a URI).
    pub location: String,
}

/// Date-time representation.
#[derive(Debug, Clone, Serialize)]
pub struct DateTime {
    /// ISO 8601 formatted string.
    pub iso8601: String,
    /// Unix timestamp.
    pub timestamp: i64,
}

impl DateTime {
    /// Format in OpenSSL's default date style: `Feb  3 23:57:06 2026 GMT`.
    pub fn to_openssl(&self) -> String {
        match ::time::OffsetDateTime::from_unix_timestamp(self.timestamp) {
            Ok(dt) => {
                let month = match u8::from(dt.month()) {
                    1 => "Jan",
                    2 => "Feb",
                    3 => "Mar",
                    4 => "Apr",
                    5 => "May",
                    6 => "Jun",
                    7 => "Jul",
                    8 => "Aug",
                    9 => "Sep",
                    10 => "Oct",
                    11 => "Nov",
                    12 => "Dec",
                    _ => "???",
                };
                format!(
                    "{} {:2} {:02}:{:02}:{:02} {} GMT",
                    month,
                    dt.day(),
                    dt.hour(),
                    dt.minute(),
                    dt.second(),
                    dt.year()
                )
            }
            Err(_) => self.iso8601.clone(),
        }
    }
}

impl std::fmt::Display for DateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_openssl())
    }
}

impl CertificateInfo {
    /// Return the subject as a one-line string.
    pub fn subject_string(&self) -> String {
        self.subject.to_oneline()
    }

    /// Return the issuer as a one-line string.
    pub fn issuer_string(&self) -> String {
        self.issuer.to_oneline()
    }

    /// Return the serial number as a colon-separated hex string (e.g., "10:00").
    pub fn serial_hex(&self) -> &str {
        &self.serial
    }

    /// Return the serial number in compact hex format matching OpenSSL output (e.g., "1000").
    pub fn serial_compact(&self) -> String {
        self.serial.replace(':', "")
    }

    /// Return the notBefore date as a string (OpenSSL format).
    pub fn not_before_string(&self) -> String {
        self.not_before.to_openssl()
    }

    /// Return the notAfter date as a string (OpenSSL format).
    pub fn not_after_string(&self) -> String {
        self.not_after.to_openssl()
    }

    /// Compute the fingerprint of the certificate using the given digest algorithm.
    pub fn fingerprint(&self, algorithm: DigestAlgorithm) -> String {
        crate::fingerprint::compute_fingerprint(&self.raw_der, algorithm)
    }

    /// Return the public key in PEM format.
    pub fn public_key_pem(&self) -> &str {
        &self.public_key.pem
    }

    /// Return the RSA modulus as a hex string, if this is an RSA certificate.
    pub fn modulus_hex(&self) -> Option<&str> {
        self.public_key.modulus.as_deref()
    }

    /// Extract all email addresses from the subject and SAN extension.
    pub fn emails(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut emails = Vec::new();
        // Check subject emailAddress attribute
        for (key, val) in &self.subject.components {
            if (key == "emailAddress" || key == "Email") && seen.insert(val.clone()) {
                emails.push(val.clone());
            }
        }
        // Check SAN
        for ext in &self.extensions {
            if let ExtensionValue::SubjectAltName(entries) = &ext.value {
                for entry in entries {
                    if let SanEntry::Email(e) = entry {
                        if seen.insert(e.clone()) {
                            emails.push(e.clone());
                        }
                    }
                }
            }
        }
        emails
    }

    /// Extract all SAN entries.
    pub fn san_entries(&self) -> Vec<&SanEntry> {
        self.extensions
            .iter()
            .find_map(|ext| match &ext.value {
                ExtensionValue::SubjectAltName(entries) => Some(entries.iter().collect()),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// Extract OCSP responder URLs from the AIA extension.
    pub fn ocsp_urls(&self) -> Vec<String> {
        self.extensions
            .iter()
            .find_map(|ext| match &ext.value {
                ExtensionValue::AuthorityInfoAccess(entries) => Some(
                    entries
                        .iter()
                        .filter(|e| e.method == "OCSP")
                        .map(|e| e.location.clone())
                        .collect(),
                ),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// Extract Key Usage values, if the extension is present.
    pub fn key_usage(&self) -> Option<Vec<String>> {
        self.extensions.iter().find_map(|ext| match &ext.value {
            ExtensionValue::KeyUsage(usages) => Some(usages.clone()),
            _ => None,
        })
    }

    /// Extract Extended Key Usage values, if the extension is present.
    pub fn ext_key_usage(&self) -> Option<Vec<String>> {
        self.extensions.iter().find_map(|ext| match &ext.value {
            ExtensionValue::ExtendedKeyUsage(usages) => Some(usages.clone()),
            _ => None,
        })
    }
}
