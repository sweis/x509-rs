//! Human-readable and JSON formatting of certificate information.

use crate::fields::{
    AiaEntry, CertificateInfo, DigestAlgorithm, Extension, ExtensionValue, SanEntry,
};
use crate::XcertError;
use std::fmt::Write;

/// Format certificate information as human-readable text.
///
/// If `show_all` is true, includes signature bytes and full public key details.
pub fn display_text(cert: &CertificateInfo, show_all: bool) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "Certificate:");
    let _ = writeln!(out, "  Version: {} (0x{:x})", cert.version, cert.version.saturating_sub(1));
    let _ = writeln!(out, "  Serial: {}", cert.serial);
    let _ = writeln!(out, "  Signature Algorithm: {}", cert.signature_algorithm);
    let _ = writeln!(out, "  Issuer: {}", cert.issuer_string());
    let _ = writeln!(out, "  Validity:");
    let _ = writeln!(out, "    Not Before: {}", cert.not_before);
    let _ = writeln!(out, "    Not After:  {}", cert.not_after);
    let _ = writeln!(out, "  Subject: {}", cert.subject_string());

    // Public key summary
    let _ = writeln!(out, "  Public Key:");
    let _ = write!(out, "    Algorithm: {}", cert.public_key.algorithm);
    if let Some(bits) = cert.public_key.key_size {
        let _ = write!(out, " ({} bit)", bits);
    }
    if let Some(curve) = &cert.public_key.curve {
        let _ = write!(out, " [{}]", curve);
    }
    out.push('\n');

    if show_all {
        if let Some(modulus) = &cert.public_key.modulus {
            let truncated = modulus.get(..40).unwrap_or(modulus);
            let _ = writeln!(out, "    Modulus: {}...", truncated);
        }
    }

    // Extensions
    if !cert.extensions.is_empty() {
        let _ = writeln!(out, "  Extensions:");
        for ext in &cert.extensions {
            format_extension(&mut out, ext);
        }
    }

    // Fingerprint
    let fp = cert.fingerprint(DigestAlgorithm::Sha256);
    let _ = writeln!(out, "  Fingerprint (SHA-256): {}", fp);

    // Signature (only with --all)
    if show_all && !cert.signature_hex.is_empty() {
        let truncated = cert.signature_hex.get(..40).unwrap_or(&cert.signature_hex);
        let _ = writeln!(out, "  Signature: {}...", truncated);
    }

    out
}

fn format_extension(out: &mut String, ext: &Extension) {
    let critical_str = if ext.critical { " [critical]" } else { "" };

    match &ext.value {
        ExtensionValue::BasicConstraints { ca, path_len } => {
            let pl = match path_len {
                Some(n) => format!(", pathlen:{}", n),
                None => String::new(),
            };
            let _ = writeln!(out, "    Basic Constraints:{} CA={}{}", critical_str, ca, pl);
        }
        ExtensionValue::KeyUsage(usages) => {
            let _ = writeln!(out, "    Key Usage:{} {}", critical_str, usages.join(", "));
        }
        ExtensionValue::ExtendedKeyUsage(usages) => {
            let _ = writeln!(
                out,
                "    Extended Key Usage:{} {}",
                critical_str,
                usages.join(", ")
            );
        }
        ExtensionValue::SubjectAltName(entries) => {
            let _ = writeln!(out, "    Subject Alternative Name:{}", critical_str);
            for entry in entries {
                match entry {
                    SanEntry::Dns(name) => {
                        let _ = writeln!(out, "      DNS: {}", name);
                    }
                    SanEntry::Email(email) => {
                        let _ = writeln!(out, "      Email: {}", email);
                    }
                    SanEntry::Ip(ip) => {
                        let _ = writeln!(out, "      IP: {}", ip);
                    }
                    SanEntry::Uri(uri) => {
                        let _ = writeln!(out, "      URI: {}", uri);
                    }
                    SanEntry::DirName(dn) => {
                        let _ = writeln!(out, "      DirName: {}", dn);
                    }
                    SanEntry::Other(s) => {
                        let _ = writeln!(out, "      Other: {}", s);
                    }
                }
            }
        }
        ExtensionValue::SubjectKeyIdentifier(hex) => {
            let _ = writeln!(out, "    Subject Key Identifier:{} {}", critical_str, hex);
        }
        ExtensionValue::AuthorityKeyIdentifier { key_id, .. } => {
            if let Some(kid) = key_id {
                let _ = writeln!(
                    out,
                    "    Authority Key Identifier:{} keyid:{}",
                    critical_str, kid
                );
            } else {
                let _ = writeln!(out, "    Authority Key Identifier:{}", critical_str);
            }
        }
        ExtensionValue::AuthorityInfoAccess(entries) => {
            let _ = writeln!(out, "    Authority Information Access:{}", critical_str);
            for AiaEntry { method, location } in entries {
                let _ = writeln!(out, "      {}: {}", method, location);
            }
        }
        ExtensionValue::CrlDistributionPoints(uris) => {
            let _ = writeln!(out, "    CRL Distribution Points:{}", critical_str);
            for uri in uris {
                let _ = writeln!(out, "      {}", uri);
            }
        }
        ExtensionValue::CertificatePolicies(oids) => {
            let _ = writeln!(
                out,
                "    Certificate Policies:{} {}",
                critical_str,
                oids.join(", ")
            );
        }
        ExtensionValue::NsComment(comment) => {
            let _ = writeln!(out, "    Netscape Comment:{} {}", critical_str, comment);
        }
        ExtensionValue::Raw(hex) => {
            let truncated = hex.get(..40).unwrap_or(hex);
            let suffix = if hex.len() > 40 { "..." } else { "" };
            let _ = writeln!(
                out,
                "    {} ({}):{}  {}{}",
                ext.name, ext.oid, critical_str, truncated, suffix
            );
        }
    }
}

/// Serialize certificate information to a pretty-printed JSON string.
pub fn to_json(cert: &CertificateInfo) -> Result<String, XcertError> {
    serde_json::to_string_pretty(cert).map_err(XcertError::Json)
}
