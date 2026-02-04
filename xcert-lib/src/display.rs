//! Human-readable and JSON formatting of certificate information.

use crate::fields::{
    AiaEntry, CertificateInfo, DigestAlgorithm, Extension, ExtensionValue, SanEntry,
};
use crate::XcertError;

/// Format certificate information as human-readable text.
///
/// If `show_all` is true, includes signature bytes and full public key details.
pub fn display_text(cert: &CertificateInfo, show_all: bool) -> String {
    let mut out = String::new();

    out.push_str("Certificate:\n");
    out.push_str(&format!("  Version: {} (v{})\n", cert.version, cert.version));
    out.push_str(&format!("  Serial: {}\n", cert.serial));
    out.push_str(&format!("  Signature Algorithm: {}\n", cert.signature_algorithm));
    out.push_str(&format!("  Issuer: {}\n", cert.issuer_string()));
    out.push_str("  Validity:\n");
    out.push_str(&format!("    Not Before: {}\n", cert.not_before));
    out.push_str(&format!("    Not After:  {}\n", cert.not_after));
    out.push_str(&format!("  Subject: {}\n", cert.subject_string()));

    // Public key summary
    out.push_str("  Public Key:\n");
    out.push_str(&format!("    Algorithm: {}", cert.public_key.algorithm));
    if let Some(bits) = cert.public_key.key_size {
        out.push_str(&format!(" ({} bit)", bits));
    }
    if let Some(curve) = &cert.public_key.curve {
        out.push_str(&format!(" [{}]", curve));
    }
    out.push('\n');

    if show_all {
        if let Some(modulus) = &cert.public_key.modulus {
            out.push_str(&format!("    Modulus: {}...\n", &modulus[..std::cmp::min(40, modulus.len())]));
        }
    }

    // Extensions
    if !cert.extensions.is_empty() {
        out.push_str("  Extensions:\n");
        for ext in &cert.extensions {
            format_extension(&mut out, ext);
        }
    }

    // Fingerprint
    let fp = cert.fingerprint(DigestAlgorithm::Sha256);
    out.push_str(&format!("  Fingerprint (SHA-256): {}\n", fp));

    // Signature (only with --all)
    if show_all && !cert.signature_hex.is_empty() {
        out.push_str(&format!(
            "  Signature: {}...\n",
            &cert.signature_hex[..std::cmp::min(40, cert.signature_hex.len())]
        ));
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
            out.push_str(&format!(
                "    Basic Constraints:{} CA={}{}\n",
                critical_str, ca, pl
            ));
        }
        ExtensionValue::KeyUsage(usages) => {
            out.push_str(&format!(
                "    Key Usage:{} {}\n",
                critical_str,
                usages.join(", ")
            ));
        }
        ExtensionValue::ExtendedKeyUsage(usages) => {
            out.push_str(&format!(
                "    Extended Key Usage:{} {}\n",
                critical_str,
                usages.join(", ")
            ));
        }
        ExtensionValue::SubjectAltName(entries) => {
            out.push_str(&format!("    Subject Alternative Name:{}\n", critical_str));
            for entry in entries {
                match entry {
                    SanEntry::Dns(name) => out.push_str(&format!("      DNS: {}\n", name)),
                    SanEntry::Email(email) => out.push_str(&format!("      Email: {}\n", email)),
                    SanEntry::Ip(ip) => out.push_str(&format!("      IP: {}\n", ip)),
                    SanEntry::Uri(uri) => out.push_str(&format!("      URI: {}\n", uri)),
                    SanEntry::DirName(dn) => out.push_str(&format!("      DirName: {}\n", dn)),
                    SanEntry::Other(s) => out.push_str(&format!("      Other: {}\n", s)),
                }
            }
        }
        ExtensionValue::SubjectKeyIdentifier(hex) => {
            out.push_str(&format!(
                "    Subject Key Identifier:{} {}\n",
                critical_str, hex
            ));
        }
        ExtensionValue::AuthorityKeyIdentifier { key_id, .. } => {
            if let Some(kid) = key_id {
                out.push_str(&format!(
                    "    Authority Key Identifier:{} keyid:{}\n",
                    critical_str, kid
                ));
            } else {
                out.push_str(&format!(
                    "    Authority Key Identifier:{}\n",
                    critical_str
                ));
            }
        }
        ExtensionValue::AuthorityInfoAccess(entries) => {
            out.push_str(&format!("    Authority Information Access:{}\n", critical_str));
            for AiaEntry { method, location } in entries {
                out.push_str(&format!("      {}: {}\n", method, location));
            }
        }
        ExtensionValue::CrlDistributionPoints(uris) => {
            out.push_str(&format!("    CRL Distribution Points:{}\n", critical_str));
            for uri in uris {
                out.push_str(&format!("      {}\n", uri));
            }
        }
        ExtensionValue::CertificatePolicies(oids) => {
            out.push_str(&format!(
                "    Certificate Policies:{} {}\n",
                critical_str,
                oids.join(", ")
            ));
        }
        ExtensionValue::NsComment(comment) => {
            out.push_str(&format!(
                "    Netscape Comment:{} {}\n",
                critical_str, comment
            ));
        }
        ExtensionValue::Raw(hex) => {
            out.push_str(&format!(
                "    {} ({}):{}",
                ext.name, ext.oid, critical_str
            ));
            if hex.len() <= 40 {
                out.push_str(&format!(" {}\n", hex));
            } else {
                out.push_str(&format!(" {}...\n", &hex[..40]));
            }
        }
    }
}

/// Serialize certificate information to a pretty-printed JSON string.
pub fn to_json(cert: &CertificateInfo) -> Result<String, XcertError> {
    serde_json::to_string_pretty(cert).map_err(XcertError::Json)
}
