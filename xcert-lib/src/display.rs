//! Human-readable and JSON formatting of certificate information.

use crate::fields::{AiaEntry, CertificateInfo, DigestAlgorithm, Extension, ExtensionValue};
use crate::XcertError;
use colored::Colorize;
use std::fmt::Write;

/// Color scheme for certificate display (inspired by jq).
///
/// - Dates: cyan
/// - Hex values (serial, fingerprint, key identifiers): magenta
/// - URLs: blue
/// - Strings (names, algorithms): green
/// - Labels/keys: bold white (default terminal color, bold)
mod colors {
    use colored::{ColoredString, Colorize};

    /// Format a date value.
    pub fn date(s: &str) -> ColoredString {
        s.cyan()
    }

    /// Format a hex value (serial numbers, fingerprints, key IDs).
    pub fn hex(s: &str) -> ColoredString {
        s.magenta()
    }

    /// Format a URL.
    pub fn url(s: &str) -> ColoredString {
        s.blue()
    }

    /// Format a string value (names, algorithms, etc.).
    pub fn string(s: &str) -> ColoredString {
        s.green()
    }

    /// Format a label/key.
    pub fn label(s: &str) -> ColoredString {
        s.bold()
    }

    /// Format a boolean value.
    pub fn boolean(b: bool) -> ColoredString {
        if b {
            "true".yellow()
        } else {
            "false".yellow()
        }
    }

    /// Format a number.
    pub fn number<T: std::fmt::Display>(n: T) -> ColoredString {
        n.to_string().cyan()
    }
}

/// Format certificate information as human-readable text with colors.
///
/// If `show_all` is true, includes signature bytes and full public key details.
pub fn display_text(cert: &CertificateInfo, show_all: bool) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "{}:", colors::label("Certificate"));
    let _ = writeln!(
        out,
        "  {}: {} ({})",
        colors::label("Version"),
        colors::number(cert.version),
        colors::hex(&format!("0x{:x}", cert.version.saturating_sub(1)))
    );
    let _ = writeln!(
        out,
        "  {}: {}",
        colors::label("Serial"),
        colors::hex(&cert.serial)
    );
    let _ = writeln!(
        out,
        "  {}: {}",
        colors::label("Signature Algorithm"),
        colors::string(&cert.signature_algorithm)
    );
    let _ = writeln!(
        out,
        "  {}: {}",
        colors::label("Issuer"),
        colors::string(&cert.issuer_string())
    );
    let _ = writeln!(out, "  {}:", colors::label("Validity"));
    let _ = writeln!(
        out,
        "    {}: {}",
        colors::label("Not Before"),
        colors::date(&cert.not_before.to_string())
    );
    let _ = writeln!(
        out,
        "    {}:  {}",
        colors::label("Not After"),
        colors::date(&cert.not_after.to_string())
    );
    let _ = writeln!(
        out,
        "  {}: {}",
        colors::label("Subject"),
        colors::string(&cert.subject_string())
    );

    // Public key summary
    let _ = writeln!(out, "  {}:", colors::label("Public Key"));
    let _ = write!(
        out,
        "    {}: {}",
        colors::label("Algorithm"),
        colors::string(&cert.public_key.algorithm)
    );
    if let Some(bits) = cert.public_key.key_size {
        let _ = write!(out, " ({} bit)", colors::number(bits));
    }
    if let Some(curve) = &cert.public_key.curve {
        let _ = write!(out, " [{}]", colors::string(curve));
    }
    out.push('\n');

    if let Some(exp) = cert.public_key.exponent {
        let _ = writeln!(
            out,
            "    {}: {} ({})",
            colors::label("Exponent"),
            colors::number(exp),
            colors::hex(&format!("0x{:x}", exp))
        );
    }

    if show_all {
        if let Some(modulus) = &cert.public_key.modulus {
            let truncated = modulus.get(..40).unwrap_or(modulus);
            let _ = writeln!(
                out,
                "    {}: {}...",
                colors::label("Modulus"),
                colors::hex(truncated)
            );
        }
    }

    // Extensions
    if !cert.extensions.is_empty() {
        let _ = writeln!(out, "  {}:", colors::label("Extensions"));
        for ext in &cert.extensions {
            format_extension(&mut out, ext);
        }
    }

    // Fingerprint
    let fp = cert.fingerprint(DigestAlgorithm::Sha256);
    let _ = writeln!(
        out,
        "  {}: {}",
        colors::label("Fingerprint (SHA-256)"),
        colors::hex(&fp)
    );

    // Signature (only with --all)
    if show_all && !cert.signature_hex.is_empty() {
        let truncated = cert.signature_hex.get(..40).unwrap_or(&cert.signature_hex);
        let _ = writeln!(
            out,
            "  {}: {}...",
            colors::label("Signature"),
            colors::hex(truncated)
        );
    }

    out
}

fn format_extension(out: &mut String, ext: &Extension) {
    let critical_str = if ext.critical {
        format!(" {}", "[critical]".red())
    } else {
        String::new()
    };

    match &ext.value {
        ExtensionValue::BasicConstraints { ca, path_len } => {
            let pl = match path_len {
                Some(n) => format!(", pathlen:{}", colors::number(n)),
                None => String::new(),
            };
            let _ = writeln!(
                out,
                "    {}:{} CA={}{}",
                colors::label("Basic Constraints"),
                critical_str,
                colors::boolean(*ca),
                pl
            );
        }
        ExtensionValue::KeyUsage(usages) => {
            let colored_usages: Vec<_> = usages.iter().map(|u| colors::string(u)).collect();
            let _ = writeln!(
                out,
                "    {}:{} {}",
                colors::label("Key Usage"),
                critical_str,
                colored_usages
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        ExtensionValue::ExtendedKeyUsage(usages) => {
            let colored_usages: Vec<_> = usages.iter().map(|u| colors::string(u)).collect();
            let _ = writeln!(
                out,
                "    {}:{} {}",
                colors::label("Extended Key Usage"),
                critical_str,
                colored_usages
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        ExtensionValue::SubjectAltName(entries) => {
            let _ = writeln!(
                out,
                "    {}:{}",
                colors::label("Subject Alternative Name"),
                critical_str
            );
            for entry in entries {
                format_san_entry(out, entry);
            }
        }
        ExtensionValue::SubjectKeyIdentifier(hex) => {
            let _ = writeln!(
                out,
                "    {}:{} {}",
                colors::label("Subject Key Identifier"),
                critical_str,
                colors::hex(hex)
            );
        }
        ExtensionValue::AuthorityKeyIdentifier { key_id, .. } => {
            if let Some(kid) = key_id {
                let _ = writeln!(
                    out,
                    "    {}:{} keyid:{}",
                    colors::label("Authority Key Identifier"),
                    critical_str,
                    colors::hex(kid)
                );
            } else {
                let _ = writeln!(
                    out,
                    "    {}:{}",
                    colors::label("Authority Key Identifier"),
                    critical_str
                );
            }
        }
        ExtensionValue::AuthorityInfoAccess(entries) => {
            let _ = writeln!(
                out,
                "    {}:{}",
                colors::label("Authority Information Access"),
                critical_str
            );
            for AiaEntry { method, location } in entries {
                let _ = writeln!(
                    out,
                    "      {}: {}",
                    colors::string(method),
                    colors::url(location)
                );
            }
        }
        ExtensionValue::CrlDistributionPoints(uris) => {
            let _ = writeln!(
                out,
                "    {}:{}",
                colors::label("CRL Distribution Points"),
                critical_str
            );
            for uri in uris {
                let _ = writeln!(out, "      {}", colors::url(uri));
            }
        }
        ExtensionValue::CertificatePolicies(oids) => {
            let colored_oids: Vec<_> = oids.iter().map(|o| colors::string(o)).collect();
            let _ = writeln!(
                out,
                "    {}:{} {}",
                colors::label("Certificate Policies"),
                critical_str,
                colored_oids
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        ExtensionValue::NsComment(comment) => {
            let _ = writeln!(
                out,
                "    {}:{} {}",
                colors::label("Netscape Comment"),
                critical_str,
                colors::string(comment)
            );
        }
        ExtensionValue::Raw(hex) => {
            let truncated = hex.get(..40).unwrap_or(hex);
            let suffix = if hex.len() > 40 { "..." } else { "" };
            let _ = writeln!(
                out,
                "    {} ({}):{}  {}{}",
                colors::label(&ext.name),
                colors::string(&ext.oid),
                critical_str,
                colors::hex(truncated),
                suffix
            );
        }
    }
}

/// Format a SAN entry with appropriate colors.
fn format_san_entry(out: &mut String, entry: &crate::fields::SanEntry) {
    use crate::fields::SanEntry;

    match entry {
        SanEntry::Dns(v) => {
            let _ = writeln!(out, "      {}: {}", colors::label("DNS"), colors::string(v));
        }
        SanEntry::Email(v) => {
            let _ = writeln!(
                out,
                "      {}: {}",
                colors::label("Email"),
                colors::string(v)
            );
        }
        SanEntry::Ip(v) => {
            let _ = writeln!(out, "      {}: {}", colors::label("IP"), colors::string(v));
        }
        SanEntry::Uri(v) => {
            let _ = writeln!(out, "      {}: {}", colors::label("URI"), colors::url(v));
        }
        SanEntry::DirName(v) => {
            let _ = writeln!(
                out,
                "      {}: {}",
                colors::label("DirName"),
                colors::string(v)
            );
        }
        SanEntry::Other(v) => {
            let _ = writeln!(
                out,
                "      {}: {}",
                colors::label("Other"),
                colors::string(v)
            );
        }
    }
}

/// Serialize certificate information to a pretty-printed JSON string.
pub fn to_json(cert: &CertificateInfo) -> Result<String, XcertError> {
    serde_json::to_string_pretty(cert).map_err(XcertError::Json)
}
