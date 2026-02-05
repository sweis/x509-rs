//! Certificate parsing from PEM and DER formats.

use crate::fields::{
    AiaEntry, CertificateInfo, DateTime, DistinguishedName, Extension, ExtensionValue,
    PublicKeyInfo, SanEntry,
};
use crate::oid;
use crate::util;
use crate::XcertError;
use x509_parser::prelude::*;

/// Parse a certificate from PEM or DER (auto-detected).
///
/// If the input begins with `-----BEGIN` (after stripping whitespace), it is
/// treated as PEM. Otherwise it is treated as DER.
pub fn parse_cert(input: &[u8]) -> Result<CertificateInfo, XcertError> {
    if input.is_empty() {
        return Err(XcertError::ParseError("empty input".into()));
    }

    if util::is_pem(input) {
        parse_pem(input)
    } else {
        parse_der(input)
    }
}

/// Parse a certificate from PEM format.
pub fn parse_pem(input: &[u8]) -> Result<CertificateInfo, XcertError> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(input)
        .map_err(|e| XcertError::PemError(format!("{}", e)))?;

    if pem.label != "CERTIFICATE"
        && pem.label != "TRUSTED CERTIFICATE"
        && pem.label != "X509 CERTIFICATE"
    {
        return Err(XcertError::PemError(format!(
            "expected CERTIFICATE, got {}",
            pem.label
        )));
    }

    parse_der(&pem.contents)
}

/// Parse a certificate from DER format.
pub fn parse_der(input: &[u8]) -> Result<CertificateInfo, XcertError> {
    let (remaining, x509) =
        X509Certificate::from_der(input).map_err(|e| XcertError::DerError(format!("{}", e)))?;

    // Use only the actual certificate bytes, not any trailing data,
    // so that fingerprints are computed over the correct content.
    let cert_len = input.len() - remaining.len();
    let cert_der = input.get(..cert_len).unwrap_or(input);
    build_certificate_info(&x509, cert_der)
}

/// Build a CertificateInfo from a parsed X509Certificate.
fn build_certificate_info(
    x509: &X509Certificate,
    raw_der: &[u8],
) -> Result<CertificateInfo, XcertError> {
    let tbs = &x509.tbs_certificate;

    let raw_version = tbs.version.0;
    if raw_version > 2 {
        return Err(XcertError::ParseError(format!(
            "unsupported X.509 version {} (expected v1, v2, or v3)",
            raw_version + 1
        )));
    }
    let version = raw_version + 1;

    let serial = format_serial(tbs.raw_serial());

    let signature_algorithm = format_sig_algorithm(&x509.signature_algorithm);

    let issuer = build_dn(&tbs.issuer);
    let subject = build_dn(&tbs.subject);

    let not_before = build_datetime(&tbs.validity.not_before);
    let not_after = build_datetime(&tbs.validity.not_after);

    let public_key = build_public_key_info(&tbs.subject_pki)?;

    let extensions = build_extensions(tbs.extensions())?;

    let signature_hex = hex::encode(&*x509.signature_value.data);

    Ok(CertificateInfo {
        version,
        serial,
        signature_algorithm,
        issuer,
        subject,
        not_before,
        not_after,
        public_key,
        extensions,
        signature_hex,
        raw_der: raw_der.to_vec(),
    })
}

/// Format a serial number as a colon-separated uppercase hex string,
/// stripping leading zero bytes but keeping at least one byte.
fn format_serial(raw: &[u8]) -> String {
    let stripped = match raw.iter().position(|&b| b != 0) {
        Some(pos) => raw.get(pos..).unwrap_or(raw),
        None => raw.get(raw.len().saturating_sub(1)..).unwrap_or(raw),
    };
    util::hex_colon_upper(stripped)
}

fn format_sig_algorithm(algo: &AlgorithmIdentifier) -> String {
    match algo.algorithm.to_id_string().as_str() {
        oid::SHA1_WITH_RSA => "sha1WithRSAEncryption".into(),
        oid::SHA256_WITH_RSA => "sha256WithRSAEncryption".into(),
        oid::SHA384_WITH_RSA => "sha384WithRSAEncryption".into(),
        oid::SHA512_WITH_RSA => "sha512WithRSAEncryption".into(),
        oid::ECDSA_WITH_SHA256 => "ecdsa-with-SHA256".into(),
        oid::ECDSA_WITH_SHA384 => "ecdsa-with-SHA384".into(),
        oid::ECDSA_WITH_SHA512 => "ecdsa-with-SHA512".into(),
        oid::ED25519 => "Ed25519".into(),
        other => other.to_string(),
    }
}

pub(crate) fn build_dn(name: &X509Name) -> DistinguishedName {
    let mut components = Vec::new();
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let key = util::oid_short_name(&attr.attr_type().to_id_string());
            let value = attr.as_str().unwrap_or("<binary>").to_string();
            components.push((key, value));
        }
    }
    DistinguishedName { components }
}

fn build_datetime(asn1_time: &ASN1Time) -> DateTime {
    let ts = asn1_time.timestamp();
    let iso = match ::time::OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            dt.year(),
            u8::from(dt.month()),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        Err(_) => format!("{}", ts),
    };
    DateTime {
        iso8601: iso,
        timestamp: ts,
    }
}

fn build_public_key_info(spki: &SubjectPublicKeyInfo) -> Result<PublicKeyInfo, XcertError> {
    let oid_str = spki.algorithm.algorithm.to_id_string();

    let (algorithm, key_size, curve, modulus, exponent) = match oid_str.as_str() {
        oid::RSA_ENCRYPTION => {
            if let Some((mod_hex, bits, exp)) = extract_rsa_params(&spki.subject_public_key.data) {
                ("RSA".into(), Some(bits), None, Some(mod_hex), Some(exp))
            } else {
                ("RSA".into(), None, None, None, None)
            }
        }
        oid::EC_PUBLIC_KEY => {
            let curve_name = extract_ec_curve(&spki.algorithm);
            let key_size = match curve_name.as_str() {
                "P-256" => Some(256),
                "P-384" => Some(384),
                "P-521" => Some(521),
                _ => None,
            };
            ("EC".into(), key_size, Some(curve_name), None, None)
        }
        oid::ED25519 => ("Ed25519".into(), Some(256), None, None, None),
        oid::ED448 => ("Ed448".into(), Some(448), None, None, None),
        _ => (oid_str, None, None, None, None),
    };

    let pem = build_spki_pem(spki)?;

    Ok(PublicKeyInfo {
        algorithm,
        key_size,
        curve,
        modulus,
        exponent,
        pem,
    })
}

/// Extract RSA modulus and exponent from raw public key DER.
///
/// Returns `None` if the DER structure cannot be parsed, rather than
/// silently returning incorrect fallback values.
fn extract_rsa_params(data: &[u8]) -> Option<(String, u32, u64)> {
    let (_, parsed) = x509_parser::der_parser::parse_der(data).ok()?;
    let seq = parsed.as_sequence().ok()?;
    let bigint = seq.first().and_then(|m| m.as_bigint().ok())?;
    let bytes = bigint.to_bytes_be().1;
    // Skip leading zero byte used for DER positive integer encoding
    let significant = match bytes.split_first() {
        Some((&0, rest)) if !rest.is_empty() => rest,
        _ => &bytes,
    };
    let bits = (significant.len() as u32) * 8;
    let exponent = seq.get(1).and_then(|e| e.as_u64().ok())?;
    Some((hex::encode_upper(significant), bits, exponent))
}

fn extract_ec_curve(algo: &AlgorithmIdentifier) -> String {
    if let Some(params) = &algo.parameters {
        if let Ok(oid) = params.as_oid() {
            return match oid.to_id_string().as_str() {
                oid::CURVE_P256 => "P-256".into(),
                oid::CURVE_P384 => "P-384".into(),
                oid::CURVE_P521 => "P-521".into(),
                other => other.to_string(),
            };
        }
    }
    "unknown".into()
}

fn build_spki_pem(spki: &SubjectPublicKeyInfo) -> Result<String, XcertError> {
    use x509_parser::der_parser::asn1_rs::ToDer;

    // Encode individual components using asn1-rs ToDer for correct TLV encoding.
    let oid_der =
        spki.algorithm.algorithm.to_der_vec().map_err(|e| {
            XcertError::ParseError(format!("failed to encode algorithm OID: {}", e))
        })?;
    let params_der = match &spki.algorithm.parameters {
        Some(any) => any.to_der_vec().map_err(|e| {
            XcertError::ParseError(format!("failed to encode algorithm parameters: {}", e))
        })?,
        None => Vec::new(), // absent parameters (e.g. EdDSA per RFC 8410)
    };

    let key_data = &spki.subject_public_key.data;

    // Build AlgorithmIdentifier SEQUENCE content
    let mut algo_content = Vec::new();
    algo_content.extend_from_slice(&oid_der);
    algo_content.extend_from_slice(&params_der);

    // Build BIT STRING content (unused-bits byte + key data)
    let mut bitstring_content = Vec::with_capacity(1 + key_data.len());
    bitstring_content.push(0x00); // unused bits
    bitstring_content.extend_from_slice(key_data);

    // Wrap each in its TLV envelope, then wrap in outer SEQUENCE
    let algo_seq = der_wrap(0x30, &algo_content)?;
    let bitstring = der_wrap(0x03, &bitstring_content)?;

    let mut outer_content = Vec::new();
    outer_content.extend_from_slice(&algo_seq);
    outer_content.extend_from_slice(&bitstring);
    let spki_der = der_wrap(0x30, &outer_content)?;

    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        util::base64_wrap(&spki_der)
    ))
}

/// Maximum content length for DER TLV encoding with a 3-byte length field.
const MAX_DER_CONTENT_LEN: usize = 0xFF_FFFF; // 16 MiB

/// Wrap content bytes in a DER tag-length-value envelope.
///
/// Supports content lengths up to [`MAX_DER_CONTENT_LEN`] (16 MiB).
/// Returns an error if content exceeds this limit.
fn der_wrap(tag: u8, content: &[u8]) -> Result<Vec<u8>, XcertError> {
    let len = content.len();
    if len > MAX_DER_CONTENT_LEN {
        return Err(XcertError::ParseError(format!(
            "DER content length {} exceeds maximum supported ({})",
            len, MAX_DER_CONTENT_LEN
        )));
    }
    let mut buf = Vec::with_capacity(1 + 4 + len);
    buf.push(tag);
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 0x1_0000 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(content);
    Ok(buf)
}

fn build_extensions(extensions: &[X509Extension]) -> Result<Vec<Extension>, XcertError> {
    extensions.iter().map(build_extension).collect()
}

fn build_extension(ext: &X509Extension) -> Result<Extension, XcertError> {
    let oid = ext.oid.to_id_string();
    let name = extension_oid_to_name(&oid);
    let critical = ext.critical;

    let value = match ext.parsed_extension() {
        ParsedExtension::BasicConstraints(bc) => ExtensionValue::BasicConstraints {
            ca: bc.ca,
            path_len: bc.path_len_constraint,
        },
        ParsedExtension::KeyUsage(ku) => {
            let mut usages = Vec::new();
            if ku.digital_signature() {
                usages.push("Digital Signature".into());
            }
            if ku.non_repudiation() {
                usages.push("Non Repudiation".into());
            }
            if ku.key_encipherment() {
                usages.push("Key Encipherment".into());
            }
            if ku.data_encipherment() {
                usages.push("Data Encipherment".into());
            }
            if ku.key_agreement() {
                usages.push("Key Agreement".into());
            }
            if ku.key_cert_sign() {
                usages.push("Certificate Sign".into());
            }
            if ku.crl_sign() {
                usages.push("CRL Sign".into());
            }
            if ku.encipher_only() {
                usages.push("Encipher Only".into());
            }
            if ku.decipher_only() {
                usages.push("Decipher Only".into());
            }
            ExtensionValue::KeyUsage(usages)
        }
        ParsedExtension::ExtendedKeyUsage(eku) => {
            let mut usages = Vec::new();
            if eku.any {
                usages.push("Any Extended Key Usage".into());
            }
            if eku.server_auth {
                usages.push("TLS Web Server Authentication".into());
            }
            if eku.client_auth {
                usages.push("TLS Web Client Authentication".into());
            }
            if eku.code_signing {
                usages.push("Code Signing".into());
            }
            if eku.email_protection {
                usages.push("E-mail Protection".into());
            }
            if eku.time_stamping {
                usages.push("Time Stamping".into());
            }
            if eku.ocsp_signing {
                usages.push("OCSP Signing".into());
            }
            for oid in &eku.other {
                usages.push(eku_oid_to_name(&oid.to_id_string()));
            }
            ExtensionValue::ExtendedKeyUsage(usages)
        }
        ParsedExtension::SubjectAlternativeName(san) => {
            let entries = san
                .general_names
                .iter()
                .map(general_name_to_san_entry)
                .collect();
            ExtensionValue::SubjectAltName(entries)
        }
        ParsedExtension::SubjectKeyIdentifier(ski) => {
            ExtensionValue::SubjectKeyIdentifier(util::hex_colon_upper(ski.0))
        }
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            let key_id = aki
                .key_identifier
                .as_ref()
                .map(|ki| util::hex_colon_upper(ki.0));
            let issuer = aki.authority_cert_issuer.as_ref().map(|names| {
                names
                    .iter()
                    .map(|gn| format!("{:?}", gn))
                    .collect::<Vec<_>>()
                    .join(", ")
            });
            ExtensionValue::AuthorityKeyIdentifier { key_id, issuer }
        }
        ParsedExtension::AuthorityInfoAccess(aia) => {
            let entries = aia
                .accessdescs
                .iter()
                .map(|desc| {
                    let method = match desc.access_method.to_id_string().as_str() {
                        oid::ACCESS_OCSP => "OCSP".into(),
                        oid::ACCESS_CA_ISSUERS => "CA Issuers".into(),
                        other => other.to_string(),
                    };
                    let location = format_general_name(&desc.access_location);
                    AiaEntry { method, location }
                })
                .collect();
            ExtensionValue::AuthorityInfoAccess(entries)
        }
        ParsedExtension::CRLDistributionPoints(cdp) => {
            let mut uris = Vec::new();
            for point in &cdp.points {
                if let Some(x509_parser::extensions::DistributionPointName::FullName(names)) =
                    &point.distribution_point
                {
                    for gn in names {
                        if let GeneralName::URI(uri) = gn {
                            uris.push(uri.to_string());
                        }
                    }
                }
            }
            ExtensionValue::CrlDistributionPoints(uris)
        }
        ParsedExtension::CertificatePolicies(policies) => {
            let oids: Vec<String> = policies
                .iter()
                .map(|p| p.policy_id.to_id_string())
                .collect();
            ExtensionValue::CertificatePolicies(oids)
        }
        ParsedExtension::NsCertComment(comment) => ExtensionValue::NsComment(comment.to_string()),
        _ => {
            let hex = hex::encode(ext.value);
            ExtensionValue::Raw(hex)
        }
    };

    Ok(Extension {
        oid,
        name,
        critical,
        value,
    })
}

fn extension_oid_to_name(oid_str: &str) -> String {
    match oid_str {
        oid::EXT_SUBJECT_KEY_ID => "Subject Key Identifier".into(),
        oid::EXT_KEY_USAGE => "Key Usage".into(),
        oid::EXT_SUBJECT_ALT_NAME => "Subject Alternative Name".into(),
        oid::EXT_ISSUER_ALT_NAME => "Issuer Alternative Name".into(),
        oid::EXT_BASIC_CONSTRAINTS => "Basic Constraints".into(),
        oid::EXT_NAME_CONSTRAINTS => "Name Constraints".into(),
        oid::EXT_CRL_DISTRIBUTION_POINTS => "CRL Distribution Points".into(),
        oid::EXT_CERTIFICATE_POLICIES => "Certificate Policies".into(),
        oid::EXT_POLICY_MAPPINGS => "Policy Mappings".into(),
        oid::EXT_AUTHORITY_KEY_ID => "Authority Key Identifier".into(),
        oid::EXT_POLICY_CONSTRAINTS => "Policy Constraints".into(),
        oid::EXT_EXTENDED_KEY_USAGE => "Extended Key Usage".into(),
        oid::EXT_INHIBIT_ANY_POLICY => "Inhibit Any-Policy".into(),
        oid::EXT_AUTHORITY_INFO_ACCESS => "Authority Information Access".into(),
        oid::EXT_SUBJECT_INFO_ACCESS => "Subject Information Access".into(),
        oid::EXT_NETSCAPE_CERT_TYPE => "Netscape Cert Type".into(),
        oid::EXT_NETSCAPE_COMMENT => "Netscape Comment".into(),
        other => other.to_string(),
    }
}

/// Map uncommon EKU OIDs to human-readable names.
///
/// Only called for `eku.other` OIDs — the common OIDs (serverAuth, clientAuth,
/// codeSigning, emailProtection, timeStamping, ocspSigning, anyEKU) are already
/// handled by the boolean fields on `ExtendedKeyUsage`.
fn eku_oid_to_name(oid_str: &str) -> String {
    match oid_str {
        oid::EKU_IPSEC_END_SYSTEM => "IPSec End System".into(),
        oid::EKU_IPSEC_TUNNEL => "IPSec Tunnel".into(),
        oid::EKU_IPSEC_USER => "IPSec User".into(),
        oid::EKU_MS_SERVER_GATED_CRYPTO => "Microsoft Server Gated Crypto".into(),
        oid::EKU_NS_SERVER_GATED_CRYPTO => "Netscape Server Gated Crypto".into(),
        other => other.to_string(),
    }
}

fn general_name_to_san_entry(gn: &GeneralName) -> SanEntry {
    match gn {
        GeneralName::DNSName(name) => SanEntry::Dns(name.to_string()),
        GeneralName::RFC822Name(email) => SanEntry::Email(email.to_string()),
        GeneralName::IPAddress(ip_bytes) => SanEntry::Ip(format_ip_bytes(ip_bytes)),
        GeneralName::URI(uri) => SanEntry::Uri(uri.to_string()),
        GeneralName::DirectoryName(dn) => SanEntry::DirName(build_dn(dn).to_oneline()),
        other => SanEntry::Other(format!("{:?}", other)),
    }
}

fn format_general_name(gn: &GeneralName) -> String {
    match general_name_to_san_entry(gn) {
        SanEntry::Dns(v)
        | SanEntry::Email(v)
        | SanEntry::Ip(v)
        | SanEntry::Uri(v)
        | SanEntry::DirName(v)
        | SanEntry::Other(v) => v,
    }
}

pub(crate) fn format_ip_bytes(bytes: &[u8]) -> String {
    if let Ok(octets) = <[u8; 4]>::try_from(bytes) {
        std::net::Ipv4Addr::from(octets).to_string()
    } else if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
        util::format_ipv6_expanded(&std::net::Ipv6Addr::from(octets))
    } else {
        hex::encode(bytes)
    }
}
