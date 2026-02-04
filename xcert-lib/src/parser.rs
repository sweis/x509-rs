//! Certificate parsing from PEM and DER formats.

use crate::fields::{
    AiaEntry, CertificateInfo, DateTime, DistinguishedName, Extension, ExtensionValue,
    PublicKeyInfo, SanEntry,
};
use crate::XcertError;
use x509_parser::der_parser::asn1_rs;
use x509_parser::prelude::*;

/// Parse a certificate from PEM or DER (auto-detected).
///
/// If the input begins with `-----BEGIN` (after stripping whitespace), it is
/// treated as PEM. Otherwise it is treated as DER.
pub fn parse_cert(input: &[u8]) -> Result<CertificateInfo, XcertError> {
    if input.is_empty() {
        return Err(XcertError::ParseError("empty input".into()));
    }

    let trimmed = input
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take(11)
        .copied()
        .collect::<Vec<_>>();

    if trimmed.starts_with(b"-----BEGIN") {
        parse_pem(input)
    } else {
        parse_der(input)
    }
}

/// Parse a certificate from PEM format.
pub fn parse_pem(input: &[u8]) -> Result<CertificateInfo, XcertError> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(input)
        .map_err(|e| XcertError::PemError(format!("{}", e)))?;

    if pem.label != "CERTIFICATE" && pem.label != "TRUSTED CERTIFICATE" {
        return Err(XcertError::PemError(format!(
            "expected CERTIFICATE, got {}",
            pem.label
        )));
    }

    parse_der(&pem.contents)
}

/// Parse a certificate from DER format.
pub fn parse_der(input: &[u8]) -> Result<CertificateInfo, XcertError> {
    let (_, x509) = X509Certificate::from_der(input)
        .map_err(|e| XcertError::DerError(format!("{}", e)))?;

    build_certificate_info(&x509, input)
}

/// Build a CertificateInfo from a parsed X509Certificate.
fn build_certificate_info(
    x509: &X509Certificate,
    raw_der: &[u8],
) -> Result<CertificateInfo, XcertError> {
    let tbs = &x509.tbs_certificate;

    let version = tbs.version.0 + 1;

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
        Some(pos) => &raw[pos..],
        None => &raw[raw.len().saturating_sub(1)..],
    };
    stripped
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_sig_algorithm(algo: &AlgorithmIdentifier) -> String {
    match algo.algorithm.to_id_string().as_str() {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".into(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".into(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".into(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".into(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".into(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".into(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".into(),
        "1.3.101.112" => "Ed25519".into(),
        other => other.to_string(),
    }
}

fn build_dn(name: &X509Name) -> DistinguishedName {
    let mut components = Vec::new();
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let key = oid_to_short_name(&attr.attr_type());
            let value = attr.as_str().unwrap_or("<binary>").to_string();
            components.push((key, value));
        }
    }
    DistinguishedName { components }
}

fn oid_to_short_name(oid: &asn1_rs::Oid) -> String {
    let oid_str = format!("{}", oid);
    match oid_str.as_str() {
        "2.5.4.3" => "CN".into(),
        "2.5.4.4" => "SN".into(),
        "2.5.4.5" => "serialNumber".into(),
        "2.5.4.6" => "C".into(),
        "2.5.4.7" => "L".into(),
        "2.5.4.8" => "ST".into(),
        "2.5.4.9" => "street".into(),
        "2.5.4.10" => "O".into(),
        "2.5.4.11" => "OU".into(),
        "2.5.4.12" => "title".into(),
        "2.5.4.17" => "postalCode".into(),
        "2.5.4.42" => "GN".into(),
        "1.2.840.113549.1.9.1" => "emailAddress".into(),
        "0.9.2342.19200300.100.1.25" => "DC".into(),
        other => other.to_string(),
    }
}

fn build_datetime(time: &ASN1Time) -> DateTime {
    let ts = time.timestamp();
    let iso = format_timestamp_iso8601(ts);
    DateTime {
        iso8601: iso,
        timestamp: ts,
    }
}

fn format_timestamp_iso8601(ts: i64) -> String {
    const SECONDS_PER_DAY: i64 = 86400;
    const DAYS_PER_400Y: i64 = 146097;

    let days = ts.div_euclid(SECONDS_PER_DAY);
    let rem = ts.rem_euclid(SECONDS_PER_DAY);

    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // Civil date from day count (algorithm from Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(DAYS_PER_400Y);
    let doe = z.rem_euclid(DAYS_PER_400Y);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, min, sec
    )
}

fn build_public_key_info(
    spki: &SubjectPublicKeyInfo,
) -> Result<PublicKeyInfo, XcertError> {
    let oid_str = spki.algorithm.algorithm.to_id_string();

    let (algorithm, key_size, curve, modulus) = match oid_str.as_str() {
        "1.2.840.113549.1.1.1" => {
            let (mod_hex, bits) = extract_rsa_modulus(&spki.subject_public_key.data);
            ("RSA".into(), Some(bits), None, Some(mod_hex))
        }
        "1.2.840.10045.2.1" => {
            let curve_name = extract_ec_curve(&spki.algorithm);
            let key_size = match curve_name.as_str() {
                "P-256" => Some(256),
                "P-384" => Some(384),
                "P-521" => Some(521),
                _ => None,
            };
            ("EC".into(), key_size, Some(curve_name), None)
        }
        "1.3.101.112" => ("Ed25519".into(), Some(256), None, None),
        "1.3.101.113" => ("Ed448".into(), Some(448), None, None),
        _ => (oid_str, None, None, None),
    };

    let pem = build_spki_pem(spki);

    Ok(PublicKeyInfo {
        algorithm,
        key_size,
        curve,
        modulus,
        pem,
    })
}

/// Extract RSA modulus from raw public key DER.
fn extract_rsa_modulus(data: &[u8]) -> (String, u32) {
    if let Ok((_, parsed)) = x509_parser::der_parser::parse_der(data) {
        if let Ok(seq) = parsed.as_sequence() {
            if let Some(modulus_obj) = seq.first() {
                if let Ok(bigint) = modulus_obj.as_bigint() {
                    let bytes = bigint.to_bytes_be().1;
                    // Skip leading zero byte used for DER positive integer encoding
                    let significant = if !bytes.is_empty() && bytes[0] == 0 {
                        &bytes[1..]
                    } else {
                        &bytes[..]
                    };
                    let hex = significant
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<String>();
                    let bits = (significant.len() as u32) * 8;
                    return (hex, bits);
                }
            }
        }
    }
    let hex = data
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();
    let bits = (data.len() as u32) * 8;
    (hex, bits)
}

fn extract_ec_curve(algo: &AlgorithmIdentifier) -> String {
    if let Some(params) = &algo.parameters {
        if let Ok(oid) = params.as_oid() {
            return match oid.to_id_string().as_str() {
                "1.2.840.10045.3.1.7" => "P-256".into(),
                "1.3.132.0.34" => "P-384".into(),
                "1.3.132.0.35" => "P-521".into(),
                other => other.to_string(),
            };
        }
    }
    "unknown".into()
}

fn build_spki_pem(spki: &SubjectPublicKeyInfo) -> String {
    let algo_der = serialize_algorithm(&spki.algorithm);
    let key_data = &spki.subject_public_key.data;

    let mut bitstring_inner = Vec::new();
    bitstring_inner.push(0x00); // unused bits
    bitstring_inner.extend_from_slice(&key_data);

    let mut spki_body = Vec::new();
    spki_body.extend_from_slice(&algo_der);
    spki_body.push(0x03); // BIT STRING tag
    write_der_length(&mut spki_body, bitstring_inner.len());
    spki_body.extend_from_slice(&bitstring_inner);

    let mut spki_der = Vec::new();
    spki_der.push(0x30); // SEQUENCE tag
    write_der_length(&mut spki_der, spki_body.len());
    spki_der.extend_from_slice(&spki_body);

    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64_encode_wrapped(&spki_der)
    )
}

fn serialize_algorithm(algo: &AlgorithmIdentifier) -> Vec<u8> {
    let oid_der = encode_oid(&algo.algorithm);
    let params_der = match &algo.parameters {
        Some(any) => any.data.to_vec(),
        None => vec![0x05, 0x00],
    };

    let mut body = Vec::new();
    body.extend_from_slice(&oid_der);
    body.extend_from_slice(&params_der);

    let mut result = Vec::new();
    result.push(0x30);
    write_der_length(&mut result, body.len());
    result.extend_from_slice(&body);
    result
}

fn encode_oid(oid: &asn1_rs::Oid) -> Vec<u8> {
    let raw = oid.as_bytes();
    let mut result = Vec::new();
    result.push(0x06);
    write_der_length(&mut result, raw.len());
    result.extend_from_slice(raw);
    result
}

fn write_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 0x10000 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn base64_encode_wrapped(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut line_len = 0;
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        line_len += 4;
        if line_len >= 64 {
            result.push('\n');
            line_len = 0;
        }
    }
    result
}

fn build_extensions(
    extensions: &[X509Extension],
) -> Result<Vec<Extension>, XcertError> {
    let mut result = Vec::new();
    for ext in extensions {
        result.push(build_extension(ext)?);
    }
    Ok(result)
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
            let hex = ski
                .0
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":");
            ExtensionValue::SubjectKeyIdentifier(hex)
        }
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            let key_id = aki.key_identifier.as_ref().map(|ki| {
                ki.0.iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(":")
            });
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
                        "1.3.6.1.5.5.7.48.1" => "OCSP".into(),
                        "1.3.6.1.5.5.7.48.2" => "CA Issuers".into(),
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
                if let Some(dn) = &point.distribution_point {
                    if let x509_parser::extensions::DistributionPointName::FullName(names) = dn {
                        for gn in names {
                            if let GeneralName::URI(uri) = gn {
                                uris.push(uri.to_string());
                            }
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
        ParsedExtension::NsCertComment(comment) => {
            ExtensionValue::NsComment(comment.to_string())
        }
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

fn extension_oid_to_name(oid: &str) -> String {
    match oid {
        "2.5.29.14" => "Subject Key Identifier".into(),
        "2.5.29.15" => "Key Usage".into(),
        "2.5.29.17" => "Subject Alternative Name".into(),
        "2.5.29.18" => "Issuer Alternative Name".into(),
        "2.5.29.19" => "Basic Constraints".into(),
        "2.5.29.30" => "Name Constraints".into(),
        "2.5.29.31" => "CRL Distribution Points".into(),
        "2.5.29.32" => "Certificate Policies".into(),
        "2.5.29.33" => "Policy Mappings".into(),
        "2.5.29.35" => "Authority Key Identifier".into(),
        "2.5.29.36" => "Policy Constraints".into(),
        "2.5.29.37" => "Extended Key Usage".into(),
        "2.5.29.54" => "Inhibit Any-Policy".into(),
        "1.3.6.1.5.5.7.1.1" => "Authority Information Access".into(),
        "1.3.6.1.5.5.7.1.11" => "Subject Information Access".into(),
        "2.16.840.1.113730.1.1" => "Netscape Cert Type".into(),
        "2.16.840.1.113730.1.13" => "Netscape Comment".into(),
        other => other.to_string(),
    }
}

fn eku_oid_to_name(oid: &str) -> String {
    match oid {
        "1.3.6.1.5.5.7.3.1" => "TLS Web Server Authentication".into(),
        "1.3.6.1.5.5.7.3.2" => "TLS Web Client Authentication".into(),
        "1.3.6.1.5.5.7.3.3" => "Code Signing".into(),
        "1.3.6.1.5.5.7.3.4" => "E-mail Protection".into(),
        "1.3.6.1.5.5.7.3.8" => "Time Stamping".into(),
        "1.3.6.1.5.5.7.3.9" => "OCSP Signing".into(),
        "2.5.29.37.0" => "Any Extended Key Usage".into(),
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
    match gn {
        GeneralName::URI(uri) => uri.to_string(),
        GeneralName::DNSName(name) => name.to_string(),
        GeneralName::RFC822Name(email) => email.to_string(),
        GeneralName::IPAddress(ip) => format_ip_bytes(ip),
        other => format!("{:?}", other),
    }
}

fn format_ip_bytes(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => {
            let mut parts = Vec::new();
            for chunk in bytes.chunks(2) {
                parts.push(format!("{:x}", (chunk[0] as u16) << 8 | chunk[1] as u16));
            }
            parts.join(":")
        }
        _ => hex::encode(bytes),
    }
}
