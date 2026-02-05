//! Centralized OID string constants used throughout xcert-lib.
//!
//! Object Identifiers (OIDs) are defined by ITU-T X.660 and referenced
//! extensively in RFC 5280 (X.509), RFC 3279 (algorithms), RFC 5480 (ECC),
//! and RFC 8410 (EdDSA).  Grouping them here avoids magic strings scattered
//! across modules and gives each OID a readable name.

// ── X.509 Distinguished Name attributes (RFC 4519 / X.520) ──────────────

pub const COMMON_NAME: &str = "2.5.4.3";
pub const SURNAME: &str = "2.5.4.4";
pub const SERIAL_NUMBER: &str = "2.5.4.5";
pub const COUNTRY: &str = "2.5.4.6";
pub const LOCALITY: &str = "2.5.4.7";
pub const STATE_OR_PROVINCE: &str = "2.5.4.8";
pub const STREET_ADDRESS: &str = "2.5.4.9";
pub const ORGANIZATION: &str = "2.5.4.10";
pub const ORGANIZATIONAL_UNIT: &str = "2.5.4.11";
pub const TITLE: &str = "2.5.4.12";
pub const POSTAL_CODE: &str = "2.5.4.17";
pub const GIVEN_NAME: &str = "2.5.4.42";
pub const EMAIL_ADDRESS: &str = "1.2.840.113549.1.9.1"; // PKCS#9
pub const DOMAIN_COMPONENT: &str = "0.9.2342.19200300.100.1.25";

// ── Signature algorithms ─────────────────────────────────────────────────

pub const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
pub const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";
pub const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
pub const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
pub const ECDSA_WITH_SHA512: &str = "1.2.840.10045.4.3.4";
pub const ED25519: &str = "1.3.101.112";
pub const ED448: &str = "1.3.101.113";

// ── Public key types ─────────────────────────────────────────────────────

pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

// ── Named elliptic curves ────────────────────────────────────────────────

pub const CURVE_P256: &str = "1.2.840.10045.3.1.7";
pub const CURVE_P384: &str = "1.3.132.0.34";
pub const CURVE_P521: &str = "1.3.132.0.35";

// ── X.509v3 extensions (RFC 5280 Section 4.2) ───────────────────────────

pub const EXT_SUBJECT_KEY_ID: &str = "2.5.29.14";
pub const EXT_KEY_USAGE: &str = "2.5.29.15";
pub const EXT_SUBJECT_ALT_NAME: &str = "2.5.29.17";
pub const EXT_ISSUER_ALT_NAME: &str = "2.5.29.18";
pub const EXT_BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub const EXT_NAME_CONSTRAINTS: &str = "2.5.29.30";
pub const EXT_CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
pub const EXT_CERTIFICATE_POLICIES: &str = "2.5.29.32";
pub const EXT_POLICY_MAPPINGS: &str = "2.5.29.33";
pub const EXT_AUTHORITY_KEY_ID: &str = "2.5.29.35";
pub const EXT_POLICY_CONSTRAINTS: &str = "2.5.29.36";
pub const EXT_EXTENDED_KEY_USAGE: &str = "2.5.29.37";
pub const EXT_FRESHEST_CRL: &str = "2.5.29.46";
pub const EXT_INHIBIT_ANY_POLICY: &str = "2.5.29.54";

// ── PKIX Authority/Subject Information Access (RFC 5280 Section 4.2.2) ──

pub const EXT_AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";
pub const EXT_SUBJECT_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.11";
pub const EXT_TLS_FEATURE: &str = "1.3.6.1.5.5.7.1.12";
pub const ACCESS_OCSP: &str = "1.3.6.1.5.5.7.48.1";
pub const ACCESS_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";

// ── Extended Key Usage values (RFC 5280 Section 4.2.1.12) ────────────────

pub const EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
pub const EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
pub const EKU_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
pub const EKU_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
pub const EKU_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
pub const EKU_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
pub const EKU_ANY: &str = "2.5.29.37.0";

// ── Certificate Transparency (RFC 6962) ──────────────────────────────────

pub const EXT_SCT_LIST: &str = "1.3.6.1.4.1.11129.2.4.2";
pub const EXT_CT_POISON: &str = "1.3.6.1.4.1.11129.2.4.3";

// ── Netscape extensions (legacy) ─────────────────────────────────────────

pub const EXT_NETSCAPE_CERT_TYPE: &str = "2.16.840.1.113730.1.1";
pub const EXT_NETSCAPE_COMMENT: &str = "2.16.840.1.113730.1.13";
