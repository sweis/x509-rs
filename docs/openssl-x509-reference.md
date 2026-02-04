# OpenSSL x509 Command Reference

This document captures the full functionality of `openssl x509` (OpenSSL 3.x) to
inform the design of a Rust replacement tool.

## Overview

`openssl x509` is described as a "Certificate display and signing command." It is
a multi-purpose utility that can:

- **Display** certificate information in various formats
- **Convert** certificates between PEM and DER encodings
- **Extract** individual fields (subject, issuer, serial, dates, extensions, etc.)
- **Compute** fingerprints using various digest algorithms
- **Check** certificate validity (expiry, hostname, email, IP matching)
- **Sign** certificates (self-signed or CA-signed, acting as a "micro CA")
- **Convert** between certificates and CSRs
- **Manage** trust settings on certificates

---

## Input/Output

### Input Formats
| Format | Description |
|--------|-------------|
| PEM    | Base64-encoded DER wrapped in `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` headers. Default. |
| DER    | Raw binary ASN.1 encoding. |

### Input Sources
- `-in <file>` reads from a file (default: stdin)
- `-req` changes input expectation from certificate to PKCS#10 CSR
- `-new` generates a certificate from scratch (no input file; requires `-subj`)

### Output Formats
- `-outform PEM|DER` controls output encoding (default: PEM)
- `-out <file>` writes to file (default: stdout)
- `-noout` suppresses encoded certificate output (only prints requested fields)
- `-nocert` suppresses certificate output but allows requested printing

---

## Display Options

These options print specific fields from the certificate. Multiple can be combined.

### Full Text Display
| Option | Description |
|--------|-------------|
| `-text` | Print the full certificate in human-readable form: version, serial, signature algorithm, issuer, validity, subject, public key, extensions, signature. |
| `-certopt <val>` | Customize `-text` output. Values: `no_header`, `no_version`, `no_serial`, `no_signame`, `no_validity`, `no_subject`, `no_issuer`, `no_pubkey`, `no_sigdump`, `no_aux`, `no_extensions`, `ext_default`, `ext_error`, `ext_parse`, `ext_dump`, `ca_default`, `compatible`. |
| `-dateopt <val>` | Date format: `rfc_822` (default) or `iso_8601`. |

### Individual Field Extraction
| Option | Description |
|--------|-------------|
| `-subject` | Print subject distinguished name. |
| `-issuer` | Print issuer distinguished name. |
| `-serial` | Print serial number (hex). |
| `-startdate` | Print notBefore date. |
| `-enddate` | Print notAfter date. |
| `-dates` | Print both notBefore and notAfter. |
| `-email` | Print email addresses from subject and SAN. |
| `-alias` | Print certificate alias (if set). |
| `-modulus` | Print RSA public key modulus. |
| `-pubkey` | Print SubjectPublicKeyInfo in PEM format. |
| `-ocspid` | Print OCSP hash values for subject and public key. |
| `-ocsp_uri` | Print OCSP responder URL(s) from AIA extension. |
| `-purpose` | Analyze extensions and print what purposes the cert is valid for. |

### Name Formatting
| Option | Description |
|--------|-------------|
| `-nameopt <val>` | Control subject/issuer name display format. |

Preset name formats: `compat` (`/C=US/CN=Foo`), `RFC2253`, `oneline` (default, comma-separated), `multiline` (indented).

Individual sub-options: `esc_2253`, `esc_ctrl`, `esc_msb`, `utf8`, `dump_nostr`, `dump_der`, `dump_all`, `dump_unknown`, `use_quote`, `sep_comma_plus`, `sep_comma_plus_space`, `sep_semi_plus_space`, `sep_multiline`, `dn_rev`, `nofname`, `sname`, `lname`, `oid`, `align`, `space_eq`, `show_type`, `ignore_type`.

### Extension Display
| Option | Description |
|--------|-------------|
| `-ext <names>` | Print only the listed extensions (comma-separated). Example: `-ext subjectAltName,basicConstraints` |

Common extension names: `basicConstraints`, `keyUsage`, `extendedKeyUsage`, `subjectKeyIdentifier`, `authorityKeyIdentifier`, `subjectAltName`, `issuerAltName`, `authorityInfoAccess`, `crlDistributionPoints`, `certificatePolicies`, `nameConstraints`, `nsComment`.

### Hash/Fingerprint Options
| Option | Description |
|--------|-------------|
| `-fingerprint` | Compute and print digest of DER-encoded certificate. Default: SHA1. |
| `-sha256`, `-sha384`, `-sha512`, `-sha1`, `-md5` | Select digest algorithm for fingerprint and signing. |
| `-subject_hash` | Print SHA1-based subject name hash (for directory indexing). |
| `-subject_hash_old` | Print MD5-based subject name hash (pre-1.0.0 compat). |
| `-issuer_hash` | Print SHA1-based issuer name hash. |
| `-issuer_hash_old` | Print MD5-based issuer name hash. |
| `-hash` | Synonym for `-subject_hash`. |

---

## Checking/Verification Options

These check properties of the certificate and set the exit code accordingly.

| Option | Description | Exit 0 | Exit 1 |
|--------|-------------|--------|--------|
| `-checkend <seconds>` | Check if cert expires within N seconds. | Not expiring | Will expire |
| `-checkhost <host>` | Check if cert matches hostname. | Match | No match |
| `-checkemail <email>` | Check if cert matches email. | Match | No match |
| `-checkip <ip>` | Check if cert matches IP address. | Match | No match |

Note: These perform single-certificate checks only, not chain validation.

---

## Signing Options

### Self-Signing
| Option | Description |
|--------|-------------|
| `-key <file>` | Private key for signing. Produces self-signed cert. Also used as cert public key unless `-force_pubkey` given. |
| `-signkey <file>` | Alias for `-key`. |
| `-days <n>` | Validity period in days (default: 30). |
| `-set_serial <n>` | Set serial number (decimal or `0x` hex). |
| `-subj <dn>` | Set/override subject DN. Format: `/type=value/type=value/...` |
| `-force_pubkey <file>` | Override public key in output certificate. |
| `-preserve_dates` | Keep existing validity dates when re-signing. |
| `-badsig` | Corrupt the signature (for testing). |

### CA Signing (Micro-CA)
| Option | Description |
|--------|-------------|
| `-CA <file>` | CA certificate for signing. Sets issuer from CA subject. |
| `-CAkey <file>` | CA private key (defaults to key in `-CA` file). |
| `-CAform <fmt>` | CA cert format (PEM/DER/P12). |
| `-CAserial <file>` | File tracking serial numbers. |
| `-CAcreateserial` | Create serial file if missing (random initial value). |

### CSR Handling
| Option | Description |
|--------|-------------|
| `-req` | Input is a CSR instead of a certificate. |
| `-x509toreq` | Convert certificate to CSR (requires `-key`). |
| `-copy_extensions <val>` | Extension handling for CSR conversion: `none` (default), `copy`/`copyall`. |

### Extension Management
| Option | Description |
|--------|-------------|
| `-extfile <file>` | Config file with X509v3 extensions to add. |
| `-extensions <section>` | Section name in extfile. |
| `-clrext` | Clear all extensions from output. |

---

## Trust Settings

Trusted certificates use `-----BEGIN TRUSTED CERTIFICATE-----` PEM headers and carry additional metadata about permitted/prohibited uses.

| Option | Description |
|--------|-------------|
| `-trustout` | Output as trusted certificate PEM. |
| `-setalias <name>` | Set certificate alias/nickname. |
| `-addtrust <use>` | Add permitted use. |
| `-addreject <use>` | Add prohibited use. |
| `-clrtrust` | Clear all permitted uses. |
| `-clrreject` | Clear all prohibited uses. |

Trust values: `clientAuth`, `serverAuth`, `emailProtection`, `codeSigning`, `OCSPSigning`, `timeStamping`, `anyExtendedKeyUsage`.

---

## Format Conversion Summary

| From | To | Command Pattern |
|------|----|-----------------|
| PEM | DER | `openssl x509 -in cert.pem -outform DER -out cert.der` |
| DER | PEM | `openssl x509 -in cert.der -inform DER -out cert.pem` |
| Cert | CSR | `openssl x509 -x509toreq -in cert.pem -key key.pem -out req.pem` |
| CSR | Cert (self) | `openssl x509 -req -in req.pem -key key.pem -out cert.pem` |
| CSR | Cert (CA) | `openssl x509 -req -in req.pem -CA ca.pem -CAkey ca.key -out cert.pem` |

---

## Scope for Replacement Tool

### In Scope (Display/Parse/Check)
The replacement tool focuses on the **read-only** operations:
- Parsing PEM and DER certificates
- Displaying full text, individual fields, and extensions
- Computing fingerprints
- Checking expiry, hostname, email, IP matching
- Format conversion (PEM <-> DER)
- Extracting public keys

### Out of Scope (Signing/CA)
The following signing/CA features are **not** targeted for the initial replacement:
- Self-signing and CA signing
- CSR generation/processing
- Trust setting management
- Certificate generation from scratch
- Extension injection from config files

These require private key handling and cryptographic signing, which is a separate concern.
