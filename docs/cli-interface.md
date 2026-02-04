# Proposed CLI Interface: `xcert`

A simplified, intuitive command-line tool for inspecting X.509 certificates.

## Design Principles

1. **Subcommand-based** -- uses `xcert <command>` instead of a flat list of flags.
   This is more discoverable and consistent with modern CLI conventions.
2. **Sensible defaults** -- `xcert show cert.pem` does the right thing without flags.
3. **Input auto-detection** -- PEM vs DER is detected automatically from content;
   no `-inform` flag needed. Reads from stdin if no file is given.
4. **Consistent output** -- human-readable by default, with `--json` for machine
   consumption. No separate flags to control dozens of output formatting sub-options.
5. **No signing** -- this tool is read-only. Certificate creation and signing are
   separate concerns handled by other tools.

## Commands

### `xcert show` -- Display certificate information

The primary command. Displays a human-readable summary of the certificate.

```
xcert show [OPTIONS] [FILE]

Arguments:
  [FILE]  Certificate file (PEM or DER). Reads from stdin if omitted.

Options:
  --der          Force DER input parsing (default: auto-detect)
  --pem          Force PEM input parsing (default: auto-detect)
  --json         Output in JSON format
  --all          Show all fields including signature bytes
```

Default output includes: version, serial, algorithm, issuer, validity, subject,
public key summary, and all extensions. This is analogous to `openssl x509 -text -noout`.

### `xcert field` -- Extract a single field

Print one specific field from the certificate. Useful for scripting.

```
xcert field <FIELD> [OPTIONS] [FILE]

Fields:
  subject        Subject distinguished name
  issuer         Issuer distinguished name
  serial         Serial number (hex)
  not-before     Validity start date
  not-after      Validity end date
  fingerprint    Certificate fingerprint
  public-key     Public key in PEM format
  modulus        RSA public key modulus (hex)
  emails         Email addresses from subject and SAN
  san            Subject Alternative Names
  ocsp-url       OCSP responder URL(s) from AIA
  key-usage      Key Usage extension value
  ext-key-usage  Extended Key Usage extension value
  extensions     All extensions (names and values)

Options:
  [FILE]         Certificate file. Reads from stdin if omitted.
  --der          Force DER input parsing
  --pem          Force PEM input parsing
  --digest <ALG> Hash algorithm for fingerprint (sha256, sha384, sha512, sha1).
                 Default: sha256.
  --json         Output in JSON format
```

Examples:
```bash
# Get SHA-256 fingerprint
xcert field fingerprint cert.pem

# Get serial number
xcert field serial cert.pem

# Get SAN entries as JSON
xcert field san --json cert.pem

# Get SHA-384 fingerprint
xcert field fingerprint --digest sha384 cert.pem
```

### `xcert check` -- Validate certificate properties

Check whether the certificate satisfies certain conditions. Returns exit code 0
for pass, 1 for fail. Designed for use in scripts and CI pipelines.

```
xcert check <CHECK> <VALUE> [OPTIONS] [FILE]

Checks:
  expiry <SECONDS>    Check if cert expires within N seconds (0 = already expired)
  host <HOSTNAME>     Check if cert matches hostname
  email <EMAIL>       Check if cert matches email address
  ip <ADDRESS>        Check if cert matches IP address (v4 or v6)

Options:
  [FILE]              Certificate file. Reads from stdin if omitted.
  --der               Force DER input parsing
  --pem               Force PEM input parsing
```

Examples:
```bash
# Check if cert expires within 30 days
xcert check expiry 2592000 cert.pem

# Check hostname match
xcert check host www.example.com cert.pem

# Check IP match
xcert check ip 93.184.216.34 cert.pem

# Use in scripts
if xcert check expiry 604800 cert.pem; then
  echo "Certificate is valid for at least 7 more days"
fi
```

### `xcert convert` -- Convert between formats

Convert certificates between PEM and DER encodings.

```
xcert convert [OPTIONS] [FILE]

Options:
  [FILE]         Input certificate file. Reads from stdin if omitted.
  --to <FORMAT>  Output format: pem, der (required)
  --out <FILE>   Output file (default: stdout)
  --der          Force DER input parsing
  --pem          Force PEM input parsing
```

Examples:
```bash
# PEM to DER
xcert convert --to der cert.pem --out cert.der

# DER to PEM
xcert convert --to pem cert.der

# Pipe through stdin
cat cert.pem | xcert convert --to der > cert.der
```

## Comparison with `openssl x509`

| openssl x509 | xcert | Notes |
|---|---|---|
| `openssl x509 -text -noout -in cert.pem` | `xcert show cert.pem` | |
| `openssl x509 -subject -noout -in cert.pem` | `xcert field subject cert.pem` | |
| `openssl x509 -issuer -noout -in cert.pem` | `xcert field issuer cert.pem` | |
| `openssl x509 -serial -noout -in cert.pem` | `xcert field serial cert.pem` | |
| `openssl x509 -dates -noout -in cert.pem` | `xcert field not-before cert.pem` / `xcert field not-after cert.pem` | Separate fields instead of combined |
| `openssl x509 -fingerprint -sha256 -noout -in cert.pem` | `xcert field fingerprint cert.pem` | SHA-256 is the default |
| `openssl x509 -pubkey -noout -in cert.pem` | `xcert field public-key cert.pem` | |
| `openssl x509 -modulus -noout -in cert.pem` | `xcert field modulus cert.pem` | |
| `openssl x509 -email -noout -in cert.pem` | `xcert field emails cert.pem` | |
| `openssl x509 -ext subjectAltName -noout -in cert.pem` | `xcert field san cert.pem` | |
| `openssl x509 -ocsp_uri -noout -in cert.pem` | `xcert field ocsp-url cert.pem` | |
| `openssl x509 -checkend 3600 -noout -in cert.pem` | `xcert check expiry 3600 cert.pem` | |
| `openssl x509 -checkhost foo.com -noout -in cert.pem` | `xcert check host foo.com cert.pem` | |
| `openssl x509 -checkip 1.2.3.4 -noout -in cert.pem` | `xcert check ip 1.2.3.4 cert.pem` | |
| `openssl x509 -checkemail a@b.com -noout -in cert.pem` | `xcert check email a@b.com cert.pem` | |
| `openssl x509 -outform DER -in cert.pem -out cert.der` | `xcert convert --to der cert.pem --out cert.der` | |
| `openssl x509 -inform DER -in cert.der -outform PEM` | `xcert convert --to pem cert.der` | Auto-detects DER |

## What is NOT included (by design)

The following `openssl x509` features are intentionally excluded:

- **Signing** (`-key`, `-CA`, `-signkey`, `-req`, `-new`, `-x509toreq`) -- use a
  dedicated signing tool
- **Trust settings** (`-trustout`, `-addtrust`, `-addreject`, `-setalias`) -- an
  OpenSSL-specific concept
- **Name formatting options** (`-nameopt`) -- the tool uses a single consistent
  format. Use `--json` for machine parsing.
- **certopt** (`-certopt`) -- replaced by `--all` or `--json`
- **Subject/issuer hashes** (`-subject_hash`, `-issuer_hash`) -- OpenSSL-specific
  directory indexing
- **OCSP ID** (`-ocspid`) -- rarely needed
- **Purpose analysis** (`-purpose`) -- complex, can be added later
- **Extension injection** (`-extfile`, `-extensions`) -- part of signing
- **Bad signature** (`-badsig`) -- testing-only feature
- **C source output** (`-C`) -- removed even from OpenSSL 3.0

These can be added as future extensions if needed.
