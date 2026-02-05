# xcert-rs: Rust x509 Certificate Inspection Utility

[![CI](https://github.com/sweis/xcert-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/sweis/xcert-rs/actions/workflows/ci.yml)

A fast, memory-safe command-line tool for inspecting X.509 certificates. Read-only alternative to `openssl x509` with JSON output and colored terminal display.

## Installation

```bash
cargo install --path xcert
```

Or build from source:

```bash
cargo build --release
# Binary at target/release/xcert
```

## Usage

### Show certificate details

```bash
xcert show cert.pem
xcert show --json cert.pem          # JSON output
xcert show --all cert.pem           # Include signature bytes

# Bulk: show all certs in a directory
xcert show /etc/ssl/certs/ --json
xcert show /etc/ssl/certs/ --recurse
```

### Extract a single field

```bash
xcert field subject cert.pem
xcert field serial cert.pem
xcert field not-after cert.pem
xcert field fingerprint cert.pem
xcert field fingerprint --digest sha384 cert.pem
xcert field san --json cert.pem
xcert field public-key cert.pem

# Bulk: extract field from all certs in a directory
xcert field serial /etc/ssl/certs/ --json
xcert field not-after /etc/ssl/certs/ --recurse
```

Available fields: `subject`, `issuer`, `serial`, `not-before`, `not-after`, `fingerprint`, `public-key`, `modulus`, `exponent`, `emails`, `san`, `ocsp-url`, `key-usage`, `ext-key-usage`, `extensions`

### Check certificate properties

Returns exit code 0 for pass, 1 for fail.

```bash
xcert check expiry 30d cert.pem     # Valid for 30+ days?
xcert check expiry 1w cert.pem      # Valid for 1+ week?
xcert check host example.com cert.pem
xcert check email user@example.com cert.pem
xcert check ip 93.184.216.34 cert.pem

# Bulk: check all certs in a directory
xcert check expiry 30d /etc/ssl/certs/
xcert check expiry 30d /etc/ssl/certs/ --json
xcert check expiry 7d --failures-only /etc/ssl/certs/
```

Duration formats: `30d`, `1w`, `2h30m`, `1w3d`, or seconds (e.g., `2592000`).

### Verify certificate chains

```bash
xcert verify chain.pem
xcert verify --hostname example.com chain.pem
xcert verify --CAfile ca.pem chain.pem
xcert verify --untrusted intermediates.pem leaf.pem
xcert verify --json chain.pem

# Options
--purpose sslserver|sslclient|smimesign|codesign
--partial-chain          # Trust any cert in chain
--no-check-time          # Skip date validation
--attime <EPOCH>         # Verify at specific time
--verify-depth <N>       # Max chain depth
--verify-email <EMAIL>   # Check email in leaf
--verify-ip <IP>         # Check IP in leaf
--show-chain             # Display chain details

# Bulk: verify all certs in a directory
xcert verify --CAfile ca.pem /etc/ssl/certs/ --json
xcert verify --failures-only /etc/ssl/certs/
```

Exit code 0 = valid, 2 = invalid.

### Convert between formats

```bash
xcert convert cert.pem cert.der     # PEM to DER
xcert convert cert.der cert.pem     # DER to PEM
xcert convert cert.pem --to der     # Explicit format (stdout)
```

## JSON Output

All commands support `--json` for machine-readable output. Bulk operations return:

```json
{
  "results": [
    {"file": "path/to/cert.pem", "success": true, "data": {...}},
    {"file": "path/to/bad.pem", "success": false, "error": "..."}
  ],
  "summary": {"total": 10, "passed": 8, "failed": 2}
}
```

## Features

- Auto-detection of PEM vs DER format
- Colored terminal output (dates, hex values, URLs, strings)
- Parallel directory processing via rayon
- Certificate chain verification against system or custom trust store
- CRL revocation checking (`--crl-file`, `--crl-check`, `--crl-check-all`)
- RSA, ECDSA (P-256/P-384/P-521), Ed25519, Ed448 key types
- SHA-256/384/512/SHA-1 fingerprints
- Memory-safe Rust with `unsafe` forbidden

## Testing

```bash
cargo test
```

240 tests covering parsing, verification, checks, conversions, and compatibility with external test vectors.

## Fuzzing

```bash
cargo +nightly fuzz run parse_cert -- -max_total_time=60
```

Four fuzz targets: `parse_cert`, `parse_der`, `parse_pem`, `roundtrip`.

## Security

- `unsafe` code denied at workspace level
- Clippy warns on `unwrap()`, `expect()`, `panic!()`
- `cargo audit` for dependency scanning

## Performance

See [PERF.md](PERF.md) for benchmarks. xcert is 3.7x-4.5x faster than OpenSSL for common operations.

## License

[MIT License](LICENSE)
