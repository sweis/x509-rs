//! xcert: Command-line tool for inspecting X.509 certificates.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rayon::prelude::*;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "xcert",
    about = "A fast, memory-safe tool for inspecting X.509 certificates",
    long_about = "xcert parses and displays X.509 certificates in PEM or DER format.\n\
                  It is a modern, read-only replacement for `openssl x509` with a\n\
                  simpler interface, JSON output, and subcommand-based CLI.\n\n\
                  Input format (PEM vs DER) is auto-detected unless --pem or --der\n\
                  is specified. All commands read from stdin when no file is given.",
    after_help = "EXAMPLES:\n\
                  \n  xcert show cert.pem\
                  \n  xcert show --json cert.pem\
                  \n  xcert field subject cert.pem\
                  \n  xcert field fingerprint --digest sha384 cert.pem\
                  \n  xcert check host www.example.com cert.pem\
                  \n  xcert convert cert.pem cert.der\
                  \n  xcert verify --hostname www.example.com chain.pem\
                  \n  cat cert.pem | xcert show"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display certificate information (like openssl x509 -text)
    #[command(after_help = "EXAMPLES:\n\
                      \n  xcert show cert.pem\
                      \n  xcert show --json cert.pem\
                      \n  xcert show --all cert.pem\
                      \n  xcert show cert.der\
                      \n  cat cert.pem | xcert show")]
    Show {
        /// Certificate file (PEM or DER). Reads from stdin if omitted.
        file: Option<PathBuf>,
        /// Force DER input parsing (default: auto-detect)
        #[arg(long)]
        der: bool,
        /// Force PEM input parsing (default: auto-detect)
        #[arg(long)]
        pem: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Show all fields including signature bytes
        #[arg(long)]
        all: bool,
    },
    /// Extract a single field from the certificate
    #[command(after_help = "FIELDS:\n\
                      \n  subject        Subject distinguished name\
                      \n  issuer         Issuer distinguished name\
                      \n  serial         Serial number (colon-separated hex)\
                      \n  not-before     Not Before date (ISO 8601)\
                      \n  not-after      Not After date (ISO 8601)\
                      \n  fingerprint    Certificate fingerprint (default: SHA-256)\
                      \n  public-key     Subject public key in PEM format\
                      \n  modulus        RSA modulus in hex (RSA certificates only)\
                      \n  exponent       RSA public exponent (RSA certificates only)\
                      \n  emails         Email addresses from subject and SAN\
                      \n  san            Subject Alternative Names\
                      \n  ocsp-url       OCSP responder URL(s) from AIA extension\
                      \n  key-usage      Key Usage extension values\
                      \n  ext-key-usage  Extended Key Usage extension values\
                      \n  extensions     All extensions (use --ext to filter)\
                      \n\nEXAMPLES:\n\
                      \n  xcert field subject cert.pem\
                      \n  xcert field fingerprint cert.pem\
                      \n  xcert field fingerprint --digest sha384 cert.pem\
                      \n  xcert field san --json cert.pem\
                      \n  xcert field extensions --ext subjectAltName cert.pem\
                      \n  xcert field extensions --ext \"Key Usage\" cert.pem")]
    Field {
        /// Field to extract
        field: FieldName,
        /// Certificate file. Reads from stdin if omitted.
        file: Option<PathBuf>,
        /// Force DER input parsing (default: auto-detect)
        #[arg(long)]
        der: bool,
        /// Force PEM input parsing (default: auto-detect)
        #[arg(long)]
        pem: bool,
        /// Hash algorithm for fingerprint: sha256, sha384, sha512, sha1
        #[arg(long, default_value = "sha256")]
        digest: String,
        /// Filter extensions by name or OID (e.g., "subjectAltName", "2.5.29.17")
        #[arg(long)]
        ext: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Check certificate properties (exit code 0 = pass, 1 = fail)
    #[command(after_help = "CHECKS:\n\
                      \n  expiry <DURATION>  Pass if cert is valid for at least DURATION more\
                      \n  host <HOSTNAME>    Pass if hostname matches SAN/CN (RFC 6125 wildcards)\
                      \n  email <EMAIL>      Pass if email matches SAN or subject emailAddress\
                      \n  ip <ADDRESS>       Pass if IP matches SAN (IPv4 or IPv6)\
                      \n\nDURATION FORMAT:\n\
                      \n  Plain numbers are treated as seconds. You can also use humantime\
                      \n  notation: s, m/min, h/hr, d/day, w/week, month, y/year.\
                      \n  Combine units: 1h30m, 2d12h, 1w3d.\
                      \n\nEXAMPLES:\n\
                      \n  xcert check expiry 30d cert.pem         # valid for 30+ days?\
                      \n  xcert check expiry 2592000 cert.pem     # same, in seconds\
                      \n  xcert check expiry 1w cert.pem          # valid for 1+ week?\
                      \n  xcert check expiry 2h30m cert.pem       # valid for 2.5+ hours?\
                      \n  xcert check host www.example.com cert.pem\
                      \n  xcert check email user@example.com cert.pem\
                      \n  xcert check ip 93.184.216.34 cert.pem")]
    Check {
        /// Check to perform: expiry, host, email, ip
        check: CheckType,
        /// Value to check (duration for expiry, hostname/email/IP for others)
        value: String,
        /// Certificate file or directory. Reads from stdin if omitted.
        file: Option<PathBuf>,
        /// Force DER input parsing (default: auto-detect)
        #[arg(long)]
        der: bool,
        /// Force PEM input parsing (default: auto-detect)
        #[arg(long)]
        pem: bool,
        /// Only print failures (directory mode)
        #[arg(long)]
        failures_only: bool,
        /// Recurse into subdirectories (directory mode)
        #[arg(short, long)]
        recurse: bool,
    },
    /// Convert between PEM and DER formats
    #[command(
        after_help = "If OUTPUT is given, the format is inferred from its extension\n\
                      (.pem or .der). If OUTPUT is omitted, output goes to stdout\n\
                      and --to is required to specify the format.\n\
                      \nEXAMPLES:\n\
                      \n  xcert convert cert.pem cert.der\
                      \n  xcert convert cert.der cert.pem\
                      \n  xcert convert cert.pem --to der > out.der\
                      \n  cat cert.pem | xcert convert --to der > cert.der"
    )]
    Convert {
        /// Input certificate file. Reads from stdin if omitted.
        file: Option<PathBuf>,
        /// Output file. Format is inferred from extension (.pem or .der).
        output: Option<PathBuf>,
        /// Output format: pem, der (required when writing to stdout)
        #[arg(long, value_name = "FORMAT")]
        to: Option<String>,
        /// Force DER input parsing (default: auto-detect)
        #[arg(long)]
        der: bool,
        /// Force PEM input parsing (default: auto-detect)
        #[arg(long)]
        pem: bool,
    },
    /// Verify a certificate chain against a trust store (exit 0 = valid, 2 = fail)
    #[command(
        after_help = "FILE is a PEM bundle with the leaf certificate first, followed by\n\
                      intermediates. Uses the system trust store by default.\n\
                      \nPURPOSE VALUES:\n\
                      \n  sslserver   TLS server authentication (OID 1.3.6.1.5.5.7.3.1)\
                      \n  sslclient   TLS client authentication (OID 1.3.6.1.5.5.7.3.2)\
                      \n  smimesign   S/MIME email signing    (OID 1.3.6.1.5.5.7.3.4)\
                      \n  codesign    Code signing            (OID 1.3.6.1.5.5.7.3.3)\
                      \n  any         Any Extended Key Usage  (OID 2.5.29.37.0)\
                      \n  <OID>       Custom OID (e.g., 1.3.6.1.5.5.7.3.8)\
                      \n\nEXAMPLES:\n\
                      \n  xcert verify chain.pem\
                      \n  xcert verify --hostname www.example.com chain.pem\
                      \n  xcert verify --CAfile ca.pem --untrusted int.pem leaf.pem\
                      \n  xcert verify --purpose sslserver chain.pem\
                      \n  xcert verify --json chain.pem\
                      \n  cat chain.pem | xcert verify"
    )]
    Verify {
        /// PEM file or directory with certificate chain(s).
        /// Reads from stdin if omitted.
        file: Option<PathBuf>,
        /// Hostname to verify against the leaf certificate's SAN/CN
        #[arg(long)]
        hostname: Option<String>,
        /// PEM file containing trusted CA certificates (default: system trust store)
        #[arg(long = "CAfile", visible_alias = "ca-file", value_name = "FILE")]
        ca_file: Option<PathBuf>,
        /// Directory of trusted CA certificates in PEM format
        #[arg(long = "CApath", visible_alias = "ca-path", value_name = "DIR")]
        ca_path: Option<PathBuf>,
        /// PEM file with untrusted intermediate certificates
        #[arg(long, value_name = "FILE")]
        untrusted: Option<PathBuf>,
        /// Skip validity date checks
        #[arg(long)]
        no_check_time: bool,
        /// Allow partial chain verification (trust any cert in the chain)
        #[arg(long)]
        partial_chain: bool,
        /// Required EKU purpose: sslserver, sslclient, smimesign, codesign, any, or OID
        #[arg(long, value_name = "PURPOSE")]
        purpose: Option<String>,
        /// Verify email address against the leaf certificate's SAN/subject
        #[arg(long, value_name = "EMAIL")]
        verify_email: Option<String>,
        /// Verify IP address against the leaf certificate's SAN
        #[arg(long, value_name = "IP")]
        verify_ip: Option<String>,
        /// Verify at a specific Unix timestamp instead of current time
        #[arg(long, value_name = "EPOCH")]
        attime: Option<i64>,
        /// Maximum chain depth
        #[arg(long, value_name = "N")]
        verify_depth: Option<usize>,
        /// Display subject and issuer for each certificate in the verified chain
        #[arg(long)]
        show_chain: bool,
        /// PEM file containing CRL(s) for revocation checking
        #[arg(long = "CRLfile", visible_alias = "crl-file", value_name = "FILE")]
        crl_file: Option<PathBuf>,
        /// Check CRL revocation for the leaf certificate
        #[arg(long)]
        crl_check: bool,
        /// Check CRL revocation for all certificates in the chain
        #[arg(long)]
        crl_check_all: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Only print failures (directory mode)
        #[arg(long)]
        failures_only: bool,
        /// Recurse into subdirectories (directory mode)
        #[arg(short, long)]
        recurse: bool,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum FieldName {
    Subject,
    Issuer,
    Serial,
    NotBefore,
    NotAfter,
    Fingerprint,
    PublicKey,
    Modulus,
    Exponent,
    Emails,
    San,
    OcspUrl,
    KeyUsage,
    ExtKeyUsage,
    Extensions,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum CheckType {
    Expiry,
    Host,
    Email,
    Ip,
}

/// Maximum file size for certificate inputs (10 MiB).
const MAX_INPUT_BYTES: u64 = 10 * 1024 * 1024;

fn read_input(file: Option<&PathBuf>) -> Result<Vec<u8>> {
    match file {
        Some(path) => {
            let meta = std::fs::metadata(path)
                .with_context(|| format!("Failed to stat file: {}", path.display()))?;
            if meta.len() > MAX_INPUT_BYTES {
                anyhow::bail!(
                    "File too large ({} bytes, max {} bytes): {}",
                    meta.len(),
                    MAX_INPUT_BYTES,
                    path.display()
                );
            }
            std::fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))
        }
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .take(MAX_INPUT_BYTES)
                .read_to_end(&mut buf)
                .context("Failed to read from stdin")?;
            Ok(buf)
        }
    }
}

fn parse_input(input: &[u8], der: bool, pem: bool) -> Result<xcert_lib::CertificateInfo> {
    if der {
        Ok(xcert_lib::parse_der(input)?)
    } else if pem {
        Ok(xcert_lib::parse_pem(input)?)
    } else {
        Ok(xcert_lib::parse_cert(input)?)
    }
}

/// Infer output format ("pem" or "der") from a file extension.
fn infer_format(path: &std::path::Path) -> Option<&'static str> {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("pem") => Some("pem"),
        Some(ext) if ext.eq_ignore_ascii_case("der") => Some("der"),
        _ => None,
    }
}

/// Parse a duration string using humantime format.
///
/// Plain numbers (e.g. "3600") default to seconds. Otherwise, standard
/// humantime units are accepted: `s`, `m`, `h`, `d`, `w`, `months`, `y`, etc.
///
/// Examples: "30", "30s", "5m", "2h30m", "7d", "1w", "30days".
fn parse_duration(s: &str) -> Result<Duration> {
    // Plain integer → treat as seconds
    if s.chars().all(|c| c.is_ascii_digit()) {
        let secs: u64 = s.parse().context("Invalid duration value")?;
        return Ok(Duration::from_secs(secs));
    }
    humantime::parse_duration(s).with_context(|| format!("Invalid duration: '{s}'"))
}

/// Check if a path has a certificate file extension (.pem or .der).
fn is_cert_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some(ext) if ext.eq_ignore_ascii_case("pem") || ext.eq_ignore_ascii_case("der")
            || ext.eq_ignore_ascii_case("crt") || ext.eq_ignore_ascii_case("cer")
    )
}

/// Find all certificate files (.pem, .der, .crt, .cer) in a directory.
fn find_cert_files(dir: &Path, recurse: bool) -> Vec<PathBuf> {
    let walker = if recurse {
        walkdir::WalkDir::new(dir)
    } else {
        walkdir::WalkDir::new(dir).max_depth(1)
    };
    let mut files: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && is_cert_file(e.path()))
        .map(|e| e.into_path())
        .collect();
    files.sort();
    files
}

/// A single result from batch processing.
struct BatchResult {
    path: String,
    pass: bool,
    detail: String,
}

/// Process certificate files in parallel, printing `filename: result`.
///
/// The closure may return multiple results per file (e.g. for CA bundles
/// containing many independent certificates).
///
/// Returns the number of failures.
fn run_batch<F>(files: &[PathBuf], failures_only: bool, op: F) -> usize
where
    F: Fn(&Path) -> Vec<BatchResult> + Sync,
{
    let results: Vec<Vec<BatchResult>> = files.par_iter().map(|f| op(f)).collect();

    let mut failures = 0;
    for batch in &results {
        for r in batch {
            if !r.pass {
                failures += 1;
            }
            if failures_only && r.pass {
                continue;
            }
            if r.pass {
                println!("{}: {}", r.path, r.detail);
            } else {
                eprintln!("{}: {}", r.path, r.detail);
            }
        }
    }
    failures
}

/// Convert a verification result (or error) into a BatchResult.
fn verify_to_batch(
    label: String,
    result: Result<xcert_lib::VerificationResult, impl std::fmt::Display>,
) -> BatchResult {
    match result {
        Ok(r) => BatchResult {
            path: label,
            pass: r.is_valid,
            detail: format!("{}", r),
        },
        Err(e) => BatchResult {
            path: label,
            pass: false,
            detail: format!("FAIL ({})", e),
        },
    }
}

/// Print a single-file verification result (JSON, text valid, or text invalid).
fn print_verify_result(
    label: &str,
    result: &xcert_lib::VerificationResult,
    json: bool,
    show_chain: bool,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(result)?);
    } else if result.is_valid {
        println!("{}: {}", label, result);
        if show_chain {
            for info in &result.chain {
                println!(
                    "depth {}: subject = {}, issuer = {}",
                    info.depth, info.subject, info.issuer
                );
            }
        }
    } else {
        eprintln!("{}: {}", label, result);
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Show {
            file,
            der,
            pem,
            json,
            all,
        } => {
            let input = read_input(file.as_ref())?;
            let cert = parse_input(&input, *der, *pem)?;

            if *json {
                println!("{}", xcert_lib::to_json(&cert)?);
            } else {
                print!("{}", xcert_lib::display_text(&cert, *all));
            }
        }
        Commands::Field {
            field,
            file,
            der,
            pem,
            digest,
            ext,
            json,
        } => {
            let input = read_input(file.as_ref())?;
            let cert = parse_input(&input, *der, *pem)?;

            // If --ext is provided, extract that extension by name
            if let Some(ext_name) = ext {
                let matching: Vec<_> = cert
                    .extensions
                    .iter()
                    .filter(|e| e.name.eq_ignore_ascii_case(ext_name) || e.oid == *ext_name)
                    .collect();
                if matching.is_empty() {
                    anyhow::bail!("Extension '{}' not found", ext_name);
                }
                if *json {
                    println!("{}", serde_json::to_string_pretty(&matching)?);
                } else {
                    for e in matching {
                        println!(
                            "{}{}: {:?}",
                            e.name,
                            if e.critical { " [critical]" } else { "" },
                            e.value
                        );
                    }
                }
                return Ok(());
            }

            let output = match field {
                FieldName::Subject => cert.subject_string(),
                FieldName::Issuer => cert.issuer_string(),
                FieldName::Serial => cert.serial_hex().to_string(),
                FieldName::NotBefore => cert.not_before_string(),
                FieldName::NotAfter => cert.not_after_string(),
                FieldName::Fingerprint => {
                    let alg = match digest.as_str() {
                        "sha256" => xcert_lib::DigestAlgorithm::Sha256,
                        "sha384" => xcert_lib::DigestAlgorithm::Sha384,
                        "sha512" => xcert_lib::DigestAlgorithm::Sha512,
                        "sha1" => xcert_lib::DigestAlgorithm::Sha1,
                        _ => anyhow::bail!(
                            "Unsupported digest: {}. Use sha256, sha384, sha512, or sha1.",
                            digest
                        ),
                    };
                    cert.fingerprint(alg)
                }
                FieldName::PublicKey => cert.public_key_pem().to_string(),
                FieldName::Modulus => cert
                    .modulus_hex()
                    .unwrap_or("(not an RSA certificate)")
                    .to_string(),
                FieldName::Exponent => cert
                    .public_key
                    .exponent
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "(not an RSA certificate)".to_string()),
                FieldName::Emails => cert.emails().join("\n"),
                FieldName::San => {
                    if *json {
                        serde_json::to_string_pretty(&cert.san_entries())?
                    } else {
                        cert.san_entries()
                            .iter()
                            .map(|e| match e {
                                xcert_lib::SanEntry::Dns(v) => format!("DNS:{}", v),
                                xcert_lib::SanEntry::Email(v) => format!("email:{}", v),
                                xcert_lib::SanEntry::Ip(v) => format!("IP Address:{}", v),
                                xcert_lib::SanEntry::Uri(v) => format!("URI:{}", v),
                                xcert_lib::SanEntry::DirName(v) => format!("DirName:{}", v),
                                xcert_lib::SanEntry::Other(v) => format!("othername:{}", v),
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                }
                FieldName::OcspUrl => cert.ocsp_urls().join("\n"),
                FieldName::KeyUsage => cert.key_usage().map(|u| u.join(", ")).unwrap_or_default(),
                FieldName::ExtKeyUsage => cert
                    .ext_key_usage()
                    .map(|u| u.join(", "))
                    .unwrap_or_default(),
                FieldName::Extensions => {
                    if *json {
                        serde_json::to_string_pretty(&cert.extensions)?
                    } else {
                        cert.extensions
                            .iter()
                            .map(|e| {
                                format!(
                                    "{}{}: {:?}",
                                    e.name,
                                    if e.critical { " [critical]" } else { "" },
                                    e.value
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    }
                }
            };
            println!("{}", output);
        }
        Commands::Check {
            check,
            value,
            file,
            der,
            pem,
            failures_only,
            recurse,
        } => {
            // Directory mode: process all cert files in parallel
            if let Some(path) = file {
                if path.is_dir() {
                    let files = find_cert_files(path, *recurse);
                    if files.is_empty() {
                        anyhow::bail!(
                            "No certificate files (.pem, .der, .crt, .cer) found in {}",
                            path.display()
                        );
                    }
                    // Pre-parse duration once for expiry checks
                    let expiry_secs = if matches!(check, CheckType::Expiry) {
                        Some(parse_duration(value)?.as_secs())
                    } else {
                        None
                    };
                    let check_type = check.clone();
                    let check_value = value.clone();
                    let force_der = *der;
                    let force_pem = *pem;
                    let failures = run_batch(&files, *failures_only, |f| {
                        let label = f.display().to_string();
                        let data = match std::fs::read(f) {
                            Ok(d) => d,
                            Err(e) => {
                                return vec![BatchResult {
                                    path: label,
                                    pass: false,
                                    detail: format!("FAIL (read error: {})", e),
                                }]
                            }
                        };
                        let cert = match parse_input(&data, force_der, force_pem) {
                            Ok(c) => c,
                            Err(e) => {
                                return vec![BatchResult {
                                    path: label,
                                    pass: false,
                                    detail: format!("FAIL (parse error: {})", e),
                                }]
                            }
                        };
                        let pass = match check_type {
                            CheckType::Expiry => {
                                xcert_lib::check_expiry(&cert, expiry_secs.unwrap_or(0))
                            }
                            CheckType::Host => xcert_lib::check_host(&cert, &check_value),
                            CheckType::Email => xcert_lib::check_email(&cert, &check_value),
                            CheckType::Ip => xcert_lib::check_ip(&cert, &check_value),
                        };
                        vec![BatchResult {
                            path: label,
                            pass,
                            detail: if pass {
                                "PASS".to_string()
                            } else {
                                "FAIL".to_string()
                            },
                        }]
                    });
                    if failures > 0 {
                        std::process::exit(1);
                    }
                    return Ok(());
                }
            }

            // Single file mode
            let input = read_input(file.as_ref())?;
            let cert = parse_input(&input, *der, *pem)?;

            let pass = match check {
                CheckType::Expiry => {
                    let duration = parse_duration(value)?;
                    xcert_lib::check_expiry(&cert, duration.as_secs())
                }
                CheckType::Host => xcert_lib::check_host(&cert, value),
                CheckType::Email => xcert_lib::check_email(&cert, value),
                CheckType::Ip => xcert_lib::check_ip(&cert, value),
            };

            if !pass {
                std::process::exit(1);
            }
        }
        Commands::Convert {
            file,
            output,
            to,
            der,
            pem,
        } => {
            let input = read_input(file.as_ref())?;

            // Determine output format: explicit --to flag, inferred from output
            // file extension, or error.
            let format = if let Some(fmt) = to {
                fmt.as_str().to_owned()
            } else if let Some(out_path) = output {
                infer_format(out_path)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Cannot infer output format from '{}'. Use .pem/.der extension or --to.",
                            out_path.display()
                        )
                    })?
                    .to_owned()
            } else {
                anyhow::bail!("Output format required: use --to pem|der, or provide an output file with .pem/.der extension");
            };

            let is_pem_input = if *pem {
                true
            } else if *der {
                false
            } else {
                xcert_lib::is_pem(&input)
            };

            let output_bytes: Vec<u8> = match format.as_str() {
                "der" => {
                    if is_pem_input {
                        xcert_lib::pem_to_der(&input)?
                    } else {
                        input
                    }
                }
                "pem" => {
                    let der_input = if is_pem_input {
                        xcert_lib::pem_to_der(&input)?
                    } else {
                        input
                    };
                    xcert_lib::der_to_pem(&der_input).into_bytes()
                }
                _ => anyhow::bail!("Unsupported output format: {}. Use 'pem' or 'der'.", format),
            };

            if let Some(out_path) = output {
                std::fs::write(out_path, &output_bytes)?;
            } else {
                use std::io::Write;
                std::io::stdout().write_all(&output_bytes)?;
            }
        }
        Commands::Verify {
            file,
            hostname,
            ca_file,
            ca_path,
            untrusted,
            no_check_time,
            partial_chain,
            purpose,
            verify_email,
            verify_ip,
            attime,
            verify_depth,
            show_chain,
            crl_file,
            crl_check,
            crl_check_all,
            json,
            failures_only,
            recurse,
        } => {
            // Build shared trust store and options (used by both modes)
            let mut trust_store = if let Some(ca_file_path) = ca_file {
                xcert_lib::TrustStore::from_pem_file(ca_file_path)?
            } else {
                xcert_lib::TrustStore::system()?
            };

            if let Some(ca_dir) = ca_path {
                trust_store.add_pem_directory(ca_dir)?;
            }

            if (*crl_check || *crl_check_all) && crl_file.is_none() {
                anyhow::bail!(
                    "--crl-check and --crl-check-all require --CRLfile to specify a CRL file"
                );
            }

            let crl_ders = if let Some(crl_path) = crl_file {
                let crl_data = std::fs::read(crl_path)
                    .with_context(|| format!("Failed to read CRL file: {}", crl_path.display()))?;
                xcert_lib::parse_pem_crl(&crl_data)?
            } else {
                Vec::new()
            };

            let resolved_purpose = purpose.as_ref().map(|p| {
                xcert_lib::resolve_purpose(p)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| p.clone())
            });

            let options = xcert_lib::VerifyOptions {
                check_time: !no_check_time,
                partial_chain: *partial_chain,
                purpose: resolved_purpose,
                at_time: *attime,
                verify_depth: *verify_depth,
                verify_email: verify_email.clone(),
                verify_ip: verify_ip.clone(),
                crl_ders,
                crl_check_leaf: *crl_check || *crl_check_all,
                crl_check_all: *crl_check_all,
            };

            // Directory mode: verify all cert files in parallel
            if let Some(path) = file {
                if path.is_dir() {
                    let files = find_cert_files(path, *recurse);
                    if files.is_empty() {
                        anyhow::bail!(
                            "No certificate files (.pem, .der, .crt, .cer) found in {}",
                            path.display()
                        );
                    }
                    let failures = run_batch(&files, *failures_only, |f| {
                        let label = f.display().to_string();
                        let data = match std::fs::read(f) {
                            Ok(d) => d,
                            Err(e) => {
                                return vec![BatchResult {
                                    path: label,
                                    pass: false,
                                    detail: format!("FAIL (read error: {})", e),
                                }]
                            }
                        };
                        if let Some(untrusted_path) = untrusted {
                            let leaf_der = match xcert_lib::pem_to_der(&data) {
                                Ok(d) => d,
                                Err(e) => {
                                    return vec![BatchResult {
                                        path: label,
                                        pass: false,
                                        detail: format!("FAIL (parse error: {})", e),
                                    }]
                                }
                            };
                            let untrusted_data = match std::fs::read(untrusted_path) {
                                Ok(d) => d,
                                Err(e) => {
                                    return vec![BatchResult {
                                        path: label,
                                        pass: false,
                                        detail: format!("FAIL (read untrusted: {})", e),
                                    }]
                                }
                            };
                            let result = xcert_lib::verify_with_untrusted(
                                &leaf_der,
                                &untrusted_data,
                                &trust_store,
                                hostname.as_deref(),
                                &options,
                            );
                            return vec![verify_to_batch(label, result)];
                        }

                        // Parse PEM and detect bundle vs chain
                        let certs_der = match xcert_lib::parse_pem_chain(&data) {
                            Ok(c) => c,
                            Err(e) => {
                                return vec![BatchResult {
                                    path: label,
                                    pass: false,
                                    detail: format!("FAIL (parse error: {})", e),
                                }]
                            }
                        };

                        // If the certs don't form a chain (e.g. CA bundle),
                        // verify each certificate individually.
                        if !xcert_lib::is_certificate_chain(&certs_der) {
                            return certs_der
                                .iter()
                                .enumerate()
                                .map(|(i, cert_der)| {
                                    let cert_label = format!("{}[{}]", label, i);
                                    let result = xcert_lib::verify_chain_with_options(
                                        std::slice::from_ref(cert_der),
                                        &trust_store,
                                        hostname.as_deref(),
                                        &options,
                                    );
                                    verify_to_batch(cert_label, result)
                                })
                                .collect();
                        }

                        // Normal chain verification
                        let result = xcert_lib::verify_chain_with_options(
                            &certs_der,
                            &trust_store,
                            hostname.as_deref(),
                            &options,
                        );
                        vec![verify_to_batch(label, result)]
                    });
                    if failures > 0 {
                        std::process::exit(2);
                    }
                    return Ok(());
                }
            }

            // Single file mode
            let input = read_input(file.as_ref())?;
            let label = file
                .as_ref()
                .map_or("stdin".to_string(), |f| f.display().to_string());

            if let Some(untrusted_path) = untrusted.as_ref() {
                let leaf_der = xcert_lib::pem_to_der(&input)?;
                let untrusted_data = std::fs::read(untrusted_path).with_context(|| {
                    format!(
                        "Failed to read untrusted file: {}",
                        untrusted_path.display()
                    )
                })?;
                let result = xcert_lib::verify_with_untrusted(
                    &leaf_der,
                    &untrusted_data,
                    &trust_store,
                    hostname.as_deref(),
                    &options,
                )?;

                print_verify_result(&label, &result, *json, *show_chain)?;
                if !result.is_valid {
                    std::process::exit(2);
                }
            } else {
                // Parse PEM and detect bundle vs chain
                let certs_der = xcert_lib::parse_pem_chain(&input)?;

                if !xcert_lib::is_certificate_chain(&certs_der) {
                    // Bundle: verify each certificate individually
                    let mut any_invalid = false;
                    for (i, cert_der) in certs_der.iter().enumerate() {
                        let cert_label = format!("{}[{}]", label, i);
                        let result = xcert_lib::verify_chain_with_options(
                            std::slice::from_ref(cert_der),
                            &trust_store,
                            hostname.as_deref(),
                            &options,
                        );
                        match result {
                            Ok(r) => {
                                print_verify_result(&cert_label, &r, *json, false)?;
                                if !r.is_valid {
                                    any_invalid = true;
                                }
                            }
                            Err(e) => {
                                eprintln!("{}: FAIL ({})", cert_label, e);
                                any_invalid = true;
                            }
                        }
                    }
                    if any_invalid {
                        std::process::exit(2);
                    }
                } else {
                    // Chain: verify as a chain
                    let result = xcert_lib::verify_chain_with_options(
                        &certs_der,
                        &trust_store,
                        hostname.as_deref(),
                        &options,
                    )?;

                    print_verify_result(&label, &result, *json, *show_chain)?;
                    if !result.is_valid {
                        std::process::exit(2);
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ---- Positive cases: valid duration strings ----

    #[test]
    fn parse_plain_seconds() {
        assert_eq!(parse_duration("3600").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn parse_plain_zero() {
        assert_eq!(parse_duration("0").unwrap(), Duration::from_secs(0));
    }

    #[test]
    fn parse_large_plain_number() {
        assert_eq!(
            parse_duration("2592000").unwrap(),
            Duration::from_secs(2592000)
        );
    }

    #[test]
    fn parse_seconds_suffix() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parse_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn parse_minutes_long() {
        assert_eq!(parse_duration("5min").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn parse_hours() {
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn parse_hours_long() {
        assert_eq!(parse_duration("2hr").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn parse_days() {
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604800));
    }

    #[test]
    fn parse_days_long() {
        assert_eq!(
            parse_duration("7days").unwrap(),
            Duration::from_secs(604800)
        );
    }

    #[test]
    fn parse_weeks() {
        assert_eq!(
            parse_duration("1w").unwrap(),
            Duration::from_secs(7 * 86400)
        );
    }

    #[test]
    fn parse_weeks_long() {
        assert_eq!(
            parse_duration("2weeks").unwrap(),
            Duration::from_secs(14 * 86400)
        );
    }

    #[test]
    fn parse_combined_hours_minutes() {
        assert_eq!(
            parse_duration("2h30m").unwrap(),
            Duration::from_secs(2 * 3600 + 30 * 60)
        );
    }

    #[test]
    fn parse_combined_days_hours() {
        assert_eq!(
            parse_duration("1d12h").unwrap(),
            Duration::from_secs(86400 + 12 * 3600)
        );
    }

    #[test]
    fn parse_combined_weeks_days() {
        assert_eq!(
            parse_duration("1w3d").unwrap(),
            Duration::from_secs(10 * 86400)
        );
    }

    #[test]
    fn parse_with_spaces() {
        assert_eq!(parse_duration("1h 30m").unwrap(), Duration::from_secs(5400));
    }

    #[test]
    fn parse_seconds_long_word() {
        assert_eq!(
            parse_duration("90seconds").unwrap(),
            Duration::from_secs(90)
        );
    }

    // ---- Negative cases: invalid duration strings ----

    #[test]
    fn reject_empty_string() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn reject_bare_unit() {
        assert!(parse_duration("d").is_err());
    }

    #[test]
    fn reject_negative_number() {
        assert!(parse_duration("-30").is_err());
    }

    #[test]
    fn reject_negative_with_unit() {
        assert!(parse_duration("-5m").is_err());
    }

    #[test]
    fn reject_unknown_unit() {
        assert!(parse_duration("30x").is_err());
    }

    #[test]
    fn reject_decimal_plain_number() {
        assert!(parse_duration("3.5").is_err());
    }

    #[test]
    fn reject_garbage() {
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn reject_unit_only_no_number() {
        assert!(parse_duration("hours").is_err());
    }

    // ---- is_cert_file tests ----

    #[test]
    fn is_cert_file_pem() {
        assert!(is_cert_file(Path::new("cert.pem")));
    }

    #[test]
    fn is_cert_file_der() {
        assert!(is_cert_file(Path::new("cert.der")));
    }

    #[test]
    fn is_cert_file_crt() {
        assert!(is_cert_file(Path::new("cert.crt")));
    }

    #[test]
    fn is_cert_file_cer() {
        assert!(is_cert_file(Path::new("cert.cer")));
    }

    #[test]
    fn is_cert_file_case_insensitive() {
        assert!(is_cert_file(Path::new("cert.PEM")));
        assert!(is_cert_file(Path::new("cert.DER")));
    }

    #[test]
    fn is_cert_file_rejects_non_cert() {
        assert!(!is_cert_file(Path::new("cert.txt")));
        assert!(!is_cert_file(Path::new("cert.json")));
        assert!(!is_cert_file(Path::new("cert.key")));
        assert!(!is_cert_file(Path::new("README.md")));
    }

    #[test]
    fn is_cert_file_rejects_no_extension() {
        assert!(!is_cert_file(Path::new("cert")));
    }

    // ---- find_cert_files tests ----

    #[test]
    fn find_cert_files_finds_pem_and_der() {
        let certs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/certs");
        let files = find_cert_files(&certs_dir, false);
        assert!(!files.is_empty(), "should find cert files in tests/certs");
        // All returned files should have cert extensions
        for f in &files {
            assert!(is_cert_file(f), "non-cert file returned: {}", f.display());
        }
    }

    #[test]
    fn find_cert_files_sorted() {
        let certs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/certs");
        let files = find_cert_files(&certs_dir, false);
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(files, sorted, "files should be sorted");
    }

    #[test]
    fn find_cert_files_non_recursive_skips_subdirs() {
        let certs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/certs");
        let flat = find_cert_files(&certs_dir, false);
        // None of the flat results should be inside a subdirectory beyond certs/
        for f in &flat {
            let relative = f.strip_prefix(&certs_dir).unwrap();
            assert_eq!(
                relative.components().count(),
                1,
                "non-recursive should only return direct children: {}",
                f.display()
            );
        }
    }

    #[test]
    fn find_cert_files_empty_dir() {
        let tmp = std::env::temp_dir().join("xcert_test_empty_dir");
        let _ = std::fs::create_dir(&tmp);
        let files = find_cert_files(&tmp, false);
        assert!(files.is_empty(), "empty dir should return no files");
        let _ = std::fs::remove_dir(&tmp);
    }
}
