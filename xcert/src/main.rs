//! xcert: Command-line tool for inspecting X.509 certificates.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "xcert", about = "Inspect X.509 certificates")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display certificate information
    Show {
        /// Certificate file (PEM or DER). Reads from stdin if omitted.
        file: Option<PathBuf>,
        /// Force DER input parsing
        #[arg(long)]
        der: bool,
        /// Force PEM input parsing
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
    Field {
        /// Field to extract
        field: FieldName,
        /// Certificate file. Reads from stdin if omitted.
        file: Option<PathBuf>,
        /// Force DER input parsing
        #[arg(long)]
        der: bool,
        /// Force PEM input parsing
        #[arg(long)]
        pem: bool,
        /// Hash algorithm for fingerprint
        #[arg(long, default_value = "sha256")]
        digest: String,
        /// Extension name filter (e.g., "subjectAltName", "keyUsage")
        #[arg(long)]
        ext: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Check certificate properties (exit code 0 = pass, 1 = fail)
    Check {
        /// Check to perform
        check: CheckType,
        /// Value to check against
        value: String,
        /// Certificate file. Reads from stdin if omitted.
        file: Option<PathBuf>,
        /// Force DER input parsing
        #[arg(long)]
        der: bool,
        /// Force PEM input parsing
        #[arg(long)]
        pem: bool,
    },
    /// Convert between PEM and DER formats
    Convert {
        /// Certificate file. Reads from stdin if omitted.
        file: Option<PathBuf>,
        /// Output format
        #[arg(long, value_name = "FORMAT")]
        to: String,
        /// Output file (default: stdout)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Force DER input parsing
        #[arg(long)]
        der: bool,
        /// Force PEM input parsing
        #[arg(long)]
        pem: bool,
    },
    /// Verify a certificate chain against a trust store
    Verify {
        /// PEM file containing the certificate chain (leaf first, then intermediates).
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
        #[arg(long)]
        untrusted: Option<PathBuf>,
        /// Skip validity date checks
        #[arg(long)]
        no_check_time: bool,
        /// Allow partial chain verification (trust any cert in the chain)
        #[arg(long)]
        partial_chain: bool,
        /// Required purpose: sslserver, sslclient, smimesign, codesign, any, or an OID
        #[arg(long, value_name = "PURPOSE")]
        purpose: Option<String>,
        /// Verify email address against the leaf certificate
        #[arg(long, value_name = "EMAIL")]
        verify_email: Option<String>,
        /// Verify IP address against the leaf certificate
        #[arg(long, value_name = "IP")]
        verify_ip: Option<String>,
        /// Verify at a specific Unix timestamp
        #[arg(long, value_name = "EPOCH")]
        attime: Option<i64>,
        /// Maximum chain depth
        #[arg(long, value_name = "N")]
        verify_depth: Option<usize>,
        /// Display information about the verified chain
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

fn read_input(file: Option<&PathBuf>) -> Result<Vec<u8>> {
    match file {
        Some(path) => {
            std::fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))
        }
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
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
                        _ => anyhow::bail!("Unsupported digest: {}", digest),
                    };
                    cert.fingerprint(alg)
                }
                FieldName::PublicKey => cert.public_key_pem().to_string(),
                FieldName::Modulus => cert
                    .modulus_hex()
                    .unwrap_or("(not an RSA certificate)")
                    .to_string(),
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
        } => {
            let input = read_input(file.as_ref())?;
            let cert = parse_input(&input, *der, *pem)?;

            let pass = match check {
                CheckType::Expiry => {
                    let seconds: u64 = value.parse().context("Invalid seconds value")?;
                    xcert_lib::check_expiry(&cert, seconds)
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
            to,
            out,
            der,
            pem,
        } => {
            let input = read_input(file.as_ref())?;

            let is_pem_input = if *pem {
                true
            } else if *der {
                false
            } else {
                // auto-detect
                let trimmed: Vec<u8> = input
                    .iter()
                    .skip_while(|b| b.is_ascii_whitespace())
                    .take(11)
                    .copied()
                    .collect();
                trimmed.starts_with(b"-----BEGIN")
            };

            let output_bytes: Vec<u8> = match to.as_str() {
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
                _ => anyhow::bail!("Unsupported output format: {}. Use 'pem' or 'der'.", to),
            };

            if let Some(out_path) = out {
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
        } => {
            let input = read_input(file.as_ref())?;

            let mut trust_store = if let Some(ca_file_path) = ca_file {
                xcert_lib::TrustStore::from_pem_file(ca_file_path)?
            } else {
                xcert_lib::TrustStore::system()?
            };

            if let Some(ca_dir) = ca_path {
                trust_store.add_pem_directory(ca_dir)?;
            }

            // Load CRL file if provided
            let crl_ders = if let Some(crl_path) = crl_file {
                let crl_data = std::fs::read(crl_path)
                    .with_context(|| format!("Failed to read CRL file: {}", crl_path.display()))?;
                xcert_lib::parse_pem_crl(&crl_data)?
            } else {
                Vec::new()
            };

            // Resolve named purposes (sslserver, sslclient, etc.) to OIDs
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

            let result = if let Some(untrusted_path) = untrusted {
                // Separate leaf + untrusted intermediates (like openssl verify -untrusted)
                let leaf_der = xcert_lib::pem_to_der(&input)?;
                let untrusted_data = std::fs::read(untrusted_path).with_context(|| {
                    format!(
                        "Failed to read untrusted file: {}",
                        untrusted_path.display()
                    )
                })?;
                xcert_lib::verify_with_untrusted(
                    &leaf_der,
                    &untrusted_data,
                    &trust_store,
                    hostname.as_deref(),
                    &options,
                )?
            } else {
                xcert_lib::verify_pem_chain_with_options(
                    &input,
                    &trust_store,
                    hostname.as_deref(),
                    &options,
                )?
            };

            if *json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if result.is_valid {
                let label = file
                    .as_ref()
                    .map_or("stdin".to_string(), |f| f.display().to_string());
                println!("{}: {}", label, result);
                if *show_chain {
                    for info in &result.chain {
                        println!(
                            "depth {}: subject = {}, issuer = {}",
                            info.depth, info.subject, info.issuer
                        );
                    }
                }
            } else {
                let label = file
                    .as_ref()
                    .map_or("stdin".to_string(), |f| f.display().to_string());
                eprintln!("{}: {}", label, result);
            }

            if !result.is_valid {
                std::process::exit(2);
            }
        }
    }

    Ok(())
}
