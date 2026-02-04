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
            let cert = if *der {
                xcert_lib::parse_der(&input)?
            } else if *pem {
                xcert_lib::parse_pem(&input)?
            } else {
                xcert_lib::parse_cert(&input)?
            };

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
            json,
            ..
        } => {
            let input = read_input(file.as_ref())?;
            let cert = if *der {
                xcert_lib::parse_der(&input)?
            } else if *pem {
                xcert_lib::parse_pem(&input)?
            } else {
                xcert_lib::parse_cert(&input)?
            };

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
                            .map(|e| format!("{:?}", e))
                            .collect::<Vec<_>>()
                            .join("\n")
                    }
                }
                FieldName::OcspUrl => cert.ocsp_urls().join("\n"),
                FieldName::KeyUsage => cert
                    .key_usage()
                    .map(|u| u.join(", "))
                    .unwrap_or_default(),
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
            let cert = if *der {
                xcert_lib::parse_der(&input)?
            } else if *pem {
                xcert_lib::parse_pem(&input)?
            } else {
                xcert_lib::parse_cert(&input)?
            };

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
            let output_bytes: Vec<u8> = match to.as_str() {
                "der" => xcert_lib::pem_to_der(&input)?,
                "pem" => {
                    let der_input = if *pem {
                        xcert_lib::pem_to_der(&input)?
                    } else if *der {
                        input
                    } else {
                        // auto-detect
                        let trimmed = input
                            .iter()
                            .skip_while(|b| b.is_ascii_whitespace())
                            .take(11)
                            .copied()
                            .collect::<Vec<_>>();
                        if trimmed.starts_with(b"-----BEGIN") {
                            xcert_lib::pem_to_der(&input)?
                        } else {
                            input
                        }
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
    }

    Ok(())
}
