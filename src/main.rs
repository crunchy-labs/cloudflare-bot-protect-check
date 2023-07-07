use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use reqwest::blocking::Client;
use rustls::{SupportedCipherSuite, SupportedKxGroup, SupportedProtocolVersion};
use std::io::BufRead;
use std::path::Path;
use std::{fs, io};

#[derive(Clone, Debug, ValueEnum)]
#[allow(non_camel_case_types)]
enum CipherSuite {
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

#[allow(clippy::from_over_into)]
impl Into<&SupportedCipherSuite> for &CipherSuite {
    fn into(self) -> &'static SupportedCipherSuite {
        match self {
            CipherSuite::TLS13_AES_256_GCM_SHA384 => {
                &rustls::cipher_suite::TLS13_AES_256_GCM_SHA384
            }
            CipherSuite::TLS13_AES_128_GCM_SHA256 => {
                &rustls::cipher_suite::TLS13_AES_128_GCM_SHA256
            }
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
                &rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
            }
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
                &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            }
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            }
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
                &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
                &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
                &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            }
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
                &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            }
        }
    }
}

impl From<&SupportedCipherSuite> for CipherSuite {
    fn from(value: &SupportedCipherSuite) -> Self {
        if value == &rustls::cipher_suite::TLS13_AES_256_GCM_SHA384 {
            CipherSuite::TLS13_AES_256_GCM_SHA384
        } else if value == &rustls::cipher_suite::TLS13_AES_128_GCM_SHA256 {
            CipherSuite::TLS13_AES_128_GCM_SHA256
        } else if value == &rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256 {
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        } else if value == &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        } else if value == &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        } else if value == &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 {
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        } else if value == &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 {
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        } else if value == &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        } else if value == &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 {
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        } else {
            panic!("rustls dependency updated but code doesn't (probably)")
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
#[allow(non_camel_case_types)]
enum KxGroup {
    X25519,
    SECP256R1,
    SECP384R1,
}

#[allow(clippy::from_over_into)]
impl Into<&SupportedKxGroup> for &KxGroup {
    fn into(self) -> &'static SupportedKxGroup {
        match self {
            KxGroup::X25519 => &rustls::kx_group::X25519,
            KxGroup::SECP256R1 => &rustls::kx_group::SECP256R1,
            KxGroup::SECP384R1 => &rustls::kx_group::SECP384R1,
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
#[allow(non_camel_case_types)]
enum TlsVersion {
    Tls12,
    Tls13,
}

#[allow(clippy::from_over_into)]
impl Into<&SupportedProtocolVersion> for &TlsVersion {
    fn into(self) -> &'static SupportedProtocolVersion {
        match self {
            TlsVersion::Tls12 => &rustls::version::TLS12,
            TlsVersion::Tls13 => &rustls::version::TLS13,
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
#[allow(non_camel_case_types)]
enum Format {
    Plain,
    Json,
}

/// cloudflare-bot-protect-check - check which user agents are blocked by the cloudflare bot protection
#[derive(Parser)]
#[command(arg_required_else_help(true))]
struct Cli {
    /// Use custom tls settings. Cloudflare sometimes uses tls fingerprinting to decide if a request
    /// is made by a bot. Custom tls settings might be able to bypass this as well. Used tls backend
    /// will be rustls
    #[clap(long, default_value_t = false)]
    custom_tls: bool,
    /// TLS cipher suites to use. Only used when `--custom-tls` is set
    #[clap(long, value_enum, default_values_t = rustls::DEFAULT_CIPHER_SUITES.iter().map(|c| c.into()).collect::<Vec<CipherSuite>>())]
    cipher_suite: Vec<CipherSuite>,
    /// TLS key exchange groups. Only used when `--custom-tls` is set
    #[clap(long, value_enum, default_values_t = vec![KxGroup::X25519])]
    kx_group: Vec<KxGroup>,
    /// TLS versions to use. Only used when `--custom-tls` is set
    #[clap(long, value_enum, default_values_t = vec![TlsVersion::Tls12, TlsVersion::Tls13])]
    tls: Vec<TlsVersion>,

    /// File to read user agents from. The file must be text file where every line contains one user
    /// agent. By default, user agents are read from stdin
    #[clap(long)]
    file: Option<String>,

    /// Output format
    #[clap(long, default_value_t = Format::Plain, value_enum)]
    format: Format,

    /// Url to check
    url: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let user_agents = if let Some(file) = &cli.file {
        read_user_agent_file(file)?
    } else {
        read_user_agent_from_stdin()?
    };

    for user_agent in user_agents {
        let client = build_client(&cli, &user_agent)?;
        let result = client.get(&cli.url).send()?;

        match &cli.format {
            Format::Plain => println!("{} - {}", result.status().as_u16(), user_agent),
            Format::Json => println!(
                "{}",
                serde_json::json!({
                    "status": result.status().as_u16(),
                    "user_agent": user_agent
                })
            ),
        }
    }

    Ok(())
}

fn read_user_agent_file<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    if !path.as_ref().exists() {
        bail!("File {} does not exist", path.as_ref().to_string_lossy())
    }
    Ok(fs::read_to_string(path)?
        .split('\n')
        .map(|s| s.to_string())
        .collect())
}

fn read_user_agent_from_stdin() -> Result<Vec<String>> {
    let mut lines = vec![];
    for line in io::stdin().lock().lines() {
        lines.push(line?)
    }
    Ok(lines)
}

fn build_client(cli: &Cli, user_agent: &str) -> Result<Client> {
    let mut builder = Client::builder();
    builder = builder.user_agent(user_agent);
    if cli.custom_tls {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let tls_config = rustls::ClientConfig::builder()
            .with_cipher_suites(rustls::DEFAULT_CIPHER_SUITES)
            .with_kx_groups(
                cli.kx_group
                    .iter()
                    .map(|kx_group| kx_group.into())
                    .collect::<Vec<&SupportedKxGroup>>()
                    .as_slice(),
            )
            .with_protocol_versions(
                cli.tls
                    .iter()
                    .map(|tls| tls.into())
                    .collect::<Vec<&SupportedProtocolVersion>>()
                    .as_slice(),
            )
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        builder = builder.use_preconfigured_tls(tls_config);
    }

    Ok(builder.build()?)
}
