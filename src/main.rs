use anyhow::{Context, Result, bail};
use botgate::{
    PROTOCOL,
    config::{Config, DEFAULT_CONFIG},
    crypto::{self, Jwks},
    http_message::Request,
    report::{Profile, Report},
    signature::{self, CoveredComponent, SignatureInput, Value},
};
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};
use url::Url;

#[derive(Parser)]
#[command(
    name = "botgate",
    version,
    about = "Evidence-first Web Bot Auth analyzer"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a test Ed25519 key, JWKS directory, and policy file.
    Init {
        #[arg(long)]
        force: bool,
        #[arg(long, default_value = ".botgate")]
        directory: PathBuf,
    },
    /// Parse declared coverage and evaluate conformance/policy without fetching keys.
    Inspect(AnalyzeArgs),
    /// Explain is a human-oriented alias for inspect.
    Explain(AnalyzeArgs),
    /// Verify an Ed25519 signature using an explicitly supplied local JWK/JWKS.
    Verify(VerifyArgs),
    /// Produce a safe offline mutation matrix; no requests are sent.
    Test(VerifyArgs),
    /// Sign a raw HTTP request with the generated Ed25519 test key.
    Sign(SignArgs),
    /// Print protocol support information.
    Protocol,
}

#[derive(clap::Args)]
struct AnalyzeArgs {
    request: PathBuf,
    #[arg(long, value_enum, default_value = "ietf-draft-00")]
    profile: ProfileArg,
    #[arg(long)]
    config: Option<PathBuf>,
    /// Absolute URL used to reconstruct scheme/authority for origin-form requests.
    #[arg(long)]
    context: Option<Url>,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
}

#[derive(clap::Args)]
struct VerifyArgs {
    request: PathBuf,
    #[arg(long)]
    jwks: PathBuf,
    #[arg(long, value_enum, default_value = "ietf-draft-00")]
    profile: ProfileArg,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    context: Option<Url>,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
}

#[derive(clap::Args)]
struct SignArgs {
    request: PathBuf,
    #[arg(long, default_value = ".botgate/private.key")]
    key: PathBuf,
    #[arg(long, default_value = ".botgate/public.jwk")]
    jwk: PathBuf,
    #[arg(long)]
    agent: String,
    #[arg(long, default_value = "@authority,@method,@path")]
    components: String,
    #[arg(long, default_value_t = 300)]
    expires_in: i64,
    #[arg(long, default_value = "sig1")]
    label: String,
    /// Emit the legacy bare-string Signature-Agent form used by Cloudflare.
    #[arg(long)]
    legacy_agent: bool,
    #[arg(long)]
    context: Option<Url>,
    #[arg(short, long, default_value = "signed-request.http")]
    output: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    #[value(name = "ietf-draft-00")]
    IetfDraft00,
    Cloudflare,
}
impl From<ProfileArg> for Profile {
    fn from(v: ProfileArg) -> Self {
        match v {
            ProfileArg::IetfDraft00 => Profile::IetfDraft00,
            ProfileArg::Cloudflare => Profile::Cloudflare,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("botgate: {e:#}");
            ExitCode::from(4)
        }
    }
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { force, directory } => {
            init(&directory, force)?;
            Ok(0)
        }
        Command::Inspect(args) | Command::Explain(args) => analyze(args, None, false),
        Command::Verify(args) => verify(args, false),
        Command::Test(args) => verify(args, true),
        Command::Sign(args) => {
            sign(args)?;
            Ok(0)
        }
        Command::Protocol => {
            println!(
                "Protocol: {PROTOCOL}\nPublished: 2026-09-01\nAlgorithms in v0.1: Ed25519\nProfiles: ietf-draft-00, cloudflare"
            );
            Ok(0)
        }
    }
}

fn init(directory: &Path, force: bool) -> Result<()> {
    if directory.exists() && !force {
        bail!(
            "{} already exists; use --force to regenerate the public key files (the private key and botgate.toml are never overwritten)",
            directory.display()
        );
    }
    fs::create_dir_all(directory)?;
    let private = directory.join("private.key");
    let jwk = if private.exists() {
        crypto::jwk_from_private(&private)?
    } else {
        crypto::generate(&private)?
    };
    write_file(
        &directory.join("public.jwk"),
        (serde_json::to_string_pretty(&jwk)? + "\n").as_bytes(),
        true,
    )?;
    write_file(
        &directory.join("directory.json"),
        (serde_json::to_string_pretty(&Jwks { keys: vec![jwk] })? + "\n").as_bytes(),
        true,
    )?;
    // An existing policy may hold local edits; --force only refreshes derived key files.
    let config = directory.join("botgate.toml");
    if !config.exists() {
        write_file(&config, DEFAULT_CONFIG.as_bytes(), false)?;
    }
    println!(
        "Created {}\n  private.key (PKCS#8, mode 0600)\n  public.jwk\n  directory.json\n  botgate.toml",
        directory.display()
    );
    println!(
        "\nThe directory file must be served over HTTPS for conformant Web Bot Auth discovery."
    );
    Ok(())
}

fn analyze(args: AnalyzeArgs, jwks: Option<&Jwks>, mutations: bool) -> Result<u8> {
    let request = Request::read(&args.request)?;
    let parsed = signature::parse(&request)?;
    let config = Config::load(args.config.as_deref())?;
    let mut report = Report::analyze(
        &request,
        &parsed,
        &config.policy,
        args.profile.into(),
        jwks,
        args.context.as_ref(),
        mutations,
    );
    if let Some(source) = &config.source {
        report.policy_source = source.display().to_string();
    }
    emit(&report, args.format)?;
    Ok(if report.has_errors() { 1 } else { 0 })
}

fn verify(args: VerifyArgs, mutations: bool) -> Result<u8> {
    let keys = crypto::read_jwks(&args.jwks)?;
    analyze(
        AnalyzeArgs {
            request: args.request,
            profile: args.profile,
            config: args.config,
            context: args.context,
            format: args.format,
        },
        Some(&keys),
        mutations,
    )
}

fn emit(report: &Report, format: Format) -> Result<()> {
    match format {
        Format::Text => print!("{}", report.text()),
        Format::Json => println!("{}", serde_json::to_string_pretty(report)?),
    }
    Ok(())
}

fn sign(args: SignArgs) -> Result<()> {
    signature::validate_label(&args.label)?;
    if !args.agent.bytes().all(|byte| (b' '..=b'~').contains(&byte)) {
        bail!("--agent must be printable ASCII; use the punycode form for internationalized hosts");
    }
    let agent_url = Url::parse(&args.agent).context("parsing --agent URI")?;
    if agent_url.scheme() != "https" || agent_url.host_str().is_none() {
        bail!("Signature-Agent must be a valid https URI with a host");
    }
    if args.expires_in <= 0 {
        bail!("--expires-in must be positive");
    }
    if args.output.exists() && !args.force {
        bail!(
            "refusing to overwrite {}; use --force",
            args.output.display()
        );
    }
    let mut request = Request::read(&args.request)?;
    for name in ["signature", "signature-input", "signature-agent"] {
        request.remove_header(name);
    }
    let declared_key = crypto::read_jwks(&args.jwk)?
        .keys
        .into_iter()
        .next()
        .context("JWK file contains no keys")?;
    let key = crypto::jwk_from_private(&args.key)?;
    let keyid = crypto::thumbprint(&key)?;
    if crypto::thumbprint(&declared_key)? != keyid {
        bail!("--jwk does not contain the public key corresponding to --key");
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let mut components = Vec::new();
    let mut component_names = BTreeSet::new();
    for name in args
        .components
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_graphic() && byte != b'"' && byte != b'\\' && byte != b','
            })
        {
            bail!("invalid component name {name:?}");
        }
        let normalized = name.to_ascii_lowercase();
        if normalized != "signature-agent" && !component_names.insert(normalized.clone()) {
            bail!("duplicate component name {name}");
        }
        components.push(CoveredComponent {
            name: normalized,
            params: vec![],
        });
    }
    let agent_component = if args.legacy_agent {
        request.set_header(
            "signature-agent",
            format!("\"{}\"", escape_string(&args.agent)),
        );
        CoveredComponent {
            name: "signature-agent".into(),
            params: vec![],
        }
    } else {
        request.set_header(
            "signature-agent",
            format!("{}=\"{}\"", args.label, escape_string(&args.agent)),
        );
        CoveredComponent {
            name: "signature-agent".into(),
            params: vec![("key".into(), Value::String(args.label.clone()))],
        }
    };
    components.retain(|component| component.name != "signature-agent");
    components.push(agent_component);
    let input = SignatureInput {
        label: args.label.clone(),
        components,
        params: vec![
            ("created".into(), Value::Integer(now)),
            (
                "expires".into(),
                Value::Integer({
                    let expires = now
                        .checked_add(args.expires_in)
                        .context("--expires-in overflows the timestamp range")?;
                    if expires > 999_999_999_999_999 {
                        bail!("--expires-in exceeds the Structured Field integer range");
                    }
                    expires
                }),
            ),
            ("keyid".into(), Value::String(keyid)),
            ("tag".into(), Value::String("web-bot-auth".into())),
        ],
    };
    let bytes = crypto::sign(&request, &input, &args.key, args.context.as_ref())?;
    request.set_header(
        "signature-input",
        format!("{}={}", input.label, input.canonical_value()),
    );
    request.set_header("signature", crypto::signature_header(&input.label, &bytes));
    write_file(&args.output, &request.serialize(), args.force)?;
    println!("Wrote {}", args.output.display());
    Ok(())
}

fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn write_file(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if overwrite {
        let mut temporary = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("creating a temporary file in {}", parent.display()))?;
        temporary.write_all(bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(path)
            .map_err(|error| error.error)
            .with_context(|| format!("atomically replacing {}", path.display()))?;
    } else {
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        output.write_all(bytes)?;
        output.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn forced_output_replaces_a_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim");
        let output = directory.path().join("output");
        fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, &output).unwrap();

        write_file(&output, b"replacement", true).unwrap();

        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert_eq!(fs::read(&output).unwrap(), b"replacement");
        assert!(
            !fs::symlink_metadata(&output)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
