use anyhow::{Context, Result, bail};
use botgate::{
    PROTOCOL,
    config::{Config, DEFAULT_CONFIG},
    crypto::{self, Jwks},
    demo, directory, discovery,
    http_message::Request,
    live,
    network::NetworkPolicy,
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
    time::{Duration, SystemTime, UNIX_EPOCH},
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
    /// Verify an Ed25519 signature using local or safely discovered key material.
    Verify(VerifyArgs),
    /// Produce an offline matrix, or run controlled mutations against an authorized target.
    Test(TestArgs),
    /// Sign a raw HTTP request with the generated Ed25519 test key.
    Sign(SignArgs),
    /// Serve test key material for local development.
    Directory {
        #[command(subcommand)]
        command: DirectoryCommand,
    },
    /// Run a local verifier with an explicit authentication oracle.
    Demo {
        #[command(subcommand)]
        command: DemoCommand,
    },
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
    #[arg(long, conflicts_with = "discover")]
    jwks: Option<PathBuf>,
    /// Resolve the covered Signature-Agent URL with SSRF protections.
    #[arg(long)]
    discover: bool,
    /// Permit private, loopback, or link-local discovery only for an authorized test service.
    #[arg(long, requires = "discover")]
    allow_private_discovery: bool,
    /// Permit HTTP discovery only for a local test server; public discovery requires HTTPS.
    #[arg(long, requires = "discover")]
    allow_insecure_discovery: bool,
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
struct TestArgs {
    /// Signed request file for offline testing, or an authorized URL to sign and test live.
    source: String,
    #[arg(long, default_value = ".botgate/directory.json")]
    jwks: PathBuf,
    /// Send the known-valid request and safe mutations to this authorized target.
    #[arg(long)]
    live: Option<Url>,
    /// Signature-Agent URL used when SOURCE is a URL.
    #[arg(long)]
    agent: Option<String>,
    #[arg(long, default_value = ".botgate/private.key")]
    key: PathBuf,
    #[arg(long, default_value = ".botgate/public.jwk")]
    jwk: PathBuf,
    #[arg(long, default_value = "@authority,@method,@path,@query")]
    components: String,
    #[arg(long, default_value_t = 300)]
    expires_in: i64,
    #[arg(long, default_value = "sig1")]
    label: String,
    #[arg(long)]
    legacy_agent: bool,
    /// Permit an HTTP Signature-Agent URL only for an authorized local test directory.
    #[arg(long)]
    allow_insecure_agent: bool,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "ietf-draft-00")]
    profile: ProfileArg,
    #[arg(long)]
    context: Option<Url>,
    #[arg(long, value_delimiter = ',')]
    accepted_status: Vec<u16>,
    #[arg(long, value_delimiter = ',')]
    rejected_status: Vec<u16>,
    #[arg(long)]
    allow_private_target: bool,
    #[arg(long)]
    allow_http: bool,
    #[arg(long)]
    allow_unsafe_methods: bool,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
}

#[derive(Subcommand)]
enum DirectoryCommand {
    /// Serve directory.json on the well-known path for local tests.
    Serve {
        #[arg(long, default_value = ".botgate/directory.json")]
        directory: PathBuf,
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(long, default_value_t = 8787)]
        port: u16,
        #[arg(long)]
        allow_non_loopback: bool,
        #[arg(long, hide = true)]
        once: bool,
    },
}

#[derive(Subcommand)]
enum DemoCommand {
    /// Serve a local Web Bot Auth verifier for weak/strict policy demonstrations.
    Serve {
        #[arg(long, default_value = ".botgate/directory.json")]
        jwks: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(long, default_value_t = 8080)]
        port: u16,
        #[arg(long)]
        allow_non_loopback: bool,
        #[arg(long, hide = true)]
        max_requests: Option<usize>,
    },
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
    /// Permit an HTTP Signature-Agent URL only for an authorized local test directory.
    #[arg(long)]
    allow_insecure_agent: bool,
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
        Command::Inspect(args) | Command::Explain(args) => analyze(args, None, false, false),
        Command::Verify(args) => verify(args),
        Command::Test(args) => test(args),
        Command::Sign(args) => {
            sign(args)?;
            Ok(0)
        }
        Command::Directory { command } => match command {
            DirectoryCommand::Serve {
                directory: path,
                bind,
                port,
                allow_non_loopback,
                once,
            } => {
                directory::serve(
                    &path,
                    directory::parse_bind(&bind, port)?,
                    allow_non_loopback,
                    once,
                )?;
                Ok(0)
            }
        },
        Command::Demo { command } => match command {
            DemoCommand::Serve {
                jwks,
                config,
                bind,
                port,
                allow_non_loopback,
                max_requests,
            } => {
                let config = Config::load(config.as_deref())?;
                demo::serve(
                    &jwks,
                    &config.policy,
                    directory::parse_bind(&bind, port)?,
                    allow_non_loopback,
                    max_requests,
                )?;
                Ok(0)
            }
        },
        Command::Protocol => {
            println!(
                "Protocol: {PROTOCOL}\nPublished: 2026-09-01\nAlgorithms: Ed25519\nProfiles: ietf-draft-00, cloudflare"
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

fn analyze(
    args: AnalyzeArgs,
    jwks: Option<&Jwks>,
    identity_discovered: bool,
    mutations: bool,
) -> Result<u8> {
    let request = Request::read(&args.request)?;
    let parsed = signature::parse(&request)?;
    let config = Config::load(args.config.as_deref())?;
    let mut report = Report::analyze(
        &request,
        &parsed,
        &config.policy,
        args.profile.into(),
        jwks,
        identity_discovered,
        args.context.as_ref(),
        mutations,
    );
    if let Some(source) = &config.source {
        report.policy_source = source.display().to_string();
    }
    emit(&report, args.format)?;
    Ok(if report.has_errors() { 1 } else { 0 })
}

fn verify(args: VerifyArgs) -> Result<u8> {
    if args.jwks.is_none() && !args.discover {
        bail!("verify requires either --jwks or --discover");
    }
    let discovered;
    let keys = if args.discover {
        let request = Request::read(&args.request)?;
        let parsed = signature::parse(&request)?;
        if parsed.inputs.len() != 1 {
            bail!(
                "--discover currently requires exactly one signature so key material cannot be attributed across Signature-Agent identities"
            );
        }
        let policy = NetworkPolicy {
            allow_private: args.allow_private_discovery,
            allow_http: args.allow_insecure_discovery,
            timeout: Duration::from_secs(10),
            max_response_bytes: 1024 * 1024,
        };
        discovered = discovery::discover(&request, &parsed.inputs[0], &policy)?.jwks;
        &discovered
    } else {
        discovered = crypto::read_jwks(args.jwks.as_deref().unwrap())?;
        &discovered
    };
    analyze(
        AnalyzeArgs {
            request: args.request,
            profile: args.profile,
            config: args.config,
            context: args.context,
            format: args.format,
        },
        Some(keys),
        args.discover,
        false,
    )
}

fn test(args: TestArgs) -> Result<u8> {
    let mut config = Config::load(args.config.as_deref())?;
    if !args.accepted_status.is_empty() {
        config.expect.accepted_statuses = args.accepted_status.clone();
    }
    if !args.rejected_status.is_empty() {
        config.expect.rejected_statuses = args.rejected_status.clone();
    }
    config.validate()?;
    let source_url = Url::parse(&args.source)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"));
    let configured_target = config
        .target
        .url
        .as_deref()
        .map(Url::parse)
        .transpose()
        .context("parsing target.url")?;
    let target = args
        .live
        .clone()
        .or_else(|| source_url.clone())
        .or(configured_target);
    let context = args.context.clone().or_else(|| target.clone());
    let request = if let Some(url) = &source_url {
        let agent = args.agent.as_deref().ok_or_else(|| {
            anyhow::anyhow!("testing a URL requires --agent (the Signature-Agent identity URL)")
        })?;
        let mut request = request_for_url(url)?;
        sign_request(
            &mut request,
            &args.key,
            &args.jwk,
            agent,
            &args.components,
            args.expires_in,
            None,
            &args.label,
            args.legacy_agent,
            args.allow_insecure_agent,
            Some(url),
        )?;
        request
    } else {
        Request::read(Path::new(&args.source))?
    };
    let parsed = signature::parse(&request)?;
    let keys = crypto::read_jwks(&args.jwks)?;
    let mut report = Report::analyze(
        &request,
        &parsed,
        &config.policy,
        args.profile.into(),
        Some(&keys),
        false,
        context.as_ref(),
        true,
    );
    if let Some(source) = &config.source {
        report.policy_source = source.display().to_string();
    }
    if let Some(target) = target.as_ref() {
        if parsed.inputs.len() != 1 {
            bail!("live testing currently requires exactly one signature");
        }
        let input = &parsed.inputs[0];
        let signature = parsed
            .signatures
            .get(&input.label)
            .context("live testing requires a matching Signature member")?;
        crypto::verify(&request, input, signature, &keys, context.as_ref())
            .context("refusing live testing because the original signature is not locally valid")?;
        let network = NetworkPolicy {
            allow_private: args.allow_private_target || config.target.allow_private,
            allow_http: args.allow_http || config.target.allow_http,
            timeout: Duration::from_secs(config.target.timeout_seconds),
            max_response_bytes: config.target.max_response_bytes,
        };
        let prepared =
            if let (Some(url), Some(agent)) = (source_url.as_ref(), args.agent.as_deref()) {
                prepared_live_cases(&request, url, agent, &args, &config.tests)?
            } else {
                Vec::new()
            };
        let live_report = live::run(
            &request,
            input,
            target,
            &config.expect,
            &config.tests,
            &network,
            args.allow_unsafe_methods,
            prepared,
        )?;
        match args.format {
            Format::Text => {
                print!("{}\n{}", report.text(), live_report.text());
            }
            Format::Json => println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "analysis": report,
                    "live": live_report,
                }))?
            ),
        }
        return Ok(if report.has_errors() || live_report.has_failures() {
            1
        } else {
            0
        });
    }
    emit(&report, args.format)?;
    Ok(if report.has_errors() { 1 } else { 0 })
}

fn prepared_live_cases(
    original: &Request,
    target: &Url,
    agent: &str,
    args: &TestArgs,
    tests: &botgate::config::Tests,
) -> Result<Vec<live::PreparedCase>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let mut cases = Vec::new();
    for (enabled, name, timestamps, expected_crypto) in [
        (
            tests.expired,
            "expired",
            (now - 600, Some(now - 300)),
            "freshness_invalid",
        ),
        (
            tests.future_created,
            "future_created",
            (now + 300, Some(now + 600)),
            "freshness_invalid",
        ),
        (
            tests.long_expiration,
            "long_expiration",
            (now, Some(now + 25 * 60 * 60)),
            "policy_invalid",
        ),
        (
            tests.missing_expires,
            "missing_expires",
            (now, None),
            "conformance_invalid",
        ),
    ] {
        if enabled {
            let mut request = original.clone();
            sign_request(
                &mut request,
                &args.key,
                &args.jwk,
                agent,
                &args.components,
                args.expires_in,
                Some(timestamps),
                &args.label,
                args.legacy_agent,
                args.allow_insecure_agent,
                Some(target),
            )?;
            cases.push(live::PreparedCase {
                name: name.into(),
                expected_crypto: expected_crypto.into(),
                expected_server: live::Outcome::Rejected,
                request,
            });
        }
    }
    if tests.unknown_key {
        let temporary = tempfile::tempdir().context("creating temporary unknown key")?;
        let private = temporary.path().join("private.key");
        let public = temporary.path().join("public.jwk");
        let jwk = crypto::generate(&private)?;
        write_file(
            &public,
            (serde_json::to_string_pretty(&jwk)? + "\n").as_bytes(),
            false,
        )?;
        let mut request = original.clone();
        sign_request(
            &mut request,
            &private,
            &public,
            agent,
            &args.components,
            args.expires_in,
            None,
            &args.label,
            args.legacy_agent,
            args.allow_insecure_agent,
            Some(target),
        )?;
        cases.push(live::PreparedCase {
            name: "unknown_key".into(),
            expected_crypto: "unverified_key".into(),
            expected_server: live::Outcome::Rejected,
            request,
        });
    }
    Ok(cases)
}

fn emit(report: &Report, format: Format) -> Result<()> {
    match format {
        Format::Text => print!("{}", report.text()),
        Format::Json => println!("{}", serde_json::to_string_pretty(report)?),
    }
    Ok(())
}

fn sign(args: SignArgs) -> Result<()> {
    if args.output.exists() && !args.force {
        bail!(
            "refusing to overwrite {}; use --force",
            args.output.display()
        );
    }
    let mut request = Request::read(&args.request)?;
    sign_request(
        &mut request,
        &args.key,
        &args.jwk,
        &args.agent,
        &args.components,
        args.expires_in,
        None,
        &args.label,
        args.legacy_agent,
        args.allow_insecure_agent,
        args.context.as_ref(),
    )?;
    write_file(&args.output, &request.serialize(), args.force)?;
    println!("Wrote {}", args.output.display());
    Ok(())
}

fn request_for_url(url: &Url) -> Result<Request> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("target URL credentials and fragments are not allowed");
    }
    if !matches!(url.scheme(), "http" | "https") {
        bail!("target URL must use http or https");
    }
    let host = match url.host().context("target URL has no host")? {
        url::Host::Domain(value) => value.to_ascii_lowercase(),
        url::Host::Ipv4(value) => value.to_string(),
        url::Host::Ipv6(value) => format!("[{value}]"),
    };
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    let mut target = if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    Ok(Request {
        method: "GET".into(),
        target,
        version: "HTTP/1.1".into(),
        headers: vec![("host".into(), authority)],
        body: Vec::new(),
    })
}

#[allow(clippy::too_many_arguments)]
fn sign_request(
    request: &mut Request,
    key_path: &Path,
    jwk_path: &Path,
    agent: &str,
    component_list: &str,
    expires_in: i64,
    timestamps: Option<(i64, Option<i64>)>,
    label: &str,
    legacy_agent: bool,
    allow_insecure_agent: bool,
    context: Option<&Url>,
) -> Result<()> {
    signature::validate_label(label)?;
    if !agent.bytes().all(|byte| (b' '..=b'~').contains(&byte)) {
        bail!("--agent must be printable ASCII; use the punycode form for internationalized hosts");
    }
    let agent_url = Url::parse(agent).context("parsing --agent URI")?;
    if agent_url.host_str().is_none()
        || !(agent_url.scheme() == "https"
            || (allow_insecure_agent && agent_url.scheme() == "http"))
    {
        bail!("Signature-Agent must be a valid https URI with a host");
    }
    if expires_in <= 0 {
        bail!("--expires-in must be positive");
    }
    for name in ["signature", "signature-input", "signature-agent"] {
        request.remove_header(name);
    }
    let declared_key = crypto::read_jwks(jwk_path)?
        .keys
        .into_iter()
        .next()
        .context("JWK file contains no keys")?;
    let key = crypto::jwk_from_private(key_path)?;
    let keyid = crypto::thumbprint(&key)?;
    if crypto::thumbprint(&declared_key)? != keyid {
        bail!("--jwk does not contain the public key corresponding to --key");
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let (created, expires) = match timestamps {
        Some(values) => values,
        None => (
            now,
            Some(
                now.checked_add(expires_in)
                    .context("--expires-in overflows the timestamp range")?,
            ),
        ),
    };
    if created.unsigned_abs() > 999_999_999_999_999
        || expires.is_some_and(|value| value.unsigned_abs() > 999_999_999_999_999)
    {
        bail!("signature timestamps exceed the Structured Field integer range");
    }
    let mut components = Vec::new();
    let mut component_names = BTreeSet::new();
    for name in component_list
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
    let agent_component = if legacy_agent {
        request.set_header("signature-agent", format!("\"{}\"", escape_string(agent)));
        CoveredComponent {
            name: "signature-agent".into(),
            params: vec![],
        }
    } else {
        request.set_header(
            "signature-agent",
            format!("{}=\"{}\"", label, escape_string(agent)),
        );
        CoveredComponent {
            name: "signature-agent".into(),
            params: vec![("key".into(), Value::String(label.to_string()))],
        }
    };
    components.retain(|component| component.name != "signature-agent");
    components.push(agent_component);
    let mut params = vec![
        ("created".into(), Value::Integer(created)),
        ("keyid".into(), Value::String(keyid)),
        ("tag".into(), Value::String("web-bot-auth".into())),
    ];
    if let Some(expires) = expires {
        params.insert(1, ("expires".into(), Value::Integer(expires)));
    }
    let input = SignatureInput {
        label: label.to_string(),
        components,
        params,
    };
    let bytes = crypto::sign(request, &input, key_path, context)?;
    request.set_header(
        "signature-input",
        format!("{}={}", input.label, input.canonical_value()),
    );
    request.set_header("signature", crypto::signature_header(&input.label, &bytes));
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
