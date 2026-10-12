use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

fn botgate() -> Command {
    Command::new(env!("CARGO_BIN_EXE_botgate"))
}

fn init_keys(path: &Path) {
    assert!(
        botgate()
            .args(["init", "--directory"])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn url_mode_sends_original_and_controlled_mutations() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for index in 0..13 {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_head(&mut stream);
            assert!(request.to_ascii_lowercase().contains("signature:"));
            let authenticated = index == 0;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nX-Agent-Authenticated: {authenticated}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        }
    });

    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    init_keys(&keys);
    let url = format!("http://{address}/protected?view=full");
    let output = botgate()
        .arg("test")
        .arg(&url)
        .args(["--agent", "https://agent.example"])
        .arg("--key")
        .arg(keys.join("private.key"))
        .arg("--jwk")
        .arg(keys.join("public.jwk"))
        .arg("--jwks")
        .arg(keys.join("directory.json"))
        .args([
            "--allow-private-target",
            "--allow-http",
            "--auth-header",
            "X-Agent-Authenticated",
            "--authenticated-value",
            "true",
            "--unauthenticated-value",
            "false",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let cases = report["live"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    assert!(cases.iter().all(|case| case["passed"] == true));
    for name in [
        "changed_authority",
        "expired",
        "future_created",
        "long_expiration",
        "missing_expires",
        "unknown_key",
    ] {
        assert!(cases.iter().any(|case| case["name"] == name), "{name}");
    }
}

#[test]
fn private_target_is_blocked_without_explicit_override() {
    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    init_keys(&keys);
    let output = botgate()
        .args(["test", "http://127.0.0.1:9/protected"])
        .args(["--agent", "https://agent.example"])
        .arg("--key")
        .arg(keys.join("private.key"))
        .arg("--jwk")
        .arg(keys.join("public.jwk"))
        .arg("--jwks")
        .arg(keys.join("directory.json"))
        .args([
            "--auth-header",
            "X-Agent-Authenticated",
            "--authenticated-value",
            "true",
            "--unauthenticated-value",
            "false",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("plain HTTP is disabled"), "{error}");
}

#[test]
fn live_testing_rejects_an_expired_original_before_connecting() {
    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    init_keys(&keys);
    let request = temp.path().join("request.http");
    fs::write(
        &request,
        b"GET /protected HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n",
    )
    .unwrap();
    let signed = temp.path().join("signed.http");
    let sign = botgate()
        .arg("sign")
        .arg(&request)
        .arg("--key")
        .arg(keys.join("private.key"))
        .arg("--jwk")
        .arg(keys.join("public.jwk"))
        .args([
            "--agent",
            "https://agent.example",
            "--context",
            "http://127.0.0.1:9/protected",
        ])
        .args(["--expires-in", "1"])
        .arg("--output")
        .arg(&signed)
        .output()
        .unwrap();
    assert!(sign.status.success(), "{sign:?}");
    thread::sleep(Duration::from_secs(2));

    let output = botgate()
        .arg("test")
        .arg(&signed)
        .arg("--jwks")
        .arg(keys.join("directory.json"))
        .args([
            "--live",
            "http://127.0.0.1:9/protected",
            "--allow-private-target",
            "--allow-http",
            "--auth-header",
            "X-Agent-Authenticated",
            "--authenticated-value",
            "true",
            "--unauthenticated-value",
            "false",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("fails configured conformance or policy"),
        "{error}"
    );
}

#[test]
fn verify_can_discover_a_local_test_directory_with_explicit_overrides() {
    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    init_keys(&keys);
    let directory = fs::read(keys.join("directory.json")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_head(&mut stream);
        assert!(request.starts_with("GET /.well-known/http-message-signatures-directory HTTP/1.1"));
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/http-message-signatures-directory+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            directory.len()
        )
        .unwrap();
        stream.write_all(&directory).unwrap();
    });

    let unsigned = temp.path().join("request.http");
    fs::write(&unsigned, b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n").unwrap();
    let signed = temp.path().join("signed.http");
    let sign = botgate()
        .arg("sign")
        .arg(&unsigned)
        .arg("--key")
        .arg(keys.join("private.key"))
        .arg("--jwk")
        .arg(keys.join("public.jwk"))
        .args(["--agent", &format!("http://{address}")])
        .arg("--allow-insecure-agent")
        .arg("--output")
        .arg(&signed)
        .output()
        .unwrap();
    assert!(sign.status.success(), "{sign:?}");
    let output = botgate()
        .arg("verify")
        .arg(&signed)
        .args([
            "--discover",
            "--allow-private-discovery",
            "--allow-insecure-discovery",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    // HTTP discovery is intentionally still reported as non-conformant.
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["signatures"][0]["cryptographic_status"], "valid");
    assert_eq!(report["signatures"][0]["identity_status"], "valid");
}

#[test]
fn directory_serve_exposes_only_the_well_known_resource() {
    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    init_keys(&keys);
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut child = botgate()
        .args(["directory", "serve", "--directory"])
        .arg(keys.join("directory.json"))
        .args(["--port", &port.to_string(), "--once"])
        .spawn()
        .unwrap();
    let mut stream = (0..30)
        .find_map(|_| match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => Some(stream),
            Err(_) => {
                thread::sleep(Duration::from_millis(25));
                None
            }
        })
        .expect("directory server did not start");
    // TCP may split a request line or headers at any byte boundary.
    stream.write_all(b"GET /.well-known/http-message-").unwrap();
    thread::sleep(Duration::from_millis(10));
    stream
        .write_all(b"signatures-directory HTTP/1.1\r\nHost: localhost\r\n")
        .unwrap();
    thread::sleep(Duration::from_millis(10));
    stream.write_all(b"\r\n").unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(child.wait().unwrap().success());
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("application/http-message-signatures-directory+json"));
}

#[test]
fn built_in_demo_verifier_passes_the_strict_live_matrix() {
    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    init_keys(&keys);
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/live-test.toml");
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut server = botgate()
        .args(["demo", "serve", "--jwks"])
        .arg(keys.join("directory.json"))
        .arg("--config")
        .arg(&config)
        .args(["--port", &port.to_string(), "--max-requests", "13"])
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(150));
    let url = format!("http://127.0.0.1:{port}/protected?view=full");
    let output = botgate()
        .arg("test")
        .arg(&url)
        .args(["--agent", "https://agent.example"])
        .arg("--key")
        .arg(keys.join("private.key"))
        .arg("--jwk")
        .arg(keys.join("public.jwk"))
        .arg("--jwks")
        .arg(keys.join("directory.json"))
        .arg("--config")
        .arg(&config)
        .args(["--format", "json"])
        .output()
        .unwrap();
    if !output.status.success() {
        let _ = server.kill();
    }
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(server.wait().unwrap().success());
}

#[test]
fn built_in_demo_distinguishes_a_conformant_weak_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    init_keys(&keys);
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/weak-live-test.toml");
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut server = botgate()
        .args(["demo", "serve", "--jwks"])
        .arg(keys.join("directory.json"))
        .arg("--config")
        .arg(&config)
        .args(["--port", &port.to_string(), "--max-requests", "13"])
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(150));
    let url = format!("http://127.0.0.1:{port}/protected?view=full");
    let output = botgate()
        .arg("test")
        .arg(&url)
        .args([
            "--agent",
            "https://agent.example",
            "--components",
            "@authority",
        ])
        .arg("--key")
        .arg(keys.join("private.key"))
        .arg("--jwk")
        .arg(keys.join("public.jwk"))
        .arg("--jwks")
        .arg(keys.join("directory.json"))
        .arg("--config")
        .arg(&config)
        .args(["--format", "json"])
        .output()
        .unwrap();
    if !output.status.success() {
        let _ = server.kill();
    }
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(server.wait().unwrap().success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    for name in ["changed_method", "changed_path", "changed_query"] {
        let case = report["live"]["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        assert_eq!(case["expected_crypto"], "still_valid", "{name}");
        assert_eq!(case["observed_authentication"], "authenticated", "{name}");
        assert_eq!(case["observed_access"], "allowed", "{name}");
        assert_eq!(case["passed"], true, "{name}");
    }
}

#[test]
fn valid_identity_can_be_authenticated_but_denied_access() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for index in 0..13 {
            let (mut stream, _) = listener.accept().unwrap();
            read_head(&mut stream);
            let authenticated = matches!(index, 0..=3);
            let access = if index == 2 { "denied" } else { "allowed" };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nX-Agent-Authenticated: {authenticated}\r\nX-Agent-Access: {access}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        }
    });

    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    init_keys(&keys);
    let config = temp.path().join("live.toml");
    fs::write(
        &config,
        r#"[policy]
require_authority = true
require_method = false
require_path = false
query = "ignore"
body = "ignore"
max_age_seconds = 300
max_lifetime_seconds = 300
allowed_future_skew_seconds = 30
require_nonce = false

[target]
allow_private = true
allow_http = true

[expect]
header = "X-Agent-Authenticated"
authenticated_value = "true"
unauthenticated_value = "false"

[expect.access]
header = "X-Agent-Access"
allowed_value = "allowed"
denied_value = "denied"

[expect.access.cases]
changed_path = "denied"
"#,
    )
    .unwrap();
    let url = format!("http://{address}/protected?view=full");
    let output = botgate()
        .arg("test")
        .arg(&url)
        .args([
            "--agent",
            "https://agent.example",
            "--components",
            "@authority",
        ])
        .arg("--key")
        .arg(keys.join("private.key"))
        .arg("--jwk")
        .arg(keys.join("public.jwk"))
        .arg("--jwks")
        .arg(keys.join("directory.json"))
        .arg("--config")
        .arg(&config)
        .args(["--format", "json"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let path = report["live"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "changed_path")
        .unwrap();
    assert_eq!(path["expected_crypto"], "still_valid");
    assert_eq!(path["observed_authentication"], "authenticated");
    assert_eq!(path["observed_access"], "denied");
    assert_eq!(path["passed"], true);
}

#[test]
fn self_contained_demos_expose_distinct_trust_boundaries() {
    let strict = run_demo("strict");
    assert_case(
        &strict,
        "changed_path",
        "invalid",
        "unauthenticated",
        "denied",
    );

    let weak = run_demo("weak");
    assert_case(
        &weak,
        "changed_method",
        "still_valid",
        "authenticated",
        "allowed",
    );
    assert_case(
        &weak,
        "changed_path",
        "still_valid",
        "authenticated",
        "denied",
    );

    let access = run_demo("access");
    assert_case(&access, "original", "valid", "authenticated", "denied");
}

fn run_demo(name: &str) -> Value {
    let output = botgate()
        .args(["demo", name, "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_case(
    report: &Value,
    name: &str,
    expected_crypto: &str,
    authentication: &str,
    access: &str,
) {
    let case = report["live"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap();
    assert_eq!(case["expected_crypto"], expected_crypto, "{name}");
    assert_eq!(case["observed_authentication"], authentication, "{name}");
    assert_eq!(case["observed_access"], access, "{name}");
    assert_eq!(case["passed"], true, "{name}");
}

fn read_head(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let size = stream.read(&mut buffer).unwrap();
        if size == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..size]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(bytes).unwrap()
}

/// Serves one key directory response and reports whether it was contacted; gives up
/// once `stop` is set (or after 10s).
fn serve_directory_once(
    listener: TcpListener,
    directory: Vec<u8>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> thread::JoinHandle<bool> {
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    read_head(&mut stream);
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/http-message-signatures-directory+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        directory.len()
                    )
                    .unwrap();
                    stream.write_all(&directory).unwrap();
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if stop.load(std::sync::atomic::Ordering::SeqCst)
                        || std::time::Instant::now() > deadline
                    {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("{error}"),
            }
        }
    })
}

#[test]
fn discovery_never_attributes_an_attacker_key_to_another_identity() {
    use botgate::{crypto, http_message::Request, signature};

    let temp = tempfile::tempdir().unwrap();
    let victim_keys = temp.path().join("victim");
    init_keys(&victim_keys);
    let attacker_private = temp.path().join("attacker.key");
    let attacker_jwk = crypto::generate(&attacker_private).unwrap();
    let attacker_keyid = crypto::thumbprint(&attacker_jwk).unwrap();
    let attacker_directory = serde_json::to_vec(&crypto::Jwks {
        keys: vec![attacker_jwk],
    })
    .unwrap();

    let victim_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let attacker_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let victim = format!("http://{}", victim_listener.local_addr().unwrap());
    let attacker = format!("http://{}", attacker_listener.local_addr().unwrap());

    // One signature covers two Signature-Agent members; the attacker's is listed first,
    // the victim's is keyed to the signature label and is the identity that gets reported.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let raw = format!(
        "GET / HTTP/1.1\r\nHost: example.test\r\nSignature-Agent: sig1=\"{victim}\", attacker=\"{attacker}\"\r\nSignature-Input: sig1=(\"@authority\" \"@method\" \"@path\" \"signature-agent\";key=\"attacker\" \"signature-agent\";key=\"sig1\");created={now};expires={};keyid=\"{attacker_keyid}\";tag=\"web-bot-auth\"\r\nSignature: sig1=:AA==:\r\n\r\n",
        now + 300
    );
    let request = Request::parse(raw.as_bytes()).unwrap();
    let parsed = signature::parse(&request).unwrap();
    let bytes = crypto::sign(&request, &parsed.inputs[0], &attacker_private, None).unwrap();
    let signed = temp.path().join("attack.http");
    fs::write(
        &signed,
        raw.replace(
            "Signature: sig1=:AA==:",
            &format!("Signature: {}", crypto::signature_header("sig1", &bytes)),
        ),
    )
    .unwrap();

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let victim_server = serve_directory_once(
        victim_listener,
        fs::read(victim_keys.join("directory.json")).unwrap(),
        stop.clone(),
    );
    let attacker_server = serve_directory_once(attacker_listener, attacker_directory, stop.clone());
    let output = botgate()
        .arg("verify")
        .arg(&signed)
        .args([
            "--discover",
            "--allow-private-discovery",
            "--allow-insecure-discovery",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);

    assert!(
        victim_server.join().unwrap(),
        "the reported identity's directory was not fetched"
    );
    assert!(
        !attacker_server.join().unwrap(),
        "the attacker's key source was contacted"
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let signature = &report["signatures"][0];
    assert_eq!(signature["signature_agent"], victim.as_str());
    assert_eq!(signature["cryptographic_status"], "invalid");
    assert_ne!(signature["identity_status"], "valid");
}

#[test]
fn discovery_pins_every_resolved_address() {
    use std::net::ToSocketAddrs;

    // Needs a name with several addresses; `localhost` has two (::1, 127.0.0.1) on macOS
    // and many Linux systems. With a single address there is nothing to distinguish.
    let mut addresses: Vec<std::net::IpAddr> = ("localhost", 0)
        .to_socket_addrs()
        .unwrap()
        .map(|address| address.ip())
        .collect();
    addresses.dedup();
    if addresses.len() < 2 {
        eprintln!("skipping: localhost resolves to a single address");
        return;
    }
    // Serve only on the first address. Pinning just one address (the old bug kept the last)
    // makes discovery fail; pinning all of them lets the connection reach this one.
    let listener = TcpListener::bind((addresses[0], 0)).unwrap();
    let port = listener.local_addr().unwrap().port();

    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    init_keys(&keys);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = serve_directory_once(
        listener,
        fs::read(keys.join("directory.json")).unwrap(),
        stop.clone(),
    );

    let unsigned = temp.path().join("request.http");
    fs::write(&unsigned, b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n").unwrap();
    let signed = temp.path().join("signed.http");
    let sign = botgate()
        .arg("sign")
        .arg(&unsigned)
        .arg("--key")
        .arg(keys.join("private.key"))
        .arg("--jwk")
        .arg(keys.join("public.jwk"))
        .args(["--agent", &format!("http://localhost:{port}")])
        .arg("--allow-insecure-agent")
        .arg("--output")
        .arg(&signed)
        .output()
        .unwrap();
    assert!(sign.status.success(), "{sign:?}");
    let output = botgate()
        .arg("verify")
        .arg(&signed)
        .args([
            "--discover",
            "--allow-private-discovery",
            "--allow-insecure-discovery",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);

    assert!(
        server.join().unwrap(),
        "discovery did not reach {}",
        addresses[0]
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!("{output:?}");
    });
    assert_eq!(report["signatures"][0]["identity_status"], "valid");
}
