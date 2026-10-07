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
    stream
        .write_all(
            b"GET /.well-known/http-message-signatures-directory HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .unwrap();
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
