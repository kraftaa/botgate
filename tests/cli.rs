use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn botgate() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_botgate"));
    // Run outside the repository so a developer's local .botgate/ policy is never picked up.
    command.current_dir(env!("CARGO_TARGET_TMPDIR"));
    command
}

#[test]
fn unsigned_request_is_a_conformance_failure() {
    let request = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/request.http");
    let status = botgate().arg("inspect").arg(request).status().unwrap();
    assert_eq!(status.code(), Some(1));
}

#[test]
fn init_force_reuses_the_private_key() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("keys");
    assert!(
        botgate()
            .args(["init", "--directory"])
            .arg(&directory)
            .status()
            .unwrap()
            .success()
    );
    let before = fs::read(directory.join("private.key")).unwrap();
    assert!(
        botgate()
            .args(["init", "--force", "--directory"])
            .arg(&directory)
            .status()
            .unwrap()
            .success()
    );
    let after = fs::read(directory.join("private.key")).unwrap();
    assert_eq!(before, after);
}

#[test]
fn sign_rejects_mismatched_private_and_public_keys() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    for directory in [&first, &second] {
        assert!(
            botgate()
                .args(["init", "--directory"])
                .arg(directory)
                .status()
                .unwrap()
                .success()
        );
    }
    let request = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/request.http");
    let output = temp.path().join("signed.http");
    let status = botgate()
        .arg("sign")
        .arg(request)
        .arg("--key")
        .arg(first.join("private.key"))
        .arg("--jwk")
        .arg(second.join("public.jwk"))
        .args(["--agent", "https://agent.example", "--output"])
        .arg(output)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(4));
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn init_keys(directory: &Path) {
    assert!(
        botgate()
            .args(["init", "--directory"])
            .arg(directory)
            .status()
            .unwrap()
            .success()
    );
}

/// Signs `request` with a fresh key in `temp` and returns (signed request, JWKS path).
fn sign(temp: &Path, request: &Path, components: &str) -> (PathBuf, PathBuf) {
    let keys = temp.join("keys");
    init_keys(&keys);
    let signed = temp.join("signed.http");
    let output = botgate()
        .arg("sign")
        .arg(request)
        .arg("--key")
        .arg(keys.join("private.key"))
        .arg("--jwk")
        .arg(keys.join("public.jwk"))
        .args([
            "--agent",
            "https://agent.example",
            "--components",
            components,
        ])
        .arg("--output")
        .arg(&signed)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    (signed, keys.join("directory.json"))
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn finding_ids(report: &Value) -> Vec<&str> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect()
}

#[test]
fn verify_json_reports_valid_signature_with_key_only_identity() {
    let temp = tempfile::tempdir().unwrap();
    let (signed, jwks) = sign(
        temp.path(),
        &example("request.http"),
        "@authority,@method,@path,@query",
    );
    let output = botgate()
        .arg("verify")
        .arg(&signed)
        .arg("--jwks")
        .arg(&jwks)
        .arg("--config")
        .arg(example("strict-policy.toml"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = json(&output);
    assert_eq!(
        report["protocol"],
        "draft-ietf-webbotauth-httpsig-protocol-00"
    );
    assert_eq!(report["request"]["method"], "GET");
    let signature = &report["signatures"][0];
    assert_eq!(signature["label"], "sig1");
    assert_eq!(signature["cryptographic_status"], "valid");
    assert_eq!(signature["identity_status"], "key_only");
    assert_eq!(signature["signature_agent"], "https://agent.example");
    for property in ["authority", "method", "path", "query"] {
        assert_eq!(
            signature["effective_coverage"][property], true,
            "{property}"
        );
    }
    assert_eq!(
        signature["effective_coverage"]["body_digest_valid"],
        Value::Null
    );
    assert!(finding_ids(&report).contains(&"BG-K100"));
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["level"] != "error")
    );
}

#[test]
fn inspect_json_does_not_claim_verification() {
    let temp = tempfile::tempdir().unwrap();
    let (signed, _) = sign(
        temp.path(),
        &example("request.http"),
        "@authority,@method,@path",
    );
    let output = botgate()
        .arg("inspect")
        .arg(&signed)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = json(&output);
    assert_eq!(
        report["signatures"][0]["cryptographic_status"],
        "not_verified"
    );
    assert_eq!(report["signatures"][0]["identity_status"], "unresolved");
    assert!(report.get("mutations").is_none());
}

#[test]
fn tampered_path_fails_verification_in_json() {
    let temp = tempfile::tempdir().unwrap();
    let (signed, jwks) = sign(
        temp.path(),
        &example("request.http"),
        "@authority,@method,@path",
    );
    let text = fs::read_to_string(&signed).unwrap();
    fs::write(&signed, text.replacen("/orders/123", "/orders/124", 1)).unwrap();
    let output = botgate()
        .arg("verify")
        .arg(&signed)
        .arg("--jwks")
        .arg(&jwks)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = json(&output);
    assert_eq!(report["signatures"][0]["cryptographic_status"], "invalid");
    assert!(finding_ids(&report).contains(&"BG-K201"));
}

#[test]
fn missing_query_coverage_fails_strict_policy_in_json() {
    let temp = tempfile::tempdir().unwrap();
    let (signed, jwks) = sign(
        temp.path(),
        &example("request.http"),
        "@authority,@method,@path",
    );
    let output = botgate()
        .arg("verify")
        .arg(&signed)
        .arg("--jwks")
        .arg(&jwks)
        .arg("--config")
        .arg(example("strict-policy.toml"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = json(&output);
    assert_eq!(report["signatures"][0]["cryptographic_status"], "valid");
    assert_eq!(
        report["signatures"][0]["effective_coverage"]["query"],
        false
    );
    assert!(finding_ids(&report).contains(&"BG-P104"));
}

#[test]
fn test_command_emits_mutation_matrix_in_json() {
    let temp = tempfile::tempdir().unwrap();
    let (signed, jwks) = sign(
        temp.path(),
        &example("request.http"),
        "@authority,@method,@path",
    );
    let output = botgate()
        .arg("test")
        .arg(&signed)
        .arg("--jwks")
        .arg(&jwks)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let mutations = json(&output)["mutations"].as_array().unwrap().clone();
    assert!(!mutations.is_empty());
    let changed_query = mutations
        .iter()
        .find(|m| m["name"] == "changed_query")
        .unwrap();
    assert_eq!(changed_query["expected_crypto"], "still_valid");
}

#[test]
fn unsigned_request_json_reports_no_signatures() {
    let output = botgate()
        .arg("inspect")
        .arg(example("request.http"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report = json(&output);
    assert_eq!(report["signatures"].as_array().unwrap().len(), 0);
    assert!(finding_ids(&report).contains(&"BG-C100"));
}

const SIGNED_HEAD: &str =
    "GET / HTTP/1.1\r\nHost: example.test\r\nSignature-Agent: sig1=\"https://agent.example\"\r\n";

#[test]
fn malformed_inputs_are_input_errors() {
    let cases: &[(&str, String)] = &[
        ("empty file", String::new()),
        (
            "no blank line",
            "GET / HTTP/1.1\r\nHost: example.test\r\n".into(),
        ),
        (
            "bad version",
            "GET / HTTP/2\r\nHost: example.test\r\n\r\n".into(),
        ),
        (
            "extra request-line token",
            "GET / HTTP/1.1 x\r\n\r\n".into(),
        ),
        (
            "folded header",
            "GET / HTTP/1.1\r\nHost: example.test\r\n continued\r\n\r\n".into(),
        ),
        (
            "header without colon",
            "GET / HTTP/1.1\r\nHost example.test\r\n\r\n".into(),
        ),
        (
            "control byte in value",
            "GET / HTTP/1.1\r\nHost: exa\x01mple.test\r\n\r\n".into(),
        ),
        (
            "fragment in target",
            "GET https://example.test/#x HTTP/1.1\r\n\r\n".into(),
        ),
        (
            "duplicate Signature-Input label",
            format!(
                "{SIGNED_HEAD}Signature-Input: sig1=(\"@authority\"), sig1=(\"@method\")\r\nSignature: sig1=:AA==:\r\n\r\n"
            ),
        ),
        (
            "Signature is not a byte sequence",
            format!(
                "{SIGNED_HEAD}Signature-Input: sig1=(\"@authority\")\r\nSignature: sig1=\"abc\"\r\n\r\n"
            ),
        ),
        (
            "integer over 15 digits",
            format!(
                "{SIGNED_HEAD}Signature-Input: sig1=(\"@authority\");created=1234567890123456\r\nSignature: sig1=:AA==:\r\n\r\n"
            ),
        ),
        (
            "unterminated inner list",
            format!(
                "{SIGNED_HEAD}Signature-Input: sig1=(\"@authority\"\r\nSignature: sig1=:AA==:\r\n\r\n"
            ),
        ),
        (
            "duplicate covered component",
            format!(
                "{SIGNED_HEAD}Signature-Input: sig1=(\"@authority\" \"@authority\")\r\nSignature: sig1=:AA==:\r\n\r\n"
            ),
        ),
    ];
    let temp = tempfile::tempdir().unwrap();
    for (name, contents) in cases {
        let path = temp.path().join("input.http");
        fs::write(&path, contents).unwrap();
        for format in ["text", "json"] {
            let output = botgate()
                .arg("inspect")
                .arg(&path)
                .args(["--format", format])
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(4),
                "{name} ({format}): {output:?}"
            );
            assert!(output.stdout.is_empty(), "{name} ({format}) wrote a report");
            assert!(
                String::from_utf8_lossy(&output.stderr).starts_with("botgate: "),
                "{name} ({format}): {output:?}"
            );
        }
    }
}

#[test]
fn missing_files_and_bad_config_are_input_errors() {
    let temp = tempfile::tempdir().unwrap();
    let missing = botgate()
        .arg("inspect")
        .arg(temp.path().join("absent.http"))
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(4));

    let config = temp.path().join("policy.toml");
    fs::write(&config, "[policy]\nrequire_methd = true\n").unwrap();
    let typo = botgate()
        .arg("inspect")
        .arg(example("request.http"))
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(typo.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&typo.stderr).contains("require_methd"));
}

#[test]
fn usage_errors_exit_with_two() {
    let output = botgate().arg("inspect").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let output = botgate()
        .args(["inspect", "x.http", "--format", "yaml"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn init_force_keeps_an_edited_policy() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("keys");
    init_keys(&directory);
    let config = directory.join("botgate.toml");
    fs::write(&config, "[policy]\nrequire_nonce = true\n").unwrap();
    assert!(
        botgate()
            .args(["init", "--force", "--directory"])
            .arg(&directory)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        "[policy]\nrequire_nonce = true\n"
    );
}

#[test]
fn sign_rejects_non_ascii_agent_with_a_clear_error() {
    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    init_keys(&keys);
    let output = botgate()
        .arg("sign")
        .arg(example("request.http"))
        .arg("--key")
        .arg(keys.join("private.key"))
        .arg("--jwk")
        .arg(keys.join("public.jwk"))
        .args(["--agent", "https://bücher.example", "--output"])
        .arg(temp.path().join("signed.http"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&output.stderr).contains("punycode"));
}

#[test]
fn json_reports_which_policy_was_applied() {
    let temp = tempfile::tempdir().unwrap();
    let request = example("request.http");
    let defaults = botgate()
        .current_dir(temp.path())
        .arg("inspect")
        .arg(&request)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(json(&defaults)["policy_source"], "built-in defaults");

    // An implicitly loaded .botgate/botgate.toml must be visible in the report.
    init_keys(&temp.path().join(".botgate"));
    let implicit = botgate()
        .current_dir(temp.path())
        .arg("inspect")
        .arg(&request)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let source = json(&implicit)["policy_source"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(source.ends_with("botgate.toml"), "{source}");

    let strict = example("strict-policy.toml");
    let explicit = botgate()
        .arg("inspect")
        .arg(&request)
        .arg("--config")
        .arg(&strict)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert_eq!(
        json(&explicit)["policy_source"],
        strict.display().to_string()
    );
}
