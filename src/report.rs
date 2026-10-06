use crate::{
    PROTOCOL,
    config::{Policy, Requirement},
    crypto::{self, Jwks},
    http_message::Request,
    mutation::{self, Mutation},
    signature::{self, ParsedSignatures, SignatureInput, Value},
};
use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    IetfDraft00,
    Cloudflare,
}
impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Self::IetfDraft00 => PROTOCOL,
            Self::Cloudflare => "cloudflare-2026-10",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub protocol: String,
    /// Where the evaluated policy came from, so a CI log shows which rules applied.
    pub policy_source: String,
    pub request: RequestSummary,
    pub signatures: Vec<SignatureReport>,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mutations: Vec<Mutation>,
}

#[derive(Debug, Serialize)]
pub struct RequestSummary {
    pub method: String,
    pub target: String,
    pub body_bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct SignatureReport {
    pub label: String,
    pub covered_components: Vec<String>,
    pub effective_coverage: Coverage,
    pub cryptographic_status: Status,
    pub identity_status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_agent: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Coverage {
    pub authority: bool,
    pub method: bool,
    pub path: bool,
    pub query: bool,
    pub query_params: Vec<String>,
    pub body_digest_header: bool,
    pub body_digest_valid: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Valid,
    Invalid,
    NotVerified,
    KeyOnly,
    Unresolved,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: String,
    pub category: String,
    pub level: Level,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Info,
    Warning,
    Error,
}

impl Report {
    pub fn analyze(
        request: &Request,
        parsed: &ParsedSignatures,
        policy: &Policy,
        profile: Profile,
        jwks: Option<&Jwks>,
        context: Option<&Url>,
        include_mutations: bool,
    ) -> Self {
        let mut findings = Vec::new();
        let mut reports = Vec::new();
        for input in &parsed.inputs {
            if !parsed.signatures.contains_key(&input.label) {
                findings.push(error(
                    "BG-C103",
                    "conformance",
                    format!("Signature has no member labelled {}", input.label),
                ));
            }
        }
        for label in parsed.signatures.keys() {
            if !parsed.inputs.iter().any(|input| &input.label == label) {
                findings.push(error(
                    "BG-C109",
                    "conformance",
                    format!("Signature member {label} has no matching Signature-Input"),
                ));
            }
        }
        for input in &parsed.inputs {
            let coverage = coverage(request, input, &mut findings);
            let agent = match signature_agent(request, input) {
                Ok(agent) => {
                    if agent.is_none() && request.header("signature-agent").is_some() {
                        findings.push(error(
                            "BG-C110",
                            "conformance",
                            "no covered Signature-Agent member could be resolved",
                        ));
                    }
                    agent
                }
                Err(problem) => {
                    findings.push(error(
                        "BG-C110",
                        "conformance",
                        format!(
                            "cannot resolve Signature-Agent for {}: {problem}",
                            input.label
                        ),
                    ));
                    None
                }
            };
            profile_findings(request, input, agent.as_deref(), profile, &mut findings);
            policy_findings(&coverage, policy, &mut findings);
            time_findings(input, policy, &mut findings);
            let (crypto_status, identity_status) = if let Some(keys) = jwks {
                match parsed.signatures.get(&input.label) {
                    Some(sig) => match crypto::verify(request, input, sig, keys, context) {
                        Ok(_) => {
                            findings.push(info(
                                "BG-K100",
                                "crypto",
                                format!(
                                    "signature {} verified with the supplied key set",
                                    input.label
                                ),
                            ));
                            // Supplying a local key proves key control, not URL-to-key discovery.
                            (Status::Valid, Status::KeyOnly)
                        }
                        Err(e) => {
                            findings.push(error(
                                "BG-K201",
                                "crypto",
                                format!("signature {} is invalid: {e}", input.label),
                            ));
                            (Status::Invalid, Status::Unresolved)
                        }
                    },
                    None => (Status::Invalid, Status::Unresolved),
                }
            } else {
                (Status::NotVerified, Status::Unresolved)
            };
            reports.push(SignatureReport {
                label: input.label.clone(),
                covered_components: input
                    .components
                    .iter()
                    .map(signature::component_identifier)
                    .collect(),
                effective_coverage: coverage,
                cryptographic_status: crypto_status,
                identity_status,
                keyid: input
                    .param("keyid")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                signature_agent: agent,
            });
        }
        if parsed.inputs.is_empty() {
            findings.push(error("BG-C100", "conformance", "no signatures found"));
        }
        let mutations = if include_mutations {
            parsed
                .inputs
                .iter()
                .flat_map(|input| mutation::plan(request, input))
                .collect()
        } else {
            vec![]
        };
        Self {
            protocol: profile.name().into(),
            policy_source: "built-in defaults".into(),
            request: RequestSummary {
                method: request.method.clone(),
                target: request.target.clone(),
                body_bytes: request.body.len(),
            },
            signatures: reports,
            findings,
            mutations,
        }
    }

    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.level == Level::Error)
    }

    pub fn text(&self) -> String {
        let mut out = format!(
            "Botgate analysis\n\nProfile: {}\nPolicy:  {}\nRequest: {} {}\n",
            self.protocol, self.policy_source, self.request.method, self.request.target
        );
        for sig in &self.signatures {
            out.push_str(&format!("\nSignature {}\n", sig.label));
            out.push_str(&format!(
                "  Crypto:   {}\n",
                status_name(sig.cryptographic_status)
            ));
            out.push_str(&format!(
                "  Identity: {}\n",
                status_name(sig.identity_status)
            ));
            if let Some(agent) = &sig.signature_agent {
                out.push_str(&format!("  Agent:    {agent}\n"));
            }
            if let Some(keyid) = &sig.keyid {
                out.push_str(&format!("  Key ID:   {keyid}\n"));
            }
            out.push_str("  Covered:\n");
            for c in &sig.covered_components {
                out.push_str(&format!("    ✓ {c}\n"));
            }
            let c = &sig.effective_coverage;
            out.push_str("  Effective coverage:\n");
            for (name, bound) in [
                ("authority", c.authority),
                ("method", c.method),
                ("path", c.path),
                ("query", c.query),
            ] {
                out.push_str(&format!("    {} {name}\n", if bound { "✓" } else { "○" }));
            }
            out.push_str(&format!(
                "    {} body digest header",
                if c.body_digest_header { "✓" } else { "○" }
            ));
            if let Some(valid) = c.body_digest_valid {
                out.push_str(if valid {
                    " (digest matches)"
                } else {
                    " (DIGEST MISMATCH)"
                });
            }
            out.push('\n');
        }
        if !self.findings.is_empty() {
            out.push_str("\nFindings\n");
            for f in &self.findings {
                out.push_str(&format!(
                    "  {} {} [{}] {}\n",
                    level_mark(f.level),
                    f.id,
                    f.category,
                    f.message
                ));
            }
        }
        if !self.mutations.is_empty() {
            out.push_str("\nOffline mutation matrix (nothing sent)\n");
            for m in &self.mutations {
                out.push_str(&format!(
                    "  {:8} {:24} {:12} {}\n",
                    m.signature_label, m.name, m.expected_crypto, m.detail
                ));
            }
        }
        out
    }
}

fn coverage(request: &Request, input: &SignatureInput, findings: &mut Vec<Finding>) -> Coverage {
    let target_uri = input.covers("@target-uri");
    let request_target = input.covers("@request-target");
    // Only the whole field or its sha-256 member binds the digest Botgate recomputes.
    let digest_covered =
        input.covers("content-digest") || input.covers_member("content-digest", "sha-256");
    if input.mentions("content-digest") && !digest_covered {
        findings.push(warning(
            "BG-D102",
            "digest",
            "Content-Digest is covered only in a form that does not bind its sha-256 member",
        ));
    }
    let digest_valid = if digest_covered {
        match validate_content_digest(request) {
            Ok(v) => Some(v),
            Err(e) => {
                findings.push(warning(
                    "BG-D101",
                    "digest",
                    format!("cannot validate Content-Digest: {e}"),
                ));
                None
            }
        }
    } else {
        None
    };
    Coverage {
        authority: input.covers("@authority") || target_uri,
        method: input.covers("@method"),
        path: input.covers("@path") || target_uri || request_target,
        query: input.covers("@query") || target_uri || request_target,
        query_params: input
            .components
            .iter()
            .filter(|component| component.name == "@query-param")
            .filter_map(|component| {
                component
                    .params
                    .iter()
                    .find(|(name, _)| name == "name")
                    .and_then(|(_, value)| value.as_string())
                    .map(str::to_string)
            })
            .collect(),
        body_digest_header: digest_covered,
        body_digest_valid: digest_valid,
    }
}

fn validate_content_digest(request: &Request) -> Result<bool> {
    let raw = request
        .header("content-digest")
        .ok_or_else(|| anyhow!("covered Content-Digest header is absent"))?;
    let expected = signature::dictionary_byte_sequence_member(&raw, "sha-256")?;
    Ok(expected == Sha256::digest(&request.body).as_slice())
}

fn profile_findings(
    request: &Request,
    input: &SignatureInput,
    resolved_agent: Option<&str>,
    profile: Profile,
    findings: &mut Vec<Finding>,
) {
    let has_authority = input.covers("@authority") || input.covers("@target-uri");
    if !has_authority {
        findings.push(error(
            "BG-C101",
            "conformance",
            "Web Bot Auth requires @authority or @target-uri",
        ));
    }
    for (name, expected) in [
        ("created", "integer"),
        ("expires", "integer"),
        ("keyid", "string"),
        ("tag", "string"),
    ] {
        let valid = matches!(
            (name, input.param(name)),
            ("created" | "expires", Some(Value::Integer(_)))
                | ("keyid" | "tag", Some(Value::String(_)))
        );
        if !valid {
            findings.push(error(
                "BG-C102",
                "conformance",
                format!("required signature parameter {name} must be an {expected}"),
            ));
        }
    }
    for name in ["nonce", "alg"] {
        if input
            .param(name)
            .is_some_and(|value| !matches!(value, Value::String(_)))
        {
            findings.push(error(
                "BG-C111",
                "conformance",
                format!("signature parameter {name} must be a string"),
            ));
        }
    }
    if input
        .param("alg")
        .and_then(Value::as_str)
        .is_some_and(|alg| alg != "ed25519")
    {
        findings.push(error(
            "BG-C112",
            "conformance",
            "v0.1 can verify only alg=ed25519",
        ));
    }
    if input.param("tag").and_then(Value::as_str) != Some("web-bot-auth") {
        findings.push(error("BG-C104", "conformance", "tag must be web-bot-auth"));
    }
    if let Some(keyid) = input.param("keyid").and_then(Value::as_str) {
        if URL_SAFE_NO_PAD
            .decode(keyid)
            .map_or(true, |bytes| bytes.len() != 32)
        {
            findings.push(error(
                "BG-C113",
                "conformance",
                "keyid must be a base64url-encoded SHA-256 JWK thumbprint",
            ));
        }
    }
    let agent = request.header("signature-agent");
    match (profile, agent.as_deref()) {
        (_, None) => findings.push(error("BG-C105", "conformance", "missing Signature-Agent")),
        (Profile::IetfDraft00, Some(raw)) => {
            if raw.trim_start().starts_with('"') {
                findings.push(error("BG-C106", "conformance", "legacy bare-string Signature-Agent is accepted only as a verifier migration option; current senders must use dictionary form"));
            }
            let required = input.components.iter().any(|c| {
                c.name == "signature-agent"
                    && c.params
                        .iter()
                        .any(|(n, v)| n == "key" && v.as_string() == Some(&input.label))
            });
            if !required {
                findings.push(error("BG-C107", "conformance", "current draft requires the Signature-Agent member keyed to this signature label to be covered"));
            }
        }
        (Profile::Cloudflare, Some(raw)) => {
            if !raw.trim_start().starts_with('"') {
                findings.push(error("BG-I101", "compatibility", "Cloudflare currently requires legacy bare-string Signature-Agent and rejects dictionary form"));
            }
            if !input
                .components
                .iter()
                .any(|c| c.name == "signature-agent" && c.params.is_empty())
            {
                findings.push(error(
                    "BG-I102",
                    "compatibility",
                    "Cloudflare requires the bare signature-agent field component",
                ));
            }
            for c in &input.components {
                if c.name == "@query-param"
                    || c.name == "@status"
                    || c.params
                        .iter()
                        .any(|(p, _)| matches!(p.as_str(), "sf" | "bs" | "key" | "req" | "name"))
                {
                    findings.push(error(
                        "BG-I103",
                        "compatibility",
                        format!(
                            "Cloudflare does not support component {} with these parameters",
                            signature::component_identifier(c)
                        ),
                    ));
                }
            }
        }
    }
    if let Some(agent) = resolved_agent {
        match Url::parse(agent) {
            Ok(url) if url.scheme() == "https" && url.host_str().is_some() => {}
            _ => findings.push(error(
                "BG-C108",
                "conformance",
                "Signature-Agent must be a valid https URI with a host",
            )),
        }
    }
    let lifetime = match (
        input.param("created").and_then(Value::as_i64),
        input.param("expires").and_then(Value::as_i64),
    ) {
        (Some(c), Some(e)) => e.checked_sub(c),
        _ => None,
    };
    if lifetime.is_some_and(|n| n > 86_400) {
        findings.push(warning(
            "BG-C150",
            "recommendation",
            "signature lifetime exceeds the draft's 24-hour recommendation",
        ));
    }
}

fn policy_findings(c: &Coverage, p: &Policy, findings: &mut Vec<Finding>) {
    for (needed, actual, id, name) in [
        (p.require_authority, c.authority, "BG-P101", "authority"),
        (p.require_method, c.method, "BG-P102", "method"),
        (p.require_path, c.path, "BG-P103", "path"),
        (
            p.query == Requirement::Required,
            c.query,
            "BG-P104",
            "query",
        ),
    ] {
        if needed && !actual {
            findings.push(error(
                id,
                "policy",
                format!("policy requires {name} binding, but it is not covered"),
            ));
        }
    }
    if p.body == Requirement::Required
        && (!c.body_digest_header || c.body_digest_valid != Some(true))
    {
        findings.push(error(
            "BG-P105",
            "policy",
            "policy requires body integrity via a covered, matching Content-Digest",
        ));
    }
}

fn time_findings(input: &SignatureInput, p: &Policy, findings: &mut Vec<Finding>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let created = input.param("created").and_then(Value::as_i64);
    let expires = input.param("expires").and_then(Value::as_i64);
    if created.is_some_and(|c| c > now.saturating_add(p.allowed_future_skew_seconds)) {
        findings.push(error(
            "BG-P110",
            "policy",
            "created timestamp is too far in the future",
        ));
    }
    if expires.is_some_and(|e| e < now) {
        findings.push(error("BG-P111", "policy", "signature has expired"));
    }
    if matches!((created, expires), (Some(created), Some(expires)) if expires < created) {
        findings.push(error(
            "BG-P115",
            "policy",
            "expires timestamp precedes created timestamp",
        ));
    }
    if let (Some(max), Some(c)) = (p.max_age_seconds, created) {
        if now.saturating_sub(c) > max {
            findings.push(error(
                "BG-P112",
                "policy",
                format!("signature age exceeds {max}s"),
            ));
        }
    }
    if let (Some(max), Some(c), Some(e)) = (p.max_lifetime_seconds, created, expires) {
        if e.checked_sub(c).is_some_and(|lifetime| lifetime > max) {
            findings.push(error(
                "BG-P113",
                "policy",
                format!("signature lifetime exceeds {max}s"),
            ));
        }
    }
    if p.require_nonce && input.param("nonce").is_none() {
        findings.push(error("BG-P114", "policy", "policy requires a nonce"));
    }
}

fn signature_agent(request: &Request, input: &SignatureInput) -> Result<Option<String>> {
    let Some(raw) = request.header("signature-agent") else {
        return Ok(None);
    };
    if raw.trim_start().starts_with('"') {
        return Ok(Some(signature::parse_string_item(raw.trim())?));
    }
    let member_key = input
        .components
        .iter()
        .filter(|component| component.name == "signature-agent")
        .filter_map(|component| {
            component
                .params
                .iter()
                .find(|(name, _)| name == "key")
                .and_then(|(_, value)| value.as_string())
        })
        .find(|key| *key == input.label)
        .or_else(|| {
            input
                .components
                .iter()
                .filter(|component| component.name == "signature-agent")
                .filter_map(|component| {
                    component
                        .params
                        .iter()
                        .find(|(name, _)| name == "key")
                        .and_then(|(_, value)| value.as_string())
                })
                .next()
        });
    match member_key {
        Some(key) => Ok(Some(signature::dictionary_string_member(&raw, key)?)),
        None => Ok(None),
    }
}
fn info(id: &str, category: &str, message: impl Into<String>) -> Finding {
    Finding {
        id: id.into(),
        category: category.into(),
        level: Level::Info,
        message: message.into(),
    }
}
fn warning(id: &str, category: &str, message: impl Into<String>) -> Finding {
    Finding {
        id: id.into(),
        category: category.into(),
        level: Level::Warning,
        message: message.into(),
    }
}
fn error(id: &str, category: &str, message: impl Into<String>) -> Finding {
    Finding {
        id: id.into(),
        category: category.into(),
        level: Level::Error,
        message: message.into(),
    }
}
fn level_mark(l: Level) -> &'static str {
    match l {
        Level::Info => "INFO",
        Level::Warning => "WARN",
        Level::Error => "FAIL",
    }
}
fn status_name(s: Status) -> &'static str {
    match s {
        Status::Valid => "VALID",
        Status::Invalid => "INVALID",
        Status::NotVerified => "NOT VERIFIED",
        Status::KeyOnly => "KEY ONLY",
        Status::Unresolved => "UNRESOLVED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature;
    use base64::engine::general_purpose::STANDARD;

    fn relaxed_policy() -> Policy {
        Policy {
            require_authority: true,
            require_method: false,
            require_path: false,
            query: Requirement::Ignore,
            body: Requirement::Ignore,
            max_age_seconds: None,
            max_lifetime_seconds: None,
            allowed_future_skew_seconds: 0,
            require_nonce: false,
        }
    }

    #[test]
    fn one_query_param_does_not_satisfy_full_query_policy() {
        let raw = concat!(
            "GET /orders?view=full&admin=true HTTP/1.1\r\n",
            "Host: example.test\r\n",
            "Signature-Agent: sig1=\"https://agent.example\"\r\n",
            "Signature-Input: sig1=(\"@authority\" \"@query-param\";name=\"view\" \"signature-agent\";key=\"sig1\");created=1;expires=999999999999999;keyid=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\";tag=\"web-bot-auth\"\r\n",
            "Signature: sig1=:AA==:\r\n\r\n"
        );
        let request = Request::parse(raw.as_bytes()).unwrap();
        let parsed = signature::parse(&request).unwrap();
        let mut policy = relaxed_policy();
        policy.query = Requirement::Required;
        let report = Report::analyze(
            &request,
            &parsed,
            &policy,
            Profile::IetfDraft00,
            None,
            None,
            true,
        );
        assert!(!report.signatures[0].effective_coverage.query);
        assert_eq!(
            report.signatures[0].effective_coverage.query_params,
            ["view"]
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "BG-P104")
        );
        let query_mutation = report
            .mutations
            .iter()
            .find(|m| m.name == "changed_query")
            .unwrap();
        assert_eq!(query_mutation.expected_crypto, "still_valid");
    }

    #[test]
    fn appendix_vector_agent_is_resolved_but_label_mismatch_is_reported() {
        let raw = concat!(
            "GET / HTTP/1.1\r\nHost: example.com\r\n",
            "Signature-Agent: agent2=\"https://signature-agent.test\"\r\n",
            "Signature-Input: sig2=(\"@authority\" \"signature-agent\";key=\"agent2\");created=1735689600;expires=4889289600;keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";tag=\"web-bot-auth\"\r\n",
            "Signature: sig2=:AA==:\r\n\r\n"
        );
        let request = Request::parse(raw.as_bytes()).unwrap();
        let parsed = signature::parse(&request).unwrap();
        let report = Report::analyze(
            &request,
            &parsed,
            &relaxed_policy(),
            Profile::IetfDraft00,
            None,
            None,
            false,
        );
        assert_eq!(
            report.signatures[0].signature_agent.as_deref(),
            Some("https://signature-agent.test")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "BG-C107")
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.id == "BG-C108" || finding.id == "BG-C110")
        );
    }

    #[test]
    fn validates_sha256_among_multiple_content_digests() {
        let digest = STANDARD.encode(Sha256::digest(b"hello"));
        let raw = format!(
            "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Digest: sha-512=:AA==:, sha-256=:{digest}:\r\n\r\nhello"
        );
        let request = Request::parse(raw.as_bytes()).unwrap();
        assert!(validate_content_digest(&request).unwrap());
    }

    #[test]
    fn wrong_timestamp_type_is_a_conformance_error() {
        let raw = concat!(
            "GET / HTTP/1.1\r\nHost: example.test\r\n",
            "Signature-Agent: sig1=\"https://agent.example\"\r\n",
            "Signature-Input: sig1=(\"@authority\" \"signature-agent\";key=\"sig1\");created=\"old\";expires=4889289600;keyid=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\";tag=\"web-bot-auth\"\r\n",
            "Signature: sig1=:AA==:\r\n\r\n"
        );
        let request = Request::parse(raw.as_bytes()).unwrap();
        let parsed = signature::parse(&request).unwrap();
        let report = Report::analyze(
            &request,
            &parsed,
            &relaxed_policy(),
            Profile::IetfDraft00,
            None,
            None,
            false,
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "BG-C102" && finding.message.contains("created"))
        );
    }

    fn digest_report(component: &str) -> Report {
        let digest = STANDARD.encode(Sha256::digest(b"hello"));
        let raw = format!(
            concat!(
                "POST /x HTTP/1.1\r\n",
                "Host: example.test\r\n",
                "Content-Digest: sha-256=:{digest}:, sha-512=:AAAA:\r\n",
                "Signature-Agent: sig1=\"https://agent.example\"\r\n",
                "Signature-Input: sig1=(\"@authority\" {component} \"signature-agent\";key=\"sig1\");created=1;expires=999999999999999;keyid=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\";tag=\"web-bot-auth\"\r\n",
                "Signature: sig1=:AA==:\r\n\r\nhello"
            ),
            digest = digest,
            component = component,
        );
        let request = Request::parse(raw.as_bytes()).unwrap();
        let parsed = signature::parse(&request).unwrap();
        let mut policy = relaxed_policy();
        policy.body = Requirement::Required;
        Report::analyze(
            &request,
            &parsed,
            &policy,
            Profile::IetfDraft00,
            None,
            None,
            true,
        )
    }

    #[test]
    fn digest_member_other_than_sha256_does_not_bind_the_body() {
        let report = digest_report(r#""content-digest";key="sha-512""#);
        let coverage = &report.signatures[0].effective_coverage;
        assert!(!coverage.body_digest_header);
        assert_eq!(coverage.body_digest_valid, None);
        let ids: Vec<_> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"BG-D102"));
        assert!(ids.contains(&"BG-P105"));
        let body = report
            .mutations
            .iter()
            .find(|m| m.name == "changed_body")
            .unwrap();
        assert_eq!(body.detail, "body is not cryptographically bound");
    }

    #[test]
    fn whole_field_or_sha256_member_binds_the_body() {
        for component in [r#""content-digest""#, r#""content-digest";key="sha-256""#] {
            let report = digest_report(component);
            let coverage = &report.signatures[0].effective_coverage;
            assert!(coverage.body_digest_header, "{component}");
            assert_eq!(coverage.body_digest_valid, Some(true), "{component}");
            assert!(
                report
                    .findings
                    .iter()
                    .all(|f| f.id != "BG-P105" && f.id != "BG-D102"),
                "{component}"
            );
        }
    }

    #[test]
    fn derived_component_with_parameters_is_not_counted_as_coverage() {
        let raw = concat!(
            "GET /a?b=c HTTP/1.1\r\n",
            "Host: example.test\r\n",
            "Signature-Agent: sig1=\"https://agent.example\"\r\n",
            "Signature-Input: sig1=(\"@authority\" \"@path\";x \"@query\";x \"signature-agent\";key=\"sig1\");created=1;expires=999999999999999;keyid=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\";tag=\"web-bot-auth\"\r\n",
            "Signature: sig1=:AA==:\r\n\r\n"
        );
        let request = Request::parse(raw.as_bytes()).unwrap();
        let parsed = signature::parse(&request).unwrap();
        let report = Report::analyze(
            &request,
            &parsed,
            &relaxed_policy(),
            Profile::IetfDraft00,
            None,
            None,
            false,
        );
        let coverage = &report.signatures[0].effective_coverage;
        assert!(coverage.authority);
        assert!(!coverage.path);
        assert!(!coverage.query);
    }
}
