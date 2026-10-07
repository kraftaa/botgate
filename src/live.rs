use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use url::Url;

use crate::{
    config::{Expect, Tests},
    http_message::Request,
    mutation,
    network::{self, NetworkPolicy},
    signature::SignatureInput,
};

#[derive(Debug, Serialize)]
pub struct LiveReport {
    pub target: String,
    pub cases: Vec<LiveCase>,
}

#[derive(Debug, Serialize)]
pub struct LiveCase {
    pub name: String,
    pub expected_crypto: String,
    pub expected_server: Outcome,
    pub observed_server: Outcome,
    pub status: u16,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Accepted,
    Rejected,
    Indeterminate,
}

#[derive(Debug)]
pub struct PreparedCase {
    pub name: String,
    pub expected_crypto: String,
    pub expected_server: Outcome,
    pub request: Request,
}

impl LiveReport {
    pub fn has_failures(&self) -> bool {
        self.cases.iter().any(|case| !case.passed)
    }

    pub fn text(&self) -> String {
        let mut output = format!("Botgate live test\n\nTarget: {}\n\n", self.target);
        output.push_str(
            "Case                     Crypto expected  Server expected  Observed       Result\n",
        );
        for case in &self.cases {
            output.push_str(&format!(
                "{:<24} {:<16} {:<16} {:<14} {}\n",
                case.name,
                case.expected_crypto,
                outcome_name(case.expected_server),
                format!("{} ({})", outcome_name(case.observed_server), case.status),
                if case.passed { "PASS" } else { "FAIL" }
            ));
            if !case.detail.is_empty() {
                output.push_str(&format!("  {}\n", case.detail));
            }
        }
        output
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    request: &Request,
    input: &SignatureInput,
    target: &Url,
    expect: &Expect,
    tests: &Tests,
    policy: &NetworkPolicy,
    allow_unsafe_methods: bool,
    prepared: Vec<PreparedCase>,
) -> Result<LiveReport> {
    validate_oracle(expect)?;
    if !matches!(request.method.as_str(), "GET" | "HEAD") && !allow_unsafe_methods {
        bail!(
            "refusing to replay {} automatically; --allow-unsafe-methods is required for an authorized target",
            request.method
        );
    }
    ensure_same_request_target(request, target)?;
    let planned = mutation::plan(request, input);
    let mut cases = Vec::new();
    send_case(
        &mut cases,
        "original",
        "valid",
        Outcome::Accepted,
        request,
        target,
        expect,
        policy,
    )?;
    for item in planned {
        let enabled = match item.name {
            "changed_method" => tests.changed_method,
            "changed_path" => tests.changed_path,
            "changed_query" => tests.changed_query,
            "changed_authority" => tests.changed_authority,
            "changed_signed_header" => tests.changed_signed_header,
            "corrupted_signature" => tests.corrupted_signature,
            "changed_body" => {
                tests.changed_body && !request.body.is_empty() && allow_unsafe_methods
            }
            _ => false,
        };
        if !enabled {
            continue;
        }
        let changed = mutation::apply(request, input, item.name)?;
        let changed_target = if item.name == "changed_authority" {
            target.clone()
        } else {
            target_for_request(&changed, target)?
        };
        let expected = if item.expected_crypto.ends_with("invalid") {
            Outcome::Rejected
        } else {
            Outcome::Accepted
        };
        send_case(
            &mut cases,
            item.name,
            item.expected_crypto,
            expected,
            &changed,
            &changed_target,
            expect,
            policy,
        )?;
    }
    if tests.removed_signature_agent {
        let changed = mutation::apply(request, input, "removed_signature_agent")?;
        send_case(
            &mut cases,
            "removed_signature_agent",
            "invalid",
            Outcome::Rejected,
            &changed,
            target,
            expect,
            policy,
        )?;
    }
    if tests.changed_signature_agent {
        let changed = mutation::apply(request, input, "changed_signature_agent")?;
        send_case(
            &mut cases,
            "changed_signature_agent",
            "invalid",
            Outcome::Rejected,
            &changed,
            target,
            expect,
            policy,
        )?;
    }
    for case in prepared {
        send_case(
            &mut cases,
            &case.name,
            &case.expected_crypto,
            case.expected_server,
            &case.request,
            target,
            expect,
            policy,
        )?;
    }
    Ok(LiveReport {
        target: target.to_string(),
        cases,
    })
}

#[allow(clippy::too_many_arguments)]
fn send_case(
    cases: &mut Vec<LiveCase>,
    name: &str,
    expected_crypto: &str,
    expected_server: Outcome,
    request: &Request,
    target: &Url,
    expect: &Expect,
    policy: &NetworkPolicy,
) -> Result<()> {
    let response = network::send_request(target, request, policy)
        .with_context(|| format!("live case {name}"))?;
    let (observed, detail) = classify(&response, expect);
    cases.push(LiveCase {
        name: name.into(),
        expected_crypto: expected_crypto.into(),
        expected_server,
        observed_server: observed,
        status: response.status,
        passed: observed == expected_server,
        detail,
    });
    Ok(())
}

fn validate_oracle(expect: &Expect) -> Result<()> {
    let status_oracle =
        !expect.accepted_statuses.is_empty() && !expect.rejected_statuses.is_empty();
    let header_oracle = expect.header.is_some()
        && expect.accepted_value.is_some()
        && expect.rejected_value.is_some();
    if !status_oracle && !header_oracle {
        bail!(
            "live testing requires an explicit oracle: configure both accepted_statuses and rejected_statuses, or a header with accepted_value and rejected_value"
        );
    }
    Ok(())
}

fn classify(response: &network::HttpResponse, expect: &Expect) -> (Outcome, String) {
    if let (Some(header), Some(accepted), Some(rejected)) = (
        &expect.header,
        &expect.accepted_value,
        &expect.rejected_value,
    ) {
        let actual = response
            .headers
            .get(header)
            .and_then(|value| value.to_str().ok());
        return match actual {
            Some(value) if value == accepted => (Outcome::Accepted, format!("{header}: {value}")),
            Some(value) if value == rejected => (Outcome::Rejected, format!("{header}: {value}")),
            Some(value) => (
                Outcome::Indeterminate,
                format!("{header}: {value} does not match either configured value"),
            ),
            None => (
                Outcome::Indeterminate,
                format!("response lacks oracle header {header}"),
            ),
        };
    }
    if expect.accepted_statuses.contains(&response.status) {
        (Outcome::Accepted, String::new())
    } else if expect.rejected_statuses.contains(&response.status) {
        (Outcome::Rejected, String::new())
    } else {
        (
            Outcome::Indeterminate,
            format!(
                "HTTP {} is not classified by the configured oracle",
                response.status
            ),
        )
    }
}

fn ensure_same_request_target(request: &Request, target: &Url) -> Result<()> {
    let actual = target_for_request(request, target)?;
    if actual.as_str() != target.as_str() {
        bail!(
            "request target resolves to {actual}, not configured live target {target}; they must match exactly"
        );
    }
    let authority = request.authority(Some(target))?;
    let target_authority = target
        .host_str()
        .map(|host| match target.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        })
        .ok_or_else(|| anyhow!("target has no host"))?;
    if !authority.eq_ignore_ascii_case(&target_authority) {
        bail!("request authority {authority} does not match live target {target_authority}");
    }
    Ok(())
}

fn target_for_request(request: &Request, base: &Url) -> Result<Url> {
    if let Ok(url) = Url::parse(&request.target) {
        return Ok(url);
    }
    base.join(&request.target)
        .context("resolving request target against live target")
}

fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Accepted => "accepted",
        Outcome::Rejected => "rejected",
        Outcome::Indeterminate => "indeterminate",
    }
}
