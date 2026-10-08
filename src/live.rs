use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use url::Url;

use crate::{
    config::{AccessDecision, AccessExpect, Expect, Tests},
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
    pub expected_authentication: AuthenticationOutcome,
    pub observed_authentication: AuthenticationOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_access: Option<AccessOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_access: Option<AccessOutcome>,
    pub status: u16,
    pub authentication_passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_passed: Option<bool>,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationOutcome {
    Authenticated,
    Unauthenticated,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessOutcome {
    Allowed,
    Denied,
    Indeterminate,
}

#[derive(Debug)]
pub struct PreparedCase {
    pub name: String,
    pub expected_crypto: String,
    pub expected_authentication: AuthenticationOutcome,
    pub request: Request,
}

impl LiveReport {
    pub fn has_failures(&self) -> bool {
        self.cases.iter().any(|case| !case.passed)
    }

    pub fn text(&self) -> String {
        let mut output = format!("Botgate live test\n\nTarget: {}\n\n", self.target);
        let header = [
            "Case",
            "Expected validity",
            "Authentication",
            "Access",
            "HTTP",
            "Result",
        ]
        .map(String::from);
        let rows: Vec<([String; 6], &str)> = self
            .cases
            .iter()
            .map(|case| {
                let authentication = format!(
                    "{} -> {}",
                    authentication_name(case.expected_authentication),
                    authentication_name(case.observed_authentication)
                );
                let access = match (case.expected_access, case.observed_access) {
                    (Some(expected), Some(observed)) => {
                        format!("{} -> {}", access_name(expected), access_name(observed))
                    }
                    (None, Some(observed)) => format!("observed {}", access_name(observed)),
                    _ => "not configured".into(),
                };
                let result = if case.passed { "PASS" } else { "FAIL" };
                let cells = [
                    case.name.to_string(),
                    case.expected_crypto.to_string(),
                    authentication,
                    access,
                    case.status.to_string(),
                    result.into(),
                ];
                (cells, case.detail.as_str())
            })
            .collect();
        // Size each column to its widest cell so long labels never shift later columns.
        let mut widths = header.clone().map(|cell| cell.len());
        for (cells, _) in &rows {
            for (width, cell) in widths.iter_mut().zip(cells) {
                *width = (*width).max(cell.len());
            }
        }
        let line = |cells: &[String; 6]| {
            let padded: Vec<String> = cells
                .iter()
                .zip(widths)
                .map(|(cell, width)| format!("{cell:<width$}"))
                .collect();
            format!("{}\n", padded.join("  ").trim_end())
        };
        output.push_str(&line(&header));
        for (cells, detail) in &rows {
            output.push_str(&line(cells));
            if !detail.is_empty() {
                output.push_str(&format!("  {detail}\n"));
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
        AuthenticationOutcome::Authenticated,
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
            AuthenticationOutcome::Unauthenticated
        } else {
            AuthenticationOutcome::Authenticated
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
            AuthenticationOutcome::Unauthenticated,
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
            AuthenticationOutcome::Unauthenticated,
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
            case.expected_authentication,
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
    expected_authentication: AuthenticationOutcome,
    request: &Request,
    target: &Url,
    expect: &Expect,
    policy: &NetworkPolicy,
) -> Result<()> {
    let response = network::send_request(target, request, policy)
        .with_context(|| format!("live case {name}"))?;
    let (observed_authentication, mut detail) = classify_authentication(&response, expect);
    let expected_access = expect.access.cases.get(name).copied().map(Into::into);
    let observed_access = classify_access(&response, &expect.access);
    let authentication_passed = observed_authentication == expected_authentication;
    let access_passed = expected_access.map(|expected| observed_access == Some(expected));
    if expect.header.is_none() && expect.allow_status_authentication {
        let warning = "authentication was classified by an explicitly enabled HTTP-status contract";
        if detail.is_empty() {
            detail = warning.into();
        } else {
            detail.push_str("; ");
            detail.push_str(warning);
        }
    }
    cases.push(LiveCase {
        name: name.into(),
        expected_crypto: expected_crypto.into(),
        expected_authentication,
        observed_authentication,
        expected_access,
        observed_access,
        status: response.status,
        authentication_passed,
        access_passed,
        passed: authentication_passed && access_passed.unwrap_or(true),
        detail,
    });
    Ok(())
}

fn validate_oracle(expect: &Expect) -> Result<()> {
    let status_oracle =
        !expect.authenticated_statuses.is_empty() && !expect.unauthenticated_statuses.is_empty();
    let header_oracle = expect.header.is_some()
        && expect.authenticated_value.is_some()
        && expect.unauthenticated_value.is_some();
    if !header_oracle && !(status_oracle && expect.allow_status_authentication) {
        bail!(
            "live testing requires an authentication oracle header with authenticated_value and unauthenticated_value; status classification additionally requires allow_status_authentication = true"
        );
    }
    let access_configured = access_configured(&expect.access);
    if !expect.access.cases.is_empty() && !access_configured {
        bail!("access case expectations require a configured expect.access oracle");
    }
    Ok(())
}

fn classify_authentication(
    response: &network::HttpResponse,
    expect: &Expect,
) -> (AuthenticationOutcome, String) {
    if let (Some(header), Some(authenticated), Some(unauthenticated)) = (
        &expect.header,
        &expect.authenticated_value,
        &expect.unauthenticated_value,
    ) {
        let actual = response
            .headers
            .get(header)
            .and_then(|value| value.to_str().ok());
        return match actual {
            Some(value) if value == authenticated => (
                AuthenticationOutcome::Authenticated,
                format!("{header}: {value}"),
            ),
            Some(value) if value == unauthenticated => (
                AuthenticationOutcome::Unauthenticated,
                format!("{header}: {value}"),
            ),
            Some(value) => (
                AuthenticationOutcome::Indeterminate,
                format!("{header}: {value} does not match either configured value"),
            ),
            None => (
                AuthenticationOutcome::Indeterminate,
                format!("response lacks authentication oracle header {header}"),
            ),
        };
    }
    if expect.authenticated_statuses.contains(&response.status) {
        (AuthenticationOutcome::Authenticated, String::new())
    } else if expect.unauthenticated_statuses.contains(&response.status) {
        (AuthenticationOutcome::Unauthenticated, String::new())
    } else {
        (
            AuthenticationOutcome::Indeterminate,
            format!(
                "HTTP {} is not classified by the configured authentication contract",
                response.status
            ),
        )
    }
}

fn classify_access(
    response: &network::HttpResponse,
    access: &AccessExpect,
) -> Option<AccessOutcome> {
    if let (Some(header), Some(allowed), Some(denied)) =
        (&access.header, &access.allowed_value, &access.denied_value)
    {
        return Some(
            match response
                .headers
                .get(header)
                .and_then(|value| value.to_str().ok())
            {
                Some(value) if value == allowed => AccessOutcome::Allowed,
                Some(value) if value == denied => AccessOutcome::Denied,
                _ => AccessOutcome::Indeterminate,
            },
        );
    }
    if !access.allowed_statuses.is_empty() && !access.denied_statuses.is_empty() {
        return Some(if access.allowed_statuses.contains(&response.status) {
            AccessOutcome::Allowed
        } else if access.denied_statuses.contains(&response.status) {
            AccessOutcome::Denied
        } else {
            AccessOutcome::Indeterminate
        });
    }
    None
}

fn access_configured(access: &AccessExpect) -> bool {
    (access.header.is_some() && access.allowed_value.is_some() && access.denied_value.is_some())
        || (!access.allowed_statuses.is_empty() && !access.denied_statuses.is_empty())
}

impl From<AccessDecision> for AccessOutcome {
    fn from(value: AccessDecision) -> Self {
        match value {
            AccessDecision::Allowed => Self::Allowed,
            AccessDecision::Denied => Self::Denied,
        }
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

fn authentication_name(outcome: AuthenticationOutcome) -> &'static str {
    match outcome {
        AuthenticationOutcome::Authenticated => "authenticated",
        AuthenticationOutcome::Unauthenticated => "unauthenticated",
        AuthenticationOutcome::Indeterminate => "indeterminate",
    }
}

fn access_name(outcome: AccessOutcome) -> &'static str {
    match outcome {
        AccessOutcome::Allowed => "allowed",
        AccessOutcome::Denied => "denied",
        AccessOutcome::Indeterminate => "indeterminate",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn status_authentication_requires_an_explicit_override() {
        let mut expect = Expect {
            authenticated_statuses: vec![200],
            unauthenticated_statuses: vec![401],
            ..Expect::default()
        };
        assert!(validate_oracle(&expect).is_err());
        expect.allow_status_authentication = true;
        assert!(validate_oracle(&expect).is_ok());
    }

    #[test]
    fn access_expectations_require_an_access_oracle() {
        let mut cases = BTreeMap::new();
        cases.insert("changed_path".into(), AccessDecision::Denied);
        let expect = Expect {
            header: Some("X-Agent-Authenticated".into()),
            authenticated_value: Some("true".into()),
            unauthenticated_value: Some("false".into()),
            access: AccessExpect {
                cases,
                ..AccessExpect::default()
            },
            ..Expect::default()
        };
        assert!(validate_oracle(&expect).is_err());
    }
}
