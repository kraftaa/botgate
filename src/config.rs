use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub policy: Policy,
    pub target: Target,
    pub expect: Expect,
    pub tests: Tests,
    /// The file the policy was read from; `None` means the built-in defaults.
    #[serde(skip)]
    pub source: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Target {
    pub url: Option<String>,
    pub allow_private: bool,
    pub allow_http: bool,
    pub timeout_seconds: u64,
    pub max_response_bytes: usize,
}

impl Default for Target {
    fn default() -> Self {
        Self {
            url: None,
            allow_private: false,
            allow_http: false,
            timeout_seconds: 10,
            max_response_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Expect {
    #[serde(alias = "accepted_statuses")]
    pub authenticated_statuses: Vec<u16>,
    #[serde(alias = "rejected_statuses")]
    pub unauthenticated_statuses: Vec<u16>,
    pub allow_status_authentication: bool,
    pub header: Option<String>,
    #[serde(alias = "accepted_value")]
    pub authenticated_value: Option<String>,
    #[serde(alias = "rejected_value")]
    pub unauthenticated_value: Option<String>,
    pub access: AccessExpect,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccessExpect {
    pub allowed_statuses: Vec<u16>,
    pub denied_statuses: Vec<u16>,
    pub header: Option<String>,
    pub allowed_value: Option<String>,
    pub denied_value: Option<String>,
    pub cases: BTreeMap<String, AccessDecision>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecision {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tests {
    pub changed_method: bool,
    pub changed_path: bool,
    pub changed_query: bool,
    pub changed_authority: bool,
    pub changed_signed_header: bool,
    pub corrupted_signature: bool,
    pub removed_signature_agent: bool,
    pub changed_signature_agent: bool,
    pub changed_body: bool,
    pub expired: bool,
    pub future_created: bool,
    pub long_expiration: bool,
    pub missing_expires: bool,
    pub unknown_key: bool,
}

impl Default for Tests {
    fn default() -> Self {
        Self {
            changed_method: true,
            changed_path: true,
            changed_query: true,
            changed_authority: true,
            changed_signed_header: true,
            corrupted_signature: true,
            removed_signature_agent: true,
            changed_signature_agent: true,
            changed_body: true,
            expired: true,
            future_created: true,
            long_expiration: true,
            missing_expires: true,
            unknown_key: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub require_authority: bool,
    pub require_method: bool,
    pub require_path: bool,
    pub query: Requirement,
    pub body: Requirement,
    pub max_age_seconds: Option<i64>,
    pub max_lifetime_seconds: Option<i64>,
    pub allowed_future_skew_seconds: i64,
    pub require_nonce: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            require_authority: true,
            require_method: true,
            require_path: true,
            query: Requirement::Ignore,
            body: Requirement::Ignore,
            max_age_seconds: Some(300),
            max_lifetime_seconds: Some(300),
            allowed_future_skew_seconds: 30,
            require_nonce: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    Required,
    #[default]
    Ignore,
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let default_path = Path::new(".botgate/botgate.toml");
        let path = path.or_else(|| default_path.exists().then_some(default_path));
        match path {
            Some(path) => {
                let text = fs::read_to_string(path)
                    .with_context(|| format!("reading configuration {}", path.display()))?;
                let mut config: Self = toml::from_str(&text)
                    .with_context(|| format!("parsing configuration {}", path.display()))?;
                config.validate()?;
                config.source = Some(path.to_path_buf());
                Ok(config)
            }
            None => Ok(Self::default()),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.policy.allowed_future_skew_seconds < 0
            || self.policy.max_age_seconds.is_some_and(|value| value < 0)
            || self
                .policy
                .max_lifetime_seconds
                .is_some_and(|value| value < 0)
        {
            anyhow::bail!("policy time limits must be non-negative");
        }
        if self.target.timeout_seconds == 0 || self.target.timeout_seconds > 120 {
            anyhow::bail!("target.timeout_seconds must be between 1 and 120");
        }
        if self.target.max_response_bytes == 0 || self.target.max_response_bytes > 16 * 1024 * 1024
        {
            anyhow::bail!("target.max_response_bytes must be between 1 and 16777216");
        }
        validate_status_pair(
            &self.expect.authenticated_statuses,
            &self.expect.unauthenticated_statuses,
            "authenticated_statuses",
            "unauthenticated_statuses",
        )?;
        validate_header_oracle(
            self.expect.header.as_deref(),
            self.expect.authenticated_value.as_deref(),
            self.expect.unauthenticated_value.as_deref(),
            "expect",
        )?;
        validate_status_pair(
            &self.expect.access.allowed_statuses,
            &self.expect.access.denied_statuses,
            "access.allowed_statuses",
            "access.denied_statuses",
        )?;
        validate_header_oracle(
            self.expect.access.header.as_deref(),
            self.expect.access.allowed_value.as_deref(),
            self.expect.access.denied_value.as_deref(),
            "expect.access",
        )?;
        const CASES: &[&str] = &[
            "original",
            "changed_method",
            "changed_path",
            "changed_query",
            "changed_authority",
            "changed_signed_header",
            "changed_body",
            "corrupted_signature",
            "removed_signature_agent",
            "changed_signature_agent",
            "expired",
            "future_created",
            "long_expiration",
            "missing_expires",
            "unknown_key",
        ];
        if let Some(name) = self
            .expect
            .access
            .cases
            .keys()
            .find(|name| !CASES.contains(&name.as_str()))
        {
            anyhow::bail!("unknown access expectation case {name}");
        }
        Ok(())
    }
}

fn validate_status_pair(
    first: &[u16],
    second: &[u16],
    first_name: &str,
    second_name: &str,
) -> Result<()> {
    if first
        .iter()
        .chain(second)
        .any(|status| !(100..=599).contains(status))
    {
        anyhow::bail!("expected HTTP statuses must be between 100 and 599");
    }
    if first.iter().any(|status| second.contains(status)) {
        anyhow::bail!("{first_name} and {second_name} must not overlap");
    }
    Ok(())
}

fn validate_header_oracle(
    header: Option<&str>,
    positive: Option<&str>,
    negative: Option<&str>,
    prefix: &str,
) -> Result<()> {
    match (header, positive, negative) {
        (None, None, None) | (Some(_), Some(_), Some(_)) => {}
        _ => anyhow::bail!("{prefix} header and both outcome values must be configured together"),
    }
    if let Some(header) = header {
        if header.is_empty()
            || !header
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            anyhow::bail!("{prefix}.header is not a valid HTTP field name");
        }
    }
    Ok(())
}

pub const DEFAULT_CONFIG: &str = r#"# Botgate policy: these are application requirements, not universal Web Bot Auth rules.
[policy]
require_authority = true
require_method = true
require_path = true
query = "ignore"
body = "ignore"
max_age_seconds = 300
max_lifetime_seconds = 300
allowed_future_skew_seconds = 30
require_nonce = false

# Live testing is opt-in. Set target.url and an explicit response oracle.
# [target]
# url = "https://staging.example.com/protected"
# timeout_seconds = 10
# max_response_bytes = 1048576
# allow_private = false
# allow_http = false
#
# [expect]
# header = "X-Agent-Authenticated"
# authenticated_value = "true"
# unauthenticated_value = "false"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_policy_keys() {
        let result = toml::from_str::<Config>("[policy]\nrequire_methd = true\n");
        assert!(result.is_err());
    }

    #[test]
    fn defaults_match_generated_config() {
        let generated: Config = toml::from_str(DEFAULT_CONFIG).unwrap();
        assert_eq!(
            generated.policy.require_method,
            Policy::default().require_method
        );
        assert_eq!(
            generated.policy.require_path,
            Policy::default().require_path
        );
    }

    #[test]
    fn rejects_negative_time_limits() {
        let mut config = Config::default();
        config.policy.allowed_future_skew_seconds = -1;
        assert!(config.validate().is_err());
    }
}
