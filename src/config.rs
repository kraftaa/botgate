use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

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
    pub accepted_statuses: Vec<u16>,
    pub rejected_statuses: Vec<u16>,
    pub header: Option<String>,
    pub accepted_value: Option<String>,
    pub rejected_value: Option<String>,
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
        if self
            .expect
            .accepted_statuses
            .iter()
            .any(|status| !(100..=599).contains(status))
            || self
                .expect
                .rejected_statuses
                .iter()
                .any(|status| !(100..=599).contains(status))
        {
            anyhow::bail!("expected HTTP statuses must be between 100 and 599");
        }
        if self
            .expect
            .accepted_statuses
            .iter()
            .any(|status| self.expect.rejected_statuses.contains(status))
        {
            anyhow::bail!("accepted_statuses and rejected_statuses must not overlap");
        }
        match (
            &self.expect.header,
            &self.expect.accepted_value,
            &self.expect.rejected_value,
        ) {
            (None, None, None) | (Some(_), Some(_), Some(_)) => {}
            _ => anyhow::bail!(
                "expect.header, accepted_value, and rejected_value must be configured together"
            ),
        }
        if let Some(header) = &self.expect.header
            && (header.is_empty()
                || !header
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)))
        {
            anyhow::bail!("expect.header is not a valid HTTP field name");
        }
        Ok(())
    }
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
# accepted_statuses = [200]
# rejected_statuses = [401, 403]
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
