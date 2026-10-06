use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub policy: Policy,
    /// The file the policy was read from; `None` means the built-in defaults.
    #[serde(skip)]
    pub source: Option<std::path::PathBuf>,
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

    fn validate(&self) -> Result<()> {
        if self.policy.allowed_future_skew_seconds < 0
            || self.policy.max_age_seconds.is_some_and(|value| value < 0)
            || self
                .policy
                .max_lifetime_seconds
                .is_some_and(|value| value < 0)
        {
            anyhow::bail!("policy time limits must be non-negative");
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
