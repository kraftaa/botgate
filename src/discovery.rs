use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use url::Url;

use crate::{
    crypto::Jwks,
    directory::{MEDIA_TYPE, WELL_KNOWN_PATH, validate_directory, validate_jwks},
    http_message::Request,
    network::{self, NetworkPolicy},
    signature::{self, SignatureInput, Value},
};

#[derive(Debug)]
pub struct DiscoveryResult {
    pub identity: String,
    pub jwks: Jwks,
}

#[derive(Debug)]
struct Locator {
    url: Url,
    kind: Kind,
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Directory,
    JwksUri,
    Cimd,
}

#[derive(Deserialize)]
struct CimdDocument {
    #[serde(default)]
    jwks: Option<Jwks>,
    #[serde(default)]
    jwks_uri: Option<String>,
}

pub fn discover(
    request: &Request,
    input: &SignatureInput,
    policy: &NetworkPolicy,
) -> Result<DiscoveryResult> {
    let locator = locator(request, input, policy.allow_http)?;
    match locator.kind {
        Kind::Directory => {
            if locator.url.path() != "/"
                || locator.url.query().is_some()
                || locator.url.fragment().is_some()
            {
                bail!("directory-type Signature-Agent must be an origin URL");
            }
            let fetch = locator
                .url
                .join(WELL_KNOWN_PATH)
                .context("constructing well-known directory URL")?;
            let response = network::get(&fetch, MEDIA_TYPE, policy)?;
            require_ok(&response, &fetch)?;
            require_content_type(&response, &[MEDIA_TYPE])?;
            Ok(DiscoveryResult {
                identity: fetch.to_string(),
                jwks: validate_directory(&response.body)?,
            })
        }
        Kind::JwksUri => {
            let response = network::get(&locator.url, "application/jwk-set+json", policy)?;
            require_ok(&response, &locator.url)?;
            require_content_type(&response, JWKS_MEDIA_TYPES)?;
            Ok(DiscoveryResult {
                identity: normalized_identifier(&locator.url),
                // Direct/shared JWKS documents may use operator-assigned `kid` values.
                // Web Bot Auth selects by the JWK thumbprint carried in `keyid`.
                jwks: validate_jwks(&response.body, false)?,
            })
        }
        Kind::Cimd => {
            let response = network::get(&locator.url, "application/json", policy)?;
            require_ok(&response, &locator.url)?;
            require_json_content_type(&response)?;
            let document: CimdDocument =
                serde_json::from_slice(&response.body).context("parsing CIMD document")?;
            let jwks = match (document.jwks, document.jwks_uri) {
                (Some(keys), None) => validate_jwks(&serde_json::to_vec(&keys)?, false)?,
                (None, Some(uri)) => {
                    let uri = Url::parse(&uri).context("parsing CIMD jwks_uri")?;
                    let keys = network::get(&uri, "application/jwk-set+json", policy)?;
                    require_ok(&keys, &uri)?;
                    require_content_type(&keys, JWKS_MEDIA_TYPES)?;
                    validate_jwks(&keys.body, false)?
                }
                (Some(_), Some(_)) => bail!("CIMD must not contain both jwks and jwks_uri"),
                (None, None) => bail!("CIMD contains neither jwks nor jwks_uri"),
            };
            Ok(DiscoveryResult {
                identity: normalized_identifier(&locator.url),
                jwks,
            })
        }
    }
}

/// JWK Set media type, plus the generic JSON type that key servers commonly use.
const JWKS_MEDIA_TYPES: &[&str] = &["application/jwk-set+json", "application/json"];

/// Rejects a discovery document unless its Content-Type is one of `allowed`, ignoring parameters.
fn require_content_type(response: &network::HttpResponse, allowed: &[&str]) -> Result<()> {
    let content_type = content_type(response);
    if !allowed
        .iter()
        .any(|expected| content_type.eq_ignore_ascii_case(expected))
    {
        bail!("discovery source returned unsupported Content-Type {content_type:?}");
    }
    Ok(())
}

/// CIMD permits `application/json` and more specific `application/*+json` types.
fn require_json_content_type(response: &network::HttpResponse) -> Result<()> {
    let content_type = content_type(response);
    let accepted = content_type
        .split_once('/')
        .is_some_and(|(top_level, subtype)| {
            top_level.eq_ignore_ascii_case("application")
                && (subtype.eq_ignore_ascii_case("json")
                    || subtype.to_ascii_lowercase().ends_with("+json"))
        });
    if !accepted {
        bail!("discovery source returned unsupported Content-Type {content_type:?}");
    }
    Ok(())
}

fn content_type(response: &network::HttpResponse) -> &str {
    response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
}

fn locator(request: &Request, input: &SignatureInput, allow_http: bool) -> Result<Locator> {
    let raw = request
        .header("signature-agent")
        .ok_or_else(|| anyhow!("Signature-Agent is absent"))?;
    if raw.trim_start().starts_with('"') {
        return Ok(Locator {
            url: parse_discovery_url(&signature::parse_string_item(raw.trim())?, allow_http)?,
            kind: Kind::Directory,
        });
    }
    let key = input
        .components
        .iter()
        .filter(|component| component.name == "signature-agent")
        .find_map(|component| {
            component
                .params
                .iter()
                .find(|(name, _)| name == "key")
                .and_then(|(_, value)| value.as_string())
        })
        .ok_or_else(|| anyhow!("signature does not cover a Signature-Agent dictionary member"))?;
    let (value, params) = signature::dictionary_string_member_with_params(&raw, key)?;
    let kind = match params.iter().find(|(name, _)| name == "type") {
        None => Kind::Directory,
        Some((_, Value::Token(value))) if value == "directory" => Kind::Directory,
        Some((_, Value::Token(value))) if value == "jwks_uri" => Kind::JwksUri,
        Some((_, Value::Token(value))) if value == "cimd" => Kind::Cimd,
        Some((_, _)) => bail!("unsupported Signature-Agent type parameter"),
    };
    Ok(Locator {
        url: parse_discovery_url(&value, allow_http)?,
        kind,
    })
}

fn parse_discovery_url(value: &str, allow_http: bool) -> Result<Url> {
    let url = Url::parse(value).context("parsing Signature-Agent URL")?;
    if url.host_str().is_none()
        || !(url.scheme() == "https" || (allow_http && url.scheme() == "http"))
    {
        bail!("Signature-Agent discovery requires an https URL with a host");
    }
    Ok(url)
}

fn require_ok(response: &network::HttpResponse, url: &Url) -> Result<()> {
    if response.status != 200 {
        bail!("discovery at {url} returned HTTP {}", response.status);
    }
    Ok(())
}

fn normalized_identifier(url: &Url) -> String {
    let mut identifier = url.clone();
    identifier.set_query(None);
    identifier.set_fragment(None);
    identifier.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};

    fn response(content_type: Option<&'static str>) -> network::HttpResponse {
        let mut headers = HeaderMap::new();
        if let Some(value) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(value));
        }
        network::HttpResponse {
            status: 200,
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn key_sources_must_declare_a_json_content_type() {
        for accepted in [
            "application/jwk-set+json",
            "application/json; charset=utf-8",
            "Application/JSON",
        ] {
            assert!(
                require_content_type(&response(Some(accepted)), JWKS_MEDIA_TYPES).is_ok(),
                "{accepted}"
            );
        }
        for rejected in [Some("text/html"), Some("text/plain"), None] {
            assert!(
                require_content_type(&response(rejected), JWKS_MEDIA_TYPES).is_err(),
                "{rejected:?}"
            );
        }
        assert!(require_content_type(&response(Some("application/json")), &[MEDIA_TYPE]).is_err());
    }

    #[test]
    fn cimd_accepts_application_json_media_types() {
        for accepted in [
            "application/json",
            "application/client-metadata+json; charset=utf-8",
            "Application/Vnd.Example+JSON",
        ] {
            assert!(
                require_json_content_type(&response(Some(accepted))).is_ok(),
                "{accepted}"
            );
        }
        for rejected in [
            Some("text/json"),
            Some("text/example+json"),
            Some("application/json-seq"),
            None,
        ] {
            assert!(
                require_json_content_type(&response(rejected)).is_err(),
                "{rejected:?}"
            );
        }
    }
}
