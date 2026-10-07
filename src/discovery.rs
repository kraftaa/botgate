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
            let content_type = response
                .headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .split(';')
                .next()
                .unwrap_or_default()
                .trim();
            if !content_type.eq_ignore_ascii_case(MEDIA_TYPE) {
                bail!("directory returned unsupported Content-Type {content_type:?}");
            }
            Ok(DiscoveryResult {
                identity: fetch.to_string(),
                jwks: validate_jwks(&response.body, false)?,
            })
        }
        Kind::JwksUri => {
            let response = network::get(&locator.url, "application/jwk-set+json", policy)?;
            require_ok(&response, &locator.url)?;
            Ok(DiscoveryResult {
                identity: normalized_identifier(&locator.url),
                jwks: validate_directory(&response.body)?,
            })
        }
        Kind::Cimd => {
            let response = network::get(&locator.url, "application/json", policy)?;
            require_ok(&response, &locator.url)?;
            let document: CimdDocument =
                serde_json::from_slice(&response.body).context("parsing CIMD document")?;
            let jwks = match (document.jwks, document.jwks_uri) {
                (Some(keys), None) => validate_jwks(&serde_json::to_vec(&keys)?, false)?,
                (None, Some(uri)) => {
                    let uri = Url::parse(&uri).context("parsing CIMD jwks_uri")?;
                    let keys = network::get(&uri, "application/jwk-set+json", policy)?;
                    require_ok(&keys, &uri)?;
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
