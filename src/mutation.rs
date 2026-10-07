use crate::{http_message::Request, signature::SignatureInput};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Mutation {
    pub signature_label: String,
    pub name: &'static str,
    pub component: &'static str,
    pub expected_crypto: &'static str,
    pub safe_to_send: bool,
    pub detail: String,
}

pub fn plan(request: &Request, input: &SignatureInput) -> Vec<Mutation> {
    let target_uri = input.covers("@target-uri");
    let request_target = input.covers("@request-target");
    let signed_digest =
        input.covers("content-digest") || input.covers_member("content-digest", "sha-256");
    let mut mutations = vec![
        Mutation {
            signature_label: input.label.clone(),
            name: "changed_method",
            component: "@method",
            expected_crypto: validity(input.covers("@method")),
            safe_to_send: false,
            detail: format!(
                "{} -> {}",
                request.method,
                if request.method == "HEAD" {
                    "GET"
                } else {
                    "HEAD"
                }
            ),
        },
        Mutation {
            signature_label: input.label.clone(),
            name: "changed_path",
            component: "@path",
            expected_crypto: validity(input.covers("@path") || target_uri || request_target),
            safe_to_send: true,
            detail: format!(
                "{} -> /__botgate_mutated__",
                request.path().unwrap_or_default()
            ),
        },
        Mutation {
            signature_label: input.label.clone(),
            name: "changed_query",
            component: "@query",
            expected_crypto: validity(input.covers("@query") || target_uri || request_target),
            safe_to_send: true,
            detail: "append __botgate=1".into(),
        },
        Mutation {
            signature_label: input.label.clone(),
            name: "changed_authority",
            component: "@authority",
            expected_crypto: validity(input.covers("@authority") || target_uri),
            safe_to_send: false,
            detail: "Host authority changed while the connection remains pinned to the authorized target".into(),
        },
        Mutation {
            signature_label: input.label.clone(),
            name: "changed_body",
            component: "content-digest",
            expected_crypto: if signed_digest {
                "digest_invalid"
            } else {
                "still_valid"
            },
            safe_to_send: false,
            detail: if signed_digest {
                "HTTP signature still verifies because the digest header is unchanged; separate Content-Digest validation fails"
            } else {
                "body is not cryptographically bound"
            }
            .into(),
        },
        Mutation {
            signature_label: input.label.clone(),
            name: "changed_signature_agent",
            component: "signature-agent",
            expected_crypto: validity(input.mentions("signature-agent")),
            safe_to_send: false,
            detail: "key-discovery identity changed".into(),
        },
        Mutation {
            signature_label: input.label.clone(),
            name: "corrupted_signature",
            component: "signature",
            expected_crypto: "invalid",
            safe_to_send: true,
            detail: "flip one signature byte".into(),
        },
    ];
    if let Some(name) = mutable_covered_header(request, input) {
        mutations.push(Mutation {
            signature_label: input.label.clone(),
            name: "changed_signed_header",
            component: "covered field",
            expected_crypto: "invalid",
            safe_to_send: true,
            detail: format!("change covered {name} field"),
        });
    }
    mutations
}

fn validity(bound: bool) -> &'static str {
    if bound { "invalid" } else { "still_valid" }
}

pub fn apply(request: &Request, input: &SignatureInput, name: &str) -> Result<Request> {
    let mut changed = request.clone();
    match name {
        "changed_method" => {
            changed.method = if request.method == "HEAD" {
                "GET"
            } else {
                "HEAD"
            }
            .into();
            changed.body.clear();
            changed.remove_header("content-length");
        }
        "changed_path" => {
            if let Ok(mut url) = url::Url::parse(&request.target) {
                url.set_path("/__botgate_mutated__");
                changed.target = url.to_string();
            } else {
                let query = request
                    .target
                    .split_once('?')
                    .map(|(_, query)| format!("?{query}"))
                    .unwrap_or_default();
                changed.target = format!("/__botgate_mutated__{query}");
            }
        }
        "changed_query" => {
            changed.target.push(if changed.target.contains('?') {
                '&'
            } else {
                '?'
            });
            changed.target.push_str("__botgate=1");
        }
        "changed_authority" => {
            changed.set_header("host", "botgate.invalid".into());
        }
        "changed_signed_header" => {
            let name = mutable_covered_header(request, input)
                .context("signature covers no mutable ordinary header")?;
            changed.set_header(name, "botgate-mutated".into());
        }
        "corrupted_signature" => {
            let raw = changed
                .header("signature")
                .ok_or_else(|| anyhow!("Signature header is absent"))?;
            let start = raw.find("=:").context("malformed Signature header")? + 2;
            let end = raw[start..]
                .find(':')
                .map(|offset| start + offset)
                .context("malformed Signature byte sequence")?;
            let mut bytes = STANDARD
                .decode(&raw[start..end])
                .context("invalid Signature base64")?;
            let first = bytes.first_mut().context("empty Signature byte sequence")?;
            *first ^= 1;
            changed.set_header(
                "signature",
                format!("{}{}{}", &raw[..start], STANDARD.encode(bytes), &raw[end..]),
            );
        }
        "removed_signature_agent" => changed.remove_header("signature-agent"),
        "changed_signature_agent" => {
            let raw = changed
                .header("signature-agent")
                .ok_or_else(|| anyhow!("Signature-Agent header is absent"))?;
            changed.set_header(
                "signature-agent",
                if raw.trim_start().starts_with('"') {
                    "\"not-a-url\"".into()
                } else {
                    let label = raw.split('=').next().unwrap_or("sig1");
                    format!("{label}=\"not-a-url\"")
                },
            );
        }
        "changed_body" => {
            changed.body.push(0x42);
            changed.remove_header("content-length");
        }
        _ => bail!("unknown mutation {name}"),
    }
    Ok(changed)
}

fn mutable_covered_header<'a>(request: &'a Request, input: &SignatureInput) -> Option<&'a str> {
    request.headers.iter().find_map(|(name, _)| {
        (name != "signature"
            && name != "signature-input"
            && name != "signature-agent"
            && input.mentions(name))
        .then_some(name.as_str())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::CoveredComponent;

    #[test]
    fn changes_an_ordinary_covered_header() {
        let request = Request {
            method: "GET".into(),
            target: "/".into(),
            version: "HTTP/1.1".into(),
            headers: vec![
                ("host".into(), "example.test".into()),
                ("x-signed".into(), "original".into()),
            ],
            body: vec![],
        };
        let input = SignatureInput {
            label: "sig1".into(),
            components: vec![CoveredComponent {
                name: "x-signed".into(),
                params: vec![],
            }],
            params: vec![],
        };

        assert!(
            plan(&request, &input)
                .iter()
                .any(|mutation| mutation.name == "changed_signed_header")
        );
        let changed = apply(&request, &input, "changed_signed_header").unwrap();
        assert_eq!(changed.header("x-signed"), Some("botgate-mutated".into()));
    }
}
