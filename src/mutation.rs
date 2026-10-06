use crate::{http_message::Request, signature::SignatureInput};
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
    vec![
        Mutation {
            signature_label: input.label.clone(),
            name: "changed_method",
            component: "@method",
            expected_crypto: validity(input.covers("@method")),
            safe_to_send: false,
            detail: format!("{} -> POST", request.method),
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
            detail: "authority changed; cross-origin sending is disabled".into(),
        },
        Mutation {
            signature_label: input.label.clone(),
            name: "changed_body",
            component: "content-digest",
            expected_crypto: "still_valid",
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
    ]
}

fn validity(bound: bool) -> &'static str {
    if bound { "invalid" } else { "still_valid" }
}
