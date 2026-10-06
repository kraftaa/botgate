//! Property tests for the HTTP message and Structured Fields parsers.
//! The same invariants are exercised with coverage guidance by the targets in `fuzz/`.

use botgate::{http_message::Request, signature};
use proptest::prelude::*;
use url::Url;

fn method() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("GET".to_string()),
        Just("POST".to_string()),
        "[A-Z]{1,8}"
    ]
}

fn target() -> impl Strategy<Value = String> {
    (
        "(/[a-z0-9._~-]{0,8}){1,4}",
        proptest::option::of("[a-z0-9=&+%]{0,16}"),
    )
        .prop_map(|(path, query)| match query {
            Some(q) => format!("{path}?{q}"),
            None => path,
        })
}

fn header_name() -> impl Strategy<Value = String> {
    "[A-Za-z][A-Za-z0-9-]{0,15}"
}

/// Visible ASCII with interior spaces/tabs; parsing trims leading and trailing whitespace.
fn header_value() -> impl Strategy<Value = String> {
    "([!-~]([ \t!-~]{0,30}[!-~])?)?"
}

fn request_bytes() -> impl Strategy<Value = (String, String, Vec<(String, String)>, Vec<u8>)> {
    (
        method(),
        target(),
        proptest::collection::vec((header_name(), header_value()), 0..8),
        proptest::collection::vec(any::<u8>(), 0..64),
    )
}

fn render(method: &str, target: &str, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("{method} {target} HTTP/1.1\r\nHost: example.test\r\n").into_bytes();
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// A covered component identifier from the set Botgate reconstructs, with optional parameters.
fn component() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("\"@method\"".to_string()),
        Just("\"@authority\"".to_string()),
        Just("\"@path\"".to_string()),
        Just("\"@query\"".to_string()),
        Just("\"@target-uri\"".to_string()),
        Just("\"@request-target\"".to_string()),
        "[a-z][a-z0-9-]{0,10}".prop_map(|name| format!("\"x-{name}\"")),
        "[a-z][a-z0-9]{0,6}".prop_map(|key| format!("\"x-dict\";key=\"{key}\"")),
    ]
}

fn parameter_value() -> impl Strategy<Value = String> {
    prop_oneof![
        (0i64..=999_999_999_999_999).prop_map(|n| n.to_string()),
        "[ !#-\\[\\]-~]{0,16}".prop_map(|s| format!("\"{s}\"")),
        "[a-z][a-z0-9_.:/*-]{0,10}",
        Just("?0".to_string()),
    ]
}

fn signature_input() -> impl Strategy<Value = String> {
    (
        "[a-z][a-z0-9_-]{0,8}",
        proptest::collection::vec(component(), 1..6),
        proptest::collection::btree_map("[a-z][a-z0-9_-]{0,8}", parameter_value(), 0..6),
    )
        .prop_map(|(label, components, params)| {
            let mut seen = std::collections::BTreeSet::new();
            let components: Vec<_> = components
                .into_iter()
                .filter(|c| seen.insert(c.clone()))
                .collect();
            let params: String = params
                .into_iter()
                .map(|(name, value)| format!(";{name}={value}"))
                .collect();
            format!("{label}=({}){params}", components.join(" "))
        })
}

proptest! {
    #[test]
    fn request_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        if let Ok(request) = Request::parse(&bytes) {
            let _ = request.path();
            let _ = request.query();
            let _ = request.authority(None);
            let _ = request.target_uri(None);
        }
    }

    #[test]
    fn error_messages_never_contain_control_bytes(
        bytes in prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..256),
            // A valid request line, so arbitrary bytes reach header parsing.
            proptest::collection::vec(any::<u8>(), 0..128).prop_map(|tail| {
                let mut bytes = b"GET / HTTP/1.1\r\n".to_vec();
                bytes.extend(tail);
                bytes.extend_from_slice(b"\r\n\r\n");
                bytes
            }),
        ]
    ) {
        let message = match Request::parse(&bytes) {
            Err(error) => format!("{error:#}"),
            Ok(request) => match signature::parse(&request) {
                Err(error) => format!("{error:#}"),
                Ok(_) => return Ok(()),
            },
        };
        prop_assert!(!message.chars().any(char::is_control), "{message:?}");
    }

    #[test]
    fn printable_garbage_never_panics(text in "[ -~\r\n\t]{0,200}") {
        if let Ok(request) = Request::parse(text.as_bytes()) {
            let _ = signature::parse(&request);
        }
    }

    #[test]
    fn well_formed_requests_parse_and_round_trip((method, target, headers, body) in request_bytes()) {
        let request = Request::parse(&render(&method, &target, &headers, &body))
            .expect("well-formed request parses");
        prop_assert_eq!(&request.method, &method);
        prop_assert_eq!(&request.target, &target);
        prop_assert_eq!(&request.body, &body);
        prop_assert_eq!(request.headers.len(), headers.len() + 1);

        let reparsed = Request::parse(&request.serialize()).expect("serialized request reparses");
        prop_assert_eq!(reparsed.method, request.method);
        prop_assert_eq!(reparsed.target, request.target);
        prop_assert_eq!(reparsed.headers, request.headers);
        prop_assert_eq!(reparsed.body, request.body);
    }

    #[test]
    fn signature_input_survives_canonical_round_trip(header in signature_input()) {
        let raw = format!("GET / HTTP/1.1\r\nHost: example.test\r\nSignature-Input: {header}\r\n\r\n");
        let request = Request::parse(raw.as_bytes()).unwrap();
        let parsed = signature::parse(&request).expect("generated Signature-Input parses");
        prop_assert_eq!(parsed.inputs.len(), 1);
        let input = &parsed.inputs[0];

        let mut copy = request.clone();
        copy.set_header("signature-input", format!("{}={}", input.label, input.canonical_value()));
        let reparsed = signature::parse(&copy).expect("canonical Signature-Input reparses");
        prop_assert_eq!(&reparsed.inputs[0].components, &input.components);
        prop_assert_eq!(&reparsed.inputs[0].params, &input.params);
        prop_assert_eq!(reparsed.inputs[0].canonical_value(), input.canonical_value());
    }

    #[test]
    fn signature_base_has_one_line_per_component(
        header in signature_input(),
        dict_key in "[a-z][a-z0-9]{0,6}",
        value in header_value(),
    ) {
        let raw = format!(
            "GET /a?b=c HTTP/1.1\r\nHost: example.test\r\nX-Dict: {dict_key}=\"{}\"\r\nSignature-Input: {header}\r\n\r\n",
            value.replace(['"', '\\'], "")
        );
        let Ok(request) = Request::parse(raw.as_bytes()) else { return Ok(()); };
        let parsed = signature::parse(&request).unwrap();
        let context = Url::parse("https://example.test").unwrap();
        for input in &parsed.inputs {
            for context in [None, Some(&context)] {
                if let Ok(base) = signature::signature_base(&request, input, context) {
                    prop_assert_eq!(base.lines().count(), input.components.len() + 1);
                    prop_assert!(!base.contains('\r'));
                    prop_assert!(base.lines().last().unwrap().starts_with("\"@signature-params\": "));
                }
            }
        }
    }
}
