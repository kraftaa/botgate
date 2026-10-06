#![no_main]

use botgate::{http_message::Request, signature};
use libfuzzer_sys::fuzz_target;
use url::Url;

fuzz_target!(|data: &[u8]| {
    let Ok(request) = Request::parse(data) else {
        return;
    };
    let Ok(parsed) = signature::parse(&request) else {
        return;
    };
    let context = Url::parse("https://fuzz.example").unwrap();
    for input in &parsed.inputs {
        for context in [None, Some(&context)] {
            let Ok(base) = signature::signature_base(&request, input, context) else {
                continue;
            };
            // One line per component plus @signature-params; no value may inject a line.
            assert_eq!(base.lines().count(), input.components.len() + 1);
            assert!(!base.contains('\r'));
            assert!(
                base.lines()
                    .last()
                    .unwrap()
                    .starts_with("\"@signature-params\": ")
            );
        }
    }
});
