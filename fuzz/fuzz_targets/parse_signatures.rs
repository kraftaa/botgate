#![no_main]

use botgate::{http_message::Request, signature};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(request) = Request::parse(data) else {
        return;
    };
    let Ok(parsed) = signature::parse(&request) else {
        return;
    };
    // Re-serializing an accepted Signature-Input must parse back to the same value.
    for input in &parsed.inputs {
        let mut copy = request.clone();
        copy.set_header(
            "signature-input",
            format!("{}={}", input.label, input.canonical_value()),
        );
        copy.remove_header("signature");
        let reparsed = signature::parse(&copy).expect("canonical Signature-Input reparses");
        assert_eq!(reparsed.inputs.len(), 1);
        assert_eq!(reparsed.inputs[0].components, input.components);
        assert_eq!(reparsed.inputs[0].params, input.params);
        assert_eq!(
            reparsed.inputs[0].canonical_value(),
            input.canonical_value()
        );
    }
});
