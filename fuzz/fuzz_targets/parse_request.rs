#![no_main]

use botgate::http_message::Request;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(request) = Request::parse(data) else {
        return;
    };
    // Derived components must fail cleanly, never panic.
    let _ = request.path();
    let _ = request.query();
    let _ = request.authority(None);
    let _ = request.target_uri(None);

    // Anything accepted must survive serialization unchanged.
    let reparsed = Request::parse(&request.serialize()).expect("serialized request reparses");
    assert_eq!(reparsed.method, request.method);
    assert_eq!(reparsed.target, request.target);
    assert_eq!(reparsed.version, request.version);
    assert_eq!(reparsed.headers, request.headers);
    assert_eq!(reparsed.body, request.body);
});
