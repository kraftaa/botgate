# Botgate

Botgate is an evidence-first conformance and coverage analyzer for Web Bot Auth and RFC 9421 HTTP Message Signatures.

It answers four separate questions:

1. Is the message shaped correctly for a selected protocol profile?
2. Does the signature verify with an explicitly supplied key?
3. Which request properties are cryptographically bound?
4. Does that coverage satisfy the application's declared policy?

Botgate deliberately does **not** infer authentication from an HTTP status code. A `200` response is not evidence that a server accepted a signature; the resource may simply be public.

## Status

This repository implements a focused v0.1:

- current `draft-ietf-webbotauth-httpsig-protocol-00` inspection;
- the current Cloudflare compatibility profile;
- current dictionary-form and legacy string-form `Signature-Agent` handling;
- RFC 9421 signature-base reconstruction for the common request components;
- RFC 8941 canonicalization for selected Structured Field dictionary members;
- Ed25519 signing and verification;
- JWK thumbprint/key selection;
- semantic coverage and configurable policy evaluation;
- `Content-Digest` SHA-256 validation;
- JSON output for CI;
- a safe offline mutation matrix.

It does not fetch untrusted key-directory URLs or send active mutations. Those operations require an SSRF-safe resolver and an explicit authentication oracle; pretending that response status alone is an oracle would produce misleading results.

## Build

```sh
cargo build --release
```

## End-to-end example

Generate a test key and policy:

```sh
target/release/botgate init
```

This creates:

```text
.botgate/
├── private.key       # Ed25519 PKCS#8, mode 0600 on Unix
├── public.jwk
├── directory.json
└── botgate.toml
```

The whole `.botgate/` directory is excluded by `.gitignore`. Botgate never prints the private key. A conformant remote key directory must be served over HTTPS.

Running `botgate init --force` regenerates `public.jwk` and `directory.json` from the existing private key. It never overwrites `private.key` or an existing `botgate.toml`.

On Unix, the private key is created atomically with mode `0600`. On Windows it is created with `create_new` but inherits the directory's ACL; restrict access to `.botgate/` yourself.

Sign the example request using the current IETF form:

```sh
target/release/botgate sign examples/request.http \
  --agent https://agent.example \
  --components @authority,@method,@path,@query \
  --output signed-request.http
```

Inspect declared coverage without loading a key:

```sh
target/release/botgate inspect signed-request.http \
  --config examples/strict-policy.toml
```

Verify cryptographically using a local JWKS:

```sh
target/release/botgate verify signed-request.http \
  --jwks .botgate/directory.json \
  --config examples/strict-policy.toml
```

Show the offline mutation matrix:

```sh
target/release/botgate test signed-request.http \
  --jwks .botgate/directory.json \
  --config examples/strict-policy.toml
```

Nothing is sent by `test`. In particular, Botgate never turns a `GET` into a live `POST` or `DELETE` request.
The matrix is generated independently for every signature in the request.

## Cloudflare interoperability

The September 2026 working-group draft requires new senders to emit dictionary-form `Signature-Agent`, keyed by the signature label:

```http
Signature-Agent: sig1="https://agent.example"
Signature-Input: sig1=("@authority" "signature-agent";key="sig1");...
```

Cloudflare currently documents the older bare-string form. Generate and analyze that form explicitly:

```sh
target/release/botgate sign examples/request.http \
  --agent https://agent.example \
  --components @authority \
  --legacy-agent \
  --output cloudflare-request.http

target/release/botgate inspect cloudflare-request.http --profile cloudflare
target/release/botgate inspect cloudflare-request.http --profile ietf-draft-00
```

The second command reports why the same request is legacy rather than conformant for a new IETF-draft sender.

## Policy

Policy requirements are application requirements, not claims that every conforming Web Bot Auth signature must cover the same fields.
Without `--config`, Botgate automatically loads `.botgate/botgate.toml` from the current directory when it exists; otherwise it uses the same built-in defaults produced by `init`. Every report names the policy it applied (`Policy:` in text, `policy_source` in JSON). In CI, pass `--config` explicitly so a change to `.botgate/` cannot silently alter the gate. Unknown keys and negative time limits are rejected.

```toml
[policy]
require_authority = true
require_method = true
require_path = true
query = "required"
body = "ignore"
max_age_seconds = 300
max_lifetime_seconds = 300
allowed_future_skew_seconds = 30
require_nonce = false
```

Coverage is semantic rather than a flat string check. For example, `@target-uri` satisfies authority, path, and query coverage, while `@path` does not cover the query. Body integrity requires a covered `Content-Digest` (the whole field, or its `sha-256` member via `;key="sha-256"`) whose SHA-256 value matches the body bytes. Covering only another member, such as `sha-512`, does not count.
Individual `@query-param` components are reported as partial evidence and do not satisfy a policy requiring the entire query to be bound. `@request-target` covers path and query for the raw HTTP/1.1 requests accepted by v0.1.

## JSON and exit behavior

Use `--format json` with `inspect`, `verify`, or `test`.

```sh
botgate inspect request.http --format json
```

Exit status is `0` when no error-level findings exist, `1` when conformance, compatibility, crypto, or policy findings fail, and `4` for input or configuration errors detected after argument parsing. Clap uses its conventional status `2` for command-line usage errors. JSON retains independent finding categories and cryptographic/identity states so CI does not need to infer meaning from prose.

## Trust model

Verification with `--jwks` establishes that the supplied key validates the signature. It intentionally reports identity as `key_only`: loading a local JWK does not prove that an HTTPS `Signature-Agent` URL published that key. URL attribution requires a safe HTTPS discovery operation and its cache state.

The signing command derives the thumbprint from the private key and refuses to proceed if `--jwk` names a different key pair.

Similarly, signing `Content-Digest` binds the digest header. Botgate separately recomputes the digest before reporting body integrity.

## Supported signature components

v0.1 reconstructs:

- `@method`
- `@authority`
- `@scheme`
- `@path`
- `@query`
- `@target-uri`
- `@request-target`
- `@query-param`;`name=...`
- ordinary HTTP fields
- dictionary field members selected with `;key=...`

Unsupported derived components cause verification to fail explicitly rather than being guessed.
Input files use a strict raw HTTP/1.0 or HTTP/1.1 request format; malformed control data, folded headers, and ambiguous authorities are rejected before analysis.

## Non-goals

Botgate does not impersonate commercial agents, bypass bot protection, solve CAPTCHAs, crawl sites, score “AI readiness,” or replace authorization and bot-management systems.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```

The minimum supported Rust version is 1.86. CI runs the test suite on Linux, macOS, and Windows.

`cargo test` includes property tests for the HTTP and Structured Fields parsers. Coverage-guided fuzz targets live in `fuzz/` and need a nightly toolchain and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run parse_request
cargo +nightly fuzz run parse_signatures
cargo +nightly fuzz run signature_base
```

See [SECURITY.md](SECURITY.md) for the trust model and how to report vulnerabilities.

The protocol is still an Internet-Draft. Profile-specific behavior is kept separate in the report engine, and `botgate protocol` identifies the implemented draft.

## References

- [Web Bot Auth working-group draft 00](https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol-00)
- [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [Cloudflare Web Bot Auth documentation](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/)
