# Botgate

Botgate is an evidence-first conformance and coverage analyzer for Web Bot Auth and RFC 9421 HTTP Message Signatures.

It answers five separate questions:

1. Is the message shaped correctly for a selected protocol profile?
2. Does the signature verify with a supplied or safely discovered key?
3. Which request properties are cryptographically bound?
4. Does that coverage satisfy the application's declared policy?
5. Does an authorized server enforce the same boundary under controlled mutations?

Botgate deliberately does **not** infer authentication from an HTTP status code. Live tests require the user to define an acceptance/rejection oracle using classified statuses or a dedicated response header.

## Status

The current implementation includes:

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
- an offline mutation matrix;
- controlled live-server testing with an explicit authentication oracle;
- expired, future-created, long/missing-expiry, unknown-key, method, path, query, authority, covered-header, identity-header, and corrupted-signature cases;
- SSRF-resistant `Signature-Agent` discovery for directory, `jwks_uri`, and CIMD forms;
- a local well-known key-directory server;
- a local weak/strict verifier for reproducible demonstrations.

Network operations disable redirects and proxies, pin a validated DNS result, cap response sizes and timeouts, and reject private, loopback, link-local, and special-use addresses by default. Local test overrides are explicit.

## Install

You do not need Rust or Cargo to use Botgate.

On macOS or Linux, install with Homebrew:

```sh
brew install kraftaa/tap/botgate
```

If you already use Python tooling, install the same native Botgate binary on
macOS, Linux, or Windows with `pipx`:

```sh
pipx install botgate
```

Or with `uv`:

```sh
uv tool install botgate
```

Inside an existing Python virtual environment, ordinary pip works too:

```sh
python -m pip install botgate
```

These package-manager installs use prebuilt native binaries; they do not
compile Botgate or install a Rust toolchain. Standalone archives, a Windows
installer, a shell installer, and SHA-256 checksums are also available on the
[Releases page](https://github.com/kraftaa/botgate/releases) as fallbacks.

Confirm the installation:

```sh
botgate --version
botgate --help
```

## End-to-end example

Generate a test key and policy:

```sh
botgate init
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
botgate sign examples/request.http \
  --agent https://agent.example \
  --components @authority,@method,@path,@query \
  --output signed-request.http
```

Inspect declared coverage without loading a key:

```sh
botgate inspect signed-request.http \
  --config examples/strict-policy.toml
```

Verify cryptographically using a local JWKS:

```sh
botgate verify signed-request.http \
  --jwks .botgate/directory.json \
  --config examples/strict-policy.toml
```

Show the offline mutation matrix (a request file means nothing is sent):

```sh
botgate test signed-request.http \
  --jwks .botgate/directory.json \
  --config examples/strict-policy.toml
```

The matrix is generated independently for every signature in the request.

## Live end-to-end test

Botgate includes a local verifier so the complete behavior can be demonstrated without another project. Start it in one terminal:

```sh
botgate demo serve \
  --jwks .botgate/directory.json \
  --config examples/strict-policy.toml
```

Then sign and test the URL directly:

```sh
botgate test 'http://127.0.0.1:8080/orders/123?view=summary' \
  --agent https://agent.example \
  --config examples/live-test.toml
```

The explicit local-network and HTTP permissions are in `examples/live-test.toml`. Against the strict verifier, the original request must be accepted and invalid mutations must be rejected. The live report compares locally predicted cryptographic behavior with the configured server oracle; an unclassified response is `indeterminate`, not success.

The original weak-versus-strict demonstration is also included. Start the demo with `examples/weak-policy.toml`, then test with `--components @authority --config examples/weak-live-test.toml`. Method, path, and query mutations remain cryptographically valid and the weak verifier accepts them; Botgate reports that as conformant behavior matching the deliberately weak policy, not as a vulnerability.

To test a real authorized HTTPS endpoint, private-network and HTTP overrides are unnecessary:

```sh
botgate test 'https://staging.example.com/protected' \
  --agent https://keys.agent.example \
  --accepted-status 200 \
  --rejected-status 401,403
```

Botgate generates only `GET` and `HEAD` mutations by default. Replaying another method requires `--allow-unsafe-methods`.

## Key discovery and directory serving

Verify a saved request using the key source covered by `Signature-Agent`:

```sh
botgate verify signed-request.http --discover
```

Discovery requires HTTPS, never follows redirects, validates directory content, limits response bytes and key count, and keeps key material scoped to one Signature-Agent identity. For local development, serve the generated directory at the draft's well-known path:

```sh
botgate directory serve --port 8787
```

The built-in directory server binds to loopback and uses HTTP, so it is for local tests only. A conformant public directory must use HTTPS and the specified media type.

## Cloudflare interoperability

The September 2026 working-group draft requires new senders to emit dictionary-form `Signature-Agent`, keyed by the signature label:

```http
Signature-Agent: sig1="https://agent.example"
Signature-Input: sig1=("@authority" "signature-agent";key="sig1");...
```

Cloudflare currently documents the older bare-string form. Generate and analyze that form explicitly:

```sh
botgate sign examples/request.http \
  --agent https://agent.example \
  --components @authority \
  --legacy-agent \
  --output cloudflare-request.http

botgate inspect cloudflare-request.http --profile cloudflare
botgate inspect cloudflare-request.http --profile ietf-draft-00
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

[target]
url = "https://staging.example.com/protected"
timeout_seconds = 10
max_response_bytes = 1048576
allow_private = false
allow_http = false

[expect]
accepted_statuses = [200]
rejected_statuses = [401, 403]

# A header oracle is stronger when the endpoint can provide one:
# header = "X-Bot-Authenticated"
# accepted_value = "true"
# rejected_value = "false"

[tests]
changed_method = true
changed_path = true
changed_query = true
changed_authority = true
changed_signed_header = true
changed_body = true
corrupted_signature = true
removed_signature_agent = true
changed_signature_agent = true
expired = true
future_created = true
long_expiration = true
missing_expires = true
unknown_key = true
```

Coverage is semantic rather than a flat string check. For example, `@target-uri` satisfies authority, path, and query coverage, while `@path` does not cover the query. Body integrity requires a covered `Content-Digest` (the whole field, or its `sha-256` member via `;key="sha-256"`) whose SHA-256 value matches the body bytes. Covering only another member, such as `sha-512`, does not count.
Individual `@query-param` components are reported as partial evidence and do not satisfy a policy requiring the entire query to be bound. `@request-target` covers path and query for the raw HTTP/1.1 requests Botgate accepts.

## JSON and exit behavior

Use `--format json` with `inspect`, `verify`, or `test`.

```sh
botgate inspect request.http --format json
```

Exit status is `0` when no error-level findings exist, `1` when conformance, compatibility, crypto, or policy findings fail, and `4` for input or configuration errors detected after argument parsing. Clap uses its conventional status `2` for command-line usage errors. JSON retains independent finding categories and cryptographic/identity states so CI does not need to infer meaning from prose.

## Trust model

Verification with `--jwks` establishes that the supplied key validates the signature and reports identity as `key_only`. `--discover` reports a verified identity only when key material was fetched from the request's covered `Signature-Agent` locator and the signature validates with the selected key.

The signing command derives the thumbprint from the private key and refuses to proceed if `--jwk` names a different key pair.

Similarly, signing `Content-Digest` binds the digest header. Botgate separately recomputes the digest before reporting body integrity.

## Supported signature components

Botgate reconstructs:

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

Rust and Cargo are required only when building Botgate from source or
contributing to the project:

```sh
cargo build --release
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
Maintainer release setup is documented in [RELEASING.md](RELEASING.md).

The protocol is still an Internet-Draft. Profile-specific behavior is kept separate in the report engine, and `botgate protocol` identifies the implemented draft.

## References

- [Web Bot Auth working-group draft 00](https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol-00)
- [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [Cloudflare Web Bot Auth documentation](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/)
