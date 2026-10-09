# Security policy

## Supported versions

Botgate is pre-1.0. Only the latest released version receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| 0.3.x   | No        |
| 0.2.x   | No        |
| 0.1.x   | No        |

## Reporting a vulnerability

Report vulnerabilities through [GitHub's private vulnerability reporting form](https://github.com/kraftaa/botgate/security/advisories/new). If that form is unavailable, contact the repository owner, [@kraftaa](https://github.com/kraftaa), privately. Do not describe a suspected vulnerability in an issue, pull request, or any other shared channel. Include:

- the Botgate version (`botgate --version`) and platform;
- the command line you ran;
- a minimal input file that reproduces the problem, with any real keys, tokens, or personal data removed;
- what you expected and what happened.

You should receive an acknowledgement within 7 days. Once a fix is available, it will be released and credited in the advisory unless you ask otherwise.

## Trust model

Botgate has offline analysis and explicitly requested network modes. Its guarantees are deliberately narrow.

**What Botgate does not do**

- `inspect`, `sign`, and file-based `test` without `--live` make no network requests.
- `verify --discover` fetches only the covered `Signature-Agent` key source.
- `test URL` and file-based `test --live URL` send the original and reported mutations to the specified target.
- Live testing requires an explicit authentication oracle. A dedicated header is the default; status-only authentication requires an explicit compatibility override. Application access uses a separate optional oracle.
- Botgate does not follow redirects or use environment proxies. It validates and pins DNS resolution, limits response size and time, and blocks private, loopback, link-local, and special-use addresses unless the user provides an explicit local-test override.

**What a result means**

- `cryptographic_status: valid` means the signature verifies against a key **you supplied** with `--jwks`, whose JWK thumbprint equals the signature's `keyid`.
- `identity_status: key_only` means exactly that. A locally supplied key proves nothing about who controls the `Signature-Agent` URL; Botgate never reports that URL as verified.
- `identity_status: valid` after `--discover` means the signature verified using key material resolved from that signature's covered identity URL. Discovery is currently limited to one signature per command to prevent cross-identity key attribution.
- Coverage and policy findings describe which request properties the signature binds. A body is reported as intact only when `Content-Digest` is covered **and** its SHA-256 value matches the body bytes in the input file.
- Results are only as trustworthy as the input file. Botgate analyzes the bytes you give it; it cannot tell whether they match what a server actually received.

**Key handling**

- `botgate init` creates an Ed25519 private key at `.botgate/private.key`. On Unix it is created atomically with mode `0600`. On Windows it inherits the directory's ACL, so restrict access yourself.
- Botgate never prints the private key and never overwrites an existing one.
- Generated keys are intended for testing. Do not reuse them as production signing keys.
- `directory serve` and `demo serve` bind to loopback by default. Their non-loopback overrides expose development services and should be used only on controlled networks.

## In scope

- Parser bugs in the HTTP message or Structured Fields handling that cause panics, unbounded resource use, or inputs being accepted that a conforming implementation would reject (or the reverse).
- Any case where Botgate reports a signature as valid, a property as covered, or a policy as satisfied when it is not.
- Private-key exposure through file permissions, logs, or output.
- SSRF bypasses, redirect/proxy bypasses, DNS-rebinding issues, or unsafe mutation behavior in network modes.

## Out of scope

- Weaknesses in the Web Bot Auth draft or RFC 9421 themselves.
- Behavior of servers, CDNs, or bot-management products that Botgate analyzes requests for.
- Findings that require a modified Botgate binary or a compromised local machine.
