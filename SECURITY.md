# Security policy

## Supported versions

Botgate is pre-1.0. Only the latest released version receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Report vulnerabilities privately to the repository owner, [@kraftaa](https://github.com/kraftaa). Do not describe a suspected vulnerability in an issue, pull request, or any other shared channel. Include:

- the Botgate version (`botgate --version`) and platform;
- the command line you ran;
- a minimal input file that reproduces the problem, with any real keys, tokens, or personal data removed;
- what you expected and what happened.

You should receive an acknowledgement within 7 days. Once a fix is available, it will be released and credited in the advisory unless you ask otherwise.

## Trust model

Botgate is an offline analyzer. Its guarantees are deliberately narrow.

**What Botgate does not do**

- It makes no network requests. It never fetches `Signature-Agent` key directories, never resolves URLs, and never sends the original or mutated requests anywhere.
- The `test` command's mutation matrix is computed locally; nothing is sent.
- It does not treat an HTTP response status as evidence that a signature was accepted.

**What a result means**

- `cryptographic_status: valid` means the signature verifies against a key **you supplied** with `--jwks`, whose JWK thumbprint equals the signature's `keyid`.
- `identity_status: key_only` means exactly that. A locally supplied key proves nothing about who controls the `Signature-Agent` URL; Botgate never reports that URL as verified.
- Coverage and policy findings describe which request properties the signature binds. A body is reported as intact only when `Content-Digest` is covered **and** its SHA-256 value matches the body bytes in the input file.
- Results are only as trustworthy as the input file. Botgate analyzes the bytes you give it; it cannot tell whether they match what a server actually received.

**Key handling**

- `botgate init` creates an Ed25519 private key at `.botgate/private.key`. On Unix it is created atomically with mode `0600`. On Windows it inherits the directory's ACL, so restrict access yourself.
- Botgate never prints the private key and never overwrites an existing one.
- Generated keys are intended for testing. Do not reuse them as production signing keys.

## In scope

- Parser bugs in the HTTP message or Structured Fields handling that cause panics, unbounded resource use, or inputs being accepted that a conforming implementation would reject (or the reverse).
- Any case where Botgate reports a signature as valid, a property as covered, or a policy as satisfied when it is not.
- Private-key exposure through file permissions, logs, or output.

## Out of scope

- Weaknesses in the Web Bot Auth draft or RFC 9421 themselves.
- Behavior of servers, CDNs, or bot-management products that Botgate analyzes requests for.
- Findings that require a modified Botgate binary or a compromised local machine.
