# Releasing Botgate

Release automation stays disabled while the repository is private. Before the
first public release, complete these one-time publishing steps.

## PyPI trusted publishing

Create a pending trusted publisher for the `botgate` project on PyPI with:

- PyPI project name: `botgate`
- GitHub owner: `kraftaa`
- GitHub repository: `botgate`
- Workflow filename: `pypi.yml`
- Environment name: `pypi`

The GitHub environment named `pypi` is already configured in this repository.
No long-lived PyPI API token is required; the workflow uses short-lived OIDC
credentials.

## Homebrew tap

Create a fine-grained GitHub token with contents write access limited to
`kraftaa/homebrew-tap`, then store it in this repository as the Actions secret
`HOMEBREW_TAP_TOKEN`.

## Publish

1. Make the repository public.
2. Enable the `CI`, `Release`, and `PyPI` GitHub Actions workflows.
3. Confirm the version in `Cargo.toml` and `Cargo.lock`.
4. Push an annotated tag matching that version, for example `v0.1.0`.
5. Confirm the GitHub release, Homebrew formula, and PyPI wheels were published.

The release workflow publishes native archives and the Homebrew formula. The
PyPI workflow publishes native wheels for macOS (Apple Silicon and Intel), Linux
(ARM64 and x64), and Windows x64.
