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

The release workflow generates `botgate.rb` as a release artifact. Download and
test that formula, then commit it to `kraftaa/homebrew-tap/Formula/botgate.rb`
using the maintainer's normal GitHub credentials. No cross-repository Actions
token is required.

## Publish

1. Make the repository public.
2. Enable the `CI`, `Release`, and `PyPI` GitHub Actions workflows.
3. Confirm the version in `Cargo.toml` and `Cargo.lock`.
4. Push an annotated tag matching that version, for example `v0.1.0`.
5. Confirm the GitHub release and PyPI wheels were published.
6. Download, test, and commit `botgate.rb` to `kraftaa/homebrew-tap`.

The release workflow publishes native archives and generates the Homebrew
formula. The PyPI workflow publishes native wheels for macOS (Apple Silicon and
Intel), Linux (ARM64 and x64), and Windows x64.
