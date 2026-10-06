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
5. Confirm the release artifacts built and the PyPI wheels were published.
6. Download the release artifacts and validate `sha256.sum`.
7. Create the GitHub release from those artifacts with the maintainer's normal
   GitHub credentials. The repository-wide Actions token remains read-only.
8. Run `brew style --fix` on `botgate.rb`, remove a redundant explicit `version`
   if present, add a `test do` block, and commit the audited formula to
   `kraftaa/homebrew-tap`.

The release workflow builds native archives and generates the Homebrew formula
as downloadable workflow artifacts. The PyPI workflow publishes native wheels
for macOS (Apple Silicon and Intel), Linux (ARM64 and x64), and Windows x64.
The generated workflow's `host` job is intentionally disabled to preserve the
repository's read-only Actions token; rerunning `dist generate` requires
restoring that small customization.
