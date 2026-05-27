# Local Release Secrets

This directory is for local macOS arm64 release material. It is intentionally
ignored by git except for this README, `.gitignore`, and `release.env.example`.

Typical local files:

- `developer-id.p12`
- `AuthKey_XXXX.p8`
- `release.env`
- ad hoc release notes or handoff scratch files

The release runner automatically reads `.codex-release/release.env` when it
exists. Keep real certificate passwords, keys, and local config in ignored files
under this directory.

Notarization submission state is written under the selected release output
directory, not here, so no-publish runs can be resumed with the same
`--output-dir`.
