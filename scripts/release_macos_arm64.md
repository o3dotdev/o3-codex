# Local macOS arm64 Release

This maintainer-only flow builds and publishes GitHub Release assets for the
M-series Mac CLI release path. It intentionally does not publish npm, PyPI,
DotSlash, WinGet, Linux, Windows, Intel macOS, or the desktop `Codex.app`.

Run from a clean worktree on an M-series Mac:

```bash
python3 scripts/release_macos_arm64.py \
  --version 0.134.0-o3.5 \
  --certificate-p12 /secure/path/developer-id.p12 \
  --certificate-password "$APPLE_CERTIFICATE_PASSWORD" \
  --notary-key-p8 /secure/path/AuthKey_XXXX.p8 \
  --notary-key-id XXXX \
  --notary-issuer-id YYYY \
  --create-github-release
```

The default release target is `origin` / `o3dotdev/o3-codex` from the `o3/main`
branch. Real releases fail if run from a different branch unless
`--allow-non-release-branch` is passed.

Secrets can also come from `APPLE_CERTIFICATE_P12_PATH`,
`APPLE_CERTIFICATE_PASSWORD`, `APPLE_NOTARIZATION_KEY_P8_PATH`,
`APPLE_NOTARIZATION_KEY_ID`, and `APPLE_NOTARIZATION_ISSUER_ID`.
The script also reads `.codex-release/release.env` when it exists; use
`.codex-release/release.env.example` as the local template. Real certs, keys,
and local config files under `.codex-release/` are ignored by git.

Use `--dry-run` to validate inputs and print the planned commands without
signing, tagging, or uploading. Release outputs are written under
`dist/local-macos-arm64-release/<version>/`, which is ignored by git.
