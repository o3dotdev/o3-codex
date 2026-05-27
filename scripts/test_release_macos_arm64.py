#!/usr/bin/env python3

from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_macos_arm64 as release


class ReleaseMacosArm64Test(unittest.TestCase):
    def test_release_tag_validates_o3_version(self) -> None:
        self.assertEqual(release.release_tag("0.134.0-o3.5"), "v0.134.0-o3.5")

        with self.assertRaisesRegex(RuntimeError, "Invalid release version"):
            release.release_tag("0.134.0")

    def test_binary_asset_stems_are_target_suffixed(self) -> None:
        self.assertEqual(
            release.binary_asset_stem("codex"),
            "codex-aarch64-apple-darwin",
        )
        self.assertEqual(
            release.binary_asset_stem("codex-responses-api-proxy"),
            "codex-responses-api-proxy-aarch64-apple-darwin",
        )
        self.assertEqual(
            release.binary_asset_stem("codex-app-server"),
            "codex-app-server-aarch64-apple-darwin",
        )

    def test_release_asset_names_cover_arm64_only_outputs(self) -> None:
        self.assertEqual(
            release.release_asset_names(),
            [
                "codex-aarch64-apple-darwin.tar.gz",
                "codex-aarch64-apple-darwin.zst",
                "codex-responses-api-proxy-aarch64-apple-darwin.tar.gz",
                "codex-responses-api-proxy-aarch64-apple-darwin.zst",
                "codex-app-server-aarch64-apple-darwin.tar.gz",
                "codex-app-server-aarch64-apple-darwin.zst",
                "codex-package-aarch64-apple-darwin.tar.gz",
                "codex-package-aarch64-apple-darwin.tar.zst",
                "codex-app-server-package-aarch64-apple-darwin.tar.gz",
                "codex-app-server-package-aarch64-apple-darwin.tar.zst",
                "codex-package_SHA256SUMS",
                "config-schema.json",
            ],
        )

    def test_release_paths_default_to_ignored_dist_directory(self) -> None:
        paths = release.release_paths("0.134.0-o3.5", None, None)

        self.assertEqual(
            paths.output_dir,
            release.REPO_ROOT / "dist/local-macos-arm64-release/0.134.0-o3.5",
        )
        self.assertEqual(paths.release_dir, paths.output_dir / "build")
        self.assertEqual(paths.asset_dir, paths.output_dir / "assets")
        self.assertEqual(paths.package_dir, paths.output_dir / "packages")
        self.assertEqual(paths.notary_dir, paths.output_dir / "notary")
        self.assertEqual(paths.notary_state_file, paths.output_dir / "notary/submissions.json")
        self.assertEqual(paths.notes_file, paths.output_dir / "release-notes.md")

    def test_arg_defaults_target_o3_release_repo_and_branch(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GITHUB_REPOSITORY": "",
                "CODEX_RELEASE_REMOTE": "",
                "CODEX_RELEASE_BRANCH": "",
            },
            clear=False,
        ):
            os.environ.pop("GITHUB_REPOSITORY", None)
            os.environ.pop("CODEX_RELEASE_REMOTE", None)
            os.environ.pop("CODEX_RELEASE_BRANCH", None)
            with patch.object(
                sys,
                "argv",
                ["release_macos_arm64.py", "--version", "0.134.0-o3.5", "--dry-run"],
            ):
                args = release.parse_args()

        self.assertEqual(args.repo, "o3dotdev/o3-codex")
        self.assertEqual(args.remote, "origin")
        self.assertEqual(args.release_branch, "o3/main")

    def test_arg_defaults_can_come_from_local_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / "release.env"
            env_file.write_text(
                "GITHUB_REPOSITORY=local/repo\n"
                "CODEX_RELEASE_REMOTE=local-remote\n"
                "CODEX_RELEASE_BRANCH=local/main\n",
                encoding="utf-8",
            )
            old_env_file = release.LOCAL_RELEASE_ENV
            try:
                release.LOCAL_RELEASE_ENV = env_file
                with patch.dict(os.environ, {}, clear=True):
                    with patch.object(
                        sys,
                        "argv",
                        ["release_macos_arm64.py", "--version", "0.134.0-o3.5", "--dry-run"],
                    ):
                        args = release.parse_args()
            finally:
                release.LOCAL_RELEASE_ENV = old_env_file

        self.assertEqual(args.repo, "local/repo")
        self.assertEqual(args.remote, "local-remote")
        self.assertEqual(args.release_branch, "local/main")

    def test_local_env_file_sets_missing_values_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / "release.env"
            env_file.write_text(
                "GITHUB_REPOSITORY=o3dotdev/o3-codex\n"
                "CODEX_RELEASE_BRANCH=o3/main\n"
                "export CODEX_RELEASE_REMOTE=origin\n",
                encoding="utf-8",
            )
            old_values = {
                key: os.environ.get(key)
                for key in ["GITHUB_REPOSITORY", "CODEX_RELEASE_BRANCH", "CODEX_RELEASE_REMOTE"]
            }
            try:
                os.environ["GITHUB_REPOSITORY"] = "already/set"
                os.environ.pop("CODEX_RELEASE_BRANCH", None)
                os.environ.pop("CODEX_RELEASE_REMOTE", None)

                release.load_local_env_file(env_file)

                self.assertEqual(os.environ["GITHUB_REPOSITORY"], "already/set")
                self.assertEqual(os.environ["CODEX_RELEASE_BRANCH"], "o3/main")
                self.assertEqual(os.environ["CODEX_RELEASE_REMOTE"], "origin")
            finally:
                for key, value in old_values.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

    def test_required_string_reports_env_fallback(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "APPLE_CERTIFICATE_PASSWORD"):
            release.required_string(None, "APPLE_CERTIFICATE_PASSWORD")

    def test_redact_command_hides_sensitive_values(self) -> None:
        self.assertEqual(
            release.redact_command(
                [
                    "xcrun",
                    "notarytool",
                    "info",
                    "submission-id",
                    "--key",
                    "/secure/AuthKey.p8",
                    "--key-id",
                    "KEYID",
                    "--issuer",
                    "ISSUER",
                ]
            ),
            [
                "xcrun",
                "notarytool",
                "info",
                "submission-id",
                "--key",
                "<redacted>",
                "--key-id",
                "<redacted>",
                "--issuer",
                "<redacted>",
            ],
        )
        self.assertEqual(
            release.redact_command(["ditto", "-c", "-k", "--keepParent", "src", "dest"]),
            ["ditto", "-c", "-k", "--keepParent", "src", "dest"],
        )
        self.assertEqual(
            release.redact_command(["security", "set-key-partition-list", "-k", "secret"]),
            ["security", "set-key-partition-list", "-k", "<redacted>"],
        )

    def test_positive_int_arg_rejects_non_positive_values(self) -> None:
        self.assertEqual(release.positive_int_arg("30"), 30)
        with self.assertRaisesRegex(Exception, "positive integer"):
            release.positive_int_arg("0")

    def test_notary_state_round_trips_submission(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_file = Path(temp_dir) / "notary" / "submissions.json"
            state = release.load_notary_state(state_file)
            release.set_notary_submission(
                state,
                "codex",
                {
                    "id": "submission-id",
                    "binary": "codex",
                    "binary_sha256": "abc",
                    "status": release.IN_PROGRESS_NOTARY_STATUS,
                },
            )
            release.save_notary_state(state_file, state, dry_run=False)

            loaded = release.load_notary_state(state_file)

        self.assertEqual(loaded, state)

    def test_resumable_notary_submission_requires_matching_archive_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = release.release_paths("0.0.0-o3.0", Path(temp_dir) / "out", None)
            paths.notary_dir.mkdir(parents=True)
            archive = paths.notary_dir / "codex.zip"
            archive.write_text("signed archive", encoding="utf-8")
            state = release.load_notary_state(Path(temp_dir) / "missing.json")
            release.set_notary_submission(
                state,
                "codex",
                {
                    "id": "submission-id",
                    "binary": "codex",
                    "archive": str(archive),
                    "archive_sha256": release.sha256_file(archive),
                    "status": release.IN_PROGRESS_NOTARY_STATUS,
                },
            )

            self.assertIsNotNone(release.resumable_notary_submission(state, "codex", paths))
            archive.write_text("changed archive", encoding="utf-8")
            self.assertIsNone(release.resumable_notary_submission(state, "codex", paths))

    def test_replace_workspace_version_updates_workspace_package_only(self) -> None:
        cargo_toml = """
[package]
version = "0.0.0"

[workspace.package]
name = "workspace"
version = "0.134.0-o3.4"
edition = "2024"
"""

        self.assertEqual(
            release.replace_workspace_version(cargo_toml, "0.134.0-o3.5"),
            """
[package]
version = "0.0.0"

[workspace.package]
name = "workspace"
version = "0.134.0-o3.5"
edition = "2024"
""",
        )

    def test_non_arm64_host_is_allowed_only_for_dry_run(self) -> None:
        original_system = release.platform.system
        original_machine = release.platform.machine
        try:
            release.platform.system = lambda: "Linux"  # type: ignore[method-assign]
            release.platform.machine = lambda: "x86_64"  # type: ignore[method-assign]

            release.validate_host(dry_run=True)
            with self.assertRaisesRegex(RuntimeError, "M-series Mac"):
                release.validate_host(dry_run=False)
        finally:
            release.platform.system = original_system  # type: ignore[method-assign]
            release.platform.machine = original_machine  # type: ignore[method-assign]


if __name__ == "__main__":
    unittest.main()
