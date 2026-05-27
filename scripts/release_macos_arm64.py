#!/usr/bin/env python3
"""Build, sign, notarize, and publish a local macOS arm64 Codex release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
CODEX_RS_ROOT = REPO_ROOT / "codex-rs"
TARGET = "aarch64-apple-darwin"
DEFAULT_REPO = "o3dotdev/o3-codex"
DEFAULT_REMOTE = "origin"
DEFAULT_RELEASE_BRANCH = "o3/main"
LOCAL_RELEASE_DIR = REPO_ROOT / ".codex-release"
LOCAL_RELEASE_ENV = LOCAL_RELEASE_DIR / "release.env"
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+-o3\.[0-9]+$")
WORKSPACE_VERSION_RE = re.compile(
    r"(?ms)^(\[workspace\.package\]\s.*?^version\s*=\s*)\"[^\"]+\""
)
DEFAULT_NOTARY_TIMEOUT_SECONDS = 30 * 60
DEFAULT_NOTARY_POLL_INTERVAL_SECONDS = 30
DEFAULT_NOTARY_SUBMIT_ATTEMPTS = 3
IN_PROGRESS_NOTARY_STATUS = "In Progress"
ACCEPTED_NOTARY_STATUS = "Accepted"

# Keep this path separate from product documentation. This is maintainer-only
# release tooling for the repository.
ENTITLEMENTS_PATH = REPO_ROOT / ".github/actions/macos-code-sign/codex.entitlements.plist"
CONFIG_SCHEMA_PATH = CODEX_RS_ROOT / "core/config.schema.json"

PRIMARY_BINARIES = ("codex", "codex-responses-api-proxy")
APP_SERVER_BINARIES = ("codex-app-server",)
ALL_BINARIES = (*PRIMARY_BINARIES, *APP_SERVER_BINARIES)
REQUIRED_TOOLS = (
    "cargo",
    "codesign",
    "ditto",
    "gh",
    "git",
    "jq",
    "security",
    "tar",
    "xcrun",
    "zstd",
)


sys.path.insert(0, str(SCRIPT_DIR))
from codex_package.targets import TARGET_SPECS  # noqa: E402
from codex_package.v8 import resolve_codex_v8_cargo_env  # noqa: E402


@dataclass(frozen=True)
class Credentials:
    certificate_p12: Path | None
    certificate_password: str
    notary_key_p8: Path | None
    notary_key_id: str
    notary_issuer_id: str


@dataclass(frozen=True)
class ReleasePaths:
    output_dir: Path
    release_dir: Path
    asset_dir: Path
    package_dir: Path
    notary_dir: Path
    notary_state_file: Path
    notes_file: Path


@dataclass(frozen=True)
class NotarizationOptions:
    timeout_seconds: int
    poll_interval_seconds: int
    submit_attempts: int


@dataclass(frozen=True)
class CommandRunner:
    dry_run: bool

    def run(
        self,
        cmd: list[str],
        *,
        cwd: Path = REPO_ROOT,
        env: Mapping[str, str] | None = None,
    ) -> None:
        print("+ " + shell_join(redact_command(cmd)), flush=True)
        if self.dry_run:
            return
        subprocess.run(cmd, cwd=cwd, env=dict(env) if env is not None else None, check=True)

    def output(self, cmd: list[str], *, cwd: Path = REPO_ROOT) -> str:
        print("+ " + shell_join(redact_command(cmd)), flush=True)
        if self.dry_run:
            return ""
        return subprocess.check_output(cmd, cwd=cwd, text=True)


def parse_args() -> argparse.Namespace:
    load_local_env_file(LOCAL_RELEASE_ENV)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        required=True,
        help="Release version, e.g. 0.134.0-o3.5.",
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPO),
        help="GitHub repository for release creation.",
    )
    parser.add_argument(
        "--remote",
        default=os.environ.get("CODEX_RELEASE_REMOTE", DEFAULT_REMOTE),
        help="Git remote to push the release tag to.",
    )
    parser.add_argument(
        "--release-branch",
        default=os.environ.get("CODEX_RELEASE_BRANCH", DEFAULT_RELEASE_BRANCH),
        help="Branch that release commits and tags must be created from.",
    )
    parser.add_argument(
        "--certificate-p12",
        type=Path,
        default=env_path("APPLE_CERTIFICATE_P12_PATH"),
        help="Developer ID Application certificate .p12 path.",
    )
    parser.add_argument(
        "--certificate-password",
        default=os.environ.get("APPLE_CERTIFICATE_PASSWORD"),
        help="Password for --certificate-p12.",
    )
    parser.add_argument(
        "--notary-key-p8",
        type=Path,
        default=env_path("APPLE_NOTARIZATION_KEY_P8_PATH"),
        help="App Store Connect API key .p8 path for notarization.",
    )
    parser.add_argument(
        "--notary-key-id",
        default=os.environ.get("APPLE_NOTARIZATION_KEY_ID"),
        help="App Store Connect API key ID.",
    )
    parser.add_argument(
        "--notary-issuer-id",
        default=os.environ.get("APPLE_NOTARIZATION_ISSUER_ID"),
        help="App Store Connect issuer ID.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory for local release outputs. Defaults to dist/local-macos-arm64-release/<version>.",
    )
    parser.add_argument(
        "--notes-file",
        type=Path,
        help="Optional release notes file. Defaults to generated local macOS arm64 notes.",
    )
    parser.add_argument(
        "--notary-timeout-seconds",
        type=positive_int_arg,
        default=env_positive_int(
            "APPLE_NOTARIZATION_TIMEOUT_SECONDS",
            DEFAULT_NOTARY_TIMEOUT_SECONDS,
        ),
        help=(
            "Maximum seconds to wait for each Apple notarization submission before "
            "saving state and exiting. Set APPLE_NOTARIZATION_TIMEOUT_SECONDS to default locally."
        ),
    )
    parser.add_argument(
        "--notary-poll-interval-seconds",
        type=positive_int_arg,
        default=env_positive_int(
            "APPLE_NOTARIZATION_POLL_INTERVAL_SECONDS",
            DEFAULT_NOTARY_POLL_INTERVAL_SECONDS,
        ),
        help=(
            "Seconds between Apple notarization status polls. "
            "Set APPLE_NOTARIZATION_POLL_INTERVAL_SECONDS to default locally."
        ),
    )
    parser.add_argument(
        "--notary-submit-attempts",
        type=positive_int_arg,
        default=env_positive_int(
            "APPLE_NOTARIZATION_SUBMIT_ATTEMPTS",
            DEFAULT_NOTARY_SUBMIT_ATTEMPTS,
        ),
        help=(
            "Number of attempts for transient notarytool submit/status command failures. "
            "Set APPLE_NOTARIZATION_SUBMIT_ATTEMPTS to default locally."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs and print planned commands without signing, tagging, or uploading.",
    )
    parser.add_argument(
        "--skip-version-update",
        action="store_true",
        help="Release the version already present in codex-rs/Cargo.toml.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow releasing when the worktree has pre-existing changes.",
    )
    parser.add_argument(
        "--allow-non-release-branch",
        action="store_true",
        help="Allow releasing from a branch other than --release-branch.",
    )
    parser.add_argument(
        "--create-github-release",
        action="store_true",
        help="Push the tag and create the GitHub Release. Without this, assets are built locally only.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    validate_release_version(args.version)
    runner = CommandRunner(dry_run=args.dry_run)
    credentials = resolve_credentials(args, require=not args.dry_run)
    paths = release_paths(args.version, args.output_dir, args.notes_file)
    notary_options = NotarizationOptions(
        timeout_seconds=args.notary_timeout_seconds,
        poll_interval_seconds=args.notary_poll_interval_seconds,
        submit_attempts=args.notary_submit_attempts,
    )

    validate_host(dry_run=args.dry_run)
    validate_required_tools(REQUIRED_TOOLS)
    validate_required_files(credentials, dry_run=args.dry_run)
    validate_repo_state(
        runner,
        version=args.version,
        allow_dirty=args.allow_dirty,
        allow_non_release_branch=args.allow_non_release_branch,
        release_branch=args.release_branch,
        skip_version_update=args.skip_version_update,
    )

    if args.create_github_release and not args.skip_version_update:
        update_workspace_version(args.version, dry_run=args.dry_run)
        commit_version_bump(runner, args.version)
    elif args.skip_version_update:
        validate_current_workspace_version(args.version)
    else:
        print(
            "No-publish run: leaving workspace version unchanged; "
            "pass --create-github-release to commit the release version bump.",
            flush=True,
        )

    tag = release_tag(args.version)
    if args.create_github_release:
        ensure_tag_absent(runner, tag, remote=args.remote)
    build_binaries(runner)
    if not args.dry_run:
        prepare_release_dirs(paths)

    with signing_keychain(runner, credentials) as identity:
        sign_and_notarize_binaries(runner, credentials, identity, paths, notary_options)

    build_release_assets(runner, args.version, paths)
    create_release_notes(args.version, paths.notes_file, source=args.notes_file, dry_run=args.dry_run)

    assets = release_assets(paths.asset_dir, dry_run=args.dry_run)
    if args.create_github_release:
        create_local_tag(runner, tag, args.version)
        push_tag_and_create_release(runner, tag, args.version, args.repo, args.remote, paths, assets)
    else:
        print(
            "GitHub Release upload and local tag creation skipped; pass --create-github-release to publish.",
            flush=True,
        )

    print(f"Release outputs are in {paths.output_dir}", flush=True)
    print(f"SHA-256 manifest: {paths.asset_dir / 'codex-package_SHA256SUMS'}", flush=True)
    return 0


def env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    if not value:
        return None
    return Path(value)


def load_local_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").strip()
        if "=" not in line:
            raise RuntimeError(f"Invalid local release env line {path}:{line_no}: {raw_line!r}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = unquote_env_value(value.strip())
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise RuntimeError(f"Invalid local release env key {path}:{line_no}: {key!r}")
        os.environ.setdefault(key, value)


def unquote_env_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def validate_release_version(version: str) -> None:
    if not VERSION_RE.fullmatch(version):
        raise RuntimeError(
            f"Invalid release version {version!r}; expected format like 0.134.0-o3.5."
        )


def release_tag(version: str) -> str:
    validate_release_version(version)
    return f"v{version}"


def release_paths(
    version: str,
    output_dir: Path | None,
    notes_file: Path | None,
) -> ReleasePaths:
    root = (output_dir or REPO_ROOT / "dist/local-macos-arm64-release" / version).resolve()
    return ReleasePaths(
        output_dir=root,
        release_dir=root / "build",
        asset_dir=root / "assets",
        package_dir=root / "packages",
        notary_dir=root / "notary",
        notary_state_file=root / "notary" / "submissions.json",
        notes_file=(notes_file.resolve() if notes_file is not None else root / "release-notes.md"),
    )


def positive_int_arg(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got {value!r}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got {value!r}")
    return parsed


def env_positive_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if not value:
        return default
    try:
        return positive_int_arg(value)
    except argparse.ArgumentTypeError as exc:
        raise RuntimeError(f"Invalid {name}: {exc}") from exc


def resolve_credentials(args: argparse.Namespace, *, require: bool) -> Credentials:
    return Credentials(
        certificate_p12=optional_path(
            args.certificate_p12,
            "APPLE_CERTIFICATE_P12_PATH",
            require=require,
        ),
        certificate_password=required_string(
            args.certificate_password,
            "APPLE_CERTIFICATE_PASSWORD",
            require=require,
        ),
        notary_key_p8=optional_path(
            args.notary_key_p8,
            "APPLE_NOTARIZATION_KEY_P8_PATH",
            require=require,
        ),
        notary_key_id=required_string(
            args.notary_key_id,
            "APPLE_NOTARIZATION_KEY_ID",
            require=require,
        ),
        notary_issuer_id=required_string(
            args.notary_issuer_id,
            "APPLE_NOTARIZATION_ISSUER_ID",
            require=require,
        ),
    )


def optional_path(value: Path | None, env_name: str, *, require: bool) -> Path | None:
    if value is None:
        if not require:
            print(f"Dry-run continuing without {env_name}.", flush=True)
            return None
        raise RuntimeError(f"Missing required path; pass the flag or set {env_name}.")
    return value.resolve()


def required_path(value: Path | None, env_name: str) -> Path:
    path = optional_path(value, env_name, require=True)
    assert path is not None
    return path


def required_string(value: str | None, env_name: str, *, require: bool = True) -> str:
    if not value:
        if not require:
            print(f"Dry-run continuing without {env_name}.", flush=True)
            return f"DRY_RUN_{env_name}"
        raise RuntimeError(f"Missing required value; pass the flag or set {env_name}.")
    return value


def validate_host(*, dry_run: bool) -> None:
    system = platform.system()
    machine = normalize_machine(platform.machine())
    if system == "Darwin" and machine == "arm64":
        return
    if dry_run:
        print(
            f"Dry-run on {system}/{platform.machine()}; real releases require macOS arm64.",
            flush=True,
        )
        return
    raise RuntimeError(
        f"Local macOS arm64 releases must run on an M-series Mac; got {system}/{platform.machine()}."
    )


def normalize_machine(machine: str) -> str:
    machine = machine.lower()
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    return machine


def validate_required_tools(tools: tuple[str, ...]) -> None:
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        raise RuntimeError("Missing required tools: " + ", ".join(missing))


def validate_required_files(credentials: Credentials, *, dry_run: bool) -> None:
    for path, label in [
        (credentials.certificate_p12, "certificate"),
        (credentials.notary_key_p8, "notary key"),
        (ENTITLEMENTS_PATH, "entitlements"),
        (CONFIG_SCHEMA_PATH, "config schema"),
    ]:
        if path is None and dry_run:
            continue
        if path is None or not path.is_file():
            raise RuntimeError(f"Missing {label} file: {path}")


def validate_repo_state(
    runner: CommandRunner,
    *,
    version: str,
    allow_dirty: bool,
    allow_non_release_branch: bool,
    release_branch: str,
    skip_version_update: bool,
) -> None:
    if not (CODEX_RS_ROOT / "Cargo.toml").is_file():
        raise RuntimeError(f"Run from the repository root; missing {CODEX_RS_ROOT / 'Cargo.toml'}.")
    current_branch = runner.output(["git", "branch", "--show-current"]).strip()
    if current_branch != release_branch:
        message = f"Current branch is {current_branch or '<detached>'}; expected {release_branch}."
        if runner.dry_run:
            print(f"Dry-run continuing despite branch mismatch: {message}", flush=True)
        elif not allow_non_release_branch:
            raise RuntimeError(message + " Pass --allow-non-release-branch to override.")
    if not allow_dirty:
        status = runner.output(["git", "status", "--porcelain"])
        if status.strip():
            raise RuntimeError(
                "Worktree has uncommitted changes. Commit/stash them, or pass --allow-dirty."
            )
    if skip_version_update:
        validate_current_workspace_version(version)


def validate_current_workspace_version(version: str) -> None:
    current = read_workspace_version()
    if current != version:
        raise RuntimeError(
            f"--skip-version-update requested version {version}, but codex-rs/Cargo.toml has {current}."
        )


def read_workspace_version() -> str:
    text = (CODEX_RS_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = WORKSPACE_VERSION_RE.search(text)
    if match is None:
        raise RuntimeError("Could not find [workspace.package] version in codex-rs/Cargo.toml.")
    version_line = text[match.start() : match.end()]
    version_match = re.search(r'version\s*=\s*"([^"]+)"', version_line)
    if version_match is None:
        raise RuntimeError("Could not parse [workspace.package] version.")
    return version_match.group(1)


def replace_workspace_version(cargo_toml: str, version: str) -> str:
    validate_release_version(version)
    updated, count = WORKSPACE_VERSION_RE.subn(rf'\1"{version}"', cargo_toml, count=1)
    if count != 1:
        raise RuntimeError("Could not find [workspace.package] version to update.")
    return updated


def update_workspace_version(version: str, *, dry_run: bool) -> None:
    cargo_toml = CODEX_RS_ROOT / "Cargo.toml"
    current = cargo_toml.read_text(encoding="utf-8")
    updated = replace_workspace_version(current, version)
    if current == updated:
        print(f"codex-rs/Cargo.toml already has version {version}.", flush=True)
        return
    print(f"Updating codex-rs/Cargo.toml workspace version to {version}.", flush=True)
    if not dry_run:
        cargo_toml.write_text(updated, encoding="utf-8")


def commit_version_bump(runner: CommandRunner, version: str) -> None:
    changed = runner.output(["git", "diff", "--name-only", "--", "codex-rs/Cargo.toml"]).strip()
    if not changed:
        return
    runner.run(["git", "add", "codex-rs/Cargo.toml"])
    runner.run(["git", "commit", "-m", f"chore(release): {version}"])


def ensure_tag_absent(runner: CommandRunner, tag: str, *, remote: str) -> None:
    local = runner.output(["git", "tag", "--list", tag]).strip()
    if local:
        raise RuntimeError(f"Local tag already exists: {tag}")
    remote_output = runner.output(["git", "ls-remote", "--tags", remote, f"refs/tags/{tag}"]).strip()
    if remote_output:
        raise RuntimeError(f"Remote tag already exists on {remote}: {tag}")


def build_binaries(runner: CommandRunner) -> None:
    env = (
        os.environ
        if runner.dry_run
        else {**os.environ, **resolve_codex_v8_cargo_env(TARGET_SPECS[TARGET])}
    )
    cmd = [
        "cargo",
        "build",
        "--target",
        TARGET,
        "--release",
    ]
    for binary in ALL_BINARIES:
        cmd.extend(["--bin", binary])
    runner.run(cmd, cwd=CODEX_RS_ROOT, env=env)


def prepare_release_dirs(paths: ReleasePaths) -> None:
    for path in [paths.release_dir, paths.asset_dir, paths.package_dir]:
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)
    paths.notary_dir.mkdir(parents=True, exist_ok=True)


class signing_keychain:
    def __init__(self, runner: CommandRunner, credentials: Credentials) -> None:
        self.runner = runner
        self.credentials = credentials
        self.temp_dir: tempfile.TemporaryDirectory[str] | None = None
        self.keychain_path: Path | None = None
        self.password = secrets.token_urlsafe(24)
        self.previous_keychains: list[str] = []
        self.previous_default_keychain = ""

    def __enter__(self) -> str:
        if self.runner.dry_run:
            print("+ create temporary signing keychain", flush=True)
            return "DRY_RUN_CODESIGN_IDENTITY"

        self.temp_dir = tempfile.TemporaryDirectory(prefix="codex-local-signing-")
        self.keychain_path = Path(self.temp_dir.name) / "codex-signing.keychain-db"
        self.previous_keychains = read_keychain_list()
        self.previous_default_keychain = read_default_keychain()

        self.runner.run(["security", "create-keychain", "-p", self.password, str(self.keychain_path)])
        self.runner.run(["security", "set-keychain-settings", "-lut", "21600", str(self.keychain_path)])
        self.runner.run(["security", "unlock-keychain", "-p", self.password, str(self.keychain_path)])
        self.runner.run(
            [
                "security",
                "list-keychains",
                "-s",
                str(self.keychain_path),
                *self.previous_keychains,
            ]
        )
        self.runner.run(["security", "default-keychain", "-s", str(self.keychain_path)])
        self.runner.run(
            [
                "security",
                "import",
                str(required_path(self.credentials.certificate_p12, "APPLE_CERTIFICATE_P12_PATH")),
                "-k",
                str(self.keychain_path),
                "-P",
                self.credentials.certificate_password,
                "-T",
                "/usr/bin/codesign",
                "-T",
                "/usr/bin/security",
            ]
        )
        self.runner.run(
            [
                "security",
                "set-key-partition-list",
                "-S",
                "apple-tool:,apple:",
                "-s",
                "-k",
                self.password,
                str(self.keychain_path),
            ]
        )
        return find_single_codesign_identity(self.keychain_path)

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        if self.runner.dry_run:
            print("+ remove temporary signing keychain", flush=True)
            return
        if self.previous_keychains:
            self.runner.run(["security", "list-keychains", "-s", *self.previous_keychains])
        if self.previous_default_keychain:
            self.runner.run(["security", "default-keychain", "-s", self.previous_default_keychain])
        if self.keychain_path is not None and self.keychain_path.exists():
            self.runner.run(["security", "delete-keychain", str(self.keychain_path)])
        if self.temp_dir is not None:
            self.temp_dir.cleanup()


def read_keychain_list() -> list[str]:
    output = subprocess.check_output(["security", "list-keychains"], text=True)
    return [line.strip().strip('"') for line in output.splitlines() if line.strip()]


def read_default_keychain() -> str:
    output = subprocess.check_output(["security", "default-keychain"], text=True)
    return output.strip().strip('"')


def find_single_codesign_identity(keychain_path: Path) -> str:
    output = subprocess.check_output(
        ["security", "find-identity", "-v", "-p", "codesigning", str(keychain_path)],
        text=True,
    )
    identities = sorted(set(re.findall(r"\b[0-9A-F]{40}\b", output)))
    if not identities:
        raise RuntimeError(f"No code signing identities found in {keychain_path}.")
    if len(identities) > 1:
        raise RuntimeError(
            "Expected exactly one code signing identity in the temporary keychain; found "
            + ", ".join(identities)
        )
    return identities[0]


def sign_and_notarize_binaries(
    runner: CommandRunner,
    credentials: Credentials,
    identity: str,
    paths: ReleasePaths,
    options: NotarizationOptions,
) -> None:
    release_dir = CODEX_RS_ROOT / "target" / TARGET / "release"
    notary_state = load_notary_state(paths.notary_state_file)
    binary_paths: dict[str, Path] = {}
    for binary in ALL_BINARIES:
        binary_path = release_dir / binary
        binary_paths[binary] = binary_path
        if not runner.dry_run and not binary_path.is_file():
            raise RuntimeError(f"Built binary not found: {binary_path}")
        resumable_submission = resumable_notary_submission(notary_state, binary, paths)
        if resumable_submission is not None:
            print(
                f"Reusing Apple notarization submission for {binary}: "
                f"{resumable_submission['id']}",
                flush=True,
            )
            restore_binary_from_notary_archive(runner, resumable_submission, binary_path)
        else:
            sign_binary(runner, identity, binary_path)
        runner.run(["codesign", "--verify", "--strict", "--verbose=2", str(binary_path)])
        ensure_notary_submission(runner, credentials, binary_path, paths, notary_state, options)

    for binary in ALL_BINARIES:
        wait_for_notary_acceptance(
            runner,
            credentials,
            binary,
            binary_paths[binary],
            paths,
            notary_state,
            options,
        )


def sign_binary(runner: CommandRunner, identity: str, binary_path: Path) -> None:
    cmd = [
        "codesign",
        "--force",
        "--options",
        "runtime",
        "--timestamp",
        "--entitlements",
        str(ENTITLEMENTS_PATH),
        "--sign",
        identity,
        str(binary_path),
    ]
    runner.run(cmd)


def ensure_notary_submission(
    runner: CommandRunner,
    credentials: Credentials,
    binary_path: Path,
    paths: ReleasePaths,
    notary_state: dict[str, object],
    options: NotarizationOptions,
) -> None:
    binary = binary_path.name
    binary_sha256 = "DRY_RUN_BINARY_SHA256" if runner.dry_run else sha256_file(binary_path)
    submission = notary_submission_for_binary(notary_state, binary)
    resumable_submission = resumable_notary_submission(notary_state, binary, paths)
    if resumable_submission is not None and submission.get("status") == ACCEPTED_NOTARY_STATUS:
        print(f"Apple notarization already accepted for {binary}: {submission['id']}", flush=True)
        return

    if resumable_submission is None:
        submission = submit_binary_for_notarization(
            runner,
            credentials,
            binary_path,
            paths,
            notary_state,
            options,
            binary_sha256,
        )
    else:
        print(f"Apple notarization already submitted for {binary}: {submission['id']}", flush=True)


def wait_for_notary_acceptance(
    runner: CommandRunner,
    credentials: Credentials,
    binary: str,
    binary_path: Path,
    paths: ReleasePaths,
    notary_state: dict[str, object],
    options: NotarizationOptions,
) -> None:
    submission = notary_submission_for_binary(notary_state, binary)
    if submission is None or not submission.get("id"):
        raise RuntimeError(f"Missing Apple notarization submission for {binary}.")
    if not runner.dry_run and resumable_notary_submission(notary_state, binary, paths) is None:
        raise RuntimeError(f"Missing Apple notarization submission for {binary}.")
    if submission.get("status") == ACCEPTED_NOTARY_STATUS:
        print(f"Apple notarization already accepted for {binary}: {submission['id']}", flush=True)
        return

    submission_id = str(submission["id"])
    status = poll_notary_submission(
        runner,
        credentials,
        submission_id,
        binary,
        paths,
        notary_state,
        options,
    )
    if status != ACCEPTED_NOTARY_STATUS:
        raise RuntimeError(f"Apple notarization did not complete for {binary}: {status}")


def submit_binary_for_notarization(
    runner: CommandRunner,
    credentials: Credentials,
    binary_path: Path,
    paths: ReleasePaths,
    notary_state: dict[str, object],
    options: NotarizationOptions,
    binary_sha256: str,
) -> dict[str, object]:
    binary = binary_path.name
    notary_key = (
        Path("DRY_RUN_NOTARY_KEY.p8")
        if runner.dry_run and credentials.notary_key_p8 is None
        else required_path(credentials.notary_key_p8, "APPLE_NOTARIZATION_KEY_P8_PATH")
    )
    archive_path = paths.notary_dir / f"{binary}.zip"
    runner.run(["ditto", "-c", "-k", "--keepParent", str(binary_path), str(archive_path)])
    if runner.dry_run:
        submission_id = f"DRY_RUN_{binary}_SUBMISSION_ID"
        status = ACCEPTED_NOTARY_STATUS
    else:
        output = output_with_retries(
            runner,
            [
                "xcrun",
                "notarytool",
                "submit",
                str(archive_path),
                "--key",
                str(notary_key),
                "--key-id",
                credentials.notary_key_id,
                "--issuer",
                credentials.notary_issuer_id,
                "--output-format",
                "json",
            ],
            attempts=options.submit_attempts,
            description=f"submit {binary} for Apple notarization",
        )
        response = parse_notarytool_json(output, f"submit {binary}")
        submission_id = str(response.get("id") or "")
        status = str(response.get("status") or IN_PROGRESS_NOTARY_STATUS)
        if not submission_id:
            raise RuntimeError(f"Apple notarization submit did not return an id for {binary}.")
    archive_sha256 = "DRY_RUN_ARCHIVE_SHA256" if runner.dry_run else sha256_file(archive_path)

    submission = {
        "id": submission_id,
        "binary": binary,
        "binary_sha256": binary_sha256,
        "archive": str(archive_path),
        "archive_sha256": archive_sha256,
        "status": status,
        "submitted_at": int(time.time()),
    }
    set_notary_submission(notary_state, binary, submission)
    save_notary_state(paths.notary_state_file, notary_state, dry_run=runner.dry_run)
    print(f"Apple notarization submitted for {binary}: {submission_id} ({status})", flush=True)
    return submission


def poll_notary_submission(
    runner: CommandRunner,
    credentials: Credentials,
    submission_id: str,
    binary: str,
    paths: ReleasePaths,
    notary_state: dict[str, object],
    options: NotarizationOptions,
) -> str:
    if runner.dry_run:
        print(f"+ poll Apple notarization status for {binary}: {submission_id}", flush=True)
        return ACCEPTED_NOTARY_STATUS

    notary_key = required_path(credentials.notary_key_p8, "APPLE_NOTARIZATION_KEY_P8_PATH")
    deadline = time.monotonic() + options.timeout_seconds
    while True:
        output = output_with_retries(
            runner,
            [
                "xcrun",
                "notarytool",
                "info",
                submission_id,
                "--key",
                str(notary_key),
                "--key-id",
                credentials.notary_key_id,
                "--issuer",
                credentials.notary_issuer_id,
                "--output-format",
                "json",
            ],
            attempts=options.submit_attempts,
            description=f"poll Apple notarization status for {binary}",
        )
        response = parse_notarytool_json(output, f"info {submission_id}")
        status = str(response.get("status") or "")
        if not status:
            raise RuntimeError(f"Apple notarization info did not return a status for {binary}.")
        update_notary_submission_status(notary_state, binary, status)
        save_notary_state(paths.notary_state_file, notary_state, dry_run=False)

        print(f"Apple notarization status for {binary}: {status}", flush=True)
        if status == ACCEPTED_NOTARY_STATUS:
            return status
        if status != IN_PROGRESS_NOTARY_STATUS:
            log_path = write_notary_log(
                runner,
                credentials,
                submission_id,
                paths.notary_dir / f"{binary}-{submission_id}.notary-log.json",
                attempts=options.submit_attempts,
            )
            raise RuntimeError(
                f"Apple notarization failed for {binary}: {status}. Log: {log_path}"
            )

        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise RuntimeError(
                f"Timed out after {options.timeout_seconds}s waiting for Apple notarization "
                f"of {binary} ({submission_id}). Submission state is saved at "
                f"{paths.notary_state_file}; rerun the same command with the same --output-dir "
                "to resume polling instead of uploading again."
            )
        time.sleep(min(options.poll_interval_seconds, remaining_seconds))


def output_with_retries(
    runner: CommandRunner,
    cmd: list[str],
    *,
    attempts: int,
    description: str,
) -> str:
    for attempt in range(1, attempts + 1):
        try:
            return runner.output(cmd)
        except subprocess.CalledProcessError as exc:
            if attempt == attempts:
                raise RuntimeError(f"Failed to {description} after {attempts} attempts.") from exc
            sleep_seconds = min(30, 2 ** attempt)
            print(
                f"Retrying {description} after failed attempt {attempt}/{attempts} "
                f"in {sleep_seconds}s.",
                flush=True,
            )
            time.sleep(sleep_seconds)
    raise AssertionError("unreachable")


def parse_notarytool_json(output: str, context: str) -> dict[str, object]:
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Could not parse notarytool JSON for {context}: {output}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"Expected notarytool JSON object for {context}: {output}")
    return parsed


def write_notary_log(
    runner: CommandRunner,
    credentials: Credentials,
    submission_id: str,
    log_path: Path,
    *,
    attempts: int,
) -> Path:
    notary_key = required_path(credentials.notary_key_p8, "APPLE_NOTARIZATION_KEY_P8_PATH")
    output = output_with_retries(
        runner,
        [
            "xcrun",
            "notarytool",
            "log",
            submission_id,
            "--key",
            str(notary_key),
            "--key-id",
            credentials.notary_key_id,
            "--issuer",
            credentials.notary_issuer_id,
        ],
        attempts=attempts,
        description=f"fetch Apple notarization log {submission_id}",
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(output, encoding="utf-8")
    return log_path


def load_notary_state(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {"schema": 1, "target": TARGET, "submissions": {}}
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError(f"Invalid notary state file: {path}")
    submissions = parsed.setdefault("submissions", {})
    if not isinstance(submissions, dict):
        raise RuntimeError(f"Invalid notary state file submissions: {path}")
    parsed.setdefault("schema", 1)
    parsed.setdefault("target", TARGET)
    return parsed


def save_notary_state(path: Path, state: dict[str, object], *, dry_run: bool) -> None:
    if dry_run:
        print(f"+ write Apple notarization state {path}", flush=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp_path.replace(path)


def notary_submission_for_binary(
    state: dict[str, object],
    binary: str,
) -> dict[str, object] | None:
    submissions = state.get("submissions")
    if not isinstance(submissions, dict):
        return None
    submission = submissions.get(binary)
    if isinstance(submission, dict):
        return submission
    return None


def set_notary_submission(
    state: dict[str, object],
    binary: str,
    submission: dict[str, object],
) -> None:
    submissions = state.setdefault("submissions", {})
    if not isinstance(submissions, dict):
        raise RuntimeError("Invalid notary state: submissions is not an object.")
    submissions[binary] = submission


def update_notary_submission_status(
    state: dict[str, object],
    binary: str,
    status: str,
) -> None:
    submission = notary_submission_for_binary(state, binary)
    if submission is None:
        return
    submission["status"] = status
    submission["updated_at"] = int(time.time())


def expected_notary_archive_path(paths: ReleasePaths, binary: str) -> Path:
    return paths.notary_dir / f"{binary}.zip"


def notary_archive_path_from_submission(
    submission: dict[str, object],
    paths: ReleasePaths,
    binary: str,
) -> Path:
    archive_value = submission.get("archive")
    if isinstance(archive_value, str) and archive_value:
        return Path(archive_value)
    return expected_notary_archive_path(paths, binary)


def resumable_notary_submission(
    state: dict[str, object],
    binary: str,
    paths: ReleasePaths,
) -> dict[str, object] | None:
    submission = notary_submission_for_binary(state, binary)
    if submission is None or not submission.get("id"):
        return None
    if submission.get("status") not in {IN_PROGRESS_NOTARY_STATUS, ACCEPTED_NOTARY_STATUS}:
        return None

    archive_path = notary_archive_path_from_submission(submission, paths, binary)
    expected_archive_path = expected_notary_archive_path(paths, binary)
    if archive_path.resolve(strict=False) != expected_archive_path.resolve(strict=False):
        return None
    if not archive_path.is_file():
        return None

    archive_sha256 = submission.get("archive_sha256")
    if isinstance(archive_sha256, str) and archive_sha256:
        if archive_sha256 != sha256_file(archive_path):
            return None
    return submission


def restore_binary_from_notary_archive(
    runner: CommandRunner,
    submission: dict[str, object],
    binary_path: Path,
) -> None:
    archive_value = submission.get("archive")
    if not isinstance(archive_value, str) or not archive_value:
        raise RuntimeError(f"Notary submission for {binary_path.name} is missing archive path.")
    archive_path = Path(archive_value)
    with tempfile.TemporaryDirectory(prefix="codex-notary-restore-") as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        runner.run(["ditto", "-x", "-k", str(archive_path), str(temp_dir)])
        if runner.dry_run:
            return
        restored_binaries = [
            path
            for path in temp_dir.rglob(binary_path.name)
            if path.is_file() and not path.name.startswith("._")
        ]
        if not restored_binaries:
            raise RuntimeError(f"Notary archive did not contain {binary_path.name}: {archive_path}")
        if len(restored_binaries) > 1:
            raise RuntimeError(
                f"Notary archive contained multiple {binary_path.name} entries: {archive_path}"
            )
        restored_binary = restored_binaries[0]
        shutil.copy2(restored_binary, binary_path)
        binary_path.chmod(binary_path.stat().st_mode | 0o755)


def build_release_assets(runner: CommandRunner, version: str, paths: ReleasePaths) -> None:
    release_dir = CODEX_RS_ROOT / "target" / TARGET / "release"
    if not runner.dry_run:
        paths.asset_dir.mkdir(parents=True, exist_ok=True)

    for binary in ALL_BINARIES:
        source = release_dir / binary
        dest_name = binary_asset_stem(binary)
        dest = paths.asset_dir / dest_name
        if runner.dry_run:
            print(f"+ stage {source} as {dest}", flush=True)
        else:
            shutil.copy2(source, dest)
            dest.chmod(dest.stat().st_mode | 0o755)
        write_binary_archives(runner, paths.asset_dir, dest_name)

    build_package_archive(runner, "primary", release_dir, paths.asset_dir)
    build_package_archive(runner, "app-server", release_dir, paths.asset_dir)
    add_package_checksum_manifest(paths.asset_dir, dry_run=runner.dry_run)
    copy_config_schema(paths.asset_dir, dry_run=runner.dry_run)
    print(f"Built local macOS arm64 assets for {version}.", flush=True)


def binary_asset_stem(binary: str) -> str:
    if binary not in ALL_BINARIES:
        raise RuntimeError(f"Unexpected binary: {binary}")
    return f"{binary}-{TARGET}"


def write_binary_archives(runner: CommandRunner, asset_dir: Path, stem: str) -> None:
    runner.run(["tar", "-C", str(asset_dir), "-czf", str(asset_dir / f"{stem}.tar.gz"), stem])
    runner.run(
        [
            "zstd",
            "-T0",
            "-19",
            "-f",
            str(asset_dir / stem),
            "-o",
            str(asset_dir / f"{stem}.zst"),
        ]
    )


def build_package_archive(
    runner: CommandRunner,
    bundle: str,
    entrypoint_dir: Path,
    asset_dir: Path,
) -> None:
    runner.run(
        [
            "bash",
            str(REPO_ROOT / ".github/scripts/build-codex-package-archive.sh"),
            "--target",
            TARGET,
            "--bundle",
            bundle,
            "--entrypoint-dir",
            str(entrypoint_dir),
            "--archive-dir",
            str(asset_dir),
        ],
        env={**os.environ, "GITHUB_WORKSPACE": str(REPO_ROOT)},
    )


def add_package_checksum_manifest(asset_dir: Path, *, dry_run: bool) -> None:
    manifest = asset_dir / "codex-package_SHA256SUMS"
    archive_names = [
        f"codex-package-{TARGET}.tar.gz",
        f"codex-app-server-package-{TARGET}.tar.gz",
    ]
    if dry_run:
        print(f"+ write {manifest}", flush=True)
        return
    lines = []
    for archive_name in archive_names:
        archive = asset_dir / archive_name
        if not archive.is_file():
            raise RuntimeError(f"Missing package archive for checksum manifest: {archive}")
        lines.append(f"{sha256_file(archive)}  {archive_name}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_config_schema(asset_dir: Path, *, dry_run: bool) -> None:
    dest = asset_dir / "config-schema.json"
    if dry_run:
        print(f"+ copy {CONFIG_SCHEMA_PATH} {dest}", flush=True)
    else:
        shutil.copy2(CONFIG_SCHEMA_PATH, dest)


def create_release_notes(
    version: str,
    notes_file: Path,
    *,
    source: Path | None,
    dry_run: bool,
) -> None:
    if dry_run:
        print(f"+ write release notes {notes_file}", flush=True)
        return
    if source is not None:
        if source != notes_file:
            notes_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, notes_file)
        return
    notes_file.parent.mkdir(parents=True, exist_ok=True)
    notes_file.write_text(
        f"Local macOS arm64 release {version}.\n\n"
        "This release publishes signed and notarized aarch64-apple-darwin Codex CLI assets only.\n",
        encoding="utf-8",
    )


def create_local_tag(runner: CommandRunner, tag: str, version: str) -> None:
    runner.run(["git", "tag", "-a", tag, "-m", f"Release {version}"])


def push_tag_and_create_release(
    runner: CommandRunner,
    tag: str,
    version: str,
    repo: str,
    remote: str,
    paths: ReleasePaths,
    assets: list[Path],
) -> None:
    if not assets:
        raise RuntimeError("No release assets found to upload.")
    runner.run(["git", "push", remote, f"refs/tags/{tag}"])
    runner.run(
        [
            "gh",
            "release",
            "create",
            tag,
            *[str(asset) for asset in assets],
            "--repo",
            repo,
            "--title",
            version,
            "--notes-file",
            str(paths.notes_file),
        ]
    )


def release_assets(asset_dir: Path, *, dry_run: bool) -> list[Path]:
    names = release_asset_names()
    if dry_run:
        return [asset_dir / name for name in names]
    assets = [asset_dir / name for name in names]
    missing = [asset for asset in assets if not asset.is_file()]
    if missing:
        raise RuntimeError(
            "Missing release assets: " + ", ".join(str(asset) for asset in missing)
        )
    return assets


def release_asset_names() -> list[str]:
    binary_archives = []
    for binary in ALL_BINARIES:
        stem = binary_asset_stem(binary)
        binary_archives.extend([f"{stem}.tar.gz", f"{stem}.zst"])
    return [
        *binary_archives,
        f"codex-package-{TARGET}.tar.gz",
        f"codex-package-{TARGET}.tar.zst",
        f"codex-app-server-package-{TARGET}.tar.gz",
        f"codex-app-server-package-{TARGET}.tar.zst",
        "codex-package_SHA256SUMS",
        "config-schema.json",
    ]


def redact_command(args: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    secret_value_flags = {
        "-P",
        "-p",
        "--issuer",
        "--key",
        "--key-id",
        "--password",
    }
    redact_security_partition_password = len(args) >= 2 and args[0:2] == [
        "security",
        "set-key-partition-list",
    ]
    for arg in args:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        redacted.append(arg)
        if arg in secret_value_flags or (arg == "-k" and redact_security_partition_password):
            redact_next = True
    return redacted


def shell_join(args: list[str]) -> str:
    return " ".join(sh_quote(arg) for arg in args)


def sh_quote(arg: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:=+-]+", arg):
        return arg
    return "'" + arg.replace("'", "'\"'\"'") + "'"


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as err:
        print(f"error: {err}", file=sys.stderr)
        raise SystemExit(1)
