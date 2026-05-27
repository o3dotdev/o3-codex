#!/usr/bin/env python3
"""Build, sign, notarize, and publish a local macOS arm64 Codex release."""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
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
    notes_file: Path


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
        print("+ " + shell_join(cmd), flush=True)
        if self.dry_run:
            return
        subprocess.run(cmd, cwd=cwd, env=dict(env) if env is not None else None, check=True)

    def output(self, cmd: list[str], *, cwd: Path = REPO_ROOT) -> str:
        print("+ " + shell_join(cmd), flush=True)
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

    if not args.skip_version_update:
        update_workspace_version(args.version, dry_run=args.dry_run)
        commit_version_bump(runner, args.version)
    else:
        validate_current_workspace_version(args.version)

    tag = release_tag(args.version)
    ensure_tag_absent(runner, tag, remote=args.remote)
    build_binaries(runner)
    if not args.dry_run:
        prepare_release_dirs(paths)

    with signing_keychain(runner, credentials) as identity:
        sign_and_notarize_binaries(runner, credentials, identity)

    build_release_assets(runner, args.version, paths)
    create_release_notes(args.version, paths.notes_file, source=args.notes_file, dry_run=args.dry_run)
    create_local_tag(runner, tag, args.version)

    assets = release_assets(paths.asset_dir, dry_run=args.dry_run)
    if args.create_github_release:
        push_tag_and_create_release(runner, tag, args.version, args.repo, args.remote, paths, assets)
    else:
        print("GitHub Release upload skipped; pass --create-github-release to publish.", flush=True)

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
        notes_file=(notes_file.resolve() if notes_file is not None else root / "release-notes.md"),
    )


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
    if paths.output_dir.exists():
        shutil.rmtree(paths.output_dir)
    paths.release_dir.mkdir(parents=True)
    paths.asset_dir.mkdir(parents=True)
    paths.package_dir.mkdir(parents=True)


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
) -> None:
    release_dir = CODEX_RS_ROOT / "target" / TARGET / "release"
    for binary in ALL_BINARIES:
        binary_path = release_dir / binary
        if not runner.dry_run and not binary_path.is_file():
            raise RuntimeError(f"Built binary not found: {binary_path}")
        sign_binary(runner, identity, binary_path)
        notarize_binary(runner, credentials, binary_path)
        runner.run(["codesign", "--verify", "--strict", "--verbose=2", str(binary_path)])


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


def notarize_binary(
    runner: CommandRunner,
    credentials: Credentials,
    binary_path: Path,
) -> None:
    notary_key = (
        Path("DRY_RUN_NOTARY_KEY.p8")
        if runner.dry_run and credentials.notary_key_p8 is None
        else required_path(credentials.notary_key_p8, "APPLE_NOTARIZATION_KEY_P8_PATH")
    )
    with tempfile.TemporaryDirectory(prefix="codex-notary-") as temp_dir_str:
        archive_path = Path(temp_dir_str) / f"{binary_path.name}.zip"
        runner.run(["ditto", "-c", "-k", "--keepParent", str(binary_path), str(archive_path)])
        runner.run(
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
                "--wait",
            ]
        )


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
