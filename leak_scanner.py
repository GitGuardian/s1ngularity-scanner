#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# ///

import argparse
import json
import os
import re
import shutil
import subprocess as sp
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Any

# Configuration constants
MIN_PYTHON_VERSION = (3, 9)
SECRETS_FILE_NAME = "gg_gathered_values"

if sys.version_info < MIN_PYTHON_VERSION:
    print(f"Invalid python version, use a version >= {'.'.join(map(str, MIN_PYTHON_VERSION))}")
    sys.exit(1)

# Default values for command line arguments
MIN_CHARS_DEFAULT = 5
MAX_PUBLIC_OCCURRENCES_DEFAULT = 10
TIMEOUT_DEFAULT = 0

# Progress and UI constants
SPINNER_UPDATE_INTERVAL = 0.2
PROGRESS_UPDATE_INTERVAL = 1.0
PROGRESS_FILE_FREQUENCY = 3

PRIVATE_KEYS_FILENAMES = (
    # SSH user keys
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "private_key",
    # SSH host keys
    "ssh_host_rsa_key",
    "ssh_host_dsa_key",
    "ssh_host_ecdsa_key",
    "ssh_host_ed25519_key",
    # Keystores and wallets
    "keystore",
    "keystore.json",
    "wallet",
    "wallet.dat",
)
PRIVATE_KEYS_SUFFIXES = (
    # Common key formats
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".gpg",
    # Additional cryptographic formats
    ".keyfile",
    ".jks",           # Java KeyStore
    ".asc",           # ASCII armored GnuPG
    ".pgp",           # PGP private key
    ".prv",           # Generic private key
    ".pkcs8",         # PKCS#8 format
    ".pkcs1",         # PKCS#1 format
    ".kdbx",          # KeePass database
    # Authentication and cloud keys
    ".keytab",        # Kerberos keytab
    ".pvk",           # Private key (Azure)
    ".ppk",           # PuTTY private key
    # Cryptocurrency and keychain
    ".wallet",        # Generic wallet
    ".seed",          # Seed phrase
    ".mnemonic",      # Mnemonic phrase
    ".keychain",      # macOS Keychain
    ".kdb",           # KeePass database (older)
)


class Source(Enum):
    ENV_VAR = "ENVIRONMENT_VAR"
    GITHUB_TOKEN = "GITHUB_TOKEN"
    NPMRC = "NPMRC_HOME"
    ENV_FILE = "ENV_FILE"
    PRIVATE_KEY = "PRIVATE_KEY"


# Source tracking constants
SOURCE_SEPARATOR = "__"

assignment_regex = re.compile(
    r"""
    ^\s*
    [a-zA-Z_]\w*
    \s*=\s*
    (?P<value>.{1,5000})
""",
    re.VERBOSE,
)

json_assignment_regex = re.compile(
    r"""
    "[a-zA-Z_]\w*"
    \s*:\s*
    "(?P<value>.{1,5000}?)"
""",
    re.VERBOSE,
)


def remove_quotes(value: str) -> str:
    if len(value) > 1 and value[0] == value[-1] and value[0] in ["'", '"']:
        return value[1:-1]
    return value


def extract_assigned_values(text: str) -> set[str]:
    res = []
    for line in text.splitlines():
        for m in re.finditer(assignment_regex, line):
            pwd_value = m.group("value")
            res.append(pwd_value.strip())
            if "#" in pwd_value:
                res.append(pwd_value.split("#")[0].strip())

        for m in re.finditer(json_assignment_regex, line):
            pwd_value = m.group("value")
            res.append(pwd_value)

    return {remove_quotes(val) for val in res}


def handle_github_token_command(*args) -> str | None:
    if shutil.which("gh"):
        try:
            result = sp.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
                stdin=sp.DEVNULL,
            )
            if result.returncode == 0 and result.stdout:
                token = result.stdout.strip()
                if re.match(r"^(gho_|ghp_)", token):
                    return token
        except (sp.TimeoutExpired, sp.SubprocessError):
            pass
    return None


def indices_to_delete(dirs: list[str]) -> list[int]:
    """Return indices of directories to skip during os.walk traversal."""
    indices = []
    for i, dirname in enumerate(dirs):
        if dirname.startswith(".") and dirname not in {".env", ".ssh", ".gnupg"} and not dirname.startswith(".env"):
            indices.append(i)
        elif dirname == "node_modules":
            indices.append(i)
    return indices


def select_file(fpath: Path) -> str | None:
    """Return the file key prefix if this file should be processed."""
    # Use our enhanced path encoding for safety
    safe_path = str(fpath).replace("/", "__SLASH__").replace(".", "__DOT__")
    if fpath.name == ".npmrc":
        return f"{Source.NPMRC.value}{SOURCE_SEPARATOR}{safe_path}"
    elif fpath.name.startswith(".env") and not "example" in fpath.name:
        return f"{Source.ENV_FILE.value}{SOURCE_SEPARATOR}{safe_path}"
    elif any(fname in fpath.name for fname in PRIVATE_KEYS_FILENAMES) or any(
        fpath.name.endswith(suffix) for suffix in PRIVATE_KEYS_SUFFIXES
    ):
        return f"{Source.PRIVATE_KEY.value}{SOURCE_SEPARATOR}{safe_path}"
    return None


class FileGatherer:
    """Handles file scanning and progress display for gathering secrets from files."""

    def __init__(self, timeout: int, verbose: bool = False) -> None:
        self.timeout = timeout
        self.verbose = verbose
        self.home = Path.home()
        self.results = {}
        self.start_time = time.time()
        # Combined tracking: files visited during traversal + files actually scanned
        self.total_files_visited = 0
        self.files_scanned = 0
        self.npmrc_files_matched = 0
        self.npmrc_secrets_extracted = 0
        self.env_files_matched = 0
        self.env_secrets_extracted = 0
        self.private_key_files_matched = 0
        self.private_key_secrets_extracted = 0
        self.last_progress_time = self.start_time
        self.last_spinner_time = self.start_time
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"]
        self.spinner_index = 0

    def _count_file_types_and_show_final_counts(self, current_time: float) -> None:
        """Count values by file type and show final counts with enhanced statistics."""
        npmrc_values = sum(1 for k in self.results.keys() if k.startswith(Source.NPMRC.value))
        env_values = sum(1 for k in self.results.keys() if k.startswith(Source.ENV_FILE.value))
        private_key_values = sum(1 for k in self.results.keys() if k.startswith(Source.PRIVATE_KEY.value))
        elapsed = int(current_time - self.start_time)

        print(f"\r   └─ Total files visited: {self.total_files_visited} ({elapsed}s)" + " " * 20)
        print(
            f"     ├─ Configuration files: {self.npmrc_files_matched} matched, {self.npmrc_files_matched} scanned, {self.npmrc_secrets_extracted} secrets extracted"
        )
        print(
            f"     ├─ Environment files: {self.env_files_matched} matched, {self.env_files_matched} scanned, {self.env_secrets_extracted} secrets extracted"
        )
        print(
            f"     └─ Private key files: {self.private_key_files_matched} matched, {self.private_key_files_matched} scanned, {self.private_key_secrets_extracted} secrets extracted"
        )

    def _show_timeout_message_and_counts(self, current_time: float) -> None:
        """Show timeout message and final counts."""
        if self.files_scanned > 0:
            if self.verbose:
                print(
                    f"⏰ Timeout of {self.timeout}s reached after visiting {self.total_files_visited} files and scanning {self.files_scanned} files. Not all files will be scanned. To scan more files, specify a bigger timeout with the --timeout option"
                )
            else:
                print(
                    f"\r⏰ Timeout reached after {self.total_files_visited} files visited, {self.files_scanned} scanned ({self.timeout}s)"
                    + " " * 10
                    + "\n",
                    end="",
                )
        else:
            if self.verbose:
                print(
                    f"⏰ Timeout of {self.timeout}s reached after visiting {self.total_files_visited} files while searching. Not all files will be scanned. To scan more files, specify a bigger timeout with the --timeout option"
                )

        self._count_file_types_and_show_final_counts(current_time)

    def _update_spinner_progress(self, current_time: float) -> None:
        """Update and show spinner progress during scanning."""
        if (current_time - self.last_spinner_time) >= SPINNER_UPDATE_INTERVAL:
            self.spinner_index += 1
            spinner = self.spinner_chars[self.spinner_index % len(self.spinner_chars)]
            elapsed = int(current_time - self.start_time)

            if self.files_scanned == 0:
                print(
                    f"\r{spinner} Searching directories... {self.total_files_visited} files visited ({elapsed}s)",
                    end="",
                    flush=True,
                )
            else:
                print(
                    f"\r{spinner} Scanning... {self.total_files_visited} visited, {self.files_scanned} scanned ({elapsed}s)",
                    end="",
                    flush=True,
                )

            self.last_spinner_time = current_time

    def _show_file_progress_if_needed(self, current_time: float) -> None:
        """Show progress update when processing files if conditions are met."""
        should_show_progress = (
            self.files_scanned % PROGRESS_FILE_FREQUENCY == 0
            or self.files_scanned == 1
            or (current_time - self.last_progress_time) >= PROGRESS_UPDATE_INTERVAL
        )

        if should_show_progress:
            spinner = self.spinner_chars[self.spinner_index % len(self.spinner_chars)]
            elapsed = int(current_time - self.start_time)
            print(
                f"\r{spinner} Scanning... {self.total_files_visited} visited, {self.files_scanned} scanned ({elapsed}s)",
                end="",
                flush=True,
            )
            self.last_progress_time = current_time

    def _process_file_and_extract_values(self, fpath: Path, filekey: str) -> None:
        """Process a single file, extract values, and show results."""
        self.files_scanned += 1

        # Count file types matched
        if filekey.startswith(Source.NPMRC.value):
            self.npmrc_files_matched += 1
        elif filekey.startswith(Source.ENV_FILE.value):
            self.env_files_matched += 1
        elif filekey.startswith(Source.PRIVATE_KEY.value):
            self.private_key_files_matched += 1
        try:
            text = fpath.read_text()
        except Exception:
            if self.verbose:
                print(f"Failed reading {fpath}")
            return

        # Handle private key files differently - use full content as single value
        if filekey.startswith(Source.PRIVATE_KEY.value):
            if len(text) > 10000:
                if self.verbose:
                    print(f"\r   Ignoring file too big: {fpath}")
                return
            # For private keys, use "PRIVATE_KEY" as the value name and full content as value
            key = f"{filekey}{SOURCE_SEPARATOR}PRIVATE_KEY"
            # This is for public pipeline
            self.results[key] = '"' + "\\n+".join(text.splitlines()) + '"'

            # This is for s1gularity uploaded secrets
            self.results[key + "_var"] = '"' + "\\\\\\\\n".join(text.splitlines()) + '"'
            self.private_key_secrets_extracted += 1

            if self.verbose:
                print(f"\r   Found private key in {fpath}" + " " * 20)
        else:
            # For other files, extract assigned values as before
            values = extract_assigned_values(text)

            if values:
                # Count files that actually have secrets extracted (our enhancement)
                if filekey.startswith(Source.NPMRC.value):
                    self.npmrc_secrets_extracted += 1
                elif filekey.startswith(Source.ENV_FILE.value):
                    self.env_secrets_extracted += 1

            if self.verbose:
                if values:
                    print(f"\r   Found {len(values)} values in {fpath}" + " " * 20)
                else:
                    print(f"\r   No values found in {fpath}" + " " * 20)

            for value in values:
                key = f"{filekey}{SOURCE_SEPARATOR}{value}"
                self.results[key] = value

    def gather(self) -> dict[str, str]:
        """Main method to gather files and return results."""
        # Show initial progress immediately
        spinner = self.spinner_chars[0]
        if self.verbose:
            print(f"\r{spinner} Starting filesystem scan...", end="", flush=True)
        else:
            print(f"\r{spinner} Starting scan...", end="", flush=True)

        try:
            for root, dirs, files in os.walk(self.home):
                current_time = time.time()

                # Check timeout before processing directory - fix for timeout 0 bug
                if self.timeout > 0 and (current_time - self.start_time) > self.timeout:
                    self._show_timeout_message_and_counts(current_time)
                    return self.results

                # Update spinner during directory traversal to show we're alive
                self._update_spinner_progress(current_time)

                # Remove unwanted directories during traversal (performance optimization)
                nb_deleted = 0
                for ind in indices_to_delete(dirs):
                    del dirs[ind - nb_deleted]
                    nb_deleted += 1

                # Process files in current directory
                for filename in files:
                    fpath = Path(root) / filename
                    self.total_files_visited += 1

                    filekey = select_file(fpath)

                    if filekey is None:
                        continue

                    self._process_file_and_extract_values(fpath, filekey)

                    # Show progress update when we find files
                    current_time = time.time()
                    self._show_file_progress_if_needed(current_time)

                    # Check timeout after processing file
                    if self.timeout > 0 and (current_time - self.start_time) > self.timeout:
                        self._show_timeout_message_and_counts(current_time)
                        return self.results

        except KeyboardInterrupt:
            print("\nScan interrupted by user")
            return self.results

        # Show final completion counts
        self._count_file_types_and_show_final_counts(time.time())
        return self.results


def gather_files_by_patterns(timeout: int, verbose: bool = False) -> dict[str, str]:
    """Gather secrets from files using enhanced FileGatherer class."""
    gatherer = FileGatherer(timeout, verbose)
    return gatherer.gather()


def get_source_description(source_part: str) -> str:
    """Convert source prefix to human-readable description."""
    source_mapping = {
        Source.ENV_VAR.value: "Environment variable",
        Source.GITHUB_TOKEN.value: "GitHub Token (gh auth token)",
        Source.NPMRC.value: "~/.npmrc",
    }

    if source_part.startswith(Source.ENV_FILE.value):
        # Use our enhanced path decoding with __SLASH__/__DOT__
        path_part = source_part.replace(f"{Source.ENV_FILE.value}{SOURCE_SEPARATOR}", "")
        return path_part.replace("__SLASH__", "/").replace("__DOT__", ".")
    elif source_part.startswith(Source.PRIVATE_KEY.value):
        path_part = source_part.replace(f"{Source.PRIVATE_KEY.value}{SOURCE_SEPARATOR}", "")
        return path_part.replace("__SLASH__", "/").replace("__DOT__", ".")

    return source_mapping.get(source_part, source_part)


def display_leak(i: int, leak: dict[str, Any], source_type: str, source_path: str, secret_part: str) -> None:
    """Display a single leaked secret with formatting."""
    print(f"🔑 Secret #{i}")
    print(f"   Name: {secret_part}")
    print(f"   Source: {source_type}")
    print(f"   Path: {source_path}")
    print(f"   Hash: {leak.get('hash', '')}")
    count = leak.get("count", 0)
    print(f"   Locations: {count} distinct Public GitHub repositories")
    if leak.get("url"):
        print(f"   First seen: {leak.get('url')} (only first location shown for security)")
    print()


def gather_all_secrets(timeout: int, verbose: bool = False) -> dict[str, str]:
    all_values = {}

    # Collect environment variables
    env_vars = 0
    for value in os.environ.values():
        key = f"{Source.ENV_VAR.value}{SOURCE_SEPARATOR}{value}"
        all_values[key] = value
        env_vars += 1

    print(f"   ├─ Environment variables: {env_vars} found")

    # Collect GitHub token
    gh_token = handle_github_token_command()
    github_found = False
    if gh_token:
        key = f"{Source.GITHUB_TOKEN.value}{SOURCE_SEPARATOR}{gh_token}"
        all_values[key] = gh_token
        github_found = True

    # Show GitHub token progress
    if github_found:
        print(f"   ├─ GitHub token: found")
    else:
        print(f"   ├─ GitHub token: not found")

    # Collect files using enhanced FileGatherer
    file_values = gather_files_by_patterns(timeout, verbose)
    all_values.update(file_values)

    return all_values


def find_leaks(args) -> None:
    if shutil.which("ggshield") is None:
        print("Please install ggshield first, see https://github.com/GitGuardian/ggshield#installation")
        sys.exit(1)

    print("🔍 S1ngularity Scanner - Detecting if your secrets have been leaked publicly")
    print("🔒 All processing occurs locally, no secrets transmitted")

    if args.verbose:
        print()
        timeout_desc = f"{args.timeout}s" if args.timeout > 0 else "unlimited"
        keep_desc = "yes" if args.keep_temp_file else "no"
        print(
            f"⚙️  Settings: min-chars={args.min_chars}, timeout={timeout_desc}, keep-temp-file={keep_desc}, max-public-occurrences={args.max_public_occurrences}"
        )
        print()

    if args.verbose:
        timeout_desc = f"timeout: {args.timeout}s" if args.timeout > 0 else "no timeout"
        print(f"📁 Scanning system ({timeout_desc})...")

    values_with_sources = gather_all_secrets(args.timeout, args.verbose)

    if args.verbose:
        print()

    selected_items = [(k, v) for k, v in values_with_sources.items() if v is not None and len(v) >= args.min_chars]
    total_values = len(values_with_sources)
    filtered_count = total_values - len(selected_items)

    if filtered_count > 0:
        print(f"   • {filtered_count} values filtered out (shorter than {args.min_chars} characters)")
        print(
            f"🔍 Checking {len(selected_items)} potential secrets against GitGuardian's public exposure database HMSL..."
        )

    else:
        print(
            f"🔍 Checking {len(selected_items)} potential secrets against GitGuardian's public exposure database HMSL..."
        )

    secrets_file = Path(SECRETS_FILE_NAME)
    env_content = "\n".join([f"{k}={v}" for k, v in selected_items])
    secrets_file.write_text(env_content)
    result = sp.run(
        ["ggshield", "hmsl", "check", SECRETS_FILE_NAME, "--type", "env", "-n", "key", "--json"],
        stdout=sp.PIPE,
        stderr=sp.DEVNULL,
        text=True,
    )

    if result.stdout:
        try:
            data = json.loads(result.stdout)
            total_leak_count = data.get("leaks_count", 0)
            selected_leaks = [
                leak for leak in data.get("leaks", []) if leak.get("count", 0) < args.max_public_occurrences
            ]
            leak_count = len(selected_leaks)
            filtered_count = total_leak_count - leak_count

            if filtered_count > 0:
                print(
                    f"ℹ️  Filtered out {filtered_count} leak{'s' if filtered_count > 1 else ''} with high public occurrence count (≥{args.max_public_occurrences})"
                )

            if leak_count > 0:
                print(f"⚠️  Found {leak_count} leaked secret{'s' if leak_count > 1 else ''}")
                print()
                for i, leak in enumerate(selected_leaks, 1):
                    key_name = leak.get("name", "")
                    if SOURCE_SEPARATOR in key_name:
                        source_part, secret_part = key_name.split(SOURCE_SEPARATOR, 1)
                        source_path = get_source_description(source_part)
                        # Determine source type based on the source part
                        if source_part == Source.ENV_VAR.value:
                            source_type = "Environment variable"
                        elif source_part == Source.GITHUB_TOKEN.value:
                            source_type = "GitHub Token"
                        elif source_part.startswith(Source.NPMRC.value):
                            source_type = "Configuration file"
                        elif source_part.startswith(Source.ENV_FILE.value):
                            source_type = "Environment file"
                        elif source_part.startswith(Source.PRIVATE_KEY.value):
                            source_type = "Private key file"
                        else:
                            source_type = "Unknown"

                        # Special handling for ENV_FILE where encoded path+secret is in secret_part
                        if source_part == Source.ENV_FILE.value and source_path == "":
                            encoded_patterns = [
                                "__SLASH____DOT__env__DOT__production__",
                                "__SLASH____DOT__env__DOT__test__",
                                "__SLASH____DOT__env__",
                            ]

                            for pattern in encoded_patterns:
                                if pattern in secret_part:
                                    parts = secret_part.split(pattern, 1)
                                    if len(parts) == 2:
                                        filepath_encoded = parts[0] + pattern.rstrip("__")  # Keep the .env part
                                        actual_secret = parts[1]

                                        # Decode the filepath
                                        decoded_filepath = filepath_encoded.replace("__SLASH__", "/").replace(
                                            "__DOT__", "."
                                        )
                                        if not decoded_filepath.startswith("/"):
                                            decoded_filepath = "/" + decoded_filepath

                                        source_path = decoded_filepath
                                        secret_part = actual_secret
                                        break
                        display_leak(i, leak, source_type, source_path, secret_part)
                print("💡 Note: Results may include false positives (non-secret values matching leak patterns).")
                print("   Always verify results before taking action. If confirmed as real secrets:")
                print("   1. Immediately revoke and rotate the credential")
                print("   2. Review when the leak occurred and what systems may be compromised")

            else:
                print("✅ All clear! No leaked secrets found.")

        except (json.JSONDecodeError, KeyError) as e:
            if args.verbose:
                print("Error parsing results, showing raw output:")
                sp.run(["ggshield", "hmsl", "check", SECRETS_FILE_NAME, "-n", "cleartext"])
            else:
                print("⚠️  Error checking secrets - run with --verbose for details")

    if not args.keep_temp_file:
        try:
            os.remove(SECRETS_FILE_NAME)
            if args.verbose:
                print(f"Cleaned up temporary file {SECRETS_FILE_NAME}")
        except FileNotFoundError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--min-chars",
        type=int,
        help="Values with less chars than this are not considered",
        default=MIN_CHARS_DEFAULT,
    )
    parser.add_argument(
        "--keep-temp-file",
        action="store_true",
        help="Keep the temporary file containing gathered values instead of deleting it",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Number of seconds before aborting discovery of files on hard drive. Use 0 for unlimited scanning (default: 0).",
        default=TIMEOUT_DEFAULT,
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed scanning progress and debug information"
    )
    parser.add_argument(
        "--max-public-occurrences",
        type=int,
        help="Maximum number of public occurrences for a leak to be reported (default: 10)",
        default=MAX_PUBLIC_OCCURRENCES_DEFAULT,
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    find_leaks(args)
