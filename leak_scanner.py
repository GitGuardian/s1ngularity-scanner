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
from dataclasses import dataclass

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
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "private_key",
)
PRIVATE_KEYS_SUFFIXES = (".key", ".pem", ".p12", ".pfx", ".gpg")


@dataclass
class SecretMetadata:
    """Store metadata about where a secret came from."""
    source_type: str
    source_path: str
    secret_name: str


class SecretTracker:
    """Track secrets with clean metadata instead of encoded keys."""
    
    def __init__(self):
        self.secrets = {}  # key -> secret_value
        self.metadata = {}  # key -> SecretMetadata
        self._counter = 0
    
    def add_secret(self, source_type: str, source_path: str, secret_name: str, secret_value: str) -> str:
        """Add a secret and return its key for ggshield."""
        self._counter += 1
        key = f"{source_type}{KEY_SEPARATOR}{self._counter}"
        
        self.secrets[key] = secret_value
        self.metadata[key] = SecretMetadata(source_type, source_path, secret_name)
        
        return key
    
    def get_metadata(self, key: str) -> SecretMetadata:
        """Get metadata for a key."""
        return self.metadata.get(key)
    
    def get_secrets_for_ggshield(self) -> dict[str, str]:
        """Get the key=value pairs for ggshield."""
        return self.secrets.copy()


class Source(Enum):
    ENV_VAR = "ENVIRONMENT_VAR"
    GITHUB_TOKEN = "GITHUB_TOKEN"
    NPMRC = "NPMRC_HOME"
    ENV_FILE = "ENV_FILE"
    PRIVATE_KEY = "PRIVATE_KEY"


# Source tracking constants
KEY_SEPARATOR = "|"

# Global tracker instance
_secret_tracker = None

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


def select_file(fpath: Path) -> tuple[str, str] | None:
    """Return (source_type, file_path) if this file should be processed."""
    if fpath.name == ".npmrc":
        return (Source.NPMRC.value, str(fpath))
    elif fpath.name.startswith(".env") and not "example" in fpath.name:
        return (Source.ENV_FILE.value, str(fpath))
    elif any(fname in fpath.name for fname in PRIVATE_KEYS_FILENAMES) or any(
        fpath.name.endswith(suffix) for suffix in PRIVATE_KEYS_SUFFIXES
    ):
        return (Source.PRIVATE_KEY.value, str(fpath))
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

    def _process_file_and_extract_values(self, fpath: Path, source_type: str, file_path: str) -> None:
        """Process a single file, extract values, and show results."""
        global _secret_tracker
        self.files_scanned += 1

        # Count file types matched
        if source_type == Source.NPMRC.value:
            self.npmrc_files_matched += 1
        elif source_type == Source.ENV_FILE.value:
            self.env_files_matched += 1
        elif source_type == Source.PRIVATE_KEY.value:
            self.private_key_files_matched += 1
        try:
            text = fpath.read_text()
        except Exception:
            if self.verbose:
                print(f"Failed reading {fpath}")
            return

        # Handle private key files differently - use full content as single value
        if source_type == Source.PRIVATE_KEY.value:
            if len(text) > 10000:
                if self.verbose:
                    print(f"\r   Ignoring file too big: {fpath}")
                return
            
            # For private keys, create multiple variations for different formats
            # This is for public pipeline
            key1 = _secret_tracker.add_secret(
                source_type=source_type,
                source_path=file_path,
                secret_name="PRIVATE_KEY",
                secret_value='"' + "\\n+".join(text.splitlines()) + '"'
            )
            self.results[key1] = '"' + "\\n+".join(text.splitlines()) + '"'

            # This is for s1gularity uploaded secrets
            key2 = _secret_tracker.add_secret(
                source_type=source_type,
                source_path=file_path,
                secret_name="PRIVATE_KEY_VAR",
                secret_value='"' + "\\\\\\\\n".join(text.splitlines()) + '"'
            )
            self.results[key2] = '"' + "\\\\\\\\n".join(text.splitlines()) + '"'
            
            self.private_key_secrets_extracted += 1

            if self.verbose:
                print(f"\r   Found private key in {fpath}" + " " * 20)
        else:
            # For other files, extract assigned values as before
            values = extract_assigned_values(text)

            if values:
                # Count files that actually have secrets extracted (our enhancement)
                if source_type == Source.NPMRC.value:
                    self.npmrc_secrets_extracted += 1
                elif source_type == Source.ENV_FILE.value:
                    self.env_secrets_extracted += 1

            if self.verbose:
                if values:
                    print(f"\r   Found {len(values)} values in {fpath}" + " " * 20)
                else:
                    print(f"\r   No values found in {fpath}" + " " * 20)

            for value in values:
                # Add to global tracker
                key = _secret_tracker.add_secret(
                    source_type=source_type,
                    source_path=file_path,
                    secret_name=value,
                    secret_value=value
                )
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

                    file_info = select_file(fpath)

                    if file_info is None:
                        continue

                    source_type, file_path = file_info
                    self._process_file_and_extract_values(fpath, source_type, file_path)

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
    global _secret_tracker
    _secret_tracker = SecretTracker()

    # Collect environment variables
    env_vars = 0
    for name, value in os.environ.items():
        _secret_tracker.add_secret(
            source_type=Source.ENV_VAR.value,
            source_path="Environment variable", 
            secret_name=name,
            secret_value=value
        )
        env_vars += 1

    print(f"   ├─ Environment variables: {env_vars} found")

    # Collect GitHub token
    gh_token = handle_github_token_command()
    if gh_token:
        _secret_tracker.add_secret(
            source_type=Source.GITHUB_TOKEN.value,
            source_path="GitHub CLI",
            secret_name="gh_token", 
            secret_value=gh_token
        )
        print(f"   ├─ GitHub token: found")
    else:
        print(f"   ├─ GitHub token: not found")

    # Collect files using enhanced FileGatherer
    file_values = gather_files_by_patterns(timeout, verbose)

    return _secret_tracker.get_secrets_for_ggshield()


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
                    metadata = _secret_tracker.get_metadata(key_name)
                    
                    if metadata:
                        source_type_display = {
                            Source.ENV_VAR.value: "Environment variable",
                            Source.GITHUB_TOKEN.value: "GitHub Token", 
                            Source.NPMRC.value: "Configuration file",
                            Source.ENV_FILE.value: "Environment file",
                            Source.PRIVATE_KEY.value: "Private key file"
                        }.get(metadata.source_type, "Unknown")
                        
                        display_leak(i, leak, source_type_display, metadata.source_path, metadata.secret_name)
                    else:
                        # This should never happen with the new implementation
                        display_leak(i, leak, "Unknown", "Unknown", key_name)
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
