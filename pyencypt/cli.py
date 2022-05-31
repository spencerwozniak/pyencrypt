"""Command-line interface for PyEncrypt."""

import argparse
import logging
import sys
from pathlib import Path

from pyencypt.core.encryptor import FileEncryptor
from pyencypt.core.key_manager import KeyManager
from pyencypt.exceptions import KeyNotFoundError, PyEncryptError


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="pyencrypt",
        description="Secure file encryption tool using Fernet symmetric encryption.",
        epilog="Examples:\n"
        "  pyencrypt lock                    # Encrypt current directory\n"
        "  pyencrypt unlock                  # Decrypt current directory\n"
        "  pyencrypt lock -d /path/to/dir    # Encrypt specific directory\n"
        "  pyencrypt lock -r                 # Encrypt recursively\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available commands",
    )

    lock_parser = subparsers.add_parser(
        "lock",
        help="Encrypt files in a directory",
        description="Encrypt all files in the specified directory.",
    )
    _add_common_args(lock_parser)

    unlock_parser = subparsers.add_parser(
        "unlock",
        help="Decrypt files in a directory",
        description="Decrypt all files in the specified directory.",
    )
    _add_common_args(unlock_parser)
    unlock_parser.add_argument(
        "--keep-key",
        action="store_true",
        help="Keep the key file after decryption",
    )

    status_parser = subparsers.add_parser(
        "status",
        help="Check encryption status",
        description="Check if a directory is currently encrypted.",
    )
    status_parser.add_argument(
        "-d",
        "--directory",
        type=Path,
        default=Path.cwd(),
        help="Target directory (default: current directory)",
    )

    subparsers.add_parser(
        "generate-key",
        help="Generate a new encryption key",
        description="Generate and save a new encryption key.",
    )

    return parser


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    """Add common arguments to lock/unlock subparsers."""
    parser.add_argument(
        "-d",
        "--directory",
        type=Path,
        default=Path.cwd(),
        help="Target directory (default: current directory)",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Process subdirectories recursively",
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action="append",
        default=[],
        help="Additional patterns to exclude (can be used multiple times)",
    )


def cmd_lock(args: argparse.Namespace) -> int:
    """Handle the lock command."""
    key_manager = KeyManager(key_dir=args.directory)
    encryptor = FileEncryptor(
        key_manager=key_manager,
        exclude_patterns=set(args.exclude) if args.exclude else None,
    )

    if encryptor.is_locked:
        print(f"Directory already appears to be locked: {args.directory}")
        return 1

    print(f"Encrypting files in: {args.directory}")
    if args.recursive:
        print("Mode: recursive")

    result = encryptor.lock(directory=args.directory, recursive=args.recursive)

    print(f"\nResults:")
    print(f"  Encrypted: {result.total_processed} files")
    print(f"  Skipped:   {result.total_skipped} files")
    print(f"  Failed:    {result.total_failed} files")

    if result.failed:
        print("\nFailed files:")
        for filepath, error in result.failed:
            print(f"  - {filepath}: {error}")
        return 1

    if result.total_processed > 0:
        print(f"\nKey saved to: {key_manager.key_path}")
        print("WARNING: Keep this key safe! You need it to decrypt your files.")

    return 0


def cmd_unlock(args: argparse.Namespace) -> int:
    """Handle the unlock command."""
    key_manager = KeyManager(key_dir=args.directory)
    encryptor = FileEncryptor(
        key_manager=key_manager,
        exclude_patterns=set(args.exclude) if args.exclude else None,
    )

    if not encryptor.is_locked:
        print(f"No encryption key found in: {args.directory}")
        print("Directory does not appear to be encrypted.")
        return 1

    print(f"Decrypting files in: {args.directory}")
    if args.recursive:
        print("Mode: recursive")

    try:
        result = encryptor.unlock(directory=args.directory, recursive=args.recursive)
    except KeyNotFoundError as e:
        print(f"Error: {e}")
        return 1

    print(f"\nResults:")
    print(f"  Decrypted: {result.total_processed} files")
    print(f"  Skipped:   {result.total_skipped} files")
    print(f"  Failed:    {result.total_failed} files")

    if result.failed:
        print("\nFailed files:")
        for filepath, error in result.failed:
            print(f"  - {filepath}: {error}")
        return 1

    if not args.keep_key:
        print("\nKey file deleted.")
    else:
        print(f"\nKey file kept at: {key_manager.key_path}")

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Handle the status command."""
    key_manager = KeyManager(key_dir=args.directory)

    print(f"Directory: {args.directory}")
    if key_manager.key_exists():
        print("Status: LOCKED (encryption key present)")
        print(f"Key file: {key_manager.key_path}")
    else:
        print("Status: UNLOCKED (no encryption key found)")

    return 0


def cmd_generate_key(args: argparse.Namespace) -> int:
    """Handle the generate-key command."""
    key_manager = KeyManager()

    if key_manager.key_exists():
        print(f"Key already exists at: {key_manager.key_path}")
        print("Delete it first if you want to generate a new one.")
        return 1

    key_manager.generate_and_save()
    print(f"Generated new key at: {key_manager.key_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args(argv)

    setup_logging(args.verbose)

    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "lock": cmd_lock,
        "unlock": cmd_unlock,
        "status": cmd_status,
        "generate-key": cmd_generate_key,
    }

    try:
        return commands[args.command](args)
    except PyEncryptError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
