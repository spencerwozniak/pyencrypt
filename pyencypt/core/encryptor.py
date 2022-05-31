"""File encryption and decryption operations."""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from pyencypt.core.key_manager import KeyManager
from pyencypt.exceptions import DecryptionError, EncryptionError, FileAccessError

logger = logging.getLogger(__name__)


@dataclass
class EncryptionResult:
    """Result of an encryption/decryption operation."""

    successful: list[Path] = field(default_factory=list)
    failed: list[tuple[Path, str]] = field(default_factory=list)
    skipped: list[Path] = field(default_factory=list)

    @property
    def total_processed(self) -> int:
        return len(self.successful)

    @property
    def total_failed(self) -> int:
        return len(self.failed)

    @property
    def total_skipped(self) -> int:
        return len(self.skipped)

    def __bool__(self) -> bool:
        return len(self.failed) == 0


class FileEncryptor:
    """
    Handles file encryption and decryption operations.

    Uses Fernet symmetric encryption to securely encrypt and decrypt files.
    Supports single file operations and batch processing of directories.

    Attributes:
        key_manager: KeyManager instance for handling encryption keys.
        exclude_patterns: File patterns to exclude from encryption.
    """

    DEFAULT_EXCLUDE_PATTERNS = {
        ".pyencrypt.key",
        ".git",
        ".gitignore",
        "__pycache__",
        ".pyc",
        ".pyo",
        ".env",
    }

    def __init__(
        self,
        key_manager: KeyManager | None = None,
        exclude_patterns: set[str] | None = None,
    ):
        """
        Initialize the FileEncryptor.

        Args:
            key_manager: Custom KeyManager instance. Creates default if None.
            exclude_patterns: Custom patterns to exclude. Merges with defaults.
        """
        self.key_manager = key_manager or KeyManager()
        self.exclude_patterns = self.DEFAULT_EXCLUDE_PATTERNS.copy()
        if exclude_patterns:
            self.exclude_patterns.update(exclude_patterns)
        self._fernet: Fernet | None = None

    @property
    def is_locked(self) -> bool:
        """Check if files are currently in an encrypted (locked) state."""
        return self.key_manager.key_exists()

    def _get_fernet(self) -> Fernet:
        """Get or create a Fernet instance with the current key."""
        if self._fernet is None:
            key = self.key_manager.load_key()
            self._fernet = Fernet(key)
        return self._fernet

    def _should_exclude(self, filepath: Path) -> bool:
        """Check if a file should be excluded from encryption."""
        filename = filepath.name
        for pattern in self.exclude_patterns:
            if pattern in str(filepath) or filename == pattern:
                return True
        return False

    def encrypt_file(self, filepath: str | Path) -> Path:
        """
        Encrypt a single file in place.

        Args:
            filepath: Path to the file to encrypt.

        Returns:
            Path to the encrypted file.

        Raises:
            FileAccessError: If the file cannot be read or written.
            EncryptionError: If encryption fails.
        """
        filepath = Path(filepath)

        if not filepath.exists():
            raise FileAccessError(str(filepath), "read")

        if not filepath.is_file():
            raise EncryptionError(str(filepath), "Not a regular file")

        try:
            contents = filepath.read_bytes()
        except PermissionError:
            raise FileAccessError(str(filepath), "read")

        try:
            fernet = self._get_fernet()
            encrypted_contents = fernet.encrypt(contents)
        except Exception as e:
            raise EncryptionError(str(filepath), str(e))

        try:
            filepath.write_bytes(encrypted_contents)
        except PermissionError:
            raise FileAccessError(str(filepath), "write")

        logger.info(f"Encrypted: {filepath}")
        return filepath

    def decrypt_file(self, filepath: str | Path) -> Path:
        """
        Decrypt a single file in place.

        Args:
            filepath: Path to the file to decrypt.

        Returns:
            Path to the decrypted file.

        Raises:
            FileAccessError: If the file cannot be read or written.
            DecryptionError: If decryption fails (wrong key, corrupted file).
        """
        filepath = Path(filepath)

        if not filepath.exists():
            raise FileAccessError(str(filepath), "read")

        if not filepath.is_file():
            raise DecryptionError(str(filepath), "Not a regular file")

        try:
            encrypted_contents = filepath.read_bytes()
        except PermissionError:
            raise FileAccessError(str(filepath), "read")

        try:
            fernet = self._get_fernet()
            contents = fernet.decrypt(encrypted_contents)
        except InvalidToken:
            raise DecryptionError(str(filepath), "Invalid key or corrupted file")
        except Exception as e:
            raise DecryptionError(str(filepath), str(e))

        try:
            filepath.write_bytes(contents)
        except PermissionError:
            raise FileAccessError(str(filepath), "write")

        logger.info(f"Decrypted: {filepath}")
        return filepath

    def encrypt_directory(
        self,
        directory: str | Path | None = None,
        recursive: bool = False,
    ) -> EncryptionResult:
        """
        Encrypt all files in a directory.

        Args:
            directory: Directory to encrypt. Defaults to current directory.
            recursive: Whether to process subdirectories.

        Returns:
            EncryptionResult with details of the operation.
        """
        directory = Path(directory) if directory else Path.cwd()
        result = EncryptionResult()

        if self.is_locked:
            logger.warning("Directory appears to already be encrypted")

        if not self.key_manager.key_exists():
            self.key_manager.generate_and_save()
            self._fernet = None

        files = self._get_files(directory, recursive)

        for filepath in files:
            if self._should_exclude(filepath):
                result.skipped.append(filepath)
                logger.debug(f"Skipped (excluded): {filepath}")
                continue

            try:
                self.encrypt_file(filepath)
                result.successful.append(filepath)
            except (EncryptionError, FileAccessError) as e:
                result.failed.append((filepath, str(e)))
                logger.error(f"Failed to encrypt {filepath}: {e}")

        return result

    def decrypt_directory(
        self,
        directory: str | Path | None = None,
        recursive: bool = False,
        delete_key: bool = True,
    ) -> EncryptionResult:
        """
        Decrypt all files in a directory.

        Args:
            directory: Directory to decrypt. Defaults to current directory.
            recursive: Whether to process subdirectories.
            delete_key: Whether to delete the key file after decryption.

        Returns:
            EncryptionResult with details of the operation.
        """
        directory = Path(directory) if directory else Path.cwd()
        result = EncryptionResult()

        if not self.is_locked:
            logger.warning("No encryption key found - files may not be encrypted")
            return result

        files = self._get_files(directory, recursive)

        for filepath in files:
            if self._should_exclude(filepath):
                result.skipped.append(filepath)
                logger.debug(f"Skipped (excluded): {filepath}")
                continue

            try:
                self.decrypt_file(filepath)
                result.successful.append(filepath)
            except (DecryptionError, FileAccessError) as e:
                result.failed.append((filepath, str(e)))
                logger.error(f"Failed to decrypt {filepath}: {e}")

        if delete_key and result:
            self.key_manager.delete_key()
            self._fernet = None

        return result

    def lock(
        self,
        directory: str | Path | None = None,
        recursive: bool = False,
    ) -> EncryptionResult:
        """
        Lock (encrypt) a directory. Alias for encrypt_directory.

        Args:
            directory: Directory to lock.
            recursive: Whether to process subdirectories.

        Returns:
            EncryptionResult with details of the operation.
        """
        return self.encrypt_directory(directory, recursive)

    def unlock(
        self,
        directory: str | Path | None = None,
        recursive: bool = False,
    ) -> EncryptionResult:
        """
        Unlock (decrypt) a directory. Alias for decrypt_directory.

        Args:
            directory: Directory to unlock.
            recursive: Whether to process subdirectories.

        Returns:
            EncryptionResult with details of the operation.
        """
        return self.decrypt_directory(directory, recursive)

    def _get_files(self, directory: Path, recursive: bool) -> list[Path]:
        """Get list of files in directory."""
        if recursive:
            return [f for f in directory.rglob("*") if f.is_file()]
        return [f for f in directory.iterdir() if f.is_file()]

    def add_exclusion(self, pattern: str) -> None:
        """Add a pattern to the exclusion list."""
        self.exclude_patterns.add(pattern)

    def remove_exclusion(self, pattern: str) -> bool:
        """Remove a pattern from the exclusion list."""
        if pattern in self.exclude_patterns:
            self.exclude_patterns.discard(pattern)
            return True
        return False

    def __repr__(self) -> str:
        return f"FileEncryptor(key_manager={self.key_manager!r})"
