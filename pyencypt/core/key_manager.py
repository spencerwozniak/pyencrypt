"""Key management for encryption operations."""

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet

from pyencypt.exceptions import InvalidKeyError, KeyNotFoundError

logger = logging.getLogger(__name__)


class KeyManager:
    """
    Manages encryption keys for file encryption/decryption.

    Handles key generation, storage, retrieval, and validation using
    Fernet symmetric encryption.

    Attributes:
        key_filename: Name of the key file (default: '.pyencrypt.key')
        key_dir: Directory where the key is stored
    """

    DEFAULT_KEY_FILENAME = ".pyencrypt.key"

    def __init__(
        self,
        key_dir: str | Path | None = None,
        key_filename: str | None = None,
    ):
        """
        Initialize the KeyManager.

        Args:
            key_dir: Directory to store the key file. Defaults to current directory.
            key_filename: Custom key filename. Defaults to '.pyencrypt.key'.
        """
        self.key_dir = Path(key_dir) if key_dir else Path.cwd()
        self.key_filename = key_filename or self.DEFAULT_KEY_FILENAME
        self._cached_key: bytes | None = None

    @property
    def key_path(self) -> Path:
        """Full path to the key file."""
        return self.key_dir / self.key_filename

    def generate_key(self) -> bytes:
        """
        Generate a new Fernet encryption key.

        Returns:
            The generated key as bytes.
        """
        key = Fernet.generate_key()
        logger.debug("Generated new encryption key")
        return key

    def save_key(self, key: bytes) -> Path:
        """
        Save an encryption key to the key file.

        Args:
            key: The encryption key to save.

        Returns:
            Path to the saved key file.

        Raises:
            FileAccessError: If the key file cannot be written.
        """
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.key_path.write_bytes(key)
        self._cached_key = key
        logger.info(f"Saved encryption key to {self.key_path}")
        return self.key_path

    def load_key(self) -> bytes:
        """
        Load the encryption key from the key file.

        Returns:
            The encryption key as bytes.

        Raises:
            KeyNotFoundError: If the key file doesn't exist.
            InvalidKeyError: If the key file is empty or corrupted.
        """
        if self._cached_key is not None:
            return self._cached_key

        if not self.key_path.exists():
            raise KeyNotFoundError(str(self.key_path))

        key = self.key_path.read_bytes()
        if not key:
            raise InvalidKeyError("Key file is empty")

        self._validate_key(key)
        self._cached_key = key
        logger.debug(f"Loaded encryption key from {self.key_path}")
        return key

    def delete_key(self) -> bool:
        """
        Delete the key file.

        Returns:
            True if the key was deleted, False if it didn't exist.
        """
        if self.key_path.exists():
            self.key_path.unlink()
            self._cached_key = None
            logger.info(f"Deleted encryption key at {self.key_path}")
            return True
        return False

    def key_exists(self) -> bool:
        """Check if a key file exists."""
        return self.key_path.exists()

    def generate_and_save(self) -> bytes:
        """
        Generate a new key and save it to the key file.

        Returns:
            The generated encryption key.
        """
        key = self.generate_key()
        self.save_key(key)
        return key

    def clear_cache(self) -> None:
        """Clear the cached key from memory."""
        self._cached_key = None
        logger.debug("Cleared key cache")

    @staticmethod
    def _validate_key(key: bytes) -> None:
        """
        Validate that a key is a valid Fernet key.

        Args:
            key: The key to validate.

        Raises:
            InvalidKeyError: If the key is invalid.
        """
        try:
            Fernet(key)
        except Exception as e:
            raise InvalidKeyError(str(e))

    def __repr__(self) -> str:
        return f"KeyManager(key_dir={self.key_dir!r}, key_filename={self.key_filename!r})"
