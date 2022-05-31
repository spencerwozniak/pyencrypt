"""
PyEncrypt - A production-ready file encryption library.

This package provides secure file encryption using Fernet symmetric encryption.
"""

from pyencypt.core.encryptor import FileEncryptor
from pyencypt.core.key_manager import KeyManager
from pyencypt.exceptions import (
    PyEncryptError,
    KeyNotFoundError,
    EncryptionError,
    DecryptionError,
    FileAccessError,
)

__version__ = "1.0.0"
__author__ = "PyEncrypt Contributors"
__all__ = [
    "FileEncryptor",
    "KeyManager",
    "PyEncryptError",
    "KeyNotFoundError",
    "EncryptionError",
    "DecryptionError",
    "FileAccessError",
]
