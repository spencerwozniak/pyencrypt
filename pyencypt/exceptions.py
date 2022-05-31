"""Custom exceptions for the PyEncrypt package."""


class PyEncryptError(Exception):
    """Base exception for all PyEncrypt errors."""

    pass


class KeyNotFoundError(PyEncryptError):
    """Raised when an encryption key cannot be found."""

    def __init__(self, key_path: str | None = None):
        self.key_path = key_path
        message = "Encryption key not found"
        if key_path:
            message += f": {key_path}"
        super().__init__(message)


class EncryptionError(PyEncryptError):
    """Raised when file encryption fails."""

    def __init__(self, filepath: str, reason: str = "Unknown error"):
        self.filepath = filepath
        self.reason = reason
        super().__init__(f"Failed to encrypt '{filepath}': {reason}")


class DecryptionError(PyEncryptError):
    """Raised when file decryption fails."""

    def __init__(self, filepath: str, reason: str = "Unknown error"):
        self.filepath = filepath
        self.reason = reason
        super().__init__(f"Failed to decrypt '{filepath}': {reason}")


class FileAccessError(PyEncryptError):
    """Raised when a file cannot be accessed."""

    def __init__(self, filepath: str, operation: str = "access"):
        self.filepath = filepath
        self.operation = operation
        super().__init__(f"Cannot {operation} file: {filepath}")


class InvalidKeyError(PyEncryptError):
    """Raised when the provided key is invalid."""

    def __init__(self, reason: str = "Key is malformed or corrupted"):
        self.reason = reason
        super().__init__(f"Invalid encryption key: {reason}")
