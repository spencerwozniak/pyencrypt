"""Tests for the FileEncryptor class."""

import tempfile
from pathlib import Path

import pytest

from pyencypt.core.encryptor import FileEncryptor
from pyencypt.core.key_manager import KeyManager
from pyencypt.exceptions import DecryptionError, FileAccessError, KeyNotFoundError


class TestKeyManager:
    """Tests for KeyManager class."""

    def test_generate_key(self):
        """Test key generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            km = KeyManager(key_dir=tmpdir)
            key = km.generate_key()
            assert key is not None
            assert len(key) == 44  # Fernet keys are 44 bytes base64 encoded

    def test_save_and_load_key(self):
        """Test saving and loading a key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            km = KeyManager(key_dir=tmpdir)
            original_key = km.generate_key()
            km.save_key(original_key)

            km.clear_cache()
            loaded_key = km.load_key()
            assert loaded_key == original_key

    def test_load_nonexistent_key_raises(self):
        """Test that loading a non-existent key raises KeyNotFoundError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            km = KeyManager(key_dir=tmpdir)
            with pytest.raises(KeyNotFoundError):
                km.load_key()

    def test_key_exists(self):
        """Test key existence check."""
        with tempfile.TemporaryDirectory() as tmpdir:
            km = KeyManager(key_dir=tmpdir)
            assert not km.key_exists()

            km.generate_and_save()
            assert km.key_exists()

    def test_delete_key(self):
        """Test key deletion."""
        with tempfile.TemporaryDirectory() as tmpdir:
            km = KeyManager(key_dir=tmpdir)
            km.generate_and_save()
            assert km.key_exists()

            km.delete_key()
            assert not km.key_exists()


class TestFileEncryptor:
    """Tests for FileEncryptor class."""

    def test_encrypt_and_decrypt_file(self):
        """Test encrypting and decrypting a single file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            km = KeyManager(key_dir=tmpdir)
            encryptor = FileEncryptor(key_manager=km)

            test_file = Path(tmpdir) / "test.txt"
            original_content = b"Hello, World!"
            test_file.write_bytes(original_content)

            km.generate_and_save()

            encryptor.encrypt_file(test_file)
            encrypted_content = test_file.read_bytes()
            assert encrypted_content != original_content

            encryptor.decrypt_file(test_file)
            decrypted_content = test_file.read_bytes()
            assert decrypted_content == original_content

    def test_encrypt_directory(self):
        """Test encrypting all files in a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            km = KeyManager(key_dir=tmpdir)
            encryptor = FileEncryptor(key_manager=km)

            file1 = Path(tmpdir) / "file1.txt"
            file2 = Path(tmpdir) / "file2.txt"
            file1.write_bytes(b"Content 1")
            file2.write_bytes(b"Content 2")

            result = encryptor.encrypt_directory(tmpdir)

            assert result.total_processed == 2
            assert result.total_failed == 0

    def test_decrypt_with_wrong_key_fails(self):
        """Test that decryption fails with wrong key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            km = KeyManager(key_dir=tmpdir)
            encryptor = FileEncryptor(key_manager=km)

            test_file = Path(tmpdir) / "test.txt"
            test_file.write_bytes(b"Secret data")

            km.generate_and_save()
            encryptor.encrypt_file(test_file)

            km.generate_and_save()
            encryptor._fernet = None

            with pytest.raises(DecryptionError):
                encryptor.decrypt_file(test_file)

    def test_exclusion_patterns(self):
        """Test that excluded files are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            km = KeyManager(key_dir=tmpdir)
            encryptor = FileEncryptor(key_manager=km)
            encryptor.add_exclusion("skip_me.txt")

            regular_file = Path(tmpdir) / "regular.txt"
            skip_file = Path(tmpdir) / "skip_me.txt"
            regular_file.write_bytes(b"Encrypt me")
            skip_file.write_bytes(b"Skip me")

            result = encryptor.encrypt_directory(tmpdir)

            assert result.total_processed == 1
            assert result.total_skipped >= 1

    def test_is_locked_property(self):
        """Test the is_locked property."""
        with tempfile.TemporaryDirectory() as tmpdir:
            km = KeyManager(key_dir=tmpdir)
            encryptor = FileEncryptor(key_manager=km)

            assert not encryptor.is_locked

            km.generate_and_save()
            assert encryptor.is_locked

    def test_encrypt_nonexistent_file_raises(self):
        """Test that encrypting a non-existent file raises an error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            km = KeyManager(key_dir=tmpdir)
            km.generate_and_save()
            encryptor = FileEncryptor(key_manager=km)

            with pytest.raises(FileAccessError):
                encryptor.encrypt_file(Path(tmpdir) / "nonexistent.txt")
