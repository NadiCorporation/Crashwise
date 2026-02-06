"""Tests for secure storage module."""

import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from fuzzforge_cli.secure_storage import SecureStorage, SecureStorageError, get_storage


class TestSecureStorage:
    """Test secure storage functionality."""

    @pytest.fixture
    def temp_storage(self):
        """Create a temporary storage instance with file backend."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = SecureStorage()
            # Force file backend for testing
            storage._backend = "file"
            storage._fallback_path = Path(tmpdir) / "test_oauth"
            yield storage

    def test_file_storage_store_and_retrieve(self, temp_storage):
        """Test storing and retrieving tokens from file."""
        # Store token
        temp_storage.store_token("test_account", "secret_token_123")

        # Retrieve token
        retrieved = temp_storage.retrieve_token("test_account")
        assert retrieved == "secret_token_123"

    def test_file_storage_permissions(self, temp_storage):
        """Test that file has 600 permissions."""
        temp_storage.store_token("test_account", "secret_token")

        # Check permissions
        mode = temp_storage._fallback_path.stat().st_mode
        # Should be owner read/write only (600)
        assert mode & stat.S_IRWXU == stat.S_IRUSR | stat.S_IWUSR
        assert not (mode & stat.S_IRWXG)  # No group permissions
        assert not (mode & stat.S_IRWXO)  # No other permissions

    def test_file_storage_multiple_accounts(self, temp_storage):
        """Test storing multiple accounts."""
        temp_storage.store_token("account1", "token1")
        temp_storage.store_token("account2", "token2")

        assert temp_storage.retrieve_token("account1") == "token1"
        assert temp_storage.retrieve_token("account2") == "token2"

    def test_file_storage_update_existing(self, temp_storage):
        """Test updating an existing token."""
        temp_storage.store_token("account", "old_token")
        temp_storage.store_token("account", "new_token")

        assert temp_storage.retrieve_token("account") == "new_token"

    def test_file_storage_delete(self, temp_storage):
        """Test deleting a token."""
        temp_storage.store_token("account", "token")
        assert temp_storage.delete_token("account") is True
        assert temp_storage.retrieve_token("account") is None

    def test_file_storage_delete_nonexistent(self, temp_storage):
        """Test deleting a non-existent token."""
        assert temp_storage.delete_token("nonexistent") is False

    def test_retrieve_nonexistent(self, temp_storage):
        """Test retrieving a non-existent token."""
        assert temp_storage.retrieve_token("nonexistent") is None

    @patch("subprocess.run")
    def test_keychain_storage_macos(self, mock_run):
        """Test macOS keychain storage."""
        mock_run.return_value = Mock(returncode=0, stderr="")

        storage = SecureStorage()
        storage._backend = "keychain"

        storage.store_token("test", "secret")

        # Should call security add-generic-password
        mock_run.assert_called()
        args = mock_run.call_args[0][0]
        assert "security" in args
        assert "add-generic-password" in args

    @patch("subprocess.run")
    def test_keychain_retrieval_macos(self, mock_run):
        """Test macOS keychain retrieval."""
        mock_run.return_value = Mock(returncode=0, stdout="secret_token\n")

        storage = SecureStorage()
        storage._backend = "keychain"

        token = storage.retrieve_token("test")
        assert token == "secret_token"

    def test_storage_info_file_backend(self, temp_storage):
        """Test getting storage info for file backend."""
        info = temp_storage.get_storage_info()

        assert info["backend"] == "file"
        assert info["secure"] is False
        assert info["fallback_path"] is not None

    def test_get_storage_singleton(self):
        """Test that get_storage returns singleton."""
        storage1 = get_storage()
        storage2 = get_storage()
        assert storage1 is storage2

    def test_invalid_json_file(self, temp_storage):
        """Test handling of corrupted JSON file."""
        # Write invalid JSON
        temp_storage._fallback_path.write_text("invalid json")

        # Should return None, not raise
        assert temp_storage.retrieve_token("account") is None

    def test_storage_error_on_failure(self, temp_storage):
        """Test that SecureStorageError is raised on storage failure."""
        # Make directory read-only
        temp_storage._fallback_path.parent.chmod(0o444)

        try:
            with pytest.raises(SecureStorageError):
                temp_storage.store_token("account", "token")
        finally:
            # Restore permissions for cleanup
            temp_storage._fallback_path.parent.chmod(0o755)


class TestSecureStoragePlatformDetection:
    """Test platform-specific backend detection."""

    @patch("os.uname")
    def test_detect_macos(self, mock_uname):
        """Test macOS detection."""
        mock_uname.return_value = Mock(sysname="Darwin")

        storage = SecureStorage()
        # Mock the security command check
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            backend = storage._detect_backend()
            assert backend == "keychain"

    @patch("os.uname")
    def test_detect_linux(self, mock_uname):
        """Test Linux detection with secretstorage."""
        mock_uname.return_value = Mock(sysname="Linux")

        storage = SecureStorage()
        with patch.dict("sys.modules", {"secretstorage": Mock()}):
            backend = storage._detect_backend()
            assert backend == "secret_service"

    @patch("os.uname")
    def test_detect_linux_fallback(self, mock_uname):
        """Test Linux fallback to file when secretstorage unavailable."""
        mock_uname.return_value = Mock(sysname="Linux")

        storage = SecureStorage()
        with patch.dict("sys.modules", {}, clear=True):
            backend = storage._detect_backend()
            assert backend == "file"

    @patch("os.name", "nt")
    def test_detect_windows(self):
        """Test Windows detection."""
        storage = SecureStorage()
        with patch.dict("sys.modules", {"win32cred": Mock()}):
            backend = storage._detect_backend()
            assert backend == "windows_credential"

    def test_detect_windows_fallback(self):
        """Test Windows fallback to file."""
        storage = SecureStorage()
        with patch.dict("sys.modules", {}, clear=True):
            backend = storage._detect_backend()
            assert backend == "file"


class TestSecureStorageSecurity:
    """Test security aspects of secure storage."""

    def test_token_never_logged(self, temp_storage, caplog):
        """Verify tokens are not logged."""
        import logging

        with caplog.at_level(logging.DEBUG):
            temp_storage.store_token("account", "secret_token_value")

        # Token should not appear in logs
        assert "secret_token_value" not in caplog.text

    def test_file_not_world_readable(self, temp_storage):
        """Ensure file is not world-readable."""
        temp_storage.store_token("account", "secret")

        mode = temp_storage._fallback_path.stat().st_mode

        # No permissions for group or others
        assert not (mode & stat.S_IRGRP)
        assert not (mode & stat.S_IWGRP)
        assert not (mode & stat.S_IXGRP)
        assert not (mode & stat.S_IROTH)
        assert not (mode & stat.S_IWOTH)
        assert not (mode & stat.S_IXOTH)
