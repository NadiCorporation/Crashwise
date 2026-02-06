"""Secure cross-platform credential storage for FuzzForge.

Supports:
- macOS: Keychain (Security framework)
- Linux: Secret Service API (libsecret) or file-based fallback
- Windows: Windows Credential Manager
- Fallback: ~/.config/fuzzforge/oauth with chmod 600
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Optional


class SecureStorageError(Exception):
    """Raised when secure storage operations fail."""

    pass


class SecureStorage:
    """Cross-platform secure credential storage."""

    SERVICE_NAME = "fuzzforge"

    def __init__(self):
        self._backend = self._detect_backend()
        self._fallback_path = self._get_fallback_path()

    def _detect_backend(self) -> str:
        """Detect the best available secure storage backend."""
        system = os.uname().sysname if hasattr(os, "uname") else os.name

        if system == "Darwin":
            try:
                # Test if security command works
                import subprocess

                result = subprocess.run(
                    ["security", "dump-keychain"], capture_output=True, timeout=5
                )
                if result.returncode in [0, 1]:  # 1 is OK (empty keychain)
                    return "keychain"
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        elif system == "Linux":
            # Check for secretstorage/DBus
            try:
                import secretstorage

                return "secret_service"
            except ImportError:
                pass

        elif system == "Windows" or os.name == "nt":
            try:
                import win32cred

                return "windows_credential"
            except ImportError:
                pass

        # Fallback to file-based storage
        return "file"

    def _get_fallback_path(self) -> Path:
        """Get the path for file-based fallback storage."""
        config_dir = Path.home() / ".config" / "fuzzforge"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / "oauth"

    def _ensure_secure_permissions(self, path: Path) -> None:
        """Ensure file has 600 permissions (owner read/write only)."""
        if os.name == "posix":
            # Set owner read/write only
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def store_token(self, account: str, token: str) -> None:
        """Store a token securely.

        Args:
            account: Unique identifier for this token (e.g., 'openai_codex')
            token: The token to store

        Raises:
            SecureStorageError: If storage fails
        """
        if self._backend == "keychain":
            self._store_keychain(account, token)
        elif self._backend == "secret_service":
            self._store_secret_service(account, token)
        elif self._backend == "windows_credential":
            self._store_windows(account, token)
        else:
            self._store_file(account, token)

    def retrieve_token(self, account: str) -> Optional[str]:
        """Retrieve a stored token.

        Args:
            account: Unique identifier for this token

        Returns:
            The token if found, None otherwise

        Raises:
            SecureStorageError: If retrieval fails
        """
        if self._backend == "keychain":
            return self._retrieve_keychain(account)
        elif self._backend == "secret_service":
            return self._retrieve_secret_service(account)
        elif self._backend == "windows_credential":
            return self._retrieve_windows(account)
        else:
            return self._retrieve_file(account)

    def delete_token(self, account: str) -> bool:
        """Delete a stored token.

        Args:
            account: Unique identifier for this token

        Returns:
            True if deleted, False if not found
        """
        try:
            if self._backend == "keychain":
                return self._delete_keychain(account)
            elif self._backend == "secret_service":
                return self._delete_secret_service(account)
            elif self._backend == "windows_credential":
                return self._delete_windows(account)
            else:
                return self._delete_file(account)
        except Exception:
            return False

    def _store_keychain(self, account: str, token: str) -> None:
        """Store token in macOS Keychain."""
        import subprocess

        # Delete existing entry first
        subprocess.run(
            [
                "security",
                "delete-generic-password",
                "-s",
                self.SERVICE_NAME,
                "-a",
                account,
            ],
            capture_output=True,
        )

        # Add new entry
        result = subprocess.run(
            [
                "security",
                "add-generic-password",
                "-s",
                self.SERVICE_NAME,
                "-a",
                account,
                "-w",
                token,
                "-U",
            ],  # Update if exists
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise SecureStorageError(f"Keychain storage failed: {result.stderr}")

    def _retrieve_keychain(self, account: str) -> Optional[str]:
        """Retrieve token from macOS Keychain."""
        import subprocess

        result = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-s",
                self.SERVICE_NAME,
                "-a",
                account,
                "-w",
            ],  # Output password only
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            return result.stdout.strip()
        return None

    def _delete_keychain(self, account: str) -> bool:
        """Delete token from macOS Keychain."""
        import subprocess

        result = subprocess.run(
            [
                "security",
                "delete-generic-password",
                "-s",
                self.SERVICE_NAME,
                "-a",
                account,
            ],
            capture_output=True,
        )
        return result.returncode == 0

    def _store_secret_service(self, account: str, token: str) -> None:
        """Store token using Linux Secret Service API."""
        try:
            import secretstorage

            connection = secretstorage.dbus_init()
            collection = secretstorage.get_default_collection(connection)

            attributes = {"service": self.SERVICE_NAME, "account": account}

            # Delete existing
            for item in collection.search_items(attributes):
                item.delete()

            # Create new
            collection.create_item(
                f"FuzzForge: {account}", attributes, token, replace=True
            )
        except Exception as e:
            raise SecureStorageError(f"Secret Service storage failed: {e}")

    def _retrieve_secret_service(self, account: str) -> Optional[str]:
        """Retrieve token from Linux Secret Service."""
        try:
            import secretstorage

            connection = secretstorage.dbus_init()
            collection = secretstorage.get_default_collection(connection)

            attributes = {"service": self.SERVICE_NAME, "account": account}

            items = list(collection.search_items(attributes))
            if items:
                return items[0].get_secret().decode("utf-8")
            return None
        except Exception:
            return None

    def _delete_secret_service(self, account: str) -> bool:
        """Delete token from Linux Secret Service."""
        try:
            import secretstorage

            connection = secretstorage.dbus_init()
            collection = secretstorage.get_default_collection(connection)

            attributes = {"service": self.SERVICE_NAME, "account": account}

            items = list(collection.search_items(attributes))
            for item in items:
                item.delete()
            return len(items) > 0
        except Exception:
            return False

    def _store_windows(self, account: str, token: str) -> None:
        """Store token in Windows Credential Manager."""
        try:
            import win32cred

            target = f"{self.SERVICE_NAME}/{account}"
            credential = {
                "Type": win32cred.CRED_TYPE_GENERIC,
                "TargetName": target,
                "UserName": account,
                "CredentialBlob": token,
                "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
            }

            win32cred.CredWrite(credential, 0)
        except Exception as e:
            raise SecureStorageError(f"Windows credential storage failed: {e}")

    def _retrieve_windows(self, account: str) -> Optional[str]:
        """Retrieve token from Windows Credential Manager."""
        try:
            import win32cred

            target = f"{self.SERVICE_NAME}/{account}"
            cred = win32cred.CredRead(target, win32cred.CRED_TYPE_GENERIC, 0)
            return cred["CredentialBlob"]
        except Exception:
            return None

    def _delete_windows(self, account: str) -> bool:
        """Delete token from Windows Credential Manager."""
        try:
            import win32cred

            target = f"{self.SERVICE_NAME}/{account}"
            win32cred.CredDelete(target, win32cred.CRED_TYPE_GENERIC, 0)
            return True
        except Exception:
            return False

    def _store_file(self, account: str, token: str) -> None:
        """Store token in file with 600 permissions (fallback)."""
        try:
            import json

            data = {}
            if self._fallback_path.exists():
                with open(self._fallback_path, "r") as f:
                    data = json.load(f)

            data[account] = token

            # Write to temp file first, then move (atomic)
            temp_path = self._fallback_path.with_suffix(".tmp")
            with open(temp_path, "w") as f:
                json.dump(data, f)

            self._ensure_secure_permissions(temp_path)
            temp_path.rename(self._fallback_path)

        except Exception as e:
            raise SecureStorageError(f"File storage failed: {e}")

    def _retrieve_file(self, account: str) -> Optional[str]:
        """Retrieve token from file."""
        try:
            import json

            if not self._fallback_path.exists():
                return None

            with open(self._fallback_path, "r") as f:
                data = json.load(f)

            return data.get(account)
        except Exception:
            return None

    def _delete_file(self, account: str) -> bool:
        """Delete token from file."""
        try:
            import json

            if not self._fallback_path.exists():
                return False

            with open(self._fallback_path, "r") as f:
                data = json.load(f)

            if account in data:
                del data[account]

                with open(self._fallback_path, "w") as f:
                    json.dump(data, f)
                return True
            return False
        except Exception:
            return False

    def get_storage_info(self) -> dict:
        """Get information about the storage backend."""
        return {
            "backend": self._backend,
            "fallback_path": str(self._fallback_path)
            if self._backend == "file"
            else None,
            "secure": self._backend != "file",
        }


# Global instance
_storage = None


def get_storage() -> SecureStorage:
    """Get the global secure storage instance."""
    global _storage
    if _storage is None:
        _storage = SecureStorage()
    return _storage
