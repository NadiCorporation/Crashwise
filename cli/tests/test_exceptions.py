"""Tests for exception consolidation and backward compatibility."""

import pytest
from unittest.mock import Mock, patch
import httpx


class TestBackwardCompatibility:
    """Test that existing code continues to work after consolidation."""

    def test_cli_fuzzforge_error_inherits_sdk(self):
        """Test CLI FuzzForgeError inherits from SDK version."""
        from fuzzforge_cli.exceptions import FuzzForgeError
        from fuzzforge_sdk.exceptions import FuzzForgeError as SDKFuzzForgeError

        error = FuzzForgeError("test message", hint="test hint", exit_code=2)

        # Should be instance of SDK base
        assert isinstance(error, SDKFuzzForgeError)

        # Should have CLI-specific attributes
        assert error.hint == "test hint"
        assert error.exit_code == 2
        assert error.message == "test message"

    def test_cli_validation_error_inherits_sdk(self):
        """Test CLI ValidationError inherits from SDK version."""
        from fuzzforge_cli.exceptions import ValidationError
        from fuzzforge_sdk.exceptions import ValidationError as SDKValidationError

        error = ValidationError("field_name", "bad_value", "string")

        # Should be instance of SDK base
        assert isinstance(error, SDKValidationError)

        # Should have both CLI and SDK attributes
        assert error.field == "field_name"
        assert error.value == "bad_value"
        assert error.expected == "string"
        assert error.hint is not None

    def test_sdk_exceptions_reexported(self):
        """Test that all SDK exceptions are re-exported."""
        from fuzzforge_cli import exceptions as cli_exceptions
        from fuzzforge_sdk import exceptions as sdk_exceptions

        # Core exceptions that should be re-exported
        sdk_classes = [
            "ErrorContext",
            "FuzzForgeError",
            "FuzzForgeHTTPError",
            "DeploymentError",
            "WorkflowExecutionError",
            "WorkflowNotFoundError",
            "RunNotFoundError",
            "ContainerError",
            "VolumeError",
            "ResourceLimitError",
            "ValidationError",
            "SDKConnectionError",
            "SDKTimeoutError",
            "WebSocketError",
            "SSEError",
        ]

        for cls_name in sdk_classes:
            assert hasattr(cli_exceptions, cls_name), f"{cls_name} not re-exported"

    def test_cli_specific_exceptions_exist(self):
        """Test that CLI-specific exceptions are preserved."""
        from fuzzforge_cli import exceptions as cli_exceptions

        cli_classes = [
            "ProjectNotFoundError",
            "APIConnectionError",
            "DatabaseError",
            "FileOperationError",
        ]

        for cls_name in cli_classes:
            assert hasattr(cli_exceptions, cls_name), f"{cls_name} not found"


class TestProjectNotFoundError:
    """Test ProjectNotFoundError exception."""

    def test_default_message(self):
        """Test default error message."""
        from fuzzforge_cli.exceptions import ProjectNotFoundError

        error = ProjectNotFoundError()

        assert "No FuzzForge project found" in error.message
        assert "ff init" in error.hint
        assert error.exit_code == 1


class TestAPIConnectionError:
    """Test APIConnectionError exception."""

    def test_timeout_error(self):
        """Test timeout error handling."""
        from fuzzforge_cli.exceptions import APIConnectionError

        original = httpx.ConnectTimeout("Connection timed out")
        error = APIConnectionError("http://localhost:8000", original)

        assert "timeout" in error.message.lower()
        assert "localhost:8000" in error.message
        assert error.hint is not None
        assert error.original_error is original

    def test_connection_error(self):
        """Test connection error handling."""
        from fuzzforge_cli.exceptions import APIConnectionError

        original = httpx.ConnectError("Connection refused")
        error = APIConnectionError("http://api.example.com", original)

        assert "Failed to connect" in error.message
        assert "api.example.com" in error.message

    def test_generic_error(self):
        """Test generic error handling."""
        from fuzzforge_cli.exceptions import APIConnectionError

        original = Exception("Something went wrong")
        error = APIConnectionError("http://test.com", original)

        assert "API connection error" in error.message


class TestDatabaseError:
    """Test DatabaseError exception."""

    def test_error_message(self):
        """Test error message formatting."""
        from fuzzforge_cli.exceptions import DatabaseError

        original = Exception("SQLite error: no such table")
        error = DatabaseError("query", original)

        assert "Database error during query" in error.message
        assert "SQLite error" in error.message
        assert "init --force" in error.hint


class TestFileOperationError:
    """Test FileOperationError exception."""

    def test_error_message(self):
        """Test error message formatting."""
        from fuzzforge_cli.exceptions import FileOperationError
        from pathlib import Path

        original = PermissionError("Permission denied")
        path = Path("/test/path")
        error = FileOperationError("read", path, original)

        assert "File operation 'read' failed" in error.message
        assert "/test/path" in error.message
        assert "permissions" in error.hint.lower()


class TestErrorDisplay:
    """Test error display utilities."""

    @patch("fuzzforge_cli.exceptions.console")
    def test_show_sdk_error(self, mock_console):
        """Test displaying SDK error."""
        from fuzzforge_cli.exceptions import show_error
        from fuzzforge_sdk.exceptions import FuzzForgeError, ErrorContext

        context = ErrorContext(suggested_fixes=["Check the URL", "Verify API key"])
        error = FuzzForgeError("Test error", context=context)

        show_error(error)

        mock_console.print.assert_called()
        # Should show error panel
        calls = mock_console.print.call_args_list
        assert any("Error:" in str(call) for call in calls)

    @patch("fuzzforge_cli.exceptions.console")
    def test_show_cli_error(self, mock_console):
        """Test displaying CLI error."""
        from fuzzforge_cli.exceptions import show_error, FuzzForgeError

        error = FuzzForgeError("Test message", hint="Test hint")

        show_error(error)

        mock_console.print.assert_called()

    @patch("fuzzforge_cli.exceptions.console")
    def test_show_generic_error(self, mock_console):
        """Test displaying generic exception."""
        from fuzzforge_cli.exceptions import show_error

        error = ValueError("Generic error")

        show_error(error)

        mock_console.print.assert_called()


class TestErrorDecorator:
    """Test error handling decorator."""

    @patch("fuzzforge_cli.exceptions.show_error")
    @patch("fuzzforge_cli.exceptions.typer.Exit")
    def test_handle_cli_error(self, mock_exit, mock_show):
        """Test decorator handles CLI errors."""
        from fuzzforge_cli.exceptions import handle_errors, FuzzForgeError

        @handle_errors
        def failing_function():
            raise FuzzForgeError("Test", exit_code=2)

        with pytest.raises(SystemExit):
            failing_function()

        mock_show.assert_called_once()

    @patch("fuzzforge_cli.exceptions.show_error")
    @patch("fuzzforge_cli.exceptions.typer.Exit")
    def test_handle_sdk_error(self, mock_exit, mock_show):
        """Test decorator handles SDK errors."""
        from fuzzforge_cli.exceptions import handle_errors
        from fuzzforge_sdk.exceptions import FuzzForgeError

        @handle_errors
        def failing_function():
            raise FuzzForgeError("Test")

        with pytest.raises(SystemExit):
            failing_function()

        mock_show.assert_called_once()

    @patch("fuzzforge_cli.exceptions.console")
    @patch("fuzzforge_cli.exceptions.typer.Exit")
    def test_handle_generic_error(self, mock_exit, mock_console):
        """Test decorator handles generic errors."""
        from fuzzforge_cli.exceptions import handle_errors

        @handle_errors
        def failing_function():
            raise ValueError("Generic error")

        with pytest.raises(SystemExit):
            failing_function()

        mock_console.print.assert_called()


class TestRequireProject:
    """Test require_project utility."""

    @patch("fuzzforge_cli.exceptions.get_project_config")
    def test_project_found(self, mock_get_config):
        """Test when project is found."""
        from fuzzforge_cli.exceptions import require_project

        mock_config = Mock()
        mock_get_config.return_value = mock_config

        result = require_project()

        assert result is mock_config

    @patch("fuzzforge_cli.exceptions.get_project_config")
    def test_project_not_found(self, mock_get_config):
        """Test when project is not found."""
        from fuzzforge_cli.exceptions import require_project, ProjectNotFoundError

        mock_get_config.return_value = None

        with pytest.raises(ProjectNotFoundError):
            require_project()


class TestExceptionInheritance:
    """Test exception inheritance chains."""

    def test_all_cli_errors_inherit_base(self):
        """Test all CLI errors inherit from CLI FuzzForgeError."""
        from fuzzforge_cli.exceptions import (
            FuzzForgeError,
            ProjectNotFoundError,
            APIConnectionError,
            DatabaseError,
            FileOperationError,
            ValidationError,
        )

        errors = [
            ProjectNotFoundError(),
            APIConnectionError("url", Exception()),
            DatabaseError("op", Exception()),
            FileOperationError("op", __file__, Exception()),
            ValidationError("field", "value", "type"),
        ]

        for error in errors:
            assert isinstance(error, FuzzForgeError), (
                f"{type(error).__name__} doesn't inherit from FuzzForgeError"
            )

    def test_cli_base_inherits_sdk_base(self):
        """Test CLI FuzzForgeError inherits from SDK FuzzForgeError."""
        from fuzzforge_cli.exceptions import FuzzForgeError as CLIFuzzForgeError
        from fuzzforge_sdk.exceptions import FuzzForgeError as SDKFuzzForgeError

        error = CLIFuzzForgeError("test")

        assert isinstance(error, SDKFuzzForgeError)
        assert isinstance(error, Exception)
