"""
Enhanced exception handling for FuzzForge CLI.

This module provides:
1. CLI-specific exceptions (ProjectNotFoundError, DatabaseError, etc.)
2. Re-exports from fuzzforge_sdk.exceptions for convenience
3. Backward compatibility aliases

Migration Path:
- New code should import from fuzzforge_sdk.exceptions directly
- CLI-specific exceptions remain in this module
- All SDK exceptions are re-exported here for backward compatibility
"""
# Copyright (c) 2025 FuzzingLabs
#
# Licensed under the Business Source License 1.1 (BSL). See the LICENSE file
# at the root of this repository for details.
#
# After the Change Date (four years from publication), this version of the
# Licensed Work will be made available under the Apache License, Version 2.0.
# See the LICENSE-APACHE file or http://www.apache.org/licenses/LICENSE-2.0
#
# Additional attribution and requirements are provided in the NOTICE file.

import time
import functools
import warnings
from typing import Any, Callable, Optional, Union, List
from pathlib import Path

import typer
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

# =============================================================================
# Re-export SDK exceptions for backward compatibility
# =============================================================================
# These are the single source of truth from fuzzforge_sdk.exceptions
from fuzzforge_sdk.exceptions import (
    ErrorContext,
    FuzzForgeError as _SDKFuzzForgeError,
    FuzzForgeHTTPError,
    DeploymentError,
    WorkflowExecutionError,
    WorkflowNotFoundError,
    RunNotFoundError,
    ContainerError,
    VolumeError,
    ResourceLimitError,
    ValidationError as _SDKValidationError,
    ConnectionError as SDKConnectionError,
    TimeoutError as SDKTimeoutError,
    WebSocketError,
    SSEError,
)

# Re-export all SDK exceptions for backward compatibility
__all__ = [
    # SDK exceptions (re-exported)
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
    # CLI-specific exceptions
    "ProjectNotFoundError",
    "APIConnectionError",
    "DatabaseError",
    "FileOperationError",
    # Utilities
    "handle_errors",
    "require_project",
    "show_error",
]

console = Console()


# =============================================================================
# Backward Compatibility: CLI FuzzForgeError
# =============================================================================
# Maintains compatibility with existing CLI code while delegating to SDK base


class FuzzForgeError(_SDKFuzzForgeError):
    """Base exception for FuzzForge CLI errors.

    This class extends SDK FuzzForgeError to maintain backward compatibility
    with existing CLI code that expects 'hint' and 'exit_code' attributes.

    New code should use fuzzforge_sdk.exceptions.FuzzForgeError directly.

    Attributes:
        message: Error message
        hint: Optional hint for fixing the error
        exit_code: Exit code to use when exiting
        context: Rich error context from SDK
    """

    def __init__(
        self,
        message: str,
        hint: Optional[str] = None,
        exit_code: int = 1,
        context: Optional[ErrorContext] = None,
        original_exception: Optional[Exception] = None,
    ):
        # Call SDK base class
        super().__init__(
            message=message,
            context=context or ErrorContext(),
            original_exception=original_exception,
        )

        # CLI-specific attributes for backward compatibility
        self.hint = hint
        self.exit_code = exit_code

    def __str__(self) -> str:
        """Return string representation with hint if available."""
        if self.hint:
            return f"{self.message}\nHint: {self.hint}"
        return self.message


# =============================================================================
# Backward Compatibility: CLI ValidationError
# =============================================================================


class ValidationError(_SDKValidationError):
    """Validation error with CLI-specific formatting.

    Extends SDK ValidationError to maintain backward compatibility.
    New code should use fuzzforge_sdk.exceptions.ValidationError.
    """

    def __init__(
        self,
        field: str,
        value: Any,
        expected: str,
        context: Optional[ErrorContext] = None,
    ):
        self.field = field
        self.value = value
        self.expected = expected

        message = f"Invalid {field}: {value}"
        hint = f"Expected: {expected}"

        # Initialize SDK base
        super().__init__(
            message=message,
            field=field,
            value=str(value),
            expected=expected,
            context=context or ErrorContext(suggested_fixes=[hint]),
        )

        # Maintain backward compatibility
        self.hint = hint


# =============================================================================
# CLI-Specific Exceptions
# =============================================================================
# These are specific to CLI operations and don't belong in SDK


class ProjectNotFoundError(FuzzForgeError):
    """Raised when no FuzzForge project is found in current directory."""

    def __init__(self):
        super().__init__(
            message="No FuzzForge project found in current directory",
            hint="Run 'ff init' to initialize a new project",
            exit_code=1,
        )


class APIConnectionError(FuzzForgeError):
    """Raised when connection to FuzzForge API fails."""

    def __init__(self, url: str, original_error: Exception):
        self.url = url
        self.original_error = original_error

        if isinstance(original_error, httpx.ConnectTimeout):
            message = f"Connection timeout to FuzzForge API at {url}"
            hint = "Check if the API server is running and the URL is correct"
        elif isinstance(original_error, httpx.ConnectError):
            message = f"Failed to connect to FuzzForge API at {url}"
            hint = "Verify the API URL is correct and the server is accessible"
        elif isinstance(original_error, httpx.TimeoutException):
            message = f"Request timeout to FuzzForge API at {url}"
            hint = "The API server may be overloaded. Try again later"
        else:
            message = f"API connection error: {str(original_error)}"
            hint = "Check your network connection and API configuration"

        super().__init__(
            message=message, hint=hint, exit_code=1, original_exception=original_error
        )


class DatabaseError(FuzzForgeError):
    """Raised when database operations fail."""

    def __init__(self, operation: str, original_error: Exception):
        self.operation = operation
        self.original_error = original_error

        message = f"Database error during {operation}: {str(original_error)}"
        hint = "The database may be corrupted. Try 'ff init --force' to reset"

        super().__init__(
            message=message, hint=hint, exit_code=1, original_exception=original_error
        )


class FileOperationError(FuzzForgeError):
    """Raised when file operations fail."""

    def __init__(self, operation: str, path: Path, original_error: Exception):
        self.operation = operation
        self.path = path
        self.original_error = original_error

        message = (
            f"File operation '{operation}' failed for {path}: {str(original_error)}"
        )
        hint = f"Check permissions and that the path exists: {path}"

        super().__init__(
            message=message, hint=hint, exit_code=1, original_exception=original_error
        )


# =============================================================================
# Error Handling Utilities
# =============================================================================


def show_error(error: Exception, verbose: bool = False):
    """Display an error with rich formatting.

    Args:
        error: The exception to display
        verbose: Whether to show detailed context
    """
    if isinstance(error, _SDKFuzzForgeError):
        # SDK exception with rich context
        console.print(
            Panel(
                f"[bold red]Error:[/bold red] {error.message}",
                title=error.__class__.__name__,
                border_style="red",
            )
        )

        if error.context and error.context.suggested_fixes:
            console.print("\n[bold yellow]Suggested fixes:[/bold yellow]")
            for fix in error.context.suggested_fixes:
                console.print(f"  • {fix}")

        if verbose and error.context:
            console.print("\n[dim]Detailed context:[/dim]")
            console.print(error.get_detailed_info())

    elif isinstance(error, FuzzForgeError):
        # CLI exception with hint
        console.print(
            Panel(
                f"[bold red]{error.message}[/bold red]",
                title=error.__class__.__name__,
                border_style="red",
            )
        )

        if error.hint:
            console.print(f"\n[bold yellow]Hint:[/bold yellow] {error.hint}")
    else:
        # Generic exception
        console.print(
            Panel(
                f"[bold red]{str(error)}[/bold red]",
                title=error.__class__.__name__,
                border_style="red",
            )
        )


def handle_errors(func: Callable) -> Callable:
    """Decorator to handle and display errors consistently.

    Usage:
        @handle_errors
        def my_command():
            raise FuzzForgeError("Something went wrong")
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except FuzzForgeError as e:
            show_error(e)
            raise typer.Exit(e.exit_code)
        except _SDKFuzzForgeError as e:
            show_error(e)
            raise typer.Exit(1)
        except Exception as e:
            console.print(f"[bold red]Unexpected error:[/bold red] {e}")
            raise typer.Exit(1)

    return wrapper


def require_project():
    """Ensure we're in a FuzzForge project directory.

    Raises:
        ProjectNotFoundError: If no project found
    """
    from .config import get_project_config

    config = get_project_config()
    if config is None:
        raise ProjectNotFoundError()
    return config
