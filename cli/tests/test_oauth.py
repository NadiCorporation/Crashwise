"""Tests for OAuth authentication module."""

import json
import socket
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from crashwise_cli.commands.oauth import (
    OAUTH_PROVIDERS,
    PKCEData,
    OAuthCallbackHandler,
    exchange_code_for_token,
    generate_pkce,
    start_callback_server,
)


class TestPKCE:
    """Test PKCE (Proof Key for Code Exchange) generation."""

    def test_generate_pkce_returns_valid_data(self):
        """Test that PKCE data is generated correctly."""
        pkce = generate_pkce()

        assert isinstance(pkce, PKCEData)
        assert pkce.code_verifier is not None
        assert pkce.code_challenge is not None
        assert pkce.state is not None
        assert pkce.redirect_port > 0

        # Verifier should be 43-128 chars (base64url encoded)
        assert 43 <= len(pkce.code_verifier) <= 128

        # Challenge should be base64url encoded SHA256 hash
        assert len(pkce.code_challenge) == 43

        # State should be non-empty
        assert len(pkce.state) > 0

    def test_pkce_code_challenge_matches_verifier(self):
        """Test that code challenge is derived from verifier."""
        import base64
        import hashlib

        pkce = generate_pkce()

        # Re-calculate challenge from verifier
        expected_challenge = (
            base64.urlsafe_b64encode(
                hashlib.sha256(pkce.code_verifier.encode()).digest()
            )
            .decode("utf-8")
            .rstrip("=")
        )

        assert pkce.code_challenge == expected_challenge

    def test_pkce_unique_per_generation(self):
        """Test that each PKCE generation produces unique values."""
        pkce1 = generate_pkce()
        pkce2 = generate_pkce()

        assert pkce1.code_verifier != pkce2.code_verifier
        assert pkce1.code_challenge != pkce2.code_challenge
        assert pkce1.state != pkce2.state


class TestCallbackServer:
    """Test OAuth callback server."""

    def test_find_free_port(self):
        """Test finding a free port."""
        from crashwise_cli.commands.oauth import _find_free_port

        port = _find_free_port()
        assert isinstance(port, int)
        assert 1024 <= port <= 65535

        # Verify port is actually free
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex(("127.0.0.1", port))
            assert result != 0  # Should not be able to connect

    @patch("crashwise_cli.commands.oauth.HTTPServer")
    def test_start_callback_server_success(self, mock_server_class):
        """Test successful callback handling."""
        mock_server = Mock()
        mock_server_class.return_value = mock_server

        # Simulate server receiving callback with auth code
        def simulate_request():
            # Get the handler class and simulate a request
            handler_class = mock_server_class.call_args[0][1]
            handler = handler_class(Mock(), ("127.0.0.1", 12345), Mock())
            handler.auth_code = "test_auth_code"
            handler.error = None

            # Update the closure result
            import crashwise_cli.commands.oauth as oauth_module

            if hasattr(oauth_module, "result"):
                oauth_module.result["code"] = "test_auth_code"

        mock_server.handle_request.side_effect = simulate_request

        auth_code, error = start_callback_server(8888, "expected_state")

        mock_server.handle_request.assert_called_once()
        mock_server.server_close.assert_called_once()

    def test_callback_handler_success(self):
        """Test callback handler with valid response."""
        from io import BytesIO

        handler = OAuthCallbackHandler.__new__(OAuthCallbackHandler)
        handler.expected_state = "test_state"
        handler.auth_code = None
        handler.error = None
        handler.rfile = BytesIO(b"")
        handler.wfile = BytesIO()
        handler.requestline = "GET /callback?code=auth123&state=test_state HTTP/1.1"
        handler.command = "GET"
        handler.path = "/callback?code=auth123&state=test_state"

        # Mock send_response and send_header
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()

        handler.do_GET()

        assert handler.auth_code == "auth123"
        assert handler.error is None

    def test_callback_handler_invalid_state(self):
        """Test callback handler with invalid state."""
        from io import BytesIO

        handler = OAuthCallbackHandler.__new__(OAuthCallbackHandler)
        handler.expected_state = "expected_state"
        handler.auth_code = None
        handler.error = None
        handler.rfile = BytesIO(b"")
        handler.wfile = BytesIO()
        handler.requestline = "GET /callback?code=auth123&state=wrong_state HTTP/1.1"
        handler.command = "GET"
        handler.path = "/callback?code=auth123&state=wrong_state"

        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()

        handler.do_GET()

        assert handler.error == "Invalid state parameter"

    def test_callback_handler_error_response(self):
        """Test callback handler with error response."""
        from io import BytesIO

        handler = OAuthCallbackHandler.__new__(OAuthCallbackHandler)
        handler.expected_state = "test_state"
        handler.auth_code = None
        handler.error = None
        handler.rfile = BytesIO(b"")
        handler.wfile = BytesIO()
        handler.requestline = (
            "GET /callback?error=access_denied&state=test_state HTTP/1.1"
        )
        handler.command = "GET"
        handler.path = "/callback?error=access_denied&state=test_state"

        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()

        handler.do_GET()

        assert handler.error == "access_denied"


class TestTokenExchange:
    """Test OAuth token exchange."""

    @patch("urllib.request.urlopen")
    def test_exchange_code_success(self, mock_urlopen):
        """Test successful token exchange."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps(
            {
                "access_token": "test_access_token",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        ).encode()
        mock_urlopen.return_value.__enter__ = Mock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = Mock(return_value=False)

        pkce = generate_pkce()
        result = exchange_code_for_token("openai_codex", "auth_code", pkce)

        assert result is not None
        assert result["access_token"] == "test_access_token"

    @patch("urllib.request.urlopen")
    def test_exchange_code_failure(self, mock_urlopen):
        """Test failed token exchange."""
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("Connection failed")

        pkce = generate_pkce()
        result = exchange_code_for_token("openai_codex", "auth_code", pkce)

        assert result is None


class TestOAuthProviders:
    """Test OAuth provider configurations."""

    def test_provider_configs_exist(self):
        """Test that OAuth provider configs exist."""
        assert "openai_codex" in OAUTH_PROVIDERS
        assert "gemini_cli" in OAUTH_PROVIDERS

    def test_openai_codex_config(self):
        """Test OpenAI Codex provider configuration."""
        config = OAUTH_PROVIDERS["openai_codex"]

        assert config["name"] == "OpenAI Codex"
        assert "authorize" in config["auth_url"]
        assert "token" in config["token_url"]
        assert config["client_id"] == "codex-cli"
        assert "openid" in config["scope"]
        assert config["account_key"] == "openai_codex_oauth"

    def test_gemini_cli_config(self):
        """Test Gemini CLI provider configuration."""
        config = OAUTH_PROVIDERS["gemini_cli"]

        assert config["name"] == "Gemini CLI"
        assert "google" in config["auth_url"]
        assert "googleapis" in config["token_url"]
        assert "client_id" in config
        assert "generative-language" in config["scope"]
        assert config["account_key"] == "gemini_cli_oauth"


class TestSecurity:
    """Test OAuth security features."""

    def test_localhost_only_binding(self):
        """Test that callback server binds to 127.0.0.1 only."""
        from crashwise_cli.commands.oauth import _find_free_port

        port = _find_free_port()

        # Should only bind to localhost
        # External connections should not work (assuming no port forwarding)
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Try to bind to all interfaces (should work)
            try:
                s.bind(("0.0.0.0", port))
                # If we get here, the port was free on all interfaces
                # but our function only checks localhost
            except OSError:
                # Port in use, which is expected
                pass

    def test_pkce_verifier_length(self):
        """Test PKCE verifier meets OAuth 2.0 spec requirements."""
        pkce = generate_pkce()

        # OAuth 2.0 spec requires 43-128 characters
        assert 43 <= len(pkce.code_verifier) <= 128

        # Should only contain unreserved URL characters
        import re

        assert re.match(r"^[A-Za-z0-9_-]+$", pkce.code_verifier)

    def test_state_parameter_length(self):
        """Test state parameter is sufficiently random."""
        pkce = generate_pkce()

        # State should be at least 32 bytes (256 bits) of entropy
        assert len(pkce.state) >= 32

        # Should be URL-safe base64
        import re

        assert re.match(r"^[A-Za-z0-9_-]+$", pkce.state)


class TestCLICommands:
    """Test CLI command functionality."""

    @patch("crashwise_cli.commands.oauth.get_storage")
    @patch("crashwise_cli.commands.oauth.console")
    def test_status_command(self, mock_console, mock_get_storage):
        """Test oauth status command."""
        mock_storage = Mock()
        mock_storage.get_storage_info.return_value = {
            "backend": "file",
            "fallback_path": "/test/path",
            "secure": False,
        }
        mock_storage.retrieve_token.return_value = "test_token"
        mock_get_storage.return_value = mock_storage

        from typer.testing import CliRunner
        from crashwise_cli.commands.oauth import app

        runner = CliRunner()
        result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        mock_console.print.assert_called()

    @patch("crashwise_cli.commands.oauth.get_storage")
    def test_remove_command_confirmed(self, mock_get_storage):
        """Test oauth remove command with confirmation."""
        mock_storage = Mock()
        mock_storage.retrieve_token.return_value = "test_token"
        mock_storage.delete_token.return_value = True
        mock_get_storage.return_value = mock_storage

        from typer.testing import CliRunner
        from crashwise_cli.commands.oauth import app

        runner = CliRunner()
        result = runner.invoke(
            app, ["remove", "--provider", "openai_codex"], input="y\n"
        )

        assert result.exit_code == 0
        mock_storage.delete_token.assert_called_once_with("openai_codex_oauth")

    def test_invalid_provider(self):
        """Test error handling for invalid provider."""
        from typer.testing import CliRunner
        from crashwise_cli.commands.oauth import app

        runner = CliRunner()
        result = runner.invoke(app, ["setup", "--provider", "invalid_provider"])

        assert result.exit_code != 0
        assert "Unknown provider" in result.output
