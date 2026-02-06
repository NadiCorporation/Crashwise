"""Secure OAuth 2.0 authentication for LLM providers.

Implements OAuth 2.0 with PKCE for secure token exchange.
Tokens are stored securely (keychain/keyring) and never printed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from .secure_storage import SecureStorageError, get_storage

console = Console()
app = typer.Typer()


# OAuth provider configurations
OAUTH_PROVIDERS = {
    "openai_codex": {
        "name": "OpenAI Codex",
        "auth_url": "https://auth.openai.com/authorize",
        "token_url": "https://auth.openai.com/token",
        "client_id": "codex-cli",  # Public client
        "scope": "openid profile email",
        "account_key": "openai_codex_oauth",
    },
    "gemini_cli": {
        "name": "Gemini CLI",
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "client_id": "936476727457-ei4gcb6j3d2qv7r9a64vqq6j3l4i2h4v.apps.googleusercontent.com",  # Gemini CLI public client
        "scope": "openid email profile https://www.googleapis.com/auth/generative-language.retriever",
        "account_key": "gemini_cli_oauth",
    },
}


@dataclass
class PKCEData:
    """PKCE (Proof Key for Code Exchange) data."""

    code_verifier: str
    code_challenge: str
    state: str
    redirect_port: int


def generate_pkce() -> PKCEData:
    """Generate PKCE code verifier and challenge."""
    # Generate code verifier (random string, 43-128 chars)
    code_verifier = base64.urlsafe_b64encode(os.urandom(64)).decode("utf-8").rstrip("=")

    # Generate code challenge (SHA256 hash of verifier)
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode("utf-8")
        .rstrip("=")
    )

    # Generate state parameter for CSRF protection
    state = secrets.token_urlsafe(32)

    # Find available port on 127.0.0.1
    redirect_port = _find_free_port()

    return PKCEData(
        code_verifier=code_verifier,
        code_challenge=code_challenge,
        state=state,
        redirect_port=redirect_port,
    )


def _find_free_port() -> int:
    """Find a free port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback."""

    def __init__(self, expected_state: str, *args, **kwargs):
        self.expected_state = expected_state
        self.auth_code: Optional[str] = None
        self.error: Optional[str] = None
        self.received_state: Optional[str] = None
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        """Suppress default HTTP logging."""
        pass

    def do_GET(self):
        """Handle GET request (OAuth callback)."""
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        # Check for error
        if "error" in query:
            self.error = query["error"][0]
            self._send_error_page()
            return

        # Validate state parameter
        self.received_state = query.get("state", [None])[0]
        if self.received_state != self.expected_state:
            self.error = "Invalid state parameter"
            self._send_error_page()
            return

        # Extract authorization code
        self.auth_code = query.get("code", [None])[0]
        if not self.auth_code:
            self.error = "No authorization code received"
            self._send_error_page()
            return

        # Success - send success page
        self._send_success_page()

    def _send_success_page(self):
        """Send HTML success page."""
        html = b"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Successful</title>
            <style>
                body { font-family: sans-serif; text-align: center; padding: 50px; }
                .success { color: #4CAF50; font-size: 48px; }
                h1 { color: #333; }
                p { color: #666; }
            </style>
        </head>
        <body>
            <div class="success">&#10003;</div>
            <h1>Authentication Successful</h1>
            <p>You can close this window and return to the terminal.</p>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def _send_error_page(self):
        """Send HTML error page."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Failed</title>
            <style>
                body {{ font-family: sans-serif; text-align: center; padding: 50px; }}
                .error {{ color: #f44336; font-size: 48px; }}
                h1 {{ color: #333; }}
                p {{ color: #666; }}
            </style>
        </head>
        <body>
            <div class="error">&#10007;</div>
            <h1>Authentication Failed</h1>
            <p>{self.error}</p>
        </body>
        </html>
        """.encode()
        self.send_response(400)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)


def start_callback_server(port: int, expected_state: str, timeout: int = 120) -> tuple:
    """Start local callback server and wait for OAuth response.

    Args:
        port: Port to bind to
        expected_state: Expected state parameter for CSRF validation
        timeout: Maximum time to wait (seconds)

    Returns:
        Tuple of (auth_code, error)
    """
    result: dict[str, Optional[str]] = {"code": None, "error": None}

    class Handler(OAuthCallbackHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(expected_state, *args, **kwargs)

        def do_GET(self):
            super().do_GET()
            result["code"] = self.auth_code
            result["error"] = self.error

    server = HTTPServer(("127.0.0.1", port), Handler)
    server.timeout = timeout

    console.print(f"  🌐 Waiting for callback on 127.0.0.1:{port}...")

    # Handle single request
    server.handle_request()
    server.server_close()

    return result["code"], result["error"]


def exchange_code_for_token(
    provider_id: str, auth_code: str, pkce_data: PKCEData
) -> Optional[dict]:
    """Exchange authorization code for access token.

    Args:
        provider_id: Provider identifier
        auth_code: Authorization code from callback
        pkce_data: PKCE data including code_verifier

    Returns:
        Token response dict or None on failure
    """
    import urllib.request
    import urllib.parse

    provider = OAUTH_PROVIDERS[provider_id]

    # Build token request
    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": f"http://127.0.0.1:{pkce_data.redirect_port}/callback",
        "client_id": provider["client_id"],
        "code_verifier": pkce_data.code_verifier,
    }

    data = urllib.parse.urlencode(token_data).encode("utf-8")

    req = urllib.request.Request(
        provider["token_url"],
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        console.print(f"  ❌ Token exchange failed: {e}", style="red")
        return None


def _update_env_file(env_path: Path, key: str, value: str) -> bool:
    """Update .env file with new value (only if user explicitly requests)."""
    try:
        lines = []
        if env_path.exists():
            with open(env_path, "r") as f:
                lines = f.readlines()

        updated = False
        for i, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[i] = f"{key}={value}\n"
                updated = True
                break

        if not updated:
            lines.append(f"{key}={value}\n")

        with open(env_path, "w") as f:
            f.writelines(lines)

        return True
    except IOError:
        return False


@app.command()
def setup(
    provider: Optional[str] = typer.Option(
        None,  # Made optional for --list-providers
        "--provider",
        "-p",
        help="OAuth provider to configure (use --list-providers to see all)",
    ),
    export_to_env: bool = typer.Option(
        False,
        "--export-to-env",
        help="Export tokens to .env file (less secure, NOT recommended)",
    ),
    list_providers: bool = typer.Option(
        False,
        "--list-providers",
        "-l",
        help="List available OAuth providers and exit",
    ),
):
    """
    🔐 Setup OAuth authentication for LLM providers.

    Performs secure OAuth 2.0 flow with PKCE:
    - Opens browser for authentication
    - Starts local callback server on 127.0.0.1
    - Stores tokens securely (keychain/keyring)
    - Never displays or logs tokens

    Examples:
        ff oauth setup --list-providers              # Show available providers
        ff oauth setup -p openai_codex               # Setup OpenAI Codex
        ff oauth setup -p gemini_cli                 # Setup Gemini CLI
        ff oauth setup -p openai_codex --export-to-env  # Less secure
    """
    # Handle --list-providers
    if list_providers:
        console.print(
            Panel.fit(
                "[bold cyan]🔐 Available OAuth Providers[/bold cyan]",
                border_style="cyan",
            )
        )

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Provider ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Description", style="dim")

        for provider_id, config in OAUTH_PROVIDERS.items():
            desc = f"OAuth via {config['name']} CLI"
            table.add_row(provider_id, config["name"], desc)

        console.print(table)
        console.print("\n[dim]Usage: ff oauth setup -p <provider_id>[/dim]")
        raise typer.Exit(0)

    # Require provider if not listing
    if not provider:
        console.print(
            "❌ Provider required. Use --list-providers to see available options.",
            style="red",
        )
        raise typer.Exit(1)

    # Validate provider
    provider_id = provider.lower()
    if provider_id not in OAUTH_PROVIDERS:
        console.print(
            f"❌ Unknown provider: {provider}\n"
            f"Supported providers: {', '.join(OAUTH_PROVIDERS.keys())}",
            style="red",
        )
        raise typer.Exit(1)

    provider_config = OAUTH_PROVIDERS[provider_id]

    console.print(
        Panel.fit(
            f"[bold cyan]🔐 OAuth Authentication: {provider_config['name']}[/bold cyan]\n"
            "Secure OAuth 2.0 with PKCE - tokens stored in system keychain",
            border_style="cyan",
        )
    )

    # Security warning for --export-to-env
    if export_to_env:
        console.print(
            "⚠️  [yellow]WARNING:[/yellow] --export-to-env is less secure.\n"
            "Tokens will be written to .env file in plain text.\n",
            style="yellow",
        )
        if not Confirm.ask("Continue with less secure storage?", default=False):
            console.print("❌ Cancelled", style="red")
            raise typer.Exit(0)

    # Generate PKCE data
    console.print("  🔑 Generating secure PKCE parameters...")
    pkce_data = generate_pkce()

    # Build authorization URL
    redirect_uri = f"http://127.0.0.1:{pkce_data.redirect_port}/callback"
    auth_params = {
        "response_type": "code",
        "client_id": provider_config["client_id"],
        "redirect_uri": redirect_uri,
        "scope": provider_config["scope"],
        "state": pkce_data.state,
        "code_challenge": pkce_data.code_challenge,
        "code_challenge_method": "S256",
    }

    from urllib.parse import urlencode

    auth_url = f"{provider_config['auth_url']}?{urlencode(auth_params)}"

    # Open browser
    console.print(f"  🌐 Opening browser for authentication...")
    console.print(f"  📍 Callback URL: {redirect_uri}")

    try:
        webbrowser.open(auth_url)
    except Exception:
        console.print(f"  ⚠️  Could not open browser automatically.")
        console.print(f"  📎 Please open this URL manually:")
        console.print(f"     {auth_url}")

    # Start callback server
    auth_code, error = start_callback_server(pkce_data.redirect_port, pkce_data.state)

    if error:
        console.print(f"  ❌ Authentication failed: {error}", style="red")
        raise typer.Exit(1)

    if not auth_code:
        console.print("  ❌ No authorization code received", style="red")
        raise typer.Exit(1)

    # Exchange code for token
    console.print("  🔄 Exchanging code for token...")
    token_response = exchange_code_for_token(provider_id, auth_code, pkce_data)

    if not token_response:
        console.print("  ❌ Failed to obtain access token", style="red")
        raise typer.Exit(1)

    access_token = token_response.get("access_token")
    if not access_token:
        console.print("  ❌ No access token in response", style="red")
        raise typer.Exit(1)

    # Store token securely
    account_key = provider_config["account_key"]

    try:
        storage = get_storage()
        storage.store_token(account_key, access_token)
        storage_info = storage.get_storage_info()

        if storage_info["secure"]:
            console.print(
                f"  ✅ Token stored securely in {storage_info['backend']}",
                style="green",
            )
        else:
            console.print(
                f"  ⚠️  Token stored in file: {storage_info['fallback_path']}",
                style="yellow",
            )
            console.print(
                "     Consider installing a keyring backend for better security.",
                style="dim",
            )

    except SecureStorageError as e:
        console.print(f"  ❌ Failed to store token: {e}", style="red")
        raise typer.Exit(1)

    # Export to .env only if explicitly requested
    if export_to_env:
        console.print("  📝 Exporting token to .env file...")

        # Find env file
        current = Path.cwd()
        env_path = None
        for directory in [current] + list(current.parents):
            candidate = directory / "volumes" / "env" / ".env"
            if candidate.exists():
                env_path = candidate
                break

        if env_path:
            env_key = f"LITELLM_{account_key.upper()}"
            if _update_env_file(env_path, env_key, access_token):
                console.print(f"  ✅ Token exported to {env_path}", style="green")
            else:
                console.print("  ❌ Failed to write to .env", style="red")
        else:
            console.print("  ⚠️  .env file not found", style="yellow")

    console.print(
        f"\n✅ [bold green]{provider_config['name']} OAuth configured successfully![/bold green]"
    )
    console.print("   Token is securely stored and ready for use.")


@app.command()
def status(
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output machine-readable JSON (safe for scripting)"
    ),
):
    """
    🔍 Check OAuth authentication status.

    Shows which OAuth providers are configured (without revealing tokens).

    Examples:
        ff oauth status              # Human-readable table
        ff oauth status --json       # Machine-readable JSON
    """
    storage = get_storage()
    storage_info = storage.get_storage_info()

    # Build status data
    providers_status = {}
    for provider_id, config in OAUTH_PROVIDERS.items():
        try:
            token = storage.retrieve_token(config["account_key"])
            if token:
                providers_status[provider_id] = {
                    "name": config["name"],
                    "configured": True,
                    "storage": storage_info["backend"],
                }
            else:
                providers_status[provider_id] = {
                    "name": config["name"],
                    "configured": False,
                    "storage": None,
                }
        except Exception as e:
            providers_status[provider_id] = {
                "name": config["name"],
                "configured": False,
                "error": str(e),
            }

    if json_output:
        # Safe for scripting - no tokens, no sensitive data
        import json

        output = {
            "storage_backend": storage_info["backend"],
            "storage_path": storage_info.get("fallback_path"),
            "providers": providers_status,
        }
        console.print(json.dumps(output, indent=2))
    else:
        # Human-readable table
        console.print(
            Panel.fit(
                "[bold cyan]🔍 OAuth Authentication Status[/bold cyan]",
                border_style="cyan",
            )
        )

        console.print(f"Storage backend: [dim]{storage_info['backend']}[/dim]")
        if storage_info["fallback_path"]:
            console.print(f"Fallback path: [dim]{storage_info['fallback_path']}[/dim]")
        console.print()

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Provider", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Storage", style="dim")

        for provider_id, config in OAUTH_PROVIDERS.items():
            status_info = providers_status[provider_id]
            if status_info.get("configured"):
                table.add_row(config["name"], "✅ Configured", storage_info["backend"])
            elif "error" in status_info:
                table.add_row(config["name"], "❌ Error checking", "-")
            else:
                table.add_row(config["name"], "❌ Not configured", "-")

        console.print(table)


@app.command()
def remove(
    provider: str = typer.Option(
        ...,
        "--provider",
        "-p",
        help="OAuth provider to remove (openai_codex, gemini_cli)",
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Remove without confirmation (safe for scripting)"
    ),
):
    """
    🗑️  Remove stored OAuth credentials for a provider.

    Examples:
        ff oauth remove -p openai_codex
        ff oauth remove -p openai_codex --force  # No confirmation
    """
    provider_id = provider.lower()
    if provider_id not in OAUTH_PROVIDERS:
        console.print(f"❌ Unknown provider: {provider}", style="red")
        raise typer.Exit(1)

    provider_config = OAUTH_PROVIDERS[provider_id]
    account_key = provider_config["account_key"]

    storage = get_storage()

    # Check if token exists
    existing = storage.retrieve_token(account_key)
    if not existing:
        console.print(f"ℹ️  No credentials found for {provider_config['name']}")
        raise typer.Exit(0)

    if force or Confirm.ask(
        f"Remove OAuth credentials for {provider_config['name']}?", default=False
    ):
        if storage.delete_token(account_key):
            console.print(
                f"✅ Credentials removed for {provider_config['name']}", style="green"
            )
        else:
            console.print(f"❌ Failed to remove credentials", style="red")
            raise typer.Exit(1)
    else:
        console.print("Cancelled", style="yellow")


@app.command()
def logout(
    provider: str = typer.Option(
        ...,
        "--provider",
        "-p",
        help="OAuth provider to logout from (openai_codex, gemini_cli)",
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Logout without confirmation (safe for scripting)"
    ),
):
    """
    🚪 Logout from an OAuth provider (alias for 'remove').

    Examples:
        ff oauth logout -p openai_codex
        ff oauth logout -p openai_codex --force  # No confirmation
    """
    # Simply delegate to remove command
    ctx = typer.get_current_context()
    ctx.invoke(remove, provider=provider, force=force)


if __name__ == "__main__":
    app()
