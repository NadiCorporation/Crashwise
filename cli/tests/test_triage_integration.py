"""
Integration tests for LLM resolver + policy enforcement in CLI paths.

These tests verify that:
1. CLI commands use llm_resolver for all LLM calls
2. Policy is enforced (env fallback blocked unless allowed)
3. No tokens are exposed in error messages
4. Commands fail safely with clear errors
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest
from typer.testing import CliRunner

# Import CLI app
from crashwise_cli.main import app
from crashwise_cli.policy import Policy, ProviderPolicy, FallbackPolicy


runner = CliRunner()


class TestPolicyEnforcementInTriage:
    """Test policy enforcement in the triage command."""

    @pytest.fixture
    def mock_policy_file(self):
        """Create a restrictive policy file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("""
providers:
  allowed:
    - openai_codex
  blocked:
    - openai

fallback:
  allow_env_vars: false

limits:
  requests_per_minute: 60
""")
            path = Path(f.name)

        yield path

        # Cleanup
        path.unlink()

    @pytest.fixture
    def mock_findings_db(self):
        """Mock findings database with crash logs."""
        mock_crash = """
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000a0
READ of size 4 in fuzzer::LLVMFuzzerTestOneInput
    #0 0x4a3b2c in process_input src/parser.c:123
    #1 0x4a2a1b in main src/main.c:45
"""
        finding = {
            "id": "test-finding-1",
            "run_id": "test-run-123",
            "log": mock_crash,
            "type": "crash",
        }

        mock_db = Mock()
        mock_db.get_findings.return_value = [finding]

        return mock_db

    def test_triage_blocked_when_env_fallback_denied(self, mock_policy_file):
        """
        Integration test: Command fails safely when policy denies env fallback.

        Scenario:
        - User has env var credentials set
        - Policy denies env fallback
        - No OAuth configured
        - Command should fail with clear error (no tokens in output)
        """
        # Set env var credentials (simulating user has API key in env)
        env_vars = {
            "OPENAI_API_KEY": "sk-test1234567890abcdef",
            "LLM_PROVIDER": "openai",
        }

        with patch.dict(os.environ, env_vars, clear=False):
            with patch(
                "crashwise_cli.policy.Policy.from_file",
                return_value=Policy.from_file(mock_policy_file),
            ):
                with patch(
                    "crashwise_cli.commands.triage.get_project_db"
                ) as mock_get_db:
                    # Mock database with findings
                    mock_db = Mock()
                    mock_db.get_findings.return_value = [
                        {"id": "test-1", "log": "ERROR: AddressSanitizer: test crash"}
                    ]
                    mock_get_db.return_value = mock_db

                    # Run command
                    result = runner.invoke(app, ["findings", "triage", "test-run-123"])

                    # Should fail (exit code != 0)
                    assert result.exit_code != 0

                    # Should show policy violation error
                    assert (
                        "Policy violation" in result.output
                        or "not available" in result.output
                    )

                    # CRITICAL: Should NOT expose the API key
                    assert "sk-test1234567890abcdef" not in result.output
                    assert "sk-test" not in result.output
                    assert "test123" not in result.output

    def test_triage_succeeds_with_oauth(self, mock_policy_file):
        """
        Integration test: Command works when OAuth is configured.

        Scenario:
        - OAuth credentials stored in secure storage
        - Policy allows OAuth provider
        - Command should succeed
        """
        with patch(
            "crashwise_cli.policy.Policy.from_file",
            return_value=Policy.from_file(mock_policy_file),
        ):
            with patch("crashwise_cli.commands.triage.get_project_db") as mock_get_db:
                with patch(
                    "crashwise_cli.llm_resolver.get_storage"
                ) as mock_get_storage:
                    with patch(
                        "crashwise_cli.llm_resolver._get_env_credential"
                    ) as mock_env:
                        # Mock OAuth token available
                        mock_storage = Mock()
                        mock_storage.retrieve_token.return_value = "oauth_token_abc123"
                        mock_get_storage.return_value = mock_storage

                        # Mock env returns None (no env fallback)
                        mock_env.return_value = None

                        # Mock database
                        mock_db = Mock()
                        mock_db.get_findings.return_value = [
                            {
                                "id": "test-1",
                                "log": "ERROR: AddressSanitizer: test crash",
                            }
                        ]
                        mock_get_db.return_value = mock_db

                        # Run command
                        result = runner.invoke(
                            app, ["findings", "triage", "test-run-123"]
                        )

                        # Should not fail due to policy
                        assert "Policy violation" not in result.output

                        # Should not expose tokens
                        assert "oauth_token_abc123" not in result.output

    def test_triage_with_explicit_provider_flag(self):
        """Test that --provider flag is passed through to resolver."""
        with patch("crashwise_cli.commands.triage.get_project_db") as mock_get_db:
            with patch("crashwise_cli.llm_resolver.get_llm_client") as mock_get_llm:
                # Mock successful LLM config
                mock_get_llm.return_value = {
                    "provider": "openai_codex",
                    "model": "gpt-4o",
                    "api_key": "test_key",
                    "auth_method": "oauth",
                }

                # Mock database
                mock_db = Mock()
                mock_db.get_findings.return_value = [
                    {"id": "test-1", "log": "ERROR: crash"}
                ]
                mock_get_db.return_value = mock_db

                # Run with explicit provider
                result = runner.invoke(
                    app,
                    [
                        "findings",
                        "triage",
                        "test-run-123",
                        "--provider",
                        "openai_codex",
                        "--model",
                        "gpt-4o",
                    ],
                )

                # Verify resolver called with correct provider
                mock_get_llm.assert_called()
                call_kwargs = mock_get_llm.call_args[1]
                assert call_kwargs.get("provider") == "openai_codex"
                assert call_kwargs.get("model") == "gpt-4o"


class TestTriageOutputFormats:
    """Test triage output formats."""

    def test_triage_table_output(self):
        """Test default table output format."""
        with patch("crashwise_cli.commands.triage.get_project_db") as mock_get_db:
            with patch("crashwise_cli.llm_resolver.get_llm_client") as mock_get_llm:
                mock_get_llm.return_value = {
                    "provider": "test",
                    "model": "test-model",
                    "api_key": "test_key",
                    "auth_method": "oauth",
                }

                mock_db = Mock()
                mock_db.get_findings.return_value = [
                    {"id": "test-1", "log": "ERROR: AddressSanitizer: crash"}
                ]
                mock_get_db.return_value = mock_db

                result = runner.invoke(app, ["findings", "triage", "test-run"])

                # Should show table output
                assert result.exit_code == 0


class TestTokenSecurity:
    """Ensure tokens never appear in CLI output."""

    def test_no_tokens_in_error_messages(self):
        """Verify API keys don't leak in error messages."""
        test_keys = [
            "sk-live-1234567890abcdef",
            "ghp_xxxxxxxxxxxxxxxxxxxx",
            "oauth_token_secret123",
        ]

        for key in test_keys:
            with patch.dict(os.environ, {"OPENAI_API_KEY": key}):
                with patch(
                    "crashwise_cli.commands.triage.get_project_db"
                ) as mock_get_db:
                    mock_db = Mock()
                    mock_db.get_findings.return_value = []  # No findings
                    mock_get_db.return_value = mock_db

                    result = runner.invoke(app, ["findings", "triage", "test-run"])

                    # Key should not appear anywhere in output
                    assert key not in result.output, (
                        f"API key leaked in output: {key[:20]}..."
                    )
                    assert key[:10] not in result.output, "Partial key leaked"


class TestBackwardCompatibility:
    """Test that existing CLI behavior is preserved."""

    def test_findings_commands_still_work(self):
        """Test existing findings commands still function."""
        # Test findings list
        result = runner.invoke(app, ["findings", "--help"])
        assert result.exit_code == 0
        assert "triage" in result.output  # Should show new triage command

    def test_triage_help_shows_all_options(self):
        """Test triage command help shows all options."""
        result = runner.invoke(app, ["findings", "triage", "--help"])

        assert result.exit_code == 0
        assert "--provider" in result.output
        assert "--model" in result.output
        assert "--format" in result.output
        assert "--skip-llm" in result.output


class TestCrashLogParsing:
    """Test crash log parsing functionality."""

    def test_parse_asan_crash(self):
        """Test parsing AddressSanitizer crash log."""
        from crashwise_cli.commands.triage import parse_crash_log

        log = """
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000a0
READ of size 4 in fuzzer::LLVMFuzzerTestOneInput
    #0 0x4a3b2c in process_input src/parser.c:123
    #1 0x4a2a1b in main src/main.c:45
"""

        crash = parse_crash_log(log)

        assert crash.type == "ASAN"
        assert "heap-buffer-overflow" in crash.sanitizer_output
        assert len(crash.stack_trace) > 0
        assert "process_input" in crash.stack_trace[0]

    def test_parse_python_exception(self):
        """Test parsing Python exception."""
        from crashwise_cli.commands.triage import parse_crash_log

        log = """
Traceback (most recent call last):
  File "test.py", line 10, in <module>
    result = process(data)
  File "test.py", line 5, in process
    return data[0]
IndexError: list index out of range
"""

        crash = parse_crash_log(log)

        assert crash.type == "python_exception"
        assert len(crash.stack_trace) > 0


class TestPolicyFileEnforcement:
    """Test that policy file is respected in real execution."""

    def test_policy_file_blocks_unauthorized_provider(self, tmp_path):
        """
        Create real policy file and verify it's enforced.
        """
        # Create restrictive policy
        policy_dir = tmp_path / ".config" / "crashwise"
        policy_dir.mkdir(parents=True)
        policy_file = policy_dir / "policy.yaml"

        policy_file.write_text("""
providers:
  allowed:
    - openai_codex
  blocked: []

fallback:
  allow_env_vars: false
""")

        # Mock home directory
        with patch.dict(os.environ, {"HOME": str(tmp_path)}):
            with patch("pathlib.Path.home", return_value=tmp_path):
                with patch("crashwise_cli.policy._policy", None):  # Force reload
                    # Now test with a blocked provider
                    with patch(
                        "crashwise_cli.commands.triage.get_project_db"
                    ) as mock_get_db:
                        mock_db = Mock()
                        mock_db.get_findings.return_value = [
                            {"id": "test-1", "log": "ERROR: crash"}
                        ]
                        mock_get_db.return_value = mock_db

                        # Try to use openai (should be blocked)
                        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
                            result = runner.invoke(
                                app,
                                [
                                    "findings",
                                    "triage",
                                    "test-run",
                                    "--provider",
                                    "openai",
                                ],
                            )

                            # Should fail with policy error
                            assert result.exit_code != 0
                            assert (
                                "not available" in result.output
                                or "disabled" in result.output
                            )
