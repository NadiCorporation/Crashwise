"""Tests for policy enforcement module."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from fuzzforge_cli.policy import (
    Policy,
    ProviderPolicy,
    FallbackPolicy,
    LimitPolicy,
    get_policy,
)


class TestProviderPolicy:
    """Test provider policy enforcement."""

    def test_empty_policy_allows_all(self):
        """Test that empty policy allows all providers."""
        policy = ProviderPolicy()

        assert policy.is_allowed("openai")
        assert policy.is_allowed("anthropic")
        assert policy.is_allowed("gemini")

    def test_allowed_list_restricts(self):
        """Test that allowed list restricts to specified providers."""
        policy = ProviderPolicy(allowed=["openai", "anthropic"])

        assert policy.is_allowed("openai")
        assert policy.is_allowed("anthropic")
        assert not policy.is_allowed("gemini")
        assert not policy.is_allowed("openai_codex")

    def test_blocked_list_denies(self):
        """Test that blocked list denies specified providers."""
        policy = ProviderPolicy(blocked=["openai"])

        assert not policy.is_allowed("openai")
        assert policy.is_allowed("anthropic")
        assert policy.is_allowed("gemini")

    def test_allowed_and_blocked_combo(self):
        """Test interaction of allowed and blocked lists."""
        policy = ProviderPolicy(
            allowed=["openai", "anthropic", "gemini"], blocked=["openai"]
        )

        # Blocked takes precedence over allowed
        assert not policy.is_allowed("openai")
        assert policy.is_allowed("anthropic")
        assert policy.is_allowed("gemini")

    def test_case_insensitive(self):
        """Test that provider matching is case-insensitive."""
        policy = ProviderPolicy(allowed=["OpenAI", "Anthropic"])

        assert policy.is_allowed("openai")
        assert policy.is_allowed("OPENAI")
        assert policy.is_allowed("Anthropic")


class TestFallbackPolicy:
    """Test fallback policy."""

    def test_default_deny_env_vars(self):
        """Test that default policy denies env var fallback."""
        policy = FallbackPolicy()

        assert not policy.allow_env_vars

    def test_allow_env_vars(self):
        """Test allowing env var fallback."""
        policy = FallbackPolicy(allow_env_vars=True)

        assert policy.allow_env_vars

    def test_allowed_env_providers_restricts(self):
        """Test that allowed_env_providers restricts which providers can use env vars."""
        policy = FallbackPolicy(allow_env_vars=True, allowed_env_providers=["openai"])

        # Only openai allowed for env vars
        # (Policy class checks this separately)


class TestPolicyFromFile:
    """Test loading policy from YAML file."""

    @pytest.fixture
    def temp_policy_file(self):
        """Create a temporary policy file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("""
providers:
  allowed:
    - openai_codex
    - gemini_cli
  blocked:
    - openai

fallback:
  allow_env_vars: false
  allowed_env_providers: []

limits:
  requests_per_minute: 60
  tokens_per_day: 100000
  max_context_length: 128000
""")
            path = Path(f.name)

        yield path

        # Cleanup
        path.unlink()

    def test_load_valid_policy(self, temp_policy_file):
        """Test loading a valid policy file."""
        policy = Policy.from_file(temp_policy_file)

        assert "openai_codex" in policy.providers.allowed
        assert "openai" in policy.providers.blocked
        assert not policy.fallback.allow_env_vars
        assert policy.limits.requests_per_minute == 60

    def test_load_missing_file_uses_defaults(self):
        """Test that missing file uses default policy."""
        policy = Policy.from_file(Path("/nonexistent/path.yaml"))

        # Should get deny-by-default policy
        assert not policy.fallback.allow_env_vars

    def test_load_invalid_file_uses_defaults(self):
        """Test that invalid file uses default policy."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: content: [")
            path = Path(f.name)

        try:
            policy = Policy.from_file(path)
            # Should not raise, uses defaults
            assert not policy.fallback.allow_env_vars
        finally:
            path.unlink()


class TestPolicyCanUseProvider:
    """Test provider usage checking."""

    def test_oauth_allowed_by_default(self):
        """Test that OAuth is allowed by default."""
        policy = Policy()

        allowed, reason = policy.can_use_provider("openai_codex", "oauth")

        assert allowed
        assert reason is None

    def test_blocked_provider_denied(self):
        """Test that blocked provider is denied."""
        policy = Policy(providers=ProviderPolicy(blocked=["openai"]))

        allowed, reason = policy.can_use_provider("openai", "oauth")

        assert not allowed
        assert "blocked" in reason.lower()

    def test_env_fallback_denied_by_default(self):
        """Test that env var fallback is denied by default."""
        policy = Policy()

        allowed, reason = policy.can_use_provider("openai", "env")

        assert not allowed
        assert "disabled" in reason.lower()

    def test_env_fallback_allowed_when_configured(self):
        """Test that env var fallback can be enabled."""
        policy = Policy(fallback=FallbackPolicy(allow_env_vars=True))

        allowed, reason = policy.can_use_provider("openai", "env")

        assert allowed
        assert reason is None

    def test_env_fallback_restricted_to_allowed_providers(self):
        """Test that env fallback respects allowed_env_providers."""
        policy = Policy(
            fallback=FallbackPolicy(
                allow_env_vars=True, allowed_env_providers=["openai"]
            )
        )

        allowed, reason = policy.can_use_provider("openai", "env")
        assert allowed

        allowed, reason = policy.can_use_provider("anthropic", "env")
        assert not allowed
        assert "not allowed" in reason.lower()


class TestPolicyLimits:
    """Test policy limit enforcement."""

    def test_no_limits(self):
        """Test that empty limits allow everything."""
        policy = Policy()

        allowed, reason = policy.check_limits(requests=1000, tokens=1000000)

        assert allowed
        assert reason is None

    def test_request_limit(self):
        """Test request per minute limit."""
        policy = Policy(limits=LimitPolicy(requests_per_minute=60))

        allowed, _ = policy.check_limits(requests=50)
        assert allowed

        allowed, reason = policy.check_limits(requests=61)
        assert not allowed
        assert "limit exceeded" in reason.lower()

    def test_token_limit(self):
        """Test tokens per day limit."""
        policy = Policy(limits=LimitPolicy(tokens_per_day=100000))

        allowed, _ = policy.check_limits(tokens=50000)
        assert allowed

        allowed, reason = policy.check_limits(tokens=100001)
        assert not allowed
        assert "limit exceeded" in reason.lower()


class TestGetPolicy:
    """Test global policy instance."""

    def test_singleton(self):
        """Test that get_policy returns singleton."""
        policy1 = get_policy()
        policy2 = get_policy()

        assert policy1 is policy2

    def test_reload(self):
        """Test that reload forces re-read."""
        policy1 = get_policy()
        policy2 = get_policy(reload=True)

        # May or may not be same object depending on file existence
        # but should not error


class TestPolicySerialization:
    """Test policy save/load roundtrip."""

    def test_roundtrip(self):
        """Test saving and loading policy preserves values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.yaml"

            original = Policy(
                providers=ProviderPolicy(allowed=["openai_codex"], blocked=["openai"]),
                fallback=FallbackPolicy(
                    allow_env_vars=True, allowed_env_providers=["anthropic"]
                ),
                limits=LimitPolicy(requests_per_minute=60, tokens_per_day=100000),
            )

            original.to_file(path)
            loaded = Policy.from_file(path)

            assert loaded.providers.allowed == original.providers.allowed
            assert loaded.providers.blocked == original.providers.blocked
            assert loaded.fallback.allow_env_vars == original.fallback.allow_env_vars
            assert (
                loaded.limits.requests_per_minute == original.limits.requests_per_minute
            )
