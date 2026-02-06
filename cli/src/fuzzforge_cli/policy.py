"""
Policy enforcement for FuzzForge LLM operations.

Loads policy from ~/.config/fuzzforge/policy.yaml
Enforces provider restrictions and resource limits.

Example policy.yaml:
    providers:
      allowed:
        - openai_codex
        - gemini_cli
      blocked:
        - openai  # Block API key auth

    fallback:
      allow_env_vars: false  # Deny-by-default

    limits:
      requests_per_minute: 60
      tokens_per_day: 100000
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any

import yaml


@dataclass
class ProviderPolicy:
    """Policy for LLM providers."""

    allowed: List[str] = field(default_factory=list)
    blocked: List[str] = field(default_factory=list)

    def is_allowed(self, provider: str) -> bool:
        """Check if provider is allowed."""
        provider = provider.lower()

        # If allowed list is specified, provider must be in it
        if self.allowed and provider not in [p.lower() for p in self.allowed]:
            return False

        # Provider must not be in blocked list
        if provider in [p.lower() for p in self.blocked]:
            return False

        return True


@dataclass
class FallbackPolicy:
    """Policy for fallback behavior."""

    allow_env_vars: bool = False  # Deny-by-default
    allowed_env_providers: List[str] = field(default_factory=list)


@dataclass
class LimitPolicy:
    """Policy for resource limits."""

    requests_per_minute: Optional[int] = None
    tokens_per_day: Optional[int] = None
    max_context_length: Optional[int] = None


@dataclass
class Policy:
    """Complete FuzzForge policy configuration."""

    providers: ProviderPolicy = field(default_factory=ProviderPolicy)
    fallback: FallbackPolicy = field(default_factory=FallbackPolicy)
    limits: LimitPolicy = field(default_factory=LimitPolicy)

    @classmethod
    def from_file(cls, path: Optional[Path] = None) -> "Policy":
        """Load policy from YAML file.

        Args:
            path: Path to policy file. Defaults to ~/.config/fuzzforge/policy.yaml

        Returns:
            Policy object
        """
        if path is None:
            path = Path.home() / ".config" / "fuzzforge" / "policy.yaml"

        # Default deny-by-default policy
        default_policy = cls()

        if not path.exists():
            return default_policy

        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}

            return cls._from_dict(data)
        except Exception as e:
            # Log warning but don't fail - use defaults
            import logging

            logging.warning(f"Failed to load policy from {path}: {e}")
            return default_policy

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> "Policy":
        """Create Policy from dictionary."""
        providers_data = data.get("providers", {})
        providers = ProviderPolicy(
            allowed=providers_data.get("allowed", []),
            blocked=providers_data.get("blocked", []),
        )

        fallback_data = data.get("fallback", {})
        fallback = FallbackPolicy(
            allow_env_vars=fallback_data.get("allow_env_vars", False),
            allowed_env_providers=fallback_data.get("allowed_env_providers", []),
        )

        limits_data = data.get("limits", {})
        limits = LimitPolicy(
            requests_per_minute=limits_data.get("requests_per_minute"),
            tokens_per_day=limits_data.get("tokens_per_day"),
            max_context_length=limits_data.get("max_context_length"),
        )

        return cls(providers=providers, fallback=fallback, limits=limits)

    def to_file(self, path: Optional[Path] = None) -> None:
        """Save policy to YAML file.

        Args:
            path: Path to policy file. Defaults to ~/.config/fuzzforge/policy.yaml
        """
        if path is None:
            path = Path.home() / ".config" / "fuzzforge" / "policy.yaml"

        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "providers": {
                "allowed": self.providers.allowed,
                "blocked": self.providers.blocked,
            },
            "fallback": {
                "allow_env_vars": self.fallback.allow_env_vars,
                "allowed_env_providers": self.fallback.allowed_env_providers,
            },
            "limits": {
                "requests_per_minute": self.limits.requests_per_minute,
                "tokens_per_day": self.limits.tokens_per_day,
                "max_context_length": self.limits.max_context_length,
            },
        }

        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)

    def can_use_provider(
        self, provider: str, auth_method: str = "oauth"
    ) -> tuple[bool, Optional[str]]:
        """Check if provider can be used with given auth method.

        Args:
            provider: Provider name (e.g., 'openai_codex')
            auth_method: 'oauth' or 'env'

        Returns:
            Tuple of (allowed, reason_if_denied)
        """
        provider = provider.lower()

        # Check if provider is allowed
        if not self.providers.is_allowed(provider):
            if self.providers.blocked and provider in [
                p.lower() for p in self.providers.blocked
            ]:
                return False, f"Provider '{provider}' is blocked by policy"
            if self.providers.allowed:
                return False, f"Provider '{provider}' not in allowed list"

        # Check auth method
        if auth_method == "env":
            if not self.fallback.allow_env_vars:
                return False, "Environment variable fallback is disabled by policy"

            if self.fallback.allowed_env_providers:
                if provider not in [
                    p.lower() for p in self.fallback.allowed_env_providers
                ]:
                    return False, f"Provider '{provider}' not allowed for env var auth"

        return True, None

    def check_limits(
        self, requests: int = 0, tokens: int = 0
    ) -> tuple[bool, Optional[str]]:
        """Check if operation is within limits.

        Args:
            requests: Number of requests
            tokens: Number of tokens

        Returns:
            Tuple of (within_limits, reason_if_exceeded)
        """
        # Note: This is a simple check. For production, you'd want to track
        # actual usage over time windows.

        if (
            self.limits.requests_per_minute
            and requests > self.limits.requests_per_minute
        ):
            return (
                False,
                f"Request limit exceeded ({self.limits.requests_per_minute}/min)",
            )

        if self.limits.tokens_per_day and tokens > self.limits.tokens_per_day:
            return False, f"Token limit exceeded ({self.limits.tokens_per_day}/day)"

        return True, None


# Global policy instance
_policy: Optional[Policy] = None


def get_policy(reload: bool = False) -> Policy:
    """Get the global policy instance.

    Args:
        reload: Force reload from file

    Returns:
        Policy instance
    """
    global _policy
    if _policy is None or reload:
        _policy = Policy.from_file()
    return _policy


def create_default_policy() -> Policy:
    """Create a secure default policy.

    Default policy:
    - Only OAuth providers allowed (no env var fallback)
    - Common providers pre-allowed
    - Reasonable limits set
    """
    return Policy(
        providers=ProviderPolicy(
            allowed=["openai_codex", "gemini_cli", "openai", "anthropic", "gemini"],
            blocked=[],
        ),
        fallback=FallbackPolicy(
            allow_env_vars=False,  # Deny-by-default
            allowed_env_providers=[],
        ),
        limits=LimitPolicy(
            requests_per_minute=60, tokens_per_day=100000, max_context_length=128000
        ),
    )
