"""
Centralized LLM client resolver for Crashwise CLI.

This is the SINGLE SOURCE OF TRUTH for all LLM operations in the CLI.
All LLM calls must go through get_llm_client() to ensure:
- OAuth credentials are used preferentially
- Policy enforcement (deny-by-default)
- Secure credential handling
- No token logging

Usage:
    from crashwise_cli.llm_resolver import get_llm_client

    client = get_llm_client(
        provider="openai_codex",
        model="gpt-4o",
        workspace="my_project"
    )
    # Use client for LLM operations
"""

from __future__ import annotations

import os
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

from rich.console import Console

from .secure_storage import get_storage, SecureStorageError
from .policy import get_policy

console = Console()


class LLMResolverError(Exception):
    """Raised when LLM client cannot be created."""

    pass


class PolicyViolationError(LLMResolverError):
    """Raised when operation violates security policy."""

    pass


# Provider to OAuth account mapping
OAUTH_PROVIDERS = {
    "openai_codex": "openai_codex_oauth",
    "gemini_cli": "gemini_cli_oauth",
}

# Provider to environment variable mappings
ENV_MAPPINGS = {
    "openai": {
        "api_key": ["OPENAI_API_KEY", "LLM_API_KEY"],
        "base_url": ["OPENAI_BASE_URL", "LLM_ENDPOINT", "OPENAI_API_BASE"],
    },
    "anthropic": {
        "api_key": ["ANTHROPIC_API_KEY", "LLM_API_KEY"],
        "base_url": ["ANTHROPIC_BASE_URL", "LLM_ENDPOINT"],
    },
    "gemini": {
        "api_key": ["GEMINI_API_KEY", "GOOGLE_API_KEY", "LLM_API_KEY"],
        "base_url": ["GEMINI_BASE_URL", "LLM_ENDPOINT"],
    },
}


def _get_oauth_token(provider: str) -> Optional[str]:
    """Try to get OAuth token from secure storage.

    Args:
        provider: Provider name

    Returns:
        Token if found, None otherwise
    """
    account_key = OAUTH_PROVIDERS.get(provider.lower())
    if not account_key:
        return None

    try:
        storage = get_storage()
        return storage.retrieve_token(account_key)
    except SecureStorageError:
        return None


def _get_env_credential(provider: str, cred_type: str) -> Optional[str]:
    """Get credential from environment variables.

    Args:
        provider: Provider name
        cred_type: Type of credential ('api_key', 'base_url')

    Returns:
        Credential value if found, None otherwise
    """
    provider = provider.lower()
    mappings = ENV_MAPPINGS.get(provider, {})
    env_vars = mappings.get(cred_type, [])

    for var in env_vars:
        value = os.getenv(var)
        if value:
            return value

    return None


def _resolve_credentials(
    provider: str, prefer_oauth: bool = True
) -> Tuple[Optional[str], Optional[str], str]:
    """Resolve credentials for provider.

    Args:
        provider: Provider name
        prefer_oauth: Whether to prefer OAuth over env vars

    Returns:
        Tuple of (api_key, base_url, auth_method)
        auth_method is 'oauth' or 'env'

    Raises:
        PolicyViolationError: If auth method violates policy
    """
    policy = get_policy()

    # Try OAuth first if preferred
    if prefer_oauth:
        oauth_token = _get_oauth_token(provider)
        if oauth_token:
            allowed, reason = policy.can_use_provider(provider, "oauth")
            if not allowed:
                raise PolicyViolationError(
                    f"OAuth for provider '{provider}' blocked by policy: {reason}"
                )
            # For OAuth, we use the token as the API key
            # Base URL is typically not needed for OAuth providers
            return oauth_token, None, "oauth"

    # Fall back to environment variables
    policy = get_policy()
    allowed, reason = policy.can_use_provider(provider, "env")

    if not allowed:
        if prefer_oauth and _get_oauth_token(provider):
            # OAuth available but we didn't use it - shouldn't happen
            raise LLMResolverError(
                f"Provider '{provider}' available via OAuth but env fallback blocked"
            )
        raise PolicyViolationError(
            f"Provider '{provider}' not available: {reason}. "
            f"Run 'cw oauth setup -p {provider}' to authenticate."
        )

    api_key = _get_env_credential(provider, "api_key")
    base_url = _get_env_credential(provider, "base_url")

    if not api_key:
        # Check if OAuth is available as alternative
        if _get_oauth_token(provider):
            raise LLMResolverError(
                f"Provider '{provider}' requires OAuth authentication. "
                f"Run 'cw oauth setup -p {provider}'"
            )
        raise LLMResolverError(
            f"No credentials found for provider '{provider}'. "
            f"Set environment variables or run 'cw oauth setup -p {provider}'"
        )

    return api_key, base_url, "env"


def get_llm_client(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    workspace: Optional[str] = None,
    prefer_oauth: bool = True,
) -> Dict[str, Any]:
    """Get configured LLM client parameters.

    This is the SINGLE SOURCE OF TRUTH for LLM configuration.
    All CLI LLM operations must use this function.

    Args:
        provider: LLM provider (e.g., 'openai', 'anthropic', 'openai_codex')
                 If None, uses LLM_PROVIDER env var or defaults to 'openai'
        model: Model name (e.g., 'gpt-4o', 'claude-3-opus')
               If None, uses LLM_MODEL env var or provider default
        workspace: Optional workspace/project context
        prefer_oauth: Whether to prefer OAuth credentials (default: True)

    Returns:
        Dictionary with LLM configuration:
        {
            'provider': str,
            'model': str,
            'api_key': str,  # Never log this!
            'base_url': Optional[str],
            'auth_method': 'oauth' | 'env',
            'workspace': Optional[str]
        }

    Raises:
        LLMResolverError: If client cannot be created
        PolicyViolationError: If operation violates policy

    Example:
        >>> config = get_llm_client(provider="openai_codex", model="gpt-4o")
        >>> print(f"Using {config['provider']} via {config['auth_method']}")
        >>> # Use config['api_key'] for LLM calls (never log it!)
    """
    # Determine provider
    if provider is None:
        provider = os.getenv("LLM_PROVIDER", "openai")

    provider = provider.lower()

    # Determine model
    if model is None:
        model = os.getenv("LLM_MODEL") or os.getenv("LITELLM_MODEL")
        if not model:
            # Provider defaults
            defaults = {
                "openai": "gpt-4o",
                "openai_codex": "gpt-4o",
                "anthropic": "claude-3-opus-20240229",
                "gemini": "gemini-1.5-pro",
                "gemini_cli": "gemini-1.5-pro",
            }
            model = defaults.get(provider, "gpt-4o")

    # Resolve credentials
    api_key, base_url, auth_method = _resolve_credentials(provider, prefer_oauth)

    if not api_key:
        raise LLMResolverError(f"Failed to resolve API key for provider '{provider}'")

    # Build configuration
    config = {
        "provider": provider,
        "model": model,
        "api_key": api_key,
        "base_url": base_url,
        "auth_method": auth_method,
        "workspace": workspace,
    }

    return config


def get_litellm_config(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    workspace: Optional[str] = None,
) -> Dict[str, str]:
    """Get LiteLLM-compatible configuration.

    Returns configuration in LiteLLM format for use with libraries
    that expect LiteLLM environment variables.

    Args:
        provider: LLM provider
        model: Model name
        workspace: Optional workspace

    Returns:
        Dictionary suitable for LiteLlm initialization:
        {
            'model': str,  # e.g., 'openai/gpt-4o'
            'api_key': str,
            'api_base': Optional[str]
        }
    """
    config = get_llm_client(provider, model, workspace)

    # Map to LiteLLM format
    litellm_config = {
        "model": f"{config['provider']}/{config['model']}",
        "api_key": config["api_key"],
    }

    if config.get("base_url"):
        litellm_config["api_base"] = config["base_url"]

    return litellm_config


def check_provider_available(provider: str) -> Tuple[bool, Optional[str]]:
    """Check if a provider is available for use.

    Args:
        provider: Provider name

    Returns:
        Tuple of (available, reason_if_not)
    """
    provider = provider.lower()

    # Check policy
    policy = get_policy()

    # Check OAuth availability
    if _get_oauth_token(provider):
        allowed, reason = policy.can_use_provider(provider, "oauth")
        if allowed:
            return True, None
        return False, reason

    # Check env var availability
    api_key = _get_env_credential(provider, "api_key")
    if api_key:
        allowed, reason = policy.can_use_provider(provider, "env")
        if allowed:
            return True, None
        return False, reason

    # Not available
    return False, f"No credentials found. Run 'cw oauth setup -p {provider}'"


def list_available_providers() -> Dict[str, Dict[str, Any]]:
    """List all available providers and their status.

    Returns:
        Dictionary mapping provider names to their status:
        {
            'openai_codex': {
                'available': True,
                'auth_method': 'oauth',
                'model': 'gpt-4o'
            },
            'openai': {
                'available': False,
                'reason': 'No credentials found'
            }
        }
    """
    all_providers = list(OAUTH_PROVIDERS.keys()) + list(ENV_MAPPINGS.keys())
    result = {}

    for provider in all_providers:
        available, reason = check_provider_available(provider)

        if available:
            # Get current config
            try:
                config = get_llm_client(provider)
                result[provider] = {
                    "available": True,
                    "auth_method": config["auth_method"],
                    "model": config["model"],
                }
            except Exception as e:
                result[provider] = {"available": False, "reason": str(e)}
        else:
            result[provider] = {"available": False, "reason": reason}

    return result
