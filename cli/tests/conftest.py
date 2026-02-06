"""Test configuration for CLI tests."""

import pytest


@pytest.fixture
def mock_console():
    """Mock rich console for testing."""
    from unittest.mock import Mock

    return Mock()


@pytest.fixture
def temp_config_dir(tmp_path):
    """Create temporary config directory."""
    config_dir = tmp_path / ".fuzzforge"
    config_dir.mkdir()
    return config_dir
