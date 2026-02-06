"""Bridge module providing access to the host CLI configuration manager."""
# Copyright (c) 2026 Crashwise
#
# Licensed under the MIT License. See the LICENSE file for details.


try:
    from crashwise_cli.config import ProjectConfigManager as _ProjectConfigManager
except ImportError:  # pragma: no cover - used when CLI not available
    class _ProjectConfigManager:  # type: ignore[no-redef]
        """Fallback implementation that raises a helpful error."""

        def __init__(self, *args, **kwargs):
            raise ImportError(
                "ProjectConfigManager is unavailable. Install the Crashwise CLI "
                "package or supply a compatible configuration object."
            )

    def __getattr__(name):  # pragma: no cover - defensive
        raise ImportError("ProjectConfigManager unavailable")

ProjectConfigManager = _ProjectConfigManager

__all__ = ["ProjectConfigManager"]
