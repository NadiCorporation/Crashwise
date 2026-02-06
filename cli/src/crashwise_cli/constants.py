"""
Constants for Crashwise CLI.
"""
# Copyright (c) 2026 Crashwise
#
# Licensed under the MIT License. See the LICENSE file for details.


# Database constants
DEFAULT_DB_TIMEOUT = 30.0
DEFAULT_CLEANUP_DAYS = 90
STATS_SAMPLE_SIZE = 100

# Network constants
DEFAULT_API_TIMEOUT = 30.0
MAX_RETRIES = 3
RETRY_DELAY = 1.0
POLL_INTERVAL = 5.0

# Display constants
MAX_RUN_ID_DISPLAY_LENGTH = 15
MAX_DESCRIPTION_LENGTH = 50
MAX_DEFAULT_VALUE_LENGTH = 30

# Progress constants
PROGRESS_STEP_DELAYS = {
    "validating": 0.3,
    "connecting": 0.2,
    "uploading": 0.2,
    "creating": 0.3,
    "initializing": 0.2
}

# Status emojis
STATUS_EMOJIS = {
    "completed": "✅",
    "running": "🔄",
    "failed": "❌",
    "queued": "⏳",
    "cancelled": "⏹️",
    "pending": "📋",
    "unknown": "❓"
}

# Severity styles for Rich
SEVERITY_STYLES = {
    "error": "bold red",
    "warning": "bold yellow",
    "note": "bold blue",
    "info": "bold cyan"
}

# Default export formats
DEFAULT_EXPORT_FORMAT = "sarif"
SUPPORTED_EXPORT_FORMATS = ["sarif", "json", "csv"]

# Default configuration
DEFAULT_CONFIG = {
    "api_url": "http://localhost:8000",
    "timeout": DEFAULT_API_TIMEOUT,
    "max_retries": MAX_RETRIES,
}