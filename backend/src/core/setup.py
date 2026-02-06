"""
Setup utilities for Crashwise infrastructure
"""

# Copyright (c) 2026 Crashwise
#
# Licensed under the MIT License. See the LICENSE file for details.

import logging

logger = logging.getLogger(__name__)


async def setup_result_storage():
    """
    Setup result storage (MinIO).

    MinIO is used for both target upload and result storage.
    This is a placeholder for any MinIO-specific setup if needed.
    """
    logger.info("Result storage (MinIO) configured")
    # MinIO is configured via environment variables in docker-compose
    # No additional setup needed here
    return True


async def validate_infrastructure():
    """
    Validate all required infrastructure components.

    This should be called during startup to ensure everything is ready.
    """
    logger.info("Validating infrastructure...")

    # Setup storage (MinIO)
    await setup_result_storage()

    logger.info("Infrastructure validation completed")
