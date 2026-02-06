# Copyright (c) 2026 Crashwise
#
# Licensed under the MIT License. See the LICENSE file for details.

"""
System information endpoints for Crashwise API.

Provides system configuration and filesystem paths to CLI for worker management.
"""

import os
from typing import Dict

from fastapi import APIRouter

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/info")
async def get_system_info() -> Dict[str, str]:
    """
    Get system information including host filesystem paths.

    This endpoint exposes paths needed by the CLI to manage workers via docker-compose.
    The CRASHWISE_HOST_ROOT environment variable is set by docker-compose and points
    to the Crashwise installation directory on the host machine.

    Returns:
        Dictionary containing:
        - host_root: Absolute path to Crashwise root on host
        - docker_compose_path: Path to docker-compose.yml on host
        - workers_dir: Path to workers directory on host
    """
    host_root = os.getenv("CRASHWISE_HOST_ROOT", "")

    return {
        "host_root": host_root,
        "docker_compose_path": f"{host_root}/docker-compose.yml" if host_root else "",
        "workers_dir": f"{host_root}/workers" if host_root else "",
    }
