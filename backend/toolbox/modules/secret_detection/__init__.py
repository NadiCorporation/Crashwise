"""
Secret Detection Modules

This package contains modules for detecting secrets, credentials, and sensitive information
in codebases and repositories.

Available modules:
- TruffleHog: Comprehensive secret detection with verification
- Gitleaks: Git-specific secret scanning and leak detection
- GitGuardian: Enterprise secret detection using GitGuardian API
- LLM Secret Detector: AI-powered semantic secret detection
"""
# Copyright (c) 2026 Crashwise
#
# Licensed under the MIT License. See the LICENSE file for details.


from typing import List, Type
from ..base import BaseModule

# Module registry for automatic discovery
SECRET_DETECTION_MODULES: List[Type[BaseModule]] = []

def register_module(module_class: Type[BaseModule]):
    """Register a secret detection module"""
    SECRET_DETECTION_MODULES.append(module_class)
    return module_class

def get_available_modules() -> List[Type[BaseModule]]:
    """Get all available secret detection modules"""
    return SECRET_DETECTION_MODULES.copy()