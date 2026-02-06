"""
Android Security Analysis Modules

Modules for Android application security testing:
- JadxDecompiler: APK decompilation using Jadx
- MobSFScanner: Mobile security analysis using MobSF
- OpenGrepAndroid: Static analysis using OpenGrep/Semgrep with Android-specific rules
"""

# Copyright (c) 2026 Crashwise
#
# Licensed under the MIT License. See the LICENSE file for details.

from .jadx_decompiler import JadxDecompiler
from .opengrep_android import OpenGrepAndroid

# MobSF is optional (not available on ARM64 platform)
try:
    from .mobsf_scanner import MobSFScanner
    __all__ = ["JadxDecompiler", "MobSFScanner", "OpenGrepAndroid"]
except ImportError:
    # MobSF dependencies not available (e.g., ARM64 platform)
    MobSFScanner = None
    __all__ = ["JadxDecompiler", "OpenGrepAndroid"]
