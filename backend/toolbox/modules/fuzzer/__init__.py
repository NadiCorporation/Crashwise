"""
Fuzzing modules for Crashwise

This package contains fuzzing modules for different fuzzing engines.
"""

from .atheris_fuzzer import AtherisFuzzer
from .cargo_fuzzer import CargoFuzzer

__all__ = ["AtherisFuzzer", "CargoFuzzer"]
