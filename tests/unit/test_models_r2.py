# SPDX-License-Identifier: MIT
"""Unit tests for Milestone M2 data models and API request schemas."""
import pytest
from pydantic import ValidationError

from crashwise.api.main import CampaignCreateRequest
from crashwise.core.models import FuzzingInput, SetupTargetInput


def test_fuzzing_input_subdir_and_clone_depth() -> None:
    """Verify FuzzingInput handles target_name, target_subdir, target_clone_depth."""
    inp = FuzzingInput(
        target_repo="https://github.com/google/googletest",
        target_name="gtest",
        target_subdir="googletest",
        target_clone_depth=1,
    )
    assert inp.target_name == "gtest"
    assert inp.target_subdir == "googletest"
    assert inp.target_clone_depth == 1

    # Default clone depth is 1, target_subdir is None, target_name is None
    default_inp = FuzzingInput(target_repo="https://github.com/google/re2")
    assert default_inp.target_name is None
    assert default_inp.target_subdir is None
    assert default_inp.target_clone_depth == 1

    # Full clone depth = 0
    full_clone_inp = FuzzingInput(
        target_repo="https://github.com/google/re2",
        target_clone_depth=0,
    )
    assert full_clone_inp.target_clone_depth == 0


def test_fuzzing_input_validation_errors() -> None:
    """Verify invalid clone depth is rejected."""
    with pytest.raises(ValidationError):
        FuzzingInput(
            target_repo="https://github.com/google/re2",
            target_clone_depth=-1,
        )


def test_setup_target_input_subdir_and_clone_depth() -> None:
    """Verify SetupTargetInput supports target_name, target_subdir, and target_clone_depth."""
    inp = SetupTargetInput(
        target_repo="https://github.com/torvalds/linux",
        target_name="zlib",
        target_subdir="lib/zlib",
        target_clone_depth=0,
    )
    assert inp.target_name == "zlib"
    assert inp.target_subdir == "lib/zlib"
    assert inp.target_clone_depth == 0

    # Default values
    default_inp = SetupTargetInput(target_repo="https://github.com/DaveGamble/cJSON")
    assert default_inp.target_name is None
    assert default_inp.target_subdir is None
    assert default_inp.target_clone_depth == 1


def test_campaign_create_request_subdir_and_clone_depth() -> None:
    """Verify API CampaignCreateRequest parses target_subdir and target_clone_depth."""
    req = CampaignCreateRequest(
        target_repo="https://github.com/google/googletest",
        target_name="gtest",
        target_subdir="googletest",
        target_clone_depth=2,
    )
    assert req.target_subdir == "googletest"
    assert req.target_clone_depth == 2

    # Defaults
    default_req = CampaignCreateRequest(
        target_repo="https://github.com/google/re2",
        target_name="re2",
    )
    assert default_req.target_subdir is None
    assert default_req.target_clone_depth == 1
