"""Throwaway test for R29 STEP 2 — proves a failing required check blocks merge.

This file and its branch are deleted without merging; see the PR description.
"""

import pytest


def test_intentionally_fails_to_prove_branch_protection_blocks_merge() -> None:
    pytest.fail("R29 STEP 2: intentional failure to prove required checks block merge")
