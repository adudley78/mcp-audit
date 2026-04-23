"""Tests for the centralised network policy enforcement module."""

from __future__ import annotations

import pytest
from click.exceptions import Exit as ClickExit

from mcp_audit._network import NetworkPolicy, require_offline_compatible


class TestNetworkPolicy:
    def test_no_features_any_network_false(self) -> None:
        policy = NetworkPolicy()
        assert policy.any_network is False

    def test_verify_hashes_any_network_true(self) -> None:
        assert NetworkPolicy(verify_hashes=True).any_network is True

    def test_check_vulns_any_network_true(self) -> None:
        assert NetworkPolicy(check_vulns=True).any_network is True

    def test_verify_signatures_any_network_true(self) -> None:
        assert NetworkPolicy(verify_signatures=True).any_network is True

    def test_connect_any_network_true(self) -> None:
        assert NetworkPolicy(connect=True).any_network is True


class TestRequireOfflineCompatible:
    def test_no_conflict_does_not_raise(self) -> None:
        policy = NetworkPolicy()
        require_offline_compatible(policy, offline=True)  # no exception

    def test_check_vulns_with_offline_raises(self) -> None:
        policy = NetworkPolicy(check_vulns=True)
        with pytest.raises(ClickExit):
            require_offline_compatible(policy, offline=True)

    def test_verify_hashes_with_offline_raises(self) -> None:
        policy = NetworkPolicy(verify_hashes=True)
        with pytest.raises(ClickExit):
            require_offline_compatible(policy, offline=True)

    def test_verify_signatures_with_offline_raises(self) -> None:
        policy = NetworkPolicy(verify_signatures=True)
        with pytest.raises(ClickExit):
            require_offline_compatible(policy, offline=True)

    def test_connect_with_offline_raises(self) -> None:
        policy = NetworkPolicy(connect=True)
        with pytest.raises(ClickExit):
            require_offline_compatible(policy, offline=True)

    def test_offline_false_never_raises(self) -> None:
        policy = NetworkPolicy(
            check_vulns=True,
            verify_hashes=True,
            verify_signatures=True,
            connect=True,
        )
        require_offline_compatible(policy, offline=False)  # no exception

    def test_multiple_conflicts_listed_in_message(self) -> None:
        policy = NetworkPolicy(verify_hashes=True, check_vulns=True)
        with pytest.raises(ClickExit) as exc_info:
            require_offline_compatible(policy, offline=True)
        assert exc_info.value.exit_code == 2
