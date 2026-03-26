"""Tests for device command template dictionaries.

Verifies that each template module is importable and exposes the expected
command-name keys so callers can rely on a stable interface.
"""

from __future__ import annotations

from netops.templates.brocade import HEALTH as BROCADE_HEALTH
from netops.templates.brocade import SHOW as BROCADE_SHOW
from netops.templates.nokia_sros import HEALTH as SROS_HEALTH
from netops.templates.nokia_sros import MD_CLI
from netops.templates.nokia_sros import SHOW as SROS_SHOW
from netops.templates.paloalto import HEALTH as PA_HEALTH
from netops.templates.paloalto import SHOW as PA_SHOW


class TestBrocadeTemplates:
    def test_show_contains_core_keys(self):
        for key in ("version", "interfaces", "routes", "bgp_summary"):
            assert key in BROCADE_SHOW

    def test_health_contains_core_keys(self):
        for key in ("cpu", "memory"):
            assert key in BROCADE_HEALTH

    def test_show_values_are_strings(self):
        assert all(isinstance(v, str) for v in BROCADE_SHOW.values())

    def test_health_values_are_strings(self):
        assert all(isinstance(v, str) for v in BROCADE_HEALTH.values())


class TestNokiaSROSTemplates:
    def test_show_contains_core_keys(self):
        for key in ("version", "interfaces", "routes", "bgp_summary"):
            assert key in SROS_SHOW

    def test_health_contains_core_keys(self):
        for key in ("cpu", "memory", "environment"):
            assert key in SROS_HEALTH

    def test_mdcli_contains_core_keys(self):
        for key in ("version", "interfaces", "bgp_summary"):
            assert key in MD_CLI

    def test_show_values_are_strings(self):
        assert all(isinstance(v, str) for v in SROS_SHOW.values())


class TestPaloAltoTemplates:
    def test_show_contains_core_keys(self):
        for key in ("system_info", "interfaces", "ha_state"):
            assert key in PA_SHOW

    def test_health_contains_core_keys(self):
        for key in ("resources", "session_info", "ha_state"):
            assert key in PA_HEALTH

    def test_show_values_are_strings(self):
        assert all(isinstance(v, str) for v in PA_SHOW.values())

    def test_health_values_are_strings(self):
        assert all(isinstance(v, str) for v in PA_HEALTH.values())
