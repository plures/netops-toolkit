"""
Unit tests for netops.playbooks.generator and netops.playbooks.templates.

All tests are self-contained — no real device connections or network I/O.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from netops.playbooks.generator import (
    FailureType,
    GeneratedPlaybook,
    _build_play,
    extract_failures,
    generate_playbook,
    generate_playbooks_from_report,
)
from netops.playbooks.templates.remediation import (
    REMEDIATION_TEMPLATES,
    VENDOR_COMMAND_MODULE,
    VENDOR_CONFIG_MODULE,
    RemediationTemplate,
    get_template,
)

# ---------------------------------------------------------------------------
# Shared fixtures / test data
# ---------------------------------------------------------------------------

CISCO_IOS = "cisco_ios"
ARISTA_EOS = "arista_eos"
JUNIPER_JUNOS = "juniper_junos"

# Minimal successful health result with a CPU alert
_CPU_ALERT_RESULT = {
    "host": "router-01",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": True,
    "device_type": CISCO_IOS,
    "checks": {
        "cpu": {"utilization": 92.5, "threshold": 80.0, "alert": True, "raw": {}},
        "memory": {"utilization": 55.0, "threshold": 85.0, "alert": False, "raw": {}},
        "interface_errors": {"interfaces": [], "total": 0, "with_errors": 0, "alert": False},
        "logs": {"critical_count": 0, "major_count": 0, "events": [], "alert": False},
    },
    "overall_alert": True,
    "error": None,
}

# Result with multiple alerts (interface errors + BGP down)
_MULTI_ALERT_RESULT = {
    "host": "switch-01",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": True,
    "device_type": ARISTA_EOS,
    "checks": {
        "cpu": {"utilization": 45.0, "threshold": 80.0, "alert": False, "raw": {}},
        "memory": {"utilization": 50.0, "threshold": 85.0, "alert": False, "raw": {}},
        "interface_errors": {
            "interfaces": [{"name": "Et1", "has_errors": True}],
            "total": 24,
            "with_errors": 1,
            "alert": True,
        },
        "bgp": {
            "peers": [{"neighbor": "10.0.0.1", "is_established": False}],
            "total": 1,
            "established": 0,
            "not_established": 1,
            "alert": True,
        },
        "logs": {"critical_count": 0, "major_count": 0, "events": [], "alert": False},
    },
    "overall_alert": True,
    "error": None,
}

# Healthy result — no alerts
_HEALTHY_RESULT = {
    "host": "core-01",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": True,
    "device_type": CISCO_IOS,
    "checks": {
        "cpu": {"utilization": 30.0, "threshold": 80.0, "alert": False, "raw": {}},
        "memory": {"utilization": 40.0, "threshold": 85.0, "alert": False, "raw": {}},
        "interface_errors": {"interfaces": [], "total": 0, "with_errors": 0, "alert": False},
        "logs": {"critical_count": 0, "major_count": 0, "events": [], "alert": False},
    },
    "overall_alert": False,
    "error": None,
}

# Failed (unreachable) device result
_FAILED_RESULT = {
    "host": "dead-01",
    "timestamp": "2024-03-24T12:00:00Z",
    "success": False,
    "checks": {},
    "overall_alert": False,
    "error": "Connection refused",
}

# Aggregated report (from build_health_report)
_HEALTH_REPORT = {
    "devices": 3,
    "devices_reachable": 2,
    "devices_with_alerts": 2,
    "cpu_alerts": 1,
    "memory_alerts": 0,
    "interface_error_alerts": 1,
    "log_alerts": 0,
    "overall_alert": True,
    "results": [_CPU_ALERT_RESULT, _MULTI_ALERT_RESULT, _HEALTHY_RESULT],
}


# ---------------------------------------------------------------------------
# FailureType enum
# ---------------------------------------------------------------------------


class TestFailureType:
    def test_values_are_strings(self):
        for ft in FailureType:
            assert isinstance(ft.value, str)

    def test_expected_failure_types_exist(self):
        assert FailureType.CPU_HIGH.value == "cpu_high"
        assert FailureType.MEMORY_HIGH.value == "memory_high"
        assert FailureType.INTERFACE_ERRORS.value == "interface_errors"
        assert FailureType.BGP_PEER_DOWN.value == "bgp_peer_down"
        assert FailureType.OSPF_NEIGHBOR_DOWN.value == "ospf_neighbor_down"
        assert FailureType.NTP_UNSYNC.value == "ntp_unsync"
        assert FailureType.ENVIRONMENT_ALERT.value == "environment_alert"
        assert FailureType.LOG_ALERTS.value == "log_alerts"


# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------


class TestRemediationTemplates:
    def test_all_failure_types_have_templates(self):
        for ft in FailureType:
            assert ft.value in REMEDIATION_TEMPLATES, f"No template for {ft}"

    def test_get_template_returns_remediation_template(self):
        tmpl = get_template("cpu_high")
        assert isinstance(tmpl, RemediationTemplate)

    def test_get_template_none_for_unknown(self):
        assert get_template("completely_unknown_check") is None

    def test_template_has_description(self):
        for name, tmpl in REMEDIATION_TEMPLATES.items():
            assert tmpl.description, f"Template {name} has empty description"

    def test_template_has_pre_commands(self):
        for name, tmpl in REMEDIATION_TEMPLATES.items():
            assert tmpl.pre_commands, f"Template {name} has no pre_commands"

    def test_commands_for_fallback_to_default(self):
        tmpl = get_template("cpu_high")
        assert tmpl is not None
        cmds = tmpl.commands_for("unknown_vendor_xyz", "pre")
        assert isinstance(cmds, list)
        assert len(cmds) > 0  # _default should supply commands

    def test_cisco_ios_has_specific_commands(self):
        tmpl = get_template("interface_errors")
        assert tmpl is not None
        cmds = tmpl.commands_for("cisco_ios", "remediation")
        assert any("clear" in c.lower() for c in cmds)

    def test_arista_eos_has_specific_commands(self):
        tmpl = get_template("bgp_peer_down")
        assert tmpl is not None
        cmds = tmpl.commands_for("arista_eos", "pre")
        assert any("bgp" in c.lower() for c in cmds)

    def test_juniper_has_specific_commands(self):
        tmpl = get_template("bgp_peer_down")
        assert tmpl is not None
        cmds = tmpl.commands_for("juniper_junos", "remediation")
        assert any("bgp" in c.lower() for c in cmds)

    def test_rollback_note_is_string(self):
        for name, tmpl in REMEDIATION_TEMPLATES.items():
            assert isinstance(tmpl.rollback_note, str), f"Template {name} rollback_note not str"


# ---------------------------------------------------------------------------
# Vendor module mappings
# ---------------------------------------------------------------------------


class TestVendorModuleMappings:
    def test_command_module_has_default(self):
        assert "_default" in VENDOR_COMMAND_MODULE

    def test_config_module_has_default(self):
        assert "_default" in VENDOR_CONFIG_MODULE

    def test_cisco_ios_command_module(self):
        assert VENDOR_COMMAND_MODULE["cisco_ios"] == "cisco.ios.ios_command"

    def test_arista_eos_command_module(self):
        assert VENDOR_COMMAND_MODULE["arista_eos"] == "arista.eos.eos_command"

    def test_juniper_command_module(self):
        assert VENDOR_COMMAND_MODULE["juniper_junos"] == "junipernetworks.junos.junos_command"

    def test_cisco_ios_config_module(self):
        assert VENDOR_CONFIG_MODULE["cisco_ios"] == "cisco.ios.ios_config"


# ---------------------------------------------------------------------------
# extract_failures
# ---------------------------------------------------------------------------


class TestExtractFailures:
    def test_cpu_alert_extracted(self):
        failures = extract_failures(_CPU_ALERT_RESULT)
        failure_types = [ft for ft, _ in failures]
        assert FailureType.CPU_HIGH in failure_types

    def test_healthy_result_no_failures(self):
        failures = extract_failures(_HEALTHY_RESULT)
        assert failures == []

    def test_multiple_alerts_all_extracted(self):
        failures = extract_failures(_MULTI_ALERT_RESULT)
        failure_types = [ft for ft, _ in failures]
        assert FailureType.INTERFACE_ERRORS in failure_types
        assert FailureType.BGP_PEER_DOWN in failure_types

    def test_failed_device_no_failures(self):
        # A failed (unreachable) device should not trigger remediation
        failures = extract_failures(_FAILED_RESULT)
        assert failures == []

    def test_bgp_evpn_deduped_with_bgp(self):
        result = {
            "host": "sw",
            "success": True,
            "checks": {
                "bgp": {"alert": True},
                "bgp_evpn": {"alert": True},
            },
        }
        failures = extract_failures(result)
        failure_types = [ft for ft, _ in failures]
        # Both map to BGP_PEER_DOWN but should only appear once
        assert failure_types.count(FailureType.BGP_PEER_DOWN) == 1

    def test_unknown_check_key_ignored(self):
        result = {
            "host": "sw",
            "success": True,
            "checks": {
                "some_new_check": {"alert": True},
            },
        }
        failures = extract_failures(result)
        assert failures == []

    def test_non_alerting_check_not_extracted(self):
        result = {
            "host": "sw",
            "success": True,
            "checks": {
                "cpu": {"utilization": 10, "threshold": 80, "alert": False},
                "logs": {"critical_count": 5, "alert": True},
            },
        }
        failures = extract_failures(result)
        failure_types = [ft for ft, _ in failures]
        assert FailureType.CPU_HIGH not in failure_types
        assert FailureType.LOG_ALERTS in failure_types

    def test_returns_check_detail_in_tuple(self):
        failures = extract_failures(_CPU_ALERT_RESULT)
        assert len(failures) > 0
        ft, detail = failures[0]
        assert isinstance(ft, FailureType)
        assert isinstance(detail, dict)


# ---------------------------------------------------------------------------
# generate_playbook
# ---------------------------------------------------------------------------


class TestGeneratePlaybook:
    def test_returns_generated_playbook(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert isinstance(pb, GeneratedPlaybook)

    def test_returns_none_for_healthy_device(self):
        pb = generate_playbook(_HEALTHY_RESULT)
        assert pb is None

    def test_returns_none_for_failed_device(self):
        pb = generate_playbook(_FAILED_RESULT)
        assert pb is None

    def test_host_matches(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        assert pb.host == "router-01"

    def test_vendor_taken_from_result(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        assert pb.vendor == CISCO_IOS

    def test_vendor_override(self):
        pb = generate_playbook(_CPU_ALERT_RESULT, vendor="cisco_ios_xr")
        assert pb is not None
        assert pb.vendor == "cisco_ios_xr"

    def test_failure_types_populated(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        assert FailureType.CPU_HIGH in pb.failure_types

    def test_plays_is_nonempty_list(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        assert isinstance(pb.plays, list)
        assert len(pb.plays) > 0

    def test_dry_run_default_true(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        assert pb.dry_run is True

    def test_dry_run_false_when_live(self):
        pb = generate_playbook(_CPU_ALERT_RESULT, dry_run=False)
        assert pb is not None
        assert pb.dry_run is False

    def test_playbook_id_is_uuid(self):
        import re

        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        assert re.match(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            pb.playbook_id,
        )

    def test_created_at_is_set(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        assert pb.created_at  # non-empty string

    def test_source_timestamp_propagated(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        assert pb.source_report_timestamp == "2024-03-24T12:00:00Z"

    def test_multi_failure_has_multiple_failure_types(self):
        pb = generate_playbook(_MULTI_ALERT_RESULT)
        assert pb is not None
        assert len(pb.failure_types) >= 2

    def test_generic_vendor_fallback(self):
        result = {**_CPU_ALERT_RESULT}
        result.pop("device_type", None)
        pb = generate_playbook(result)
        assert pb is not None
        assert pb.vendor == "_default"

    def test_no_pause_flag(self):
        pb = generate_playbook(_CPU_ALERT_RESULT, include_pause=False)
        assert pb is not None
        play = pb.plays[0]
        pause_tasks = [
            t for t in play["tasks"] if "ansible.builtin.pause" in str(t)
        ]
        assert pause_tasks == []

    def test_pause_included_by_default(self):
        pb = generate_playbook(_CPU_ALERT_RESULT, include_pause=True)
        assert pb is not None
        play = pb.plays[0]
        pause_tasks = [
            t for t in play["tasks"] if "ansible.builtin.pause" in t
        ]
        assert len(pause_tasks) > 0


# ---------------------------------------------------------------------------
# GeneratedPlaybook.to_yaml
# ---------------------------------------------------------------------------


class TestGeneratedPlaybookToYaml:
    def test_to_yaml_produces_string(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        yml = pb.to_yaml()
        assert isinstance(yml, str)
        assert len(yml) > 0

    def test_to_yaml_is_valid_yaml(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        yml = pb.to_yaml()
        parsed = yaml.safe_load(yml)
        assert isinstance(parsed, list)

    def test_to_yaml_contains_hosts_key(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        yml = pb.to_yaml()
        assert "hosts:" in yml

    def test_to_yaml_contains_tasks_key(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        yml = pb.to_yaml()
        assert "tasks:" in yml

    def test_to_yaml_dry_run_var_present(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        yml = pb.to_yaml()
        assert "dry_run" in yml

    def test_to_yaml_has_remediation_task_names(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        yml = pb.to_yaml()
        # CPU remediation should mention PRE-CHECK or REMEDIATE
        assert "PRE-CHECK" in yml or "REMEDIATE" in yml

    def test_to_yaml_multi_failure_has_block_rescue(self):
        pb = generate_playbook(_MULTI_ALERT_RESULT)
        assert pb is not None
        yml = pb.to_yaml()
        assert "block:" in yml
        assert "rescue:" in yml


# ---------------------------------------------------------------------------
# GeneratedPlaybook.to_dict
# ---------------------------------------------------------------------------


class TestGeneratedPlaybookToDict:
    def test_to_dict_returns_dict(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        d = pb.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_has_required_keys(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        d = pb.to_dict()
        for key in ("playbook_id", "host", "vendor", "failure_types", "dry_run", "plays"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_failure_types_are_strings(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        d = pb.to_dict()
        for ft in d["failure_types"]:
            assert isinstance(ft, str)

    def test_to_dict_json_serialisable(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        # Should not raise
        serialised = json.dumps(pb.to_dict())
        assert len(serialised) > 0


# ---------------------------------------------------------------------------
# generate_playbooks_from_report
# ---------------------------------------------------------------------------


class TestGeneratePlaybooksFromReport:
    def test_returns_list(self):
        result = generate_playbooks_from_report(_HEALTH_REPORT)
        assert isinstance(result, list)

    def test_generates_one_playbook_per_alerting_device(self):
        # _HEALTH_REPORT has 2 alerting devices (cpu + multi-alert)
        result = generate_playbooks_from_report(_HEALTH_REPORT)
        assert len(result) == 2

    def test_healthy_device_excluded(self):
        result = generate_playbooks_from_report(_HEALTH_REPORT)
        hosts = [pb.host for pb in result]
        assert "core-01" not in hosts

    def test_accepts_bare_list(self):
        result = generate_playbooks_from_report(
            [_CPU_ALERT_RESULT, _HEALTHY_RESULT, _FAILED_RESULT]
        )
        assert len(result) == 1  # Only the CPU-alert device
        assert result[0].host == "router-01"

    def test_host_filter_applied(self):
        result = generate_playbooks_from_report(_HEALTH_REPORT, host_filter="router")
        assert len(result) == 1
        assert result[0].host == "router-01"

    def test_host_filter_case_insensitive(self):
        result = generate_playbooks_from_report(_HEALTH_REPORT, host_filter="ROUTER")
        assert len(result) == 1

    def test_host_filter_no_match_returns_empty(self):
        result = generate_playbooks_from_report(_HEALTH_REPORT, host_filter="nonexistent-device")
        assert result == []

    def test_vendor_override_applied(self):
        result = generate_playbooks_from_report(_HEALTH_REPORT, vendor="cisco_ios_xr")
        for pb in result:
            assert pb.vendor == "cisco_ios_xr"

    def test_dry_run_propagated(self):
        result = generate_playbooks_from_report(_HEALTH_REPORT, dry_run=False)
        for pb in result:
            assert pb.dry_run is False

    def test_each_playbook_is_valid_yaml(self):
        result = generate_playbooks_from_report(_HEALTH_REPORT)
        for pb in result:
            yml = pb.to_yaml()
            parsed = yaml.safe_load(yml)
            assert isinstance(parsed, list)

    def test_failed_device_excluded(self):
        report = {"results": [_FAILED_RESULT]}
        result = generate_playbooks_from_report(report)
        assert result == []


# ---------------------------------------------------------------------------
# Ansible YAML structure validation
# ---------------------------------------------------------------------------


class TestAnsibleYamlStructure:
    """Validate that the generated YAML conforms to Ansible's expected structure."""

    def _get_play(self, vendor: str = CISCO_IOS) -> dict:
        result = {**_CPU_ALERT_RESULT, "device_type": vendor}
        pb = generate_playbook(result)
        assert pb is not None
        return yaml.safe_load(pb.to_yaml())[0]

    def test_play_has_name(self):
        play = self._get_play()
        assert "name" in play

    def test_play_has_hosts(self):
        play = self._get_play()
        assert "hosts" in play
        assert play["hosts"] == "router-01"

    def test_play_has_gather_facts_false(self):
        play = self._get_play()
        assert play.get("gather_facts") is False

    def test_play_has_vars(self):
        play = self._get_play()
        assert "vars" in play
        assert "dry_run" in play["vars"]

    def test_play_has_tasks(self):
        play = self._get_play()
        assert "tasks" in play
        assert isinstance(play["tasks"], list)

    def test_block_structure_present(self):
        result = {**_MULTI_ALERT_RESULT, "device_type": ARISTA_EOS}
        pb = generate_playbook(result)
        assert pb is not None
        play = yaml.safe_load(pb.to_yaml())[0]
        # At least one task should be a block
        block_tasks = [t for t in play["tasks"] if "block" in t]
        assert len(block_tasks) > 0

    def test_block_has_rescue(self):
        result = {**_MULTI_ALERT_RESULT, "device_type": ARISTA_EOS}
        pb = generate_playbook(result)
        assert pb is not None
        play = yaml.safe_load(pb.to_yaml())[0]
        block_tasks = [t for t in play["tasks"] if "block" in t]
        for bt in block_tasks:
            assert "rescue" in bt

    def test_vendor_module_appears_in_tasks(self):
        """Check the correct Ansible module is referenced for this vendor."""
        play = self._get_play(vendor=CISCO_IOS)
        task_yaml = yaml.dump(play["tasks"])
        assert "cisco.ios.ios_command" in task_yaml

    def test_arista_module_used_for_arista(self):
        result = {**_CPU_ALERT_RESULT, "device_type": ARISTA_EOS}
        pb = generate_playbook(result)
        assert pb is not None
        play_yaml = pb.to_yaml()
        assert "arista.eos.eos_command" in play_yaml

    def test_juniper_module_used_for_juniper(self):
        result = {**_CPU_ALERT_RESULT, "device_type": JUNIPER_JUNOS}
        pb = generate_playbook(result)
        assert pb is not None
        play_yaml = pb.to_yaml()
        assert "junipernetworks.junos.junos_command" in play_yaml

    def test_remediation_task_has_when_condition(self):
        """Remediation tasks must be guarded by 'when: not dry_run | bool'."""
        result = {**_MULTI_ALERT_RESULT, "device_type": CISCO_IOS}
        pb = generate_playbook(result)
        assert pb is not None
        play = yaml.safe_load(pb.to_yaml())[0]

        def _find_whens(tasks: list) -> list[str]:
            whens = []
            for t in tasks:
                if "when" in t:
                    whens.append(t["when"])
                if "block" in t:
                    whens.extend(_find_whens(t["block"]))
                if "rescue" in t:
                    whens.extend(_find_whens(t["rescue"]))
            return whens

        whens = _find_whens(play["tasks"])
        # At least one task should be guarded
        assert any("dry_run" in w for w in whens)

    def test_pre_check_registers_variable(self):
        pb = generate_playbook(_CPU_ALERT_RESULT)
        assert pb is not None
        play = yaml.safe_load(pb.to_yaml())[0]

        def _find_registers(tasks: list) -> list[str]:
            regs = []
            for t in tasks:
                if "register" in t:
                    regs.append(t["register"])
                if "block" in t:
                    regs.extend(_find_registers(t["block"]))
            return regs

        registers = _find_registers(play["tasks"])
        assert any(r.startswith("pre_") for r in registers)


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestCLI:
    def _write_report(self, tmp_dir: Path, data: dict) -> Path:
        p = tmp_dir / "report.json"
        p.write_text(json.dumps(data))
        return p

    def test_generate_prints_yaml_to_stdout(self, capsys):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = self._write_report(Path(tmp), _HEALTH_REPORT)
            from netops.playbooks.generator import _build_parser, _handle_generate

            parser = _build_parser()
            args = parser.parse_args(["generate", "--from-health-report", str(report_path)])
            _handle_generate(args)

        captured = capsys.readouterr()
        assert "hosts:" in captured.out

    def test_generate_writes_yaml_files_to_output_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            report_path = self._write_report(tmp_path, _HEALTH_REPORT)
            out_dir = tmp_path / "playbooks"

            from netops.playbooks.generator import _build_parser, _handle_generate

            parser = _build_parser()
            args = parser.parse_args(
                [
                    "generate",
                    "--from-health-report",
                    str(report_path),
                    "--output-dir",
                    str(out_dir),
                ]
            )
            _handle_generate(args)

            yml_files = list(out_dir.glob("*.yml"))
            assert len(yml_files) == 2  # two alerting devices

    def test_generate_json_output_to_output_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            report_path = self._write_report(tmp_path, _HEALTH_REPORT)
            out_dir = tmp_path / "playbooks"

            from netops.playbooks.generator import _build_parser, _handle_generate

            parser = _build_parser()
            args = parser.parse_args(
                [
                    "generate",
                    "--from-health-report",
                    str(report_path),
                    "--output-dir",
                    str(out_dir),
                    "--json",
                ]
            )
            _handle_generate(args)

            json_files = list(out_dir.glob("*.json"))
            assert len(json_files) == 2

    def test_generate_host_filter(self, capsys):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = self._write_report(Path(tmp), _HEALTH_REPORT)

            from netops.playbooks.generator import _build_parser, _handle_generate

            parser = _build_parser()
            args = parser.parse_args(
                [
                    "generate",
                    "--from-health-report",
                    str(report_path),
                    "--host",
                    "router",
                ]
            )
            _handle_generate(args)

        captured = capsys.readouterr()
        assert "router-01" in captured.out
        assert "switch-01" not in captured.out

    def test_generate_no_alerts_prints_message(self, capsys):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = self._write_report(
                Path(tmp),
                {"results": [_HEALTHY_RESULT]},
            )

            from netops.playbooks.generator import _build_parser, _handle_generate

            parser = _build_parser()
            args = parser.parse_args(
                ["generate", "--from-health-report", str(report_path)]
            )
            _handle_generate(args)

        captured = capsys.readouterr()
        assert "No alerting" in captured.out

    def test_generate_missing_file_exits(self):
        from netops.playbooks.generator import _build_parser, _handle_generate

        parser = _build_parser()
        args = parser.parse_args(
            ["generate", "--from-health-report", "/nonexistent/report.json"]
        )
        with pytest.raises(SystemExit):
            _handle_generate(args)

    def test_generate_live_flag_sets_dry_run_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            report_path = self._write_report(tmp_path, _HEALTH_REPORT)
            out_dir = tmp_path / "playbooks"

            from netops.playbooks.generator import _build_parser, _handle_generate

            parser = _build_parser()
            args = parser.parse_args(
                [
                    "generate",
                    "--from-health-report",
                    str(report_path),
                    "--output-dir",
                    str(out_dir),
                    "--live",
                ]
            )
            _handle_generate(args)

            for f in out_dir.glob("*.yml"):
                content = f.read_text()
                assert "dry_run: 'false'" in content or 'dry_run: "false"' in content

    def test_vendor_override_in_output(self, capsys):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = self._write_report(Path(tmp), {"results": [_CPU_ALERT_RESULT]})

            from netops.playbooks.generator import _build_parser, _handle_generate

            parser = _build_parser()
            args = parser.parse_args(
                [
                    "generate",
                    "--from-health-report",
                    str(report_path),
                    "--vendor",
                    "cisco_ios_xr",
                ]
            )
            _handle_generate(args)

        captured = capsys.readouterr()
        assert "cisco.iosxr.iosxr_command" in captured.out

    def test_output_files_are_valid_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            report_path = self._write_report(tmp_path, _HEALTH_REPORT)
            out_dir = tmp_path / "playbooks"

            from netops.playbooks.generator import _build_parser, _handle_generate

            parser = _build_parser()
            args = parser.parse_args(
                [
                    "generate",
                    "--from-health-report",
                    str(report_path),
                    "--output-dir",
                    str(out_dir),
                ]
            )
            _handle_generate(args)

            for f in out_dir.glob("*.yml"):
                parsed = yaml.safe_load(f.read_text())
                assert isinstance(parsed, list)


# ---------------------------------------------------------------------------
# _build_play internal tests
# ---------------------------------------------------------------------------


class TestBuildPlay:
    def test_play_structure_keys(self):
        failures = [(FailureType.CPU_HIGH, {})]
        play = _build_play("myhost", CISCO_IOS, failures, dry_run=True, include_pause=True)
        assert play["hosts"] == "myhost"
        assert play["gather_facts"] is False
        assert "vars" in play
        assert "tasks" in play

    def test_empty_failures_produces_empty_tasks_with_pause(self):
        play = _build_play("myhost", CISCO_IOS, [], dry_run=True, include_pause=True)
        # Only the pause task; no remediation blocks
        assert len(play["tasks"]) == 1

    def test_dry_run_true_in_vars(self):
        failures = [(FailureType.LOG_ALERTS, {})]
        play = _build_play("h", CISCO_IOS, failures, dry_run=True, include_pause=False)
        assert play["vars"]["dry_run"] == "true"

    def test_dry_run_false_in_vars(self):
        failures = [(FailureType.LOG_ALERTS, {})]
        play = _build_play("h", CISCO_IOS, failures, dry_run=False, include_pause=False)
        assert play["vars"]["dry_run"] == "false"
