"""Actual WSL source boundary controls, never platform qualification."""

import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops.ansible import _controller_wsl as wsl
from netops.ansible._controller_pipe import _PipeFrames
from netops.ansible.controller_control import _Stop
from netops.ansible.controller_protocol import ProtocolError
from tests.test_nov19_coverage_wsl import case as case
from tests.test_nov19_independent_controller_execution import NONCE


def test_result_boundary_rejects_nonresult_kind_before_outcome_decoding(case):
    env, _, _, _, _ = case
    with pytest.raises(ProtocolError):
        wsl._accept_result({"kind": "pulse", "outcome": {}}, env[0])


@pytest.mark.parametrize("unknown_field", [False, True])
def test_pulse_uses_real_host_check_and_closed_message_fields(case, unknown_field):
    env, _, launch, frames, _ = case
    launch.control.ready(NONCE)
    message = {"kind": "pulse"}
    if unknown_field:
        message["credential"] = "forbidden-field"
        with pytest.raises(ProtocolError):
            wsl._control_message(frames, message, launch, _Stop(env[5]))
        assert frames.sent == []
    else:
        assert wsl._control_message(frames, message, launch, _Stop(env[5])) is None
        assert frames.sent == [{"kind": "alive"}]


@pytest.mark.parametrize("missing", ["stdin", "stdout", "neither"])
def test_owned_pipe_boundary_requires_both_streams_before_frame_construction(missing):
    # External streams only; no WSL launch, fake qualification or numeric PID.
    with io.BytesIO() as incoming, io.BytesIO() as outgoing:
        owner = SimpleNamespace(
            stdin=None if missing == "stdin" else outgoing,
            stdout=None if missing == "stdout" else incoming,
        )
        port = wsl._WslProcessIo()
        if missing != "neither":
            with pytest.raises(ProtocolError):
                port.frames(owner)
        else:
            channel = port.frames(owner)
            assert isinstance(channel, _PipeFrames)
            channel.close()


def test_launcher_size_guard_rejects_before_reading_unbounded_bytes(tmp_path, monkeypatch):
    candidate = tmp_path / "owned-launcher.exe"
    candidate.write_bytes(b"bounded")
    actual_lstat = Path.lstat

    def lstat(path):
        if path == candidate:
            return SimpleNamespace(
                st_mode=actual_lstat(path).st_mode, st_size=32 * 1024 * 1024 + 1,
            )
        return actual_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(ProtocolError):
        wsl._WslProcessIo().launcher_bytes(str(candidate))
    assert candidate.read_bytes() == b"bounded"


def test_launcher_digest_rejects_actual_owned_file_drift_between_identity_checks(
    tmp_path, monkeypatch,
):
    candidate = tmp_path / "owned-launcher.exe"
    candidate.write_bytes(b"before")
    actual_lstat = Path.lstat
    observations = 0

    def lstat(path):
        nonlocal observations
        if path == candidate:
            observations += 1
            if observations == 2:
                candidate.write_bytes(b"changed-owned-by-test")
        return actual_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(ProtocolError):
        wsl._WslProcessIo().launcher_bytes(str(candidate))
    assert observations >= 2
    assert candidate.read_bytes() == b"changed-owned-by-test"
