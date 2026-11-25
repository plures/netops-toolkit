"""Explicitly collected ordered cases for the credential guard isolation regression."""

import socket
import subprocess
from unittest.mock import Mock, patch

from netops.core import bastion


def assert_original_ports(request):
    originals = request.config._credential_guard_originals
    assert (socket.socket, subprocess.Popen, bastion.active_bastion) == originals


def test_before_credential_modules(request):
    assert_original_ports(request)


def test_after_credential_modules(request):
    assert_original_ports(request)
    process = Mock()
    process.communicate.return_value = (b"owned-offline-probe", b"")
    process.poll.return_value = 0
    launcher = Mock()
    launcher.return_value.__enter__ = Mock(return_value=process)
    launcher.return_value.__exit__ = Mock(return_value=False)
    with patch.object(subprocess, "Popen", launcher):
        result = subprocess.run(["owned-offline-probe"], capture_output=True, check=True)
    assert result.stdout == b"owned-offline-probe"
    assert result.returncode == 0
    launcher.assert_called_once()
    assert_original_ports(request)
