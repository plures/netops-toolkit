"""Bounded host facts and the existing packaging evaluator, without discovery.

This file is also the trusted prelude of the fixed isolated interpreter probes.
Keep it standalone: no project, plugin, network or service imports.
"""

from __future__ import annotations

import ctypes
import importlib
import inspect
import os
import platform
import sys
import sysconfig
from types import ModuleType
from typing import cast


class _ContextUnavailable(ValueError):
    """A factual input or the observed upstream interface is unavailable."""


def _windows_architectures() -> tuple[str, str]:
    """Read native/process machines for this process, including ARM64 emulation."""
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        current = kernel.GetCurrentProcess
        current.argtypes, current.restype = [], ctypes.c_void_p
        query = kernel.IsWow64Process2
        query.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort),
        ]
        query.restype = ctypes.c_int
        process, native = ctypes.c_ushort(), ctypes.c_ushort()
        # This is our own pseudo handle: no enumeration/open/close, PID lookup,
        # child creation, WMI or service call. Missing API is not a fallback.
        if not query(current(), ctypes.byref(process), ctypes.byref(native)):
            raise _ContextUnavailable("host-architecture-unavailable")
    except (OSError, AttributeError):
        raise _ContextUnavailable("host-architecture-unavailable") from None
    names = {0x014C: "x86", 0x01C0: "ARM", 0x01C4: "ARM",
             0x0200: "ia64", 0x8664: "AMD64", 0xAA64: "ARM64"}
    host = names.get(native.value)
    consuming = names.get(process.value or native.value)
    if host is None or consuming is None:
        raise _ContextUnavailable("host-architecture-unsupported")
    return host, consuming


def _host_architecture() -> str:
    """Read native host architecture, not environment claims or process bitness."""
    if sys.platform == "win32":
        return _windows_architectures()[0]
    if sys.platform not in ("linux", "darwin"):
        raise _ContextUnavailable("host-platform-unsupported")
    name = os.uname().machine
    if not name:
        raise _ContextUnavailable("host-architecture-unavailable")
    return name


def _marker_environment() -> dict[str, str]:
    """Observe this interpreter; absent facts are never empty-string substitutes."""
    result = {
        "implementation_name": sys.implementation.name,
        "os_name": os.name,
        "platform_machine": _host_architecture(),
        "platform_system": {"win32": "Windows", "linux": "Linux", "darwin": "Darwin"}[
            sys.platform
        ],
        "python_full_version": platform.python_version(),
        "platform_python_implementation": platform.python_implementation(),
        "python_version": ".".join(platform.python_version_tuple()[:2]),
        "sys_platform": sys.platform,
        "extra": "",
    }
    # implementation.version is distinct from the language version (e.g. PyPy).
    info = sys.implementation.version
    result["implementation_version"] = f"{info.major}.{info.minor}.{info.micro}"
    if info.releaselevel != "final":
        result["implementation_version"] += info.releaselevel[0] + str(info.serial)
    if sys.platform != "win32":
        host = os.uname()
        result.update(platform_release=host.release, platform_version=host.version)
    # Windows platform.release/version obtain WMI/shell facts. No equivalent
    # OS marketing-release/Version authority is established here. A marker
    # requiring either fact must reject, including in an otherwise inactive arm.
    return result


def _target_environment(
    target_platform: str, architecture: str, python_version: str,
) -> dict[str, str]:
    """Refuse to project this host's facts into an unobserved foreign target."""
    environment = _marker_environment()
    if (
        target_platform != environment["sys_platform"]
        or architecture != environment["platform_machine"]
        or python_version != environment["python_full_version"]
    ):
        raise _ContextUnavailable("independent-target-marker-facts-required")
    return environment


def _evaluate_marker(marker: object, environment: dict[str, str], extra: str = "") -> bool:
    """Use the actual upstream parsed tree, normalization, operators and repair."""
    origin = type(marker).__module__
    if origin not in ("packaging.markers", "pip._vendor.packaging.markers"):
        raise _ContextUnavailable("upstream-marker-interface-unavailable")
    upstream = importlib.import_module(origin)
    if type(marker) is not upstream.Marker:
        raise _ContextUnavailable("upstream-marker-interface-unavailable")
    evaluate = getattr(upstream, "_evaluate_markers", None)
    repair = getattr(upstream, "_repair_python_full_version", None)
    tree = getattr(marker, "_markers", None)
    # These are existing private Python interfaces, not a stable public ABI.
    # Refuse incompatible shapes rather than porting a grammar or guessing.
    if (
        type(tree) is not list or not callable(evaluate) or not callable(repair)
        or tuple(inspect.signature(evaluate).parameters) != ("markers", "environment")
        or tuple(inspect.signature(repair).parameters) != ("env",)
    ):
        raise _ContextUnavailable("upstream-marker-interface-unavailable")
    current = dict(environment, extra=extra)
    try:
        result = evaluate(tree, repair(current))
    except KeyError as error:
        raise _ContextUnavailable("marker-fact-unavailable:" + str(error.args[0])) from None
    if type(result) is not bool:
        raise _ContextUnavailable("upstream-marker-result-invalid")
    return cast(bool, result)


def _interpreter_tags(tags: ModuleType) -> tuple[object, ...]:
    """Keep upstream tag ordering, with explicit Windows process platforms."""
    if sys.platform != "win32":
        return tuple(tags.sys_tags())
    # sysconfig.get_platform on Windows uses the interpreter build, not
    # platform.machine/system or an environment architecture claim.
    process_platform = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    if process_platform not in ("win32", "win_amd64", "win_arm64", "win_ia64"):
        raise _ContextUnavailable("interpreter-platform-unsupported")
    platforms = [process_platform]
    interpreter_name = tags.interpreter_name()
    primary = (
        tags.cpython_tags(platforms=platforms)
        if interpreter_name == "cp" else tags.generic_tags(platforms=platforms)
    )
    # Match upstream sys_tags separately from generic_tags' primary interpreter.
    if interpreter_name == "pp":
        interpreter: str | None = "pp3"
    elif interpreter_name == "cp":
        interpreter = "cp" + tags.interpreter_version()
    else:
        interpreter = None
    return tuple(primary) + tuple(tags.compatible_tags(interpreter=interpreter, platforms=platforms))
