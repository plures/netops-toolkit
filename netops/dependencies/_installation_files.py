"""New-object Windows installation security; never modify an existing ACL."""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from pathlib import Path

from netops.ansible import artifact_platform as platform

__all__: tuple[str, ...] = ()


def _create_private_tree(
    path: Path, *, _source_guard: Callable[[], None] | None = None,
) -> None:
    """Create an exclusive owner-only root whose children inherit owner-only access."""
    native = platform.windows()
    descriptor = ctypes.c_void_p()
    try:
        if not native.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            "O:" + native.sid + "D:P(A;OICI;FA;;;" + native.sid + ")",
            1, ctypes.byref(descriptor), None,
        ):
            raise OSError("installation-security-descriptor")
        # Reuse only the existing native security-attributes STRUCTURE, not
        # its non-inheriting DACL; every object here is newly created.
        with native._security() as attributes:
            attributes.descriptor = descriptor
            if _source_guard is not None:
                _source_guard()
            if not native.kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
                raise native._error()
    finally:
        if descriptor.value:
            native._free(descriptor)


def _private_windows(path: Path, *, directory: bool) -> None:
    """Check live no-reparse owner-only inherited access without altering it."""
    native = platform.windows()
    handle = native.kernel.CreateFileW(
        str(path), 0x20000 | 0x80, 7, None, 3, 0x02000000 | 0x00200000, None,
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        raise OSError("installation-security-open")
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    try:
        if native.advapi.GetSecurityInfo(
            handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None,
            ctypes.byref(descriptor),
        ) != 0 or not owner.value or not dacl.value or native._sid_string(owner) != native.sid:
            raise OSError("installation-security-owner")
        # ACL header AceCount is uint16 at offset four. A null/empty ACL is
        # never accepted; inherited owner allows are valid within this root.
        count = ctypes.c_uint16.from_address(dacl.value + 4).value
        if not 1 <= count <= 32:
            raise OSError("installation-security-acl")
        for index in range(count):
            ace = ctypes.c_void_p()
            if not native.advapi.GetAce(dacl, index, ctypes.byref(ace)) or not ace.value:
                raise OSError("installation-security-ace")
            header = (ctypes.c_ubyte * 4).from_address(ace.value)
            if header[0] != 0 or header[1] & 8 or native._sid_string(ace.value + 8) != native.sid:
                raise OSError("installation-security-access")
        attributes = native.kernel.GetFileAttributesW(str(path))
        if attributes == 0xFFFFFFFF or attributes & 0x400 or bool(attributes & 0x10) != directory:
            raise OSError("installation-security-type")
    finally:
        if descriptor.value:
            native._free(descriptor)
        if not native.kernel.CloseHandle(handle):
            raise OSError("installation-security-close")
