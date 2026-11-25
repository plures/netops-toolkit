"""Read exact owned suspended children and supply an independent native baseline."""

from __future__ import annotations

import ctypes
from ctypes import wintypes as w


class _Basic(ctypes.Structure):
    _fields_ = [
        ("reserved", ctypes.c_void_p), ("peb", ctypes.c_void_p),
        ("reserved2", ctypes.c_void_p * 2), ("pid", ctypes.c_size_t),
        ("reserved3", ctypes.c_void_p),
    ]


class _Startup(ctypes.Structure):
    _fields_ = [
        ("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR), ("title", w.LPWSTR),
        *[(name, w.DWORD) for name in (
            "x", "y", "xsize", "ysize", "xchars", "ychars", "fill", "flags",
        )],
        ("show", w.WORD), ("reserved_size", w.WORD), ("reserved2", ctypes.c_void_p),
        ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE),
    ]


class _StartupEx(ctypes.Structure):
    _fields_ = [("base", _Startup), ("attributes", ctypes.c_void_p)]


class _ProcessInfo(ctypes.Structure):
    _fields_ = [
        ("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD),
    ]


def suspended_environment(process):
    """Read only the caller's exact returned suspended child; never open a PID."""
    assert ctypes.sizeof(ctypes.c_void_p) == 8
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    nt = ctypes.WinDLL("ntdll")
    nt.NtQueryInformationProcess.argtypes = [
        w.HANDLE, w.ULONG, ctypes.c_void_p, w.ULONG, ctypes.POINTER(w.ULONG),
    ]
    nt.NtQueryInformationProcess.restype = w.LONG
    info, needed = _Basic(), w.ULONG()
    assert nt.NtQueryInformationProcess(
        process, 0, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(needed),
    ) == 0
    kernel.ReadProcessMemory.argtypes = [
        w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel.ReadProcessMemory.restype = w.BOOL

    def read(address, size):
        body, length = ctypes.create_string_buffer(size), ctypes.c_size_t()
        assert kernel.ReadProcessMemory(process, address, body, size, ctypes.byref(length))
        assert length.value == size
        return body.raw

    parameters = int.from_bytes(read(info.peb + 0x20, 8), "little")
    environment = int.from_bytes(read(parameters + 0x80, 8), "little")
    assert parameters and environment
    body = bytearray()
    for offset in range(0, 65536, 2):
        body.extend(read(environment + offset, 2))
        if body[-4:] == b"\0\0\0\0":
            break
    else:
        raise AssertionError("bounded exact child environment block")
    return dict(entry.split("=", 1) for entry in body.decode("utf-16-le").rstrip("\0").split("\0"))


def create_native(*args):
    """Use CreateProcessW, not Popen/_winapi, with the source's exact handle list."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel.InitializeProcThreadAttributeList.restype = w.BOOL
    kernel.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p, w.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    kernel.UpdateProcThreadAttribute.restype = w.BOOL
    kernel.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel.DeleteProcThreadAttributeList.restype = None
    kernel.CreateProcessW.argtypes = [
        w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD,
        ctypes.c_void_p, w.LPCWSTR, ctypes.POINTER(_StartupEx), ctypes.POINTER(_ProcessInfo),
    ]
    kernel.CreateProcessW.restype = w.BOOL
    assert args[2:5] == (None, None, True)
    inherited = args[8].lpAttributeList["handle_list"]
    assert inherited == [args[8].hStdInput, args[8].hStdOutput, args[8].hStdError]
    assert len(set(inherited)) == 3
    size = ctypes.c_size_t()
    kernel.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    attributes = ctypes.create_string_buffer(size.value)
    assert kernel.InitializeProcThreadAttributeList(attributes, 1, 0, ctypes.byref(size))
    try:
        handles = (w.HANDLE * 3)(*inherited)
        assert kernel.UpdateProcThreadAttribute(
            attributes, 0, 0x20002, handles, ctypes.sizeof(handles), None, None,
        )
        startup, result = _StartupEx(), _ProcessInfo()
        startup.base.cb = ctypes.sizeof(startup)
        startup.base.flags = args[8].dwFlags
        startup.base.stdin, startup.base.stdout, startup.base.stderr = inherited
        startup.attributes = ctypes.addressof(attributes)
        command = ctypes.create_unicode_buffer(args[1])
        block = ctypes.create_unicode_buffer(
            "\0".join(key + "=" + value for key, value in sorted(args[6].items())) + "\0\0",
        )
        assert kernel.CreateProcessW(
            args[0], command, None, None, True, args[5] | 0x80000 | 0x400,
            block, args[7], ctypes.byref(startup), ctypes.byref(result),
        ), ctypes.get_last_error()
        # Ownership transfers back to the real source job before ResumeThread.
        return result.process, result.thread, result.pid, result.tid
    finally:
        # Attribute-list memory is not a counted handle and is never reported as one.
        kernel.DeleteProcThreadAttributeList(attributes)
