"""Handle-pinned storage; explicit new private roots, never existing ACL repair."""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from functools import partial
from pathlib import Path
from typing import IO, cast

from netops.ansible.artifact_cleanup import release_all, teardown


def macos_acl(fd: int) -> None:
    """Reject every extended ACL rather than assuming mode bits override it."""
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.acl_get_fd_np.restype = ctypes.c_void_p
    libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    libc.acl_get_entry.restype = ctypes.c_int
    libc.acl_free.argtypes = [ctypes.c_void_p]
    libc.acl_valid.argtypes = [ctypes.c_void_p]
    acl = None
    try:
        acl = libc.acl_get_fd_np(fd, 0x00000100)  # ACL_TYPE_EXTENDED
        if not acl:
            raise OSError("protected-storage-unavailable")
        entry = ctypes.c_void_p()
        if libc.acl_valid(acl) != 0:
            raise OSError("protected-storage-acl")
        ctypes.set_errno(0)
        result = libc.acl_get_entry(acl, 0, ctypes.byref(entry))
        # Darwin returns zero for an entry and -1/EINVAL when a valid ACL is empty.
        if result != -1 or ctypes.get_errno() != errno.EINVAL:
            raise OSError("protected-storage-acl")
    finally:
        if acl:
            with teardown():
                if libc.acl_free(acl) == -1:
                    raise OSError("protected-storage-cleanup")


class _FileInfo(ctypes.Structure):
    _pack_ = 4
    _fields_ = [
        ("attributes", ctypes.c_uint32), ("created", ctypes.c_uint64),
        ("accessed", ctypes.c_uint64), ("written", ctypes.c_uint64),
        ("volume", ctypes.c_uint32), ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32), ("links", ctypes.c_uint32),
        ("index_high", ctypes.c_uint32), ("index_low", ctypes.c_uint32),
    ]


class _AclSize(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint32), ("used", ctypes.c_uint32), ("free", ctypes.c_uint32),
    ]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32), ("descriptor", ctypes.c_void_p),
        ("inherit", ctypes.c_int),
    ]


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("internal", ctypes.c_size_t), ("internal_high", ctypes.c_size_t),
        ("offset", ctypes.c_uint32), ("offset_high", ctypes.c_uint32),
        ("event", ctypes.c_void_p),
    ]


class WindowsHandles:
    """Native no-reparse handles with owner-only protected DACLs.

    All ancestor handles deny delete sharing for their lifetime. Path-based
    child opens therefore cannot be redirected by renaming/replacing a parent.
    New objects receive a protected owner-only DACL at creation, before bytes.
    """

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("protected-storage-platform")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        k, a = self.kernel, self.advapi
        k.CreateFileW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ]
        k.CreateFileW.restype = ctypes.c_void_p
        for name in ("CloseHandle", "FlushFileBuffers"):
            getattr(k, name).argtypes = [ctypes.c_void_p]
        k.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.POINTER(_FileInfo)]
        k.CreateDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_SecurityAttributes)]
        k.DeleteFileW.argtypes = [ctypes.c_wchar_p]
        k.RemoveDirectoryW.argtypes = [ctypes.c_wchar_p]
        k.MoveFileExW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        k.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
        k.GetFileAttributesW.restype = ctypes.c_uint32
        k.SetFileInformationByHandle.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
        ]
        k.GetCurrentProcess.restype = ctypes.c_void_p
        k.LocalFree.argtypes = [ctypes.c_void_p]
        a.OpenProcessToken.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
        ]
        a.GetTokenInformation.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        a.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ]
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        a.GetSecurityInfo.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        a.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint32),
        ]
        a.GetAclInformation.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
        ]
        a.GetAce.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
        k.ReadFile.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p,
        ]
        k.WriteFile.argtypes = list(k.ReadFile.argtypes)
        k.LockFileEx.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_uint32, ctypes.POINTER(_Overlapped),
        ]
        self._paths: dict[int, Path] = {}
        self._mutex = threading.RLock()
        self._locks = threading.local()
        self.sid = self._current_sid()

    @staticmethod
    def _error() -> OSError:
        code = ctypes.get_last_error()
        if code in (2, 3):
            error: OSError = FileNotFoundError("protected-storage-missing")
        elif code in (80, 183):
            error = FileExistsError("protected-storage-exists")
        elif code in (32, 33):
            error = BlockingIOError("protected-storage-busy")
        else:
            error = OSError("protected-storage-native")
        # Retain the actual numeric diagnostic internally, before a later
        # CloseHandle/LocalFree can overwrite the thread's last-error slot.
        # Safe public errors still contain no paths or native message text.
        error.winerror = code
        return error

    def _sid_string(self, sid: int | ctypes.c_void_p) -> str:
        output = ctypes.c_void_p()
        try:
            if not self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(output)):
                raise self._error()
            return ctypes.wstring_at(output)
        finally:
            if output.value:
                self._free(output)

    def _current_sid(self) -> str:
        token, size = ctypes.c_void_p(), ctypes.c_uint32()
        try:
            if not self.advapi.OpenProcessToken(
                self.kernel.GetCurrentProcess(), 8, ctypes.byref(token),
            ):
                raise self._error()
            self.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            buf = ctypes.create_string_buffer(size.value)
            if not self.advapi.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
                raise self._error()
            sid = ctypes.c_void_p.from_buffer(buf).value
            if sid is None:
                raise OSError("protected-storage-owner")
            return self._sid_string(sid)
        finally:
            if token.value:
                with teardown():
                    if not self.kernel.CloseHandle(token):
                        raise self._error()

    def _free(self, pointer: ctypes.c_void_p) -> None:
        with teardown():
            if self.kernel.LocalFree(pointer):
                raise self._error()

    @contextmanager
    def _security(self, *, inherit: bool = False) -> Iterator[_SecurityAttributes]:
        descriptor = ctypes.c_void_p()
        sddl = "O:" + self.sid + "D:P(A;" + ("OICI" if inherit else "") + ";FA;;;" + self.sid + ")"
        try:
            if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None,
            ):
                raise self._error()
            yield _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, 0)
        finally:
            if descriptor.value:
                self._free(descriptor)

    def prove(self, handle: int, directory: bool) -> _FileInfo:
        """Inspect the actual handle owner, protected DACL, reparse flag and link count."""
        info, owner, dacl, descriptor = _FileInfo(), ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        if not self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise self._error()
        if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
            raise OSError("protected-storage-type")
        if not directory and info.links != 1:
            raise OSError("protected-storage-links")
        try:
            if self.advapi.GetSecurityInfo(
                handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None,
                ctypes.byref(descriptor),
            ) != 0:
                raise OSError("protected-storage-security")
            control, revision = ctypes.c_uint16(), ctypes.c_uint32()
            if (
                self._sid_string(owner) != self.sid or not dacl.value
                or not self.advapi.GetSecurityDescriptorControl(
                    descriptor, ctypes.byref(control), ctypes.byref(revision),
                ) or not control.value & 0x1000
            ):
                raise OSError("protected-storage-owner")
            size = _AclSize()
            if not self.advapi.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), 2):
                raise self._error()
            if size.count == 0:
                raise OSError("protected-storage-acl")
            allowed = 0
            for index in range(size.count):
                ace = ctypes.c_void_p()
                if not self.advapi.GetAce(dacl, index, ctypes.byref(ace)) or ace.value is None:
                    raise self._error()
                header = (ctypes.c_ubyte * 4).from_address(ace.value)
                # Only simple, non-inherit-only owner allow ACEs are accepted.
                if header[0] != 0 or header[1] & 8 or self._sid_string(ace.value + 8) != self.sid:
                    raise OSError("protected-storage-acl")
                allowed |= ctypes.c_uint32.from_address(ace.value + 4).value
            if allowed & 0x1F01FF != 0x1F01FF:
                raise OSError("protected-storage-acl")
            return info
        finally:
            if descriptor.value:
                self._free(descriptor)

    def _open(
        self, path: Path, directory: bool, *, create: bool = False, prove: bool = True,
        delete: bool = False, write: bool = False,
    ) -> int:
        access = 0x20000 | 0x80 | (1 if directory else 0x80000000)
        if create or write:
            access |= 0x40000000
        if delete:
            access |= 0x10000
        handle = None
        try:
            with self._security() as security:
                handle = self.kernel.CreateFileW(
                    str(path), access, 3 if directory else 1,
                    ctypes.byref(security) if create else None,
                    1 if create else 3, 0x02000000 | 0x00200000, None,
                )
                if handle in (None, ctypes.c_void_p(-1).value):
                    raise self._error()
            result = int(handle)
            if prove:
                self.prove(result, directory)
            else:
                info = _FileInfo()
                if (
                    not self.kernel.GetFileInformationByHandle(result, ctypes.byref(info))
                    or info.attributes & 0x400 or not info.attributes & 0x10
                ):
                    raise OSError("protected-storage-ancestor")
            with self._mutex:
                self._paths[result] = path
            return result
        except BaseException:
            if handle is not None and handle != ctypes.c_void_p(-1).value:
                with teardown():
                    self.close(int(handle))
            raise

    def close(self, handle: int) -> None:
        """Release one native handle and its path binding."""
        with self._mutex:
            self._paths.pop(handle, None)
        if not self.kernel.CloseHandle(handle):
            raise self._error()

    @contextmanager
    def directory(self, path: str) -> Iterator[int]:
        """Pin every no-reparse ancestor; require owner protection on selected root."""
        value = Path(path)
        if (
            not value.is_absolute() or ".." in value.parts or str(value).startswith("\\\\")
            or any(":" in part or "\0" in part or part.endswith((".", " "))
                   for part in value.parts[1:])
        ):
            raise OSError("protected-storage-path")
        opened: list[int] = []
        try:
            current = Path(value.anchor)
            opened.append(self._open(current, True, prove=len(value.parts) == 1))
            for index, part in enumerate(value.parts[1:], 1):
                current /= part
                opened.append(self._open(current, True, prove=index == len(value.parts) - 1))
            yield opened[-1]
        finally:
            release_all(partial(self.close, handle) for handle in reversed(opened))

    def path(self, parent: int, name: str) -> Path:
        """Resolve only a single member under an already pinned protected handle."""
        if (
            not name or name in (".", "..") or name.endswith((".", " "))
            or Path(name).name != name or any(c in name for c in "/\\:\0")
        ):
            raise OSError("protected-storage-member")
        self.prove(parent, True)
        return self._paths[parent] / name

    def create_private_directory(self, path: str, *, inherit: bool = False) -> None:
        """Create only a new protected root beneath lifetime-pinned ancestors.

        Existing roots are never repaired or adopted. The caller must separately
        prove an existing root through ``directory``.
        """
        value = Path(path)
        if (
            not value.is_absolute() or len(value.parts) < 2 or ".." in value.parts
            or str(value).startswith("\\\\")
            or any(":" in part or "\0" in part or part.endswith((".", " "))
                   for part in value.parts[1:])
        ):
            raise OSError("protected-storage-path")
        opened: list[int] = []
        try:
            current = Path(value.anchor)
            opened.append(self._open(current, True, prove=False))
            for part in value.parts[1:-1]:
                current /= part
                opened.append(self._open(current, True, prove=False))
            with self._security(inherit=inherit) as security:
                if not self.kernel.CreateDirectoryW(str(value), ctypes.byref(security)):
                    raise self._error()
            opened.append(self._open(value, True))
        finally:
            release_all(partial(self.close, handle) for handle in reversed(opened))

    def open_directory(self, parent: int, name: str) -> int:
        """Open an existing private child without following a reparse point."""
        return self._open(self.path(parent, name), True)

    def mkdir(self, parent: int, name: str) -> None:
        """Create a private child atomically with its protected DACL."""
        path = self.path(parent, name)
        with self._security() as security:
            if not self.kernel.CreateDirectoryW(str(path), ctypes.byref(security)):
                raise self._error()
        handle = self._open(path, True)
        with teardown():
            self.close(handle)

    def info(self, handle: int) -> os.stat_result:
        """Return an identity snapshot only after handle-based protection proof."""
        info = self.prove(handle, True)
        return os.stat_result((
            stat.S_IFDIR | 0o700, info.index_high << 32 | info.index_low,
            info.volume, info.links, 0, 0, 0, 0, 0, 0,
        ))

    def read(self, parent: int, name: str, limit: int) -> bytes:
        """Read a pinned private single-link file with bounded stable content."""
        handle = self._open(self.path(parent, name), False)
        try:
            before = self.prove(handle, False)
            size = before.size_high << 32 | before.size_low
            if size > limit:
                raise OSError("protected-storage-size")
            buffer, count = ctypes.create_string_buffer(size + 1), ctypes.c_uint32()
            if not self.kernel.ReadFile(handle, buffer, size + 1, ctypes.byref(count), None):
                raise self._error()
            after = self.prove(handle, False)
            stable_fields = (
                "attributes", "created", "written", "volume", "size_high", "size_low",
                "links", "index_high", "index_low",
            )
            if count.value != size or any(
                getattr(before, field) != getattr(after, field) for field in stable_fields
            ):
                raise OSError("protected-storage-changed")
            return buffer.raw[:size]
        finally:
            with teardown():
                self.close(handle)

    @contextmanager
    def log(self, parent: int, name: str) -> Iterator[IO[str]]:
        """Open/truncate only a proved private log through its pinned native handle."""
        import msvcrt

        path = self.path(parent, name)
        try:
            handle = self._open(path, False, create=True)
        except FileExistsError:
            handle = self._open(path, False, write=True)
        fd = -1
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_WRONLY)
        except BaseException:
            self.close(handle)
            raise
        # Ownership transfers to the CRT file descriptor; native close must
        # not close that same handle again.
        with self._mutex:
            self._paths.pop(handle, None)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.ftruncate(stream.fileno(), 0)
            yield stream

    def write(self, parent: int, name: str, content: bytes) -> None:
        """Create with protection, verify it, then write and flush exact bytes."""
        handle = self._open(self.path(parent, name), False, create=True)
        try:
            count = ctypes.c_uint32()
            if not self.kernel.WriteFile(handle, content, len(content), ctypes.byref(count), None):
                raise self._error()
            if count.value != len(content) or not self.kernel.FlushFileBuffers(handle):
                raise OSError("protected-storage-write")
            self.prove(handle, False)
        finally:
            with teardown():
                self.close(handle)

    def rename(self, parent: int, source: str, dest: str, replace: bool) -> None:
        """Rename a verified handle to a destination under its lifetime-pinned parent."""
        src, dst = self.path(parent, source), self.path(parent, dest)
        attributes = self.kernel.GetFileAttributesW(str(src))
        if attributes == 0xFFFFFFFF:
            raise self._error()
        handle = self._open(src, bool(attributes & 0x10), delete=True)
        try:
            # SetFileInformationByHandle's FILE_RENAME_INFO requires a NULL
            # RootDirectory and an absolute filename. A non-NULL handle with
            # a relative name fails ERROR_INVALID_PARAMETER (87). The parent
            # and every ancestor remain open without delete sharing, so this
            # absolute destination cannot be redirected by a parent rename.
            # The source remains the verified no-reparse DELETE handle.
            destination = str(dst)
            encoded = destination.encode("utf-16-le")
            class _Rename(ctypes.Structure):
                _fields_ = [
                    ("replace", ctypes.c_uint32), ("parent", ctypes.c_void_p),
                    ("length", ctypes.c_uint32),
                    ("name", ctypes.c_uint16 * (len(encoded) // 2 + 1)),
                ]

            rename = _Rename(int(replace), None, len(encoded))
            ctypes.memmove(ctypes.addressof(rename) + _Rename.name.offset, encoded, len(encoded))
            if not self.kernel.SetFileInformationByHandle(
                handle, 3, ctypes.byref(rename), ctypes.sizeof(rename),
            ):
                raise self._error()
        finally:
            with teardown():
                self.close(handle)

    def remove(self, parent: int, name: str, directory: bool = False) -> None:
        """Delete only an exact already validated owned member."""
        path = self.path(parent, name)
        handle = self._open(path, directory, delete=True)
        try:
            disposition = ctypes.c_ubyte(1)
            if not self.kernel.SetFileInformationByHandle(
                handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition),
            ):
                raise self._error()
        finally:
            with teardown():
                self.close(handle)

    def names(self, handle: int) -> list[str]:
        """Enumerate an identity-pinned directory, never descend recursively."""
        self.prove(handle, True)
        return os.listdir(self._paths[handle])

    @contextmanager
    def lock(self, parent: int, names: tuple[str, ...], timeout: float) -> Iterator[None]:
        """Lock under the caller's identity-checked, lifetime-pinned root handle."""
        import msvcrt

        held = getattr(self._locks, "held", None)
        if held is None:
            held = {}
            self._locks.held = held
        identity = self.info(parent)
        acquired: list[tuple[int, int, str]] = []
        deadline = time.monotonic() + timeout
        try:
            for name in names:
                key = (identity.st_dev, identity.st_ino, name)
                if key in held:
                    stream, depth = held[key]
                    held[key] = (stream, depth + 1)
                    acquired.append(key)
                    continue
                member = self.path(parent, name)
                # The CRT owns this separately opened read/write native handle.
                native = None
                try:
                    with self._security() as security:
                        native = self.kernel.CreateFileW(
                            str(member), 0xC0020080, 3, ctypes.byref(security),
                            4, 0x00200000, None,
                        )
                        if native in (None, ctypes.c_void_p(-1).value):
                            raise self._error()
                    self.prove(int(native), False)
                    fd = msvcrt.open_osfhandle(int(native), os.O_RDWR | os.O_BINARY)
                except BaseException:
                    if native not in (None, ctypes.c_void_p(-1).value):
                        with teardown():
                            if not self.kernel.CloseHandle(native):
                                raise self._error()
                    raise
                try:
                    stream = os.fdopen(fd, "r+b", buffering=0)
                except BaseException:
                    with teardown():
                        os.close(fd)
                    raise
                try:
                    while True:
                        try:
                            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise BlockingIOError("protected-storage-busy") from None
                            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
                    held[key] = (stream, 1)
                    acquired.append(key)
                except BaseException:
                    with teardown():
                        stream.close()
                    raise
            yield
        finally:
            def release(key: tuple[int, int, str]) -> None:
                stream, depth = held[key]
                if depth == 1:
                    del held[key]
                    stream.close()
                else:
                    held[key] = (stream, depth - 1)

            release_all(partial(release, key) for key in reversed(acquired))


_WINDOWS: WindowsHandles | None = None
_WINDOWS_INIT = threading.Lock()


def windows() -> WindowsHandles:
    """Lazily bind native APIs without probing or mutating at import."""
    global _WINDOWS
    with _WINDOWS_INIT:
        if _WINDOWS is None:
            _WINDOWS = WindowsHandles()
        return _WINDOWS


def check_acl(fd: int) -> None:
    """Enforce extended-ACL exclusion when POSIX mode bits are insufficient."""
    if sys.platform == "darwin":
        macos_acl(fd)


def info(fd: int) -> os.stat_result:
    """Read actual protected identity on the selected platform."""
    if os.name == "nt":
        return windows().info(fd)
    check_acl(fd)
    return os.fstat(fd)


def close(fd: int) -> None:
    """Close the selected platform's owned handle."""
    if os.name == "nt":
        windows().close(fd)
    else:
        os.close(fd)


def sync(fd: int) -> None:
    """Flush a POSIX directory; Windows file data was flushed before rename."""
    if os.name != "nt":
        os.fsync(fd)


def open_directory(parent: int, name: str) -> int:
    """Open one no-follow child directory and inspect extended ACLs."""
    if os.name == "nt":
        return windows().open_directory(parent, name)
    fd = os.open(
        name, os.O_RDONLY | int(getattr(os, "O_DIRECTORY")) | int(getattr(os, "O_NOFOLLOW")),
        dir_fd=parent,
    )
    try:
        check_acl(fd)
        return fd
    except BaseException:
        with teardown():
            os.close(fd)
        raise


def mkdir(parent: int, name: str) -> None:
    """Create one owner-only child directory."""
    if os.name == "nt":
        windows().mkdir(parent, name)
    else:
        os.mkdir(name, 0o700, dir_fd=parent)


def rename(parent: int, source: str, dest: str, replace: bool = False) -> None:
    """Commit a same-root name change without cross-device fallback."""
    if os.name == "nt":
        windows().rename(parent, source, dest, replace)
    elif replace:
        os.replace(source, dest, src_dir_fd=parent, dst_dir_fd=parent)
    else:
        libc = ctypes.CDLL(None, use_errno=True)
        function = getattr(libc, "renameatx_np" if sys.platform == "darwin" else "renameat2", None)
        if function is None:
            raise OSError("protected-storage-atomic-noreplace-unavailable")
        function.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
        ]
        result = function(
            parent, os.fsencode(source), parent, os.fsencode(dest),
            4 if sys.platform == "darwin" else 1,
        )
        if result != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise FileExistsError("protected-storage-exists")
            if error == errno.ENOENT:
                raise FileNotFoundError("protected-storage-missing")
            raise OSError("protected-storage-atomic-noreplace")


def remove(parent: int, name: str, directory: bool = False) -> None:
    """Remove only one exact manifest member."""
    if os.name == "nt":
        windows().remove(parent, name, directory)
    elif directory:
        os.rmdir(name, dir_fd=parent)
    else:
        os.unlink(name, dir_fd=parent)


def names(fd: int) -> list[str]:
    """List names under a pinned directory."""
    return windows().names(fd) if os.name == "nt" else cast(list[str], os.listdir(fd))
