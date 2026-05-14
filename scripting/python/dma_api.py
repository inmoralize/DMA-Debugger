"""
DMA Debugger Python API - Scriptable memory analysis and reverse engineering.

ABI NOTE: The C API now uses a unified dma_context_t*. The old separate
dma_handle_t / dump_handle_t / analyzer_handle_t types are gone. All Python
classes below share the same underlying context pointer.

Example:
    from dma_api import DMA, Analysis

    dma = DMA()
    if dma.initialize(device="fpga"):
        data = dma.read(0x1000, 0x100)
        dma.dump("memory.dmp")
        dma.shutdown()

    analysis = Analysis(dma)
    for mod in analysis.modules(0):
        print(mod)
"""

import ctypes
import os
from pathlib import Path

# Load native library
_lib_path = Path(__file__).parent.parent / "build" / "scripting" / "dma_capi.dll"
if not _lib_path.exists():
    _lib_path = Path(__file__).parent.parent / "build" / "Release" / "dma_capi.dll"
if not _lib_path.exists():
    _lib_path = Path("dma_capi.dll")

try:
    _lib = ctypes.CDLL(str(_lib_path))
except OSError:
    _lib = None

if _lib:
    _lib.dma_create.restype = ctypes.c_void_p
    _lib.dma_destroy.argtypes = [ctypes.c_void_p]
    _lib.dma_initialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    _lib.dma_initialize.restype = ctypes.c_int
    _lib.dma_shutdown.argtypes = [ctypes.c_void_p]
    _lib.dma_is_initialized.argtypes = [ctypes.c_void_p]
    _lib.dma_is_initialized.restype = ctypes.c_int
    _lib.dma_read.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
    _lib.dma_read.restype = ctypes.c_size_t
    _lib.dma_dump.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    _lib.dma_dump.restype = ctypes.c_uint64
    _lib.dump_create_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    _lib.dump_create_file.restype = ctypes.c_int
    _lib.dump_open.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    _lib.dump_open.restype = ctypes.c_int
    _lib.dump_read.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
    _lib.dump_read.restype = ctypes.c_int
    _lib.dump_close.argtypes = [ctypes.c_void_p]
    _lib.dump_is_open.argtypes = [ctypes.c_void_p]
    _lib.dump_is_open.restype = ctypes.c_int
    _lib.analyzer_find_pe.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_int,
    ]
    _lib.analyzer_find_pe.restype = ctypes.c_int
    _lib.analyzer_scan_pattern.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_int,
    ]
    _lib.analyzer_scan_pattern.restype = ctypes.c_int
    _lib.analyzer_list_processes.argtypes = [
        ctypes.c_void_p, ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
    ]
    _lib.analyzer_list_processes.restype = ctypes.c_int


class DMA:
    """DMA interface for physical memory access. Owns the underlying dma_context_t."""

    def __init__(self):
        self._ctx = None
        if _lib:
            self._ctx = _lib.dma_create()

    def __del__(self):
        self.destroy()

    def destroy(self):
        if self._ctx and _lib:
            _lib.dma_destroy(self._ctx)
            self._ctx = None

    def initialize(self, device: str = "fpga", remote: str = "") -> bool:
        if not self._ctx or not _lib:
            return False
        return bool(_lib.dma_initialize(
            self._ctx,
            device.encode() if device else None,
            remote.encode() if remote else None,
        ))

    def shutdown(self):
        if self._ctx and _lib:
            _lib.dma_shutdown(self._ctx)

    def is_initialized(self) -> bool:
        return bool(self._ctx and _lib and _lib.dma_is_initialized(self._ctx))

    def read(self, addr: int, size: int) -> bytes:
        if not self._ctx or not _lib:
            return b""
        buf = ctypes.create_string_buffer(size)
        n = _lib.dma_read(self._ctx, addr, buf, size)
        return buf.raw[:n]

    def dump(self, path: str) -> int:
        if not self._ctx or not _lib:
            return 0
        return _lib.dma_dump(self._ctx, path.encode())


class DumpManager:
    """Dump manager view over the shared dma_context_t."""

    def __init__(self, dma: DMA):
        self._ctx = dma._ctx

    def create_dump(self, path: str) -> bool:
        if not self._ctx or not _lib:
            return False
        return bool(_lib.dump_create_file(self._ctx, path.encode()))

    def open(self, path: str) -> bool:
        if not self._ctx or not _lib:
            return False
        return bool(_lib.dump_open(self._ctx, path.encode()))

    def read(self, addr: int, size: int) -> bytes:
        if not self._ctx or not _lib:
            return b""
        buf = ctypes.create_string_buffer(size)
        n = _lib.dump_read(self._ctx, addr, buf, size)
        return buf.raw[:n] if n > 0 else b""

    def close(self):
        if self._ctx and _lib:
            _lib.dump_close(self._ctx)

    def is_open(self) -> bool:
        return bool(self._ctx and _lib and _lib.dump_is_open(self._ctx))


class Analysis:
    """Analysis API — processes, modules, pattern scanning."""

    def __init__(self, dma: DMA):
        self._ctx = dma._ctx

    def list_processes(self, system_eprocess: int = 0):
        if not self._ctx or not _lib or system_eprocess == 0:
            return []
        max_procs = 512
        name_buf_size = 64
        pids = (ctypes.c_uint32 * max_procs)()
        cr3s = (ctypes.c_uint64 * max_procs)()
        names = ctypes.create_string_buffer(max_procs * name_buf_size)
        n = _lib.analyzer_list_processes(
            self._ctx, system_eprocess,
            pids, cr3s, names, max_procs, name_buf_size,
        )
        result = []
        for i in range(n):
            name = names[i * name_buf_size:(i + 1) * name_buf_size].decode(errors="ignore").strip("\x00")
            result.append({"pid": pids[i], "cr3": cr3s[i], "name": name})
        return result

    def modules(self, pid: int):
        if not self._ctx or not _lib:
            return []
        max_mods = 1024
        bases = (ctypes.c_uint64 * max_mods)()
        sizes = (ctypes.c_uint64 * max_mods)()
        n = _lib.analyzer_find_pe(self._ctx, bases, sizes, max_mods)
        return [{"base": bases[i], "size": sizes[i]} for i in range(n)]

    def scan_pattern(self, pattern: bytes):
        if not self._ctx or not _lib or not pattern:
            return []
        max_results = 4096
        results = (ctypes.c_uint64 * max_results)()
        buf = (ctypes.c_uint8 * len(pattern)).from_buffer_copy(pattern)
        n = _lib.analyzer_scan_pattern(self._ctx, buf, len(pattern), results, max_results)
        return list(results[:n])
