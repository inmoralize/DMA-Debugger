"""
DMA Debugger Python API - Scriptable memory analysis and reverse engineering.

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


class DMA:
    """DMA interface for physical memory access."""

    def __init__(self):
        self._handle = None
        if _lib:
            _lib.dma_create.restype = ctypes.c_void_p
            self._handle = _lib.dma_create()

    def initialize(self, device: str = "fpga", remote: str = "") -> bool:
        if not self._handle or not _lib:
            return False
        _lib.dma_initialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        _lib.dma_initialize.restype = ctypes.c_int
        return bool(_lib.dma_initialize(
            self._handle,
            device.encode() if device else None,
            remote.encode() if remote else None
        ))

    def shutdown(self):
        if self._handle and _lib:
            _lib.dma_shutdown(self._handle)

    def is_initialized(self) -> bool:
        if not self._handle or not _lib:
            return False
        _lib.dma_is_initialized.restype = ctypes.c_int
        return bool(_lib.dma_is_initialized(self._handle))

    def read(self, addr: int, size: int) -> bytes:
        if not self._handle or not _lib:
            return b""
        buf = ctypes.create_string_buffer(size)
        _lib.dma_read.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
        _lib.dma_read.restype = ctypes.c_size_t
        n = _lib.dma_read(self._handle, addr, buf, size)
        return buf.raw[:n]

    def dump(self, path: str) -> int:
        if not self._handle or not _lib:
            return 0
        _lib.dma_dump.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _lib.dma_dump.restype = ctypes.c_uint64
        return _lib.dma_dump(self._handle, path.encode())


class DumpManager:
    """Memory dump manager."""

    def __init__(self, dma: DMA):
        self._dma = dma
        self._handle = None
        if _lib and dma._handle:
            _lib.dump_create.restype = ctypes.c_void_p
            self._handle = _lib.dump_create(dma._handle)

    def create_dump(self, path: str) -> bool:
        if not self._handle or not _lib:
            return False
        _lib.dump_create_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        return bool(_lib.dump_create_file(self._handle, path.encode()))

    def open(self, path: str) -> bool:
        if not self._handle or not _lib:
            return False
        _lib.dump_open.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        return bool(_lib.dump_open(self._handle, path.encode()))

    def read(self, addr: int, size: int) -> bytes:
        if not self._handle or not _lib:
            return b""
        buf = ctypes.create_string_buffer(size)
        _lib.dump_read.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
        _lib.dump_read.restype = ctypes.c_int
        n = _lib.dump_read(self._handle, addr, buf, size)
        return buf.raw[:n] if n > 0 else b""

    def close(self):
        if self._handle and _lib:
            _lib.dump_close(self._handle)


class Analysis:
    """Analysis API - processes, modules, pattern scanning."""

    def __init__(self, dma: DMA, dump: DumpManager = None):
        self._dma = dma
        self._dump = dump
        self._handle = None
        if _lib and dma._handle:
            _lib.analyzer_create.restype = ctypes.c_void_p
            self._handle = _lib.analyzer_create(
                dma._handle,
                dump._handle if dump else None
            )

    def list_processes(self, system_eprocess: int = 0):
        if not self._handle or not _lib or system_eprocess == 0:
            return []
        max_procs = 512
        name_buf_size = 64
        pids = (ctypes.c_uint32 * max_procs)()
        cr3s = (ctypes.c_uint64 * max_procs)()
        names = ctypes.create_string_buffer(max_procs * name_buf_size)
        _lib.analyzer_list_processes.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_char_p, ctypes.c_int, ctypes.c_int
        ]
        n = _lib.analyzer_list_processes(
            self._handle, system_eprocess,
            pids, cr3s, names, max_procs, name_buf_size
        )
        result = []
        for i in range(n):
            name = names[i * name_buf_size:(i + 1) * name_buf_size].decode(errors="ignore").strip("\x00")
            result.append({"pid": pids[i], "cr3": cr3s[i], "name": name})
        return result

    def modules(self, pid: int):
        if not self._handle or not _lib:
            return []
        max_mods = 1024
        bases = (ctypes.c_uint64 * max_mods)()
        sizes = (ctypes.c_uint64 * max_mods)()
        _lib.analyzer_find_pe.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_int
        ]
        n = _lib.analyzer_find_pe(self._handle, bases, sizes, max_mods)
        return [{"base": bases[i], "size": sizes[i]} for i in range(n)]

    def scan_pattern(self, pattern: bytes):
        if not self._handle or not _lib or not pattern:
            return []
        max_results = 4096
        results = (ctypes.c_uint64 * max_results)()
        buf = (ctypes.c_uint8 * len(pattern)).from_buffer_copy(pattern)
        _lib.analyzer_scan_pattern.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_int
        ]
        n = _lib.analyzer_scan_pattern(
            self._handle, buf, len(pattern), results, max_results
        )
        return list(results[:n])
