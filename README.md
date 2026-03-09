# DMA Debugger

A DMA-based remote memory debugger and analysis environment for reverse engineering, memory inspection, and automated analysis of remote system memory. Runs on a secondary PC connected through a DMA PCIe device (e.g., PCILeech, FPGA DMA).

## Features

- **DMA Interface**: LeechCore integration for physical memory read/write, scatter-gather, caching, multi-threaded dumping
- **Memory Dump Manager**: Full, incremental, differential dumps with chunk indexing
- **Static Analysis**: PE scanning, pattern matching, IDA-style patterns, string extraction, entropy analysis
- **Dynamic Analysis**: Live region monitoring, snapshot diffing, hook detection
- **Symbol Resolver**: Page table walking, virtual-to-physical translation, EPROCESS/process list
- **Automated Intelligence**: Region scoring, RWX detection, manual map detection, high-entropy regions
- **Scripting**: Python API via ctypes for automation
- **Plugin System**: Extensible analysis plugins
- **GUI**: ImGui-based memory viewer with hex view, analysis tabs

## Requirements

- Windows 10/11 (64-bit)
- Visual Studio 2019+ or MSVC
- CMake 3.16+
- [LeechCore](https://github.com/ufrisk/LeechCore) (for live DMA - optional for dump analysis)
- DMA hardware (PCILeech, FPGA, etc.)

## Build

```bash
mkdir build && cd build
cmake .. -DLEECHCORE_ROOT=C:/path/to/LeechCore
cmake --build . --config Release
```

Without LeechCore (dump analysis only):

```bash
cmake .. -DBUILD_GUI=ON
cmake --build . --config Release
```

## Project Structure

```
/core          - DMA interface, memory dump, address translation
/analysis      - Static/dynamic analysis, scanners, symbol resolver, intelligence
/scripting     - C API, Python wrapper
/gui           - ImGui debugger UI
/plugins       - Plugin interface and example
/tools         - dump_tool, analyzer CLI
```

## Usage

### Dump Tool (CLI)

```bash
dump_tool --device fpga --output memory.dmp
```

### Analyzer (CLI)

```bash
analyzer memory.dmp --scan-pe --strings 6 --scan-pattern "48 8B 05 ?? ?? ?? ??"
```

### Python Scripting

```python
from python.dma_api import DMA, Analysis

dma = DMA()
if dma.initialize(device="fpga"):
    data = dma.read(0x1000, 0x100)
    dma.dump("memory.dmp")
    dma.shutdown()

# Analyze dump
dma = DMA()
dump = DumpManager(dma)
dump.open("memory.dmp")
analysis = Analysis(dma, dump)
for mod in analysis.modules(0):
    print(mod)
```

### GUI

```bash
dma_debugger_gui.exe
```

- File → Connect DMA / Open Dump
- Memory viewer with hex/ASCII
- Analysis tabs: Processes, Modules, Suspicious regions

## Performance Targets

- **16GB RAM dump**: < 60 seconds (multi-threaded, 8 workers)
- Chunk size: 64MB
- Page-aligned scatter reads for efficiency

## LeechCore Setup

1. Clone [LeechCore](https://github.com/ufrisk/LeechCore)
2. Build or obtain prebuilt `leechcore.dll` / `leechcore.lib`
3. Set `LEECHCORE_ROOT` to the installation path
4. Ensure `leechcore.dll` is in PATH when running

## License

MIT
