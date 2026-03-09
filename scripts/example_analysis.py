#!/usr/bin/env python3
"""
Example DMA Debugger script - list processes and modules.
Run from project root with: python scripts/example_analysis.py
"""

import sys
from pathlib import Path

# Add python module to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripting" / "python"))

try:
    from dma_api import DMA, DumpManager, Analysis
except ImportError as e:
    print("Error: Could not load dma_api. Build the project first:")
    print("  mkdir build && cd build")
    print("  cmake .. && cmake --build . --config Release")
    print("  Copy dma_capi.dll to scripting/python/ or add build dir to PATH")
    sys.exit(1)


def main():
    print("DMA Debugger - Example Script")
    print("=" * 40)

    dma = DMA()
    if not dma.initialize(device="fpga"):
        print("DMA not available - trying dump analysis mode...")
        # For dump-only analysis, we still need the DLL but won't connect
        pass

    if dma.is_initialized():
        print("DMA connected")
        data = dma.read(0x1000, 64)
        print(f"Read 0x1000: {len(data)} bytes")
        if len(data) >= 2:
            print(f"  First bytes: {data[:16].hex()}")
    else:
        print("Using dump file for analysis...")

    # Open dump if exists
    dump_path = Path("memory.dmp")
    if dump_path.exists():
        dump = DumpManager(dma)
        if dump.open(str(dump_path)):
            print(f"\nOpened dump: {dump_path}")
            analysis = Analysis(dma, dump)
            mods = analysis.modules(0)
            print(f"Found {len(mods)} modules")
            for m in mods[:10]:
                print(f"  0x{m['base']:X} size={m['size']}")
        else:
            print("Failed to open dump")
    else:
        print("\nNo memory.dmp found. Create one with: dump_tool --output memory.dmp")


if __name__ == "__main__":
    main()
