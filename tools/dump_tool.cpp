/**
 * DMA Dump Tool - Full memory acquisition via DMA device.
 * Usage: dump_tool [--device fpga] [--remote <conn>] [--output memory.dmp]
 */

#include "dma_interface/dma_interface.hpp"
#include "memory_dump/dump_manager.hpp"
#include <iostream>
#include <string>
#include <chrono>

int main(int argc, char* argv[]) {
    std::string device = "fpga";
    std::string remote;
    std::string output = "memory.dmp";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--device" && i + 1 < argc) device = argv[++i];
        else if (arg == "--remote" && i + 1 < argc) remote = argv[++i];
        else if (arg == "--output" && i + 1 < argc) output = argv[++i];
        else if (arg == "--help" || arg == "-h") {
            std::cout << "DMA Dump Tool\n"
                         "Usage: dump_tool [options]\n"
                         "  --device <type>   DMA device type (fpga, pcileech, etc.)\n"
                         "  --remote <conn>   Remote connection string\n"
                         "  --output <path>   Output dump file path\n";
            return 0;
        }
    }

    dma::DMAInterface dma;
    dma::DMAInterface::Config cfg;
    cfg.device_type = device;
    cfg.remote = remote;

    std::cout << "[*] Initializing DMA device (" << device << ")...\n";
    if (!dma.initialize(cfg)) {
        std::cerr << "[-] Failed to initialize DMA. Ensure LeechCore is installed and device is connected.\n";
        return 1;
    }

    std::cout << "[*] Max physical address: 0x" << std::hex << dma.get_max_physical_address() << std::dec << "\n";
    std::cout << "[*] Dumping memory to " << output << "...\n";

    auto start = std::chrono::steady_clock::now();
    uint64_t total = 0;

    dma::DumpManager mgr(&dma);
    bool ok = mgr.create_dump(output, {}, [&](uint64_t done, uint64_t total_mem) {
        total = done;
        if (total_mem > 0 && (done % (64 * 1024 * 1024)) == 0 && done > 0) {
            std::cout << "\r[*] Progress: " << (done / (1024 * 1024)) << " MB / "
                      << (total_mem / (1024 * 1024)) << " MB";
        }
    });

    auto end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    dma.shutdown();

    if (ok) {
        std::cout << "\n[+] Dump complete: " << (total / (1024 * 1024)) << " MB in "
                  << (ms / 1000.0) << " s\n";
        return 0;
    } else {
        std::cerr << "\n[-] Dump failed\n";
        return 1;
    }
}
