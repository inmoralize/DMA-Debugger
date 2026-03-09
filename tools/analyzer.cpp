/**
 * DMA Analyzer - Static analysis of memory dumps.
 * Usage: analyzer <dump_file> [--scan-pe] [--scan-pattern <hex>] [--strings] [--entropy]
 */

#include "dma_interface/dma_interface.hpp"
#include "memory_dump/dump_manager.hpp"
#include "static_analysis/static_analyzer.hpp"
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: analyzer <dump_file> [options]\n"
                     "  --scan-pe         Scan for PE images\n"
                     "  --scan-pattern <hex>  Scan for byte pattern (e.g. 48 8B 05)\n"
                     "  --strings [len]   Extract strings (min length, default 4)\n"
                     "  --entropy         Report high-entropy regions\n";
        return 1;
    }

    std::string path = argv[1];
    bool scan_pe = false;
    bool scan_strings = false;
    size_t min_str_len = 4;
    std::string pattern;
    bool scan_entropy = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--scan-pe") scan_pe = true;
        else if (arg == "--strings") {
            scan_strings = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') min_str_len = std::stoul(argv[++i]);
        } else if (arg == "--scan-pattern" && i + 1 < argc) pattern = argv[++i];
        else if (arg == "--entropy") scan_entropy = true;
    }

    dma::DMAInterface dma;
    dma::DumpManager dump(&dma);

    std::cout << "[*] Opening dump: " << path << "\n";
    if (!dump.open_dump(path)) {
        std::cerr << "[-] Failed to open dump\n";
        return 1;
    }

    dma::StaticAnalyzer analyzer(&dma, &dump);

    if (scan_pe || (argc == 2)) {
        scan_pe = true;
        std::cout << "[*] Scanning for PE images...\n";
        auto mods = analyzer.find_pe_images();
        std::cout << "[+] Found " << mods.size() << " PE images:\n";
        for (const auto& m : mods) {
            std::cout << "  0x" << std::hex << m.base_address << std::dec
                      << " " << m.name << " (" << m.size << " bytes)\n";
        }
    }

    if (!pattern.empty()) {
        std::cout << "[*] Scanning for pattern: " << pattern << "\n";
        std::vector<uint8_t> bytes;
        std::istringstream iss(pattern);
        std::string tok;
        while (iss >> tok) {
            if (tok == "?" || tok == "??") bytes.push_back(0);
            else bytes.push_back(static_cast<uint8_t>(std::stoul(tok, nullptr, 16)));
        }
        auto results = analyzer.scan_pattern("user", bytes, {});
        std::cout << "[+] Found " << results.size() << " matches\n";
        for (size_t i = 0; i < std::min(size_t(20), results.size()); ++i) {
            std::cout << "  0x" << std::hex << results[i].address << std::dec << "\n";
        }
        if (results.size() > 20) std::cout << "  ... and " << (results.size() - 20) << " more\n";
    }

    if (scan_strings) {
        std::cout << "[*] Extracting strings (min length " << min_str_len << ")...\n";
        auto hdr = dump.get_header();
        if (hdr) {
            auto strs = analyzer.extract_strings(0, hdr->total_memory, min_str_len);
            std::cout << "[+] Found " << strs.size() << " strings (showing first 50):\n";
            for (size_t i = 0; i < std::min(size_t(50), strs.size()); ++i) {
                std::string s = strs[i].value;
                if (s.size() > 60) s = s.substr(0, 57) + "...";
                std::cout << "  0x" << std::hex << strs[i].address << std::dec << " " << s << "\n";
            }
        }
    }

    dump.close();
    std::cout << "[*] Done.\n";
    return 0;
}
