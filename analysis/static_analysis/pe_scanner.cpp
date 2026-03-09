#include "pe_scanner.hpp"
#include "static_analyzer.hpp"
#include <cstring>
#include <algorithm>

namespace dma {

std::vector<PEModule> PEScanner::scan_for_pe(StaticAnalyzer* analyzer) {
    std::vector<PEModule> result;
    uint64_t scan_start = 0;
    uint64_t scan_end = 0;

    if (analyzer) {
        // Use full memory range - would need analyzer->get_scan_range()
        scan_end = 16ULL * 1024 * 1024 * 1024;  // 16GB default
    }

    const size_t chunk = 4 * 1024 * 1024;  // 4MB scan chunks
    std::vector<uint8_t> buf(chunk);

    for (uint64_t addr = scan_start; addr < scan_end; addr += chunk - 0x1000) {
        size_t to_read = std::min(chunk, scan_end - addr);
        auto data = analyzer->read_region(addr, to_read);
        if (data.size() < 64) continue;

        for (size_t i = 0; i + 64 <= data.size(); i += 0x1000) {
            if (data[i] == 'M' && data[i + 1] == 'Z') {
                if (!analyzer->is_pe_header(data.data() + i, data.size() - i))
                    continue;

                PEModule mod;
                mod.base_address = addr + i;
                mod.size = 0x10000;  // Will be refined
                mod.name = "unknown";
                mod.path = "";
                mod.is_64bit = false;
                mod.is_kernel = (addr < 0xFFFF800000000000);

                uint32_t pe_off = *reinterpret_cast<uint32_t*>(data.data() + i + 0x3C);
                if (i + pe_off + 24 < data.size()) {
                    const uint8_t* pe = data.data() + i + pe_off;
                    uint16_t machine = *reinterpret_cast<const uint16_t*>(pe + 4);
                    mod.is_64bit = (machine == 0x8664 || machine == 0xAA64);
                }
                result.push_back(mod);
                i += 0x1000 - 1;
            }
        }
    }
    return result;
}

void PEScanner::enrich_module(PEModule& mod, const uint8_t* header_data) {
    if (!header_data || header_data[0] != 'M' || header_data[1] != 'Z') return;

    uint32_t pe_off = *reinterpret_cast<const uint32_t*>(header_data + 0x3C);
    const uint8_t* pe = header_data + pe_off;
    if (pe_off + 248 > 0x1000) return;

    uint16_t machine = *reinterpret_cast<const uint16_t*>(pe + 4);
    mod.is_64bit = (machine == 0x8664 || machine == 0xAA64);

    uint16_t num_sections = *reinterpret_cast<const uint16_t*>(pe + 6);
    uint16_t opt_header_size = *reinterpret_cast<const uint16_t*>(pe + 20);
    uint32_t opt_header_off = pe_off + 24;

    if (opt_header_off + opt_header_size + 40 * num_sections > 0x1000) return;

    uint32_t size_of_image = 0;
    if (opt_header_size >= 56) {
        size_of_image = *reinterpret_cast<const uint32_t*>(pe + opt_header_off + 56);
    }
    if (size_of_image > 0) mod.size = size_of_image;

    uint32_t export_rva = 0;
    if (opt_header_size >= 112) {
        export_rva = *reinterpret_cast<const uint32_t*>(pe + opt_header_off + 96);
    }
    if (export_rva) {
        uint32_t export_dir_off = export_rva;
        if (export_dir_off < 0x1000) {
            uint32_t name_rva = *reinterpret_cast<const uint32_t*>(header_data + export_dir_off + 12);
            if (name_rva < 0x1000 && name_rva > 0) {
                const char* name = reinterpret_cast<const char*>(header_data + name_rva);
                size_t len = 0;
                while (len < 256 && name[len]) len++;
                if (len > 0) mod.name = std::string(name, len);
            }
        }
    }
}

} // namespace dma
