#include "static_analyzer.hpp"
#include "pe_scanner.hpp"
#include "pattern_scanner.hpp"
#include "../scanners/entropy_scanner.hpp"
#include "../../core/memory_dump/dump_manager.hpp"
#include "../../core/dma_interface/dma_interface.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>

namespace dma {

StaticAnalyzer::StaticAnalyzer(DMAInterface* dma, DumpManager* dump_mgr)
    : m_dma(dma), m_dump_mgr(dump_mgr) {}

void StaticAnalyzer::set_scan_range(uint64_t start, uint64_t end) {
    m_scan_start = start;
    m_scan_end = end;
}

std::vector<uint8_t> StaticAnalyzer::read_region(uint64_t addr, size_t size) {
    std::vector<uint8_t> buf(size);
    if (m_dump_mgr && m_dump_mgr->is_open()) {
        auto opt = m_dump_mgr->read(addr, size);
        if (opt) return *opt;
    }
    if (m_dma && m_dma->is_initialized()) {
        if (m_dma->read(addr, buf.data(), size) == size)
            return buf;
    }
    return {};
}

bool StaticAnalyzer::is_pe_header(const uint8_t* data, size_t size) {
    if (size < 64) return false;
    if (data[0] != 'M' || data[1] != 'Z') return false;
    uint32_t pe_offset = *reinterpret_cast<const uint32_t*>(data + 0x3C);
    if (pe_offset + 24 > size) return false;
    if (memcmp(data + pe_offset, "PE\0\0", 4) != 0) return false;
    return true;
}

std::vector<PEModule> StaticAnalyzer::find_pe_images() {
    return PEScanner::scan_for_pe(this);
}

std::vector<ScanResult> StaticAnalyzer::scan_pattern(const std::string& pattern_name,
                                                     const std::vector<uint8_t>& pattern,
                                                     const std::vector<uint8_t>& mask) {
    return PatternScanner::scan(this, pattern_name, pattern, mask);
}

std::vector<ScanResult> StaticAnalyzer::scan_pattern_ida(const std::string& pattern_name,
                                                        const std::string& ida_pattern) {
    auto [pattern, mask] = PatternScanner::parse_ida_pattern(ida_pattern);
    return scan_pattern(pattern_name, pattern, mask);
}

std::vector<ExtractedString> StaticAnalyzer::extract_strings(uint64_t base, size_t size,
                                                             size_t min_length) {
    auto data = read_region(base, size);
    if (data.empty()) return {};

    std::vector<ExtractedString> result;
    size_t i = 0;
    while (i < data.size()) {
        size_t start = i;
        while (i < data.size() && data[i] >= 0x20 && data[i] < 0x7F) i++;
        if (i - start >= min_length) {
            result.push_back({
                base + start,
                std::string(reinterpret_cast<char*>(data.data() + start), i - start),
                i - start
            });
        }
        while (i < data.size() && (data[i] < 0x20 || data[i] >= 0x7F)) i++;
    }
    return result;
}

std::vector<ExtractedString> StaticAnalyzer::extract_strings_wide(uint64_t base, size_t size,
                                                                  size_t min_length) {
    auto data = read_region(base, size);
    if (data.size() < min_length * 2) return {};

    std::vector<ExtractedString> result;
    size_t i = 0;
    while (i + 2 <= data.size()) {
        size_t start = i;
        while (i + 2 <= data.size()) {
            uint16_t w = data[i] | (data[i + 1] << 8);
            if (w >= 0x20 && w < 0x7F) {
                i += 2;
            } else {
                break;
            }
        }
        if ((i - start) / 2 >= min_length) {
            std::string s;
            for (size_t j = start; j < i; j += 2) {
                s += static_cast<char>(data[j]);
            }
            result.push_back({base + start, s, (i - start) / 2});
        }
        while (i + 2 <= data.size()) {
            uint16_t w = data[i] | (data[i + 1] << 8);
            if (w >= 0x20 && w < 0x7F) break;
            i += 2;
        }
    }
    return result;
}

std::vector<PEModule> StaticAnalyzer::locate_modules() {
    auto modules = find_pe_images();
    for (auto& m : modules) {
        auto data = read_region(m.base_address, 0x1000);
        if (data.size() >= 0x1000) {
            PEScanner::enrich_module(m, data.data());
        }
    }
    return modules;
}

std::vector<ScanResult> StaticAnalyzer::scan_yara(const std::string& rules_path) {
    (void)rules_path;
    // YARA integration - requires external yara library
    return {};
}

double StaticAnalyzer::get_entropy(uint64_t base, size_t size) {
    auto data = read_region(base, size);
    if (data.empty()) return 0;
    return EntropyScanner::calculate(data.data(), data.size());
}

} // namespace dma
