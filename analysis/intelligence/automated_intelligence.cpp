#include "automated_intelligence.hpp"
#include "../scanners/entropy_scanner.hpp"
#include <algorithm>
#include <cmath>

namespace dma {

std::vector<ScoredRegion> AutomatedIntelligence::analyze_regions(
    ReadCallback read_fn,
    const ModuleList& known_modules,
    uint64_t scan_start,
    uint64_t scan_end) {
    std::vector<ScoredRegion> result;
    const size_t page_size = 0x1000;
    const size_t chunk = 4 * 1024 * 1024;

    auto is_known = [&](uint64_t addr) {
        for (const auto& [base, size] : known_modules) {
            if (addr >= base && addr < base + size) return true;
        }
        return false;
    };

    for (uint64_t addr = scan_start; addr < scan_end; addr += chunk) {
        auto data = read_fn(addr, chunk);
        if (data.size() < 64) continue;

        for (size_t i = 0; i + 64 <= data.size(); i += page_size) {
            uint64_t page_addr = addr + i;
            if (is_known(page_addr)) continue;

            double entropy = EntropyScanner::calculate(data.data() + i, page_size);
            bool has_mz = (data[i] == 'M' && data[i + 1] == 'Z');
            bool high_entropy = entropy > 6.5;

            double score = 0;
            std::string reason;

            if (has_mz) {
                score += 3.0;
                reason += "PE_header ";
            }
            if (high_entropy) {
                score += 2.0;
                reason += "high_entropy ";
            }
            if (!is_known(page_addr) && has_mz) {
                score += 2.5;
                reason += "unknown_module ";
            }

            if (score > 0) {
                result.push_back({
                    page_addr,
                    page_size,
                    score,
                    reason,
                    false,
                    false,
                    high_entropy,
                    !is_known(page_addr),
                    false
                });
            }
        }
    }

    std::sort(result.begin(), result.end(),
              [](const ScoredRegion& a, const ScoredRegion& b) { return a.score > b.score; });
    return result;
}

std::vector<uint64_t> AutomatedIntelligence::find_rwx_pages(ReadCallback read_fn,
                                                            uint64_t start, uint64_t end) {
    (void)read_fn; (void)start; (void)end;
    return {};
}

std::vector<ScoredRegion> AutomatedIntelligence::find_high_entropy_regions(
    ReadCallback read_fn, uint64_t start, uint64_t end, double threshold) {
    std::vector<ScoredRegion> result;
    const size_t block = 0x1000;

    for (uint64_t addr = start; addr + block <= end; addr += block) {
        auto data = read_fn(addr, block);
        if (data.size() < block) continue;

        double e = EntropyScanner::calculate(data.data(), data.size());
        if (e >= threshold) {
            result.push_back({
                addr, block, e, "high_entropy",
                false, false, true, false, false
            });
        }
    }
    return result;
}

std::vector<ScoredRegion> AutomatedIntelligence::find_manual_maps(
    ReadCallback read_fn, const ModuleList& known_modules,
    uint64_t start, uint64_t end) {
    std::vector<ScoredRegion> result;
    const size_t step = 0x1000;

    auto is_known = [&](uint64_t addr) {
        for (const auto& [base, size] : known_modules) {
            if (addr >= base && addr < base + size) return true;
        }
        return false;
    };

    for (uint64_t addr = start; addr + 64 <= end; addr += step) {
        if (is_known(addr)) continue;

        auto data = read_fn(addr, 64);
        if (data.size() < 64) continue;
        if (data[0] != 'M' || data[1] != 'Z') continue;

        uint32_t pe_off = *reinterpret_cast<uint32_t*>(data.data() + 0x3C);
        if (pe_off > 0x1000) continue;
        if (data.size() < pe_off + 4) continue;
        if (memcmp(data.data() + pe_off, "PE\0\0", 4) != 0) continue;

        result.push_back({
            addr, 0x10000, 5.0, "manual_mapped_PE",
            true, false, false, true, false
        });
    }
    return result;
}

} // namespace dma
