#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace dma {

struct ScoredRegion {
    uint64_t address;
    uint64_t size;
    double score;
    std::string reason;
    bool executable;
    bool rwx;
    bool high_entropy;
    bool unknown_module;
    bool unlinked;
};

/**
 * Automated Intelligence - Prioritize important memory areas.
 */
class AutomatedIntelligence {
public:
    using ReadCallback = std::function<std::vector<uint8_t>(uint64_t addr, size_t size)>;
    using ModuleList = std::vector<std::pair<uint64_t, uint64_t>>;

    /** Score and rank regions. Higher score = more suspicious/interesting. */
    std::vector<ScoredRegion> analyze_regions(
        ReadCallback read_fn,
        const ModuleList& known_modules,
        uint64_t scan_start = 0,
        uint64_t scan_end = 16ULL * 1024 * 1024 * 1024);

    /** Detect RWX pages (suspicious) */
    std::vector<uint64_t> find_rwx_pages(ReadCallback read_fn,
                                         uint64_t start, uint64_t end);

    /** Detect high-entropy regions (packed/encrypted) */
    std::vector<ScoredRegion> find_high_entropy_regions(ReadCallback read_fn,
                                                        uint64_t start, uint64_t end,
                                                        double threshold = 6.5);

    /** Detect manual mapped images (PE in non-module region) */
    std::vector<ScoredRegion> find_manual_maps(ReadCallback read_fn,
                                              const ModuleList& known_modules,
                                              uint64_t start, uint64_t end);
};

} // namespace dma
