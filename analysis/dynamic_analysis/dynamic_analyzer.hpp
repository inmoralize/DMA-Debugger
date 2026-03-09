#pragma once

#include <cstdint>
#include <optional>
#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace dma {

class DMAInterface;

struct MemorySnapshot {
    uint64_t address;
    uint64_t size;
    std::vector<uint8_t> data;
    uint64_t timestamp;
};

struct RegionDiff {
    uint64_t address;
    uint64_t offset;
    std::vector<uint8_t> old_data;
    std::vector<uint8_t> new_data;
};

/**
 * Dynamic Analysis - Live memory monitoring via DMA.
 */
class DynamicAnalyzer {
public:
    explicit DynamicAnalyzer(DMAInterface* dma);

    /** Watch memory region for changes */
    void watch_region(uint64_t address, size_t size, uint32_t watch_id = 0);

    /** Stop watching region */
    void unwatch_region(uint32_t watch_id);

    /** Take snapshot of region */
    std::optional<MemorySnapshot> snapshot_region(uint64_t address, size_t size);

    /** Diff two snapshots */
    std::vector<RegionDiff> diff_snapshots(const MemorySnapshot& a, const MemorySnapshot& b);

    /** Poll watched regions and report changes */
    std::vector<RegionDiff> poll_changes();

    /** Detect potential hooks (modified code pages) */
    std::vector<uint64_t> detect_hooks(uint64_t base, size_t size,
                                       const std::vector<uint8_t>& expected);

    /** Track allocations (requires baseline) */
    void set_baseline(const MemorySnapshot& baseline);
    std::vector<MemorySnapshot> get_new_allocations();

private:
    DMAInterface* m_dma;
    std::unordered_map<uint32_t, std::pair<uint64_t, size_t> > m_watched;
    std::unordered_map<uint32_t, MemorySnapshot> m_baselines;
    std::optional<MemorySnapshot> m_alloc_baseline;
    uint32_t m_next_watch_id = 1;
    std::mutex m_mutex;
};

} // namespace dma
