#include "dynamic_analyzer.hpp"
#include "../../core/dma_interface/dma_interface.hpp"
#include <chrono>
#include <algorithm>

namespace dma {

DynamicAnalyzer::DynamicAnalyzer(DMAInterface* dma) : m_dma(dma) {}

void DynamicAnalyzer::watch_region(uint64_t address, size_t size, uint32_t watch_id) {
    std::lock_guard lock(m_mutex);
    if (watch_id == 0) watch_id = m_next_watch_id++;
    m_watched[watch_id] = {address, size};
    auto snap = snapshot_region(address, size);
    if (snap) m_baselines[watch_id] = *snap;
}

void DynamicAnalyzer::unwatch_region(uint32_t watch_id) {
    std::lock_guard lock(m_mutex);
    m_watched.erase(watch_id);
    m_baselines.erase(watch_id);
}

std::optional<MemorySnapshot> DynamicAnalyzer::snapshot_region(uint64_t address, size_t size) {
    if (!m_dma || !m_dma->is_initialized()) return std::nullopt;

    MemorySnapshot snap;
    snap.address = address;
    snap.size = size;
    snap.data.resize(size);
    snap.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    if (m_dma->read(address, snap.data.data(), size) != size)
        return std::nullopt;
    return snap;
}

std::vector<RegionDiff> DynamicAnalyzer::diff_snapshots(const MemorySnapshot& a,
                                                        const MemorySnapshot& b) {
    std::vector<RegionDiff> result;
    if (a.address != b.address || a.size != b.size) return result;

    size_t chunk = 64;
    for (size_t i = 0; i < a.data.size(); i += chunk) {
        size_t len = std::min(chunk, a.data.size() - i);
        if (memcmp(a.data.data() + i, b.data.data() + i, len) != 0) {
            RegionDiff diff;
            diff.address = a.address + i;
            diff.offset = i;
            diff.old_data.assign(a.data.begin() + i, a.data.begin() + i + len);
            diff.new_data.assign(b.data.begin() + i, b.data.begin() + i + len);
            result.push_back(diff);
        }
    }
    return result;
}

std::vector<RegionDiff> DynamicAnalyzer::poll_changes() {
    std::vector<RegionDiff> result;
    std::lock_guard lock(m_mutex);

    for (const auto& [id, region] : m_watched) {
        auto it = m_baselines.find(id);
        if (it == m_baselines.end()) continue;

        auto current = snapshot_region(region.first, region.second);
        if (!current) continue;

        auto diffs = diff_snapshots(it->second, *current);
        for (auto& d : diffs) result.push_back(std::move(d));
        m_baselines[id] = *current;
    }
    return result;
}

std::vector<uint64_t> DynamicAnalyzer::detect_hooks(uint64_t base, size_t size,
                                                    const std::vector<uint8_t>& expected) {
    std::vector<uint64_t> result;
    if (!m_dma || expected.empty()) return result;

    std::vector<uint8_t> current(size);
    if (m_dma->read(base, current.data(), size) != size) return result;

    for (size_t i = 0; i + expected.size() <= size; ++i) {
        if (memcmp(current.data() + i, expected.data(), expected.size()) != 0) {
            result.push_back(base + i);
        }
    }
    return result;
}

void DynamicAnalyzer::set_baseline(const MemorySnapshot& baseline) {
    m_alloc_baseline = baseline;
}

std::vector<MemorySnapshot> DynamicAnalyzer::get_new_allocations() {
    return {};
}

} // namespace dma
