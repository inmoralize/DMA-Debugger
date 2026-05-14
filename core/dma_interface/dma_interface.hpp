#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <optional>
#include <functional>

namespace dma {

/**
 * DMA Interface - Wraps LeechCore for physical memory access.
 * Supports raw reads, scatter/gather, caching, and multi-threaded dumping.
 */
class DMAInterface {
public:
    struct Config {
        std::string device_type = "fpga";      // fpga, pcileech, etc.
        std::string remote = "";               // Remote connection string
        uint64_t max_physical_addr = 0;        // 0 = auto-detect
        uint32_t page_size = 0x1000;
        bool enable_cache = true;
        size_t cache_size_mb = 256;
    };

    DMAInterface();
    ~DMAInterface();

    DMAInterface(const DMAInterface&) = delete;
    DMAInterface& operator=(const DMAInterface&) = delete;

    /** Initialize DMA device with given config. Returns true on success. */
    bool initialize(const Config& config);
    bool initialize() { return initialize(Config{}); }

    /** Shutdown and release resources */
    void shutdown();

    /** Check if interface is ready for operations */
    bool is_initialized() const { return m_initialized.load(); }

    /** Read physical memory. Returns bytes read or 0 on failure. */
    size_t read(uint64_t physical_address, void* buffer, size_t size);

    /** Write physical memory. Returns bytes written or 0 on failure. */
    size_t write(uint64_t physical_address, const void* buffer, size_t size);

    /** Scatter/gather read - efficient for non-contiguous pages */
    bool read_scatter(const std::vector<std::pair<uint64_t, size_t>>& regions,
                      std::vector<std::vector<uint8_t>>& out_buffers);

    /** Dump full physical memory to file. Returns total bytes dumped. */
    uint64_t dump_memory(const std::string& output_path,
                         std::function<void(uint64_t done, uint64_t total)> progress = {});

    /** Multi-threaded memory dump with configurable worker count */
    uint64_t dump_memory_parallel(const std::string& output_path,
                                  uint32_t num_workers = 8,
                                  std::function<void(uint64_t done, uint64_t total)> progress = {});

    /** Get maximum physical address (auto-detected or configured) */
    uint64_t get_max_physical_address() const { return m_max_physical_addr; }

    /** Get page size */
    uint32_t get_page_size() const { return m_page_size; }

    /** Cache control */
    void set_cache_enabled(bool enabled) { m_cache_enabled = enabled; }
    void clear_cache();

private:
    void* m_handle = nullptr;
    std::atomic<bool> m_initialized{false};
    uint64_t m_max_physical_addr = 0;
    uint32_t m_page_size = 0x1000;
    bool m_cache_enabled = true;
    std::mutex m_mutex;

    struct CacheEntry {
        uint64_t base_addr;
        std::vector<uint8_t> data;
    };
    std::vector<CacheEntry> m_read_cache;
    size_t m_cache_max_size = 0;

    bool read_uncached(uint64_t pa, void* buffer, size_t size);
    bool read_cached(uint64_t pa, void* buffer, size_t size);
};

} // namespace dma
