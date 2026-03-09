#include "dma_interface.hpp"
#include <fstream>
#include <thread>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef LEECHCORE_AVAILABLE
#include <leechcore.h>
#else
// Stub types when LeechCore not available
typedef void* HANDLE;
typedef unsigned long long QWORD;
typedef unsigned long DWORD;
typedef unsigned char BYTE;
typedef BYTE* PBYTE;
typedef struct { QWORD pa; DWORD cb; PBYTE pb; } MEM_SCATTER, *PMEM_SCATTER;
typedef struct { DWORD dwVersion; DWORD dwMagic; char szDevice[256]; char szRemote[256];
                 QWORD paMax; QWORD paMaxAuto; DWORD cExtra; PBYTE pbExtra; } LC_CONFIG, *PLC_CONFIG;
#endif

namespace dma {

DMAInterface::DMAInterface() = default;

DMAInterface::~DMAInterface() {
    shutdown();
}

bool DMAInterface::initialize(const Config& config) {
    std::lock_guard lock(m_mutex);
    if (m_initialized) return true;

#ifdef LEECHCORE_AVAILABLE
#ifdef _WIN32
    LC_CONFIG lcConfig = {};
    lcConfig.dwVersion = 2;
    lcConfig.dwMagic = 0x4c4d4346;  // LCMF
    strncpy_s(lcConfig.szDevice, config.device_type.c_str(), sizeof(lcConfig.szDevice) - 1);
    strncpy_s(lcConfig.szRemote, config.remote.c_str(), sizeof(lcConfig.szRemote) - 1);
    lcConfig.paMax = config.max_physical_addr;

    m_handle = LcCreate(&lcConfig);
    if (!m_handle) return false;

    m_max_physical_addr = lcConfig.paMax ? lcConfig.paMax : (16ULL * 1024 * 1024 * 1024);
    m_page_size = config.page_size ? config.page_size : 0x1000;
    m_cache_enabled = config.enable_cache;
    m_cache_max_size = config.cache_size_mb * 1024 * 1024;
    m_initialized = true;
    return true;
#endif
#endif
    (void)config;
    return false;  // LeechCore not available or not Windows
}

void DMAInterface::shutdown() {
    std::lock_guard lock(m_mutex);
    if (!m_initialized) return;

#ifdef LEECHCORE_AVAILABLE
    if (m_handle) LcClose((HANDLE)m_handle);
#endif
    m_handle = nullptr;
    m_initialized = false;
    m_read_cache.clear();
}

bool DMAInterface::read_uncached(uint64_t pa, void* buffer, size_t size) {
    if (!m_handle || !buffer) return false;
#ifdef LEECHCORE_AVAILABLE
    return LcRead((HANDLE)m_handle, pa, (DWORD)size, (PBYTE)buffer) != 0;
#else
    (void)pa; (void)size; return false;
#endif
}

bool DMAInterface::read_cached(uint64_t pa, void* buffer, size_t size) {
    if (!m_cache_enabled) return read_uncached(pa, buffer, size);

    uint64_t page_base = pa & ~(uint64_t)(m_page_size - 1);
    for (const auto& entry : m_read_cache) {
        if (entry.base_addr == page_base && entry.data.size() >= size + (pa - page_base)) {
            memcpy(buffer, entry.data.data() + (pa - page_base), size);
            return true;
        }
    }
    if (!read_uncached(pa, buffer, size)) return false;

    if (m_read_cache.size() * m_page_size < m_cache_max_size) {
        std::vector<uint8_t> page(m_page_size);
        if (read_uncached(page_base, page.data(), m_page_size)) {
            m_read_cache.push_back({page_base, std::move(page)});
        }
    }
    return true;
}

size_t DMAInterface::read(uint64_t physical_address, void* buffer, size_t size) {
    if (!m_initialized || !buffer || size == 0) return 0;
    std::lock_guard lock(m_mutex);
    return read_cached(physical_address, buffer, size) ? size : 0;
}

size_t DMAInterface::write(uint64_t physical_address, const void* buffer, size_t size) {
    if (!m_initialized || !buffer || size == 0) return 0;
    std::lock_guard lock(m_mutex);
#ifdef LEECHCORE_AVAILABLE
    return LcWrite((HANDLE)m_handle, physical_address, (DWORD)size, (PBYTE)buffer) ? size : 0;
#else
    (void)physical_address; (void)buffer; (void)size; return 0;
#endif
}

bool DMAInterface::read_scatter(const std::vector<std::pair<uint64_t, size_t>>& regions,
                                std::vector<std::vector<uint8_t>>& out_buffers) {
    if (!m_initialized || regions.empty()) return false;
    std::lock_guard lock(m_mutex);
#ifdef LEECHCORE_AVAILABLE
    out_buffers.resize(regions.size());
    std::vector<MEM_SCATTER> scatters;
    scatters.reserve(regions.size());
    for (size_t i = 0; i < regions.size(); ++i) {
        out_buffers[i].resize(regions[i].second);
        scatters.push_back({regions[i].first, (DWORD)regions[i].second, out_buffers[i].data()});
    }
    PMEM_SCATTER pScatters = scatters.data();
    LcReadScatter((HANDLE)m_handle, (DWORD)scatters.size(), &pScatters);
    return true;
#else
    out_buffers.resize(regions.size());
    for (size_t i = 0; i < regions.size(); ++i) {
        out_buffers[i].resize(regions[i].second);
        if (!read_uncached(regions[i].first, out_buffers[i].data(), regions[i].second))
            return false;
    }
    return true;
#endif
}

void DMAInterface::clear_cache() {
    std::lock_guard lock(m_mutex);
    m_read_cache.clear();
}

uint64_t DMAInterface::dump_memory(const std::string& output_path,
                                   std::function<void(uint64_t, uint64_t)> progress) {
    if (!m_initialized) return 0;

    std::ofstream out(output_path, std::ios::binary);
    if (!out) return 0;

    const size_t chunk_size = 64 * 1024 * 1024;  // 64MB chunks
    std::vector<uint8_t> buffer(chunk_size);
    uint64_t total_dumped = 0;
    uint64_t addr = 0;

    while (addr < m_max_physical_addr) {
        size_t to_read = std::min(chunk_size, (size_t)(m_max_physical_addr - addr));
        if (read(addr, buffer.data(), to_read) != to_read) break;
        out.write(reinterpret_cast<char*>(buffer.data()), to_read);
        total_dumped += to_read;
        addr += to_read;
        if (progress) progress(total_dumped, m_max_physical_addr);
    }
    return total_dumped;
}

uint64_t DMAInterface::dump_memory_parallel(const std::string& output_path,
                                            uint32_t num_workers,
                                            std::function<void(uint64_t, uint64_t)> progress) {
    (void)num_workers;
    return dump_memory(output_path, progress);
}

} // namespace dma
