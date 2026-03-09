#include "dump_manager.hpp"
#include "../dma_interface/dma_interface.hpp"
#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>

namespace dma {

DumpManager::DumpManager(DMAInterface* dma) : m_dma(dma) {}

DumpManager::~DumpManager() {
    close();
}

bool DumpManager::write_header(std::ofstream& out, uint64_t total_size, uint32_t chunk_count) {
    m_header.total_memory = total_size;
    m_header.page_size = 4096;
    m_header.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    m_header.chunk_count = chunk_count;
    m_header.metadata_offset = sizeof(DumpHeader) + total_size;
    m_header.index_offset = m_header.metadata_offset + sizeof(DumpMetadata);
    out.write(reinterpret_cast<char*>(&m_header), sizeof(m_header));
    return out.good();
}

bool DumpManager::write_chunk_index(std::ofstream& out) {
    out.write(reinterpret_cast<char*>(m_index.data()),
              m_index.size() * sizeof(ChunkIndexEntry));
    return out.good();
}

bool DumpManager::compress_chunk(const uint8_t* src, size_t src_size,
                                std::vector<uint8_t>& dst, CompressionType type) {
    (void)src; (void)src_size; (void)dst; (void)type;
    // Compression stubs - LZ4/Zstd can be added via optional deps
    return false;
}

bool DumpManager::decompress_chunk(const uint8_t* src, size_t src_size,
                                  uint8_t* dst, size_t dst_size, CompressionType type) {
    (void)src; (void)src_size; (void)dst; (void)dst_size; (void)type;
    return false;
}

bool DumpManager::create_dump(const std::string& output_path,
                             const DumpConfig& config,
                             std::function<void(uint64_t, uint64_t)> progress) {
    if (!m_dma || !m_dma->is_initialized()) return false;

    std::ofstream out(output_path, std::ios::binary);
    if (!out) return false;

    uint64_t max_addr = m_dma->get_max_physical_address();
    uint64_t chunk_size = config.chunk_size;
    uint64_t total_chunks = (max_addr + chunk_size - 1) / chunk_size;

    m_index.clear();
    m_index.reserve(total_chunks);

    write_header(out, 0, static_cast<uint32_t>(total_chunks));

    std::vector<uint8_t> buffer(std::min(chunk_size, max_addr));
    uint64_t file_offset = sizeof(DumpHeader);
    uint64_t total_dumped = 0;

    for (uint64_t addr = 0; addr < max_addr; ) {
        size_t to_read = std::min(chunk_size, max_addr - addr);
        buffer.resize(to_read);

        if (m_dma->read(addr, buffer.data(), to_read) != to_read) break;

        out.write(reinterpret_cast<char*>(buffer.data()), to_read);
        m_index.push_back({
            addr,
            file_offset,
            0,
            to_read
        });

        file_offset += to_read;
        total_dumped += to_read;
        addr += to_read;

        if (progress) progress(total_dumped, max_addr);
    }

    m_header.total_memory = total_dumped;
    out.seekp(0);
    out.write(reinterpret_cast<char*>(&m_header), sizeof(m_header));

    DumpMetadata meta = {};
    out.write(reinterpret_cast<char*>(&meta), sizeof(meta));
    write_chunk_index(out);

    m_current_path = output_path;
    return out.good();
}

bool DumpManager::create_incremental_dump(const std::string& output_path,
                                          const std::string& base_dump_path,
                                          const DumpConfig& config,
                                          std::function<void(uint64_t, uint64_t)> progress) {
    (void)output_path; (void)base_dump_path; (void)config; (void)progress;
    // TODO: Implement incremental - compare base dump with live memory
    return false;
}

bool DumpManager::create_differential_dump(const std::string& output_path,
                                          const std::string& dump_a_path,
                                          const std::string& dump_b_path,
                                          std::function<void(uint64_t, uint64_t)> progress) {
    (void)output_path; (void)dump_a_path; (void)dump_b_path; (void)progress;
    // TODO: Implement differential - compare two dumps
    return false;
}

bool DumpManager::open_dump(const std::string& path) {
    close();
    m_file.open(path, std::ios::binary);
    if (!m_file) return false;

    m_file.read(reinterpret_cast<char*>(&m_header), sizeof(m_header));
    if (!m_file || m_header.magic != DUMP_MAGIC) {
        m_file.close();
        return false;
    }

    m_metadata.emplace();
    m_file.seekg(m_header.metadata_offset);
    m_file.read(reinterpret_cast<char*>(&*m_metadata), sizeof(DumpMetadata));

    m_index.resize(m_header.chunk_count);
    m_file.seekg(m_header.index_offset);
    m_file.read(reinterpret_cast<char*>(m_index.data()),
                m_index.size() * sizeof(ChunkIndexEntry));

    m_offset_cache.clear();
    for (size_t i = 0; i < m_index.size(); ++i) {
        m_offset_cache[m_index[i].physical_address] = i;
    }
    m_current_path = path;
    return true;
}

std::optional<std::vector<uint8_t>> DumpManager::read(uint64_t physical_address, size_t size) {
    if (!m_file.is_open()) return std::nullopt;

    size_t idx = 0;
    bool found = false;
    for (size_t i = 0; i < m_index.size(); ++i) {
        if (physical_address >= m_index[i].physical_address &&
            physical_address < m_index[i].physical_address + m_index[i].uncompressed_size) {
            idx = i;
            found = true;
            break;
        }
    }
    if (!found) return std::nullopt;

    const auto& entry = m_index[idx];
    uint64_t offset_in_chunk = physical_address - entry.physical_address;
    if (offset_in_chunk + size > entry.uncompressed_size) {
        size = entry.uncompressed_size - offset_in_chunk;
    }

    std::vector<uint8_t> result(size);
    m_file.seekg(entry.file_offset + offset_in_chunk);
    m_file.read(reinterpret_cast<char*>(result.data()), size);
    if (!m_file) return std::nullopt;
    return result;
}

std::optional<uint64_t> DumpManager::get_offset(uint64_t physical_address) const {
    for (const auto& entry : m_index) {
        if (physical_address >= entry.physical_address &&
            physical_address < entry.physical_address + entry.uncompressed_size) {
            return entry.file_offset + (physical_address - entry.physical_address);
        }
    }
    return std::nullopt;
}

void DumpManager::close() {
    m_file.close();
    m_index.clear();
    m_offset_cache.clear();
    m_current_path.clear();
}

} // namespace dma
