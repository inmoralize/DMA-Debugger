#pragma once

#include "dump_format.hpp"
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <optional>
#include <unordered_map>

namespace dma {

class DMAInterface;

/**
 * Memory Dump Manager - Handles full, incremental, and differential dumps.
 * Supports compression, chunk indexing, and fast lookup.
 */
class DumpManager {
public:
    enum class CompressionType {
        None,
        LZ4,
        Zstd
    };

    struct DumpConfig {
        uint64_t chunk_size = 64 * 1024 * 1024;  // 64MB
        CompressionType compression = CompressionType::None;
        bool build_index = true;
        uint32_t parallel_workers = 8;
    };

    DumpManager(DMAInterface* dma);
    ~DumpManager();

    /** Create full memory dump */
    bool create_dump(const std::string& output_path,
                    const DumpConfig& config,
                    std::function<void(uint64_t done, uint64_t total)> progress = {});
    bool create_dump(const std::string& output_path) { return create_dump(output_path, DumpConfig{}); }

    /** Create incremental dump (only changed pages since base_dump) */
    bool create_incremental_dump(const std::string& output_path,
                                const std::string& base_dump_path,
                                const DumpConfig& config,
                                std::function<void(uint64_t done, uint64_t total)> progress = {});

    /** Create differential dump between two dumps */
    bool create_differential_dump(const std::string& output_path,
                                 const std::string& dump_a_path,
                                 const std::string& dump_b_path,
                                 std::function<void(uint64_t done, uint64_t total)> progress = {});

    /** Open existing dump for reading */
    bool open_dump(const std::string& path);

    /** Read from opened dump at physical address */
    std::optional<std::vector<uint8_t>> read(uint64_t physical_address, size_t size);

    /** Get dump metadata */
    const DumpHeader* get_header() const { return &m_header; }
    const DumpMetadata* get_metadata() const { return m_metadata ? &*m_metadata : nullptr; }

    /** Fast lookup: get file offset for physical address */
    std::optional<uint64_t> get_offset(uint64_t physical_address) const;

    /** Close current dump */
    void close();

    /** Check if dump is open */
    bool is_open() const { return m_file.is_open(); }

private:
    DMAInterface* m_dma;
    DumpHeader m_header;
    std::optional<DumpMetadata> m_metadata;
    std::vector<ChunkIndexEntry> m_index;
    std::unordered_map<uint64_t, size_t> m_offset_cache;
    std::ifstream m_file;
    std::string m_current_path;

    bool write_header(std::ofstream& out, uint64_t total_size, uint32_t chunk_count);
    bool write_chunk_index(std::ofstream& out);
    bool compress_chunk(const uint8_t* src, size_t src_size,
                       std::vector<uint8_t>& dst, CompressionType type);
    bool decompress_chunk(const uint8_t* src, size_t src_size,
                         uint8_t* dst, size_t dst_size, CompressionType type);
};

} // namespace dma
