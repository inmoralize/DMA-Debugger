#pragma once

#include <cstdint>
#include <cstring>
#include <string>

namespace dma {

/** Magic identifier for dump files */
constexpr uint32_t DUMP_MAGIC = 0x444D4144;  // "DMAD"

/** Current format version */
constexpr uint32_t DUMP_VERSION = 1;

#pragma pack(push, 1)

struct DumpHeader {
    uint32_t magic = DUMP_MAGIC;
    uint32_t version = DUMP_VERSION;
    uint64_t total_memory = 0;
    uint64_t page_size = 4096;
    uint64_t timestamp = 0;
    uint32_t flags = 0;           // compression, incremental, etc.
    uint32_t chunk_count = 0;
    uint64_t metadata_offset = 0; // Offset to metadata section
    uint64_t index_offset = 0;    // Offset to chunk index
    char reserved[64] = {};
};

struct ChunkIndexEntry {
    uint64_t physical_address;
    uint64_t file_offset;
    uint64_t compressed_size;     // 0 = uncompressed
    uint64_t uncompressed_size;
};

struct DumpMetadata {
    uint32_t process_count = 0;
    uint32_t module_count = 0;
    uint64_t pe_header_count = 0;
    char os_version[64] = {};
    char machine_id[64] = {};
};

#pragma pack(pop)

} // namespace dma
