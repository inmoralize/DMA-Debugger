#pragma once

#include <cstdint>
#include <optional>

namespace dma {

/**
 * Virtual to physical address translation.
 * Supports x64 Windows page table structures (4-level paging).
 */
struct TranslationResult {
    uint64_t physical_address;
    bool valid;
    bool executable;
    bool writable;
    bool user_mode;
};

} // namespace dma
