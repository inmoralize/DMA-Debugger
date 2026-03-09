#pragma once

#include "address_translation.hpp"
#include <cstdint>
#include <functional>
#include <vector>

namespace dma {

/**
 * Page table walker for x64 Windows.
 * Translates virtual addresses to physical using CR3/EPROCESS.
 */
class PageTableWalker {
public:
    using ReadCallback = std::function<bool(uint64_t physical_addr, void* buffer, size_t size)>;

    PageTableWalker(ReadCallback read_fn);

    /** Translate virtual to physical using directory table base (CR3) */
    std::optional<TranslationResult> translate(uint64_t virtual_address,
                                               uint64_t directory_table_base);

    /** Walk page tables and return all valid mappings in range */
    std::vector<std::pair<uint64_t, uint64_t>> get_mappings(
        uint64_t directory_table_base,
        uint64_t start_va,
        uint64_t end_va);

private:
    ReadCallback m_read;

    bool read_physical(uint64_t pa, void* buf, size_t size) {
        return m_read(pa, buf, size);
    }
};

} // namespace dma
