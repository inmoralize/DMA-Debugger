#include "page_table_walker.hpp"
#include <cstring>
#include <algorithm>

namespace dma {

// x64 page table entry structures
#pragma pack(push, 1)
struct PTE {
    uint64_t present : 1;
    uint64_t write : 1;
    uint64_t user : 1;
    uint64_t write_through : 1;
    uint64_t cache_disable : 1;
    uint64_t accessed : 1;
    uint64_t dirty : 1;
    uint64_t large_page : 1;
    uint64_t global : 1;
    uint64_t copy_on_write : 1;
    uint64_t prototype : 1;
    uint64_t reserved : 1;
    uint64_t page_frame : 40;
    uint64_t reserved2 : 11;
    uint64_t no_execute : 1;  // bit 63 (XD/NX)
};
#pragma pack(pop)

static_assert(sizeof(PTE) == 8, "PTE must be 8 bytes");

PageTableWalker::PageTableWalker(ReadCallback read_fn) : m_read(std::move(read_fn)) {}

std::optional<TranslationResult> PageTableWalker::translate(uint64_t virtual_address,
                                                            uint64_t directory_table_base) {
    uint64_t pml4_index = (virtual_address >> 39) & 0x1FF;
    uint64_t pdpt_index = (virtual_address >> 30) & 0x1FF;
    uint64_t pd_index = (virtual_address >> 21) & 0x1FF;
    uint64_t pt_index = (virtual_address >> 12) & 0x1FF;
    uint64_t offset = virtual_address & 0xFFF;

    uint64_t current = directory_table_base & ~0xFFF;

    PTE entry;
    auto read_entry = [&](uint64_t table_addr, uint64_t index) -> bool {
        uint64_t entry_addr = table_addr + index * 8;
        return read_physical(entry_addr, &entry, sizeof(entry));
    };

    if (!read_entry(current, pml4_index) || !entry.present)
        return std::nullopt;
    current = (entry.page_frame << 12);

    if (!read_entry(current, pdpt_index) || !entry.present)
        return std::nullopt;
    if (entry.large_page) {
        uint64_t pa = (entry.page_frame << 12) | (virtual_address & 0x3FFFFFFF);
        return TranslationResult{pa, true, entry.no_execute == 0, entry.write != 0, entry.user != 0};
    }
    current = (entry.page_frame << 12);

    if (!read_entry(current, pd_index) || !entry.present)
        return std::nullopt;
    if (entry.large_page) {
        uint64_t pa = (entry.page_frame << 12) | (virtual_address & 0x1FFFFF);
        return TranslationResult{pa, true, entry.no_execute == 0, entry.write != 0, entry.user != 0};
    }
    current = (entry.page_frame << 12);

    if (!read_entry(current, pt_index) || !entry.present)
        return std::nullopt;

    uint64_t pa = (entry.page_frame << 12) | offset;
    return TranslationResult{
        pa,
        true,
        entry.no_execute == 0,
        entry.write != 0,
        entry.user != 0
    };
}

std::vector<std::pair<uint64_t, uint64_t>> PageTableWalker::get_mappings(
    uint64_t directory_table_base,
    uint64_t start_va,
    uint64_t end_va) {
    std::vector<std::pair<uint64_t, uint64_t>> result;
    start_va &= ~0xFFF;
    end_va = (end_va + 0xFFF) & ~0xFFF;

    for (uint64_t va = start_va; va < end_va; va += 0x1000) {
        auto trans = translate(va, directory_table_base);
        if (trans && trans->valid) {
            if (result.empty() || result.back().second != trans->physical_address - 0x1000) {
                result.emplace_back(va, trans->physical_address);
            } else {
                result.back().second = trans->physical_address + 0xFFF;
            }
        }
    }
    return result;
}

} // namespace dma
