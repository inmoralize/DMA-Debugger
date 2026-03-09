#include "symbol_resolver.hpp"
#include "../../core/address_translation/page_table_walker.hpp"
#include <cstring>
#include <algorithm>

namespace dma {

SymbolResolver::SymbolResolver(ReadCallback read_fn) : m_read(std::move(read_fn)) {}

std::vector<ProcessInfo> SymbolResolver::get_process_list(uint64_t ps_initial_system_process) {
    std::vector<ProcessInfo> result;
    if (!ps_initial_system_process) return result;

    // EPROCESS offsets - Win10/11 x64 (verify for your build)
    const uint64_t ActiveProcessLinks_offset = 0x448;
    const uint64_t UniqueProcessId_offset = 0x440;
    const uint64_t ImageFileName_offset = 0x5a8;
    const uint64_t DirectoryTableBase_offset = 0x28;  // KPROCESS.Pcb.DirectoryTableBase

    uint64_t current = ps_initial_system_process;
    uint64_t list_head = ps_initial_system_process + ActiveProcessLinks_offset;

    for (int i = 0; i < 1000; ++i) {
        ProcessInfo info;
        info.eprocess = current;

        uint8_t buf[8];
        if (!m_read(current + UniqueProcessId_offset, buf, 8)) break;
        info.pid = *reinterpret_cast<uint32_t*>(buf);

        if (!m_read(current + DirectoryTableBase_offset, buf, 8)) break;
        info.cr3 = *reinterpret_cast<uint64_t*>(buf);

        char name[16] = {};
        if (m_read(current + ImageFileName_offset, name, 15)) {
            info.name = std::string(name);
        } else {
            info.name = "unknown";
        }

        result.push_back(info);

        if (!m_read(current + ActiveProcessLinks_offset, buf, 8)) break;
        uint64_t flink = *reinterpret_cast<uint64_t*>(buf);
        current = flink - ActiveProcessLinks_offset;
        if (current == list_head) break;
    }
    return result;
}

std::vector<ModuleInfo> SymbolResolver::get_module_list(uint32_t pid,
                                                        uint64_t eprocess,
                                                        ReadCallback read_fn) {
    (void)pid; (void)eprocess; (void)read_fn;
    return {};
}

std::optional<uint64_t> SymbolResolver::translate_virtual_to_physical(uint64_t virtual_addr,
                                                                      uint64_t cr3) {
    PageTableWalker walker(m_read);
    auto result = walker.translate(virtual_addr, cr3);
    if (result && result->valid)
        return result->physical_address;
    return std::nullopt;
}

bool SymbolResolver::load_pdb(const std::string& path) {
    (void)path;
    return false;
}

std::optional<uint64_t> SymbolResolver::resolve_symbol(const std::string& name) {
    (void)name;
    return std::nullopt;
}

} // namespace dma
