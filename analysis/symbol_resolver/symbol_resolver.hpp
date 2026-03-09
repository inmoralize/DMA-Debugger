#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <functional>

namespace dma {

struct ProcessInfo {
    uint64_t eprocess;
    uint32_t pid;
    uint64_t cr3;
    std::string name;
};

struct ModuleInfo {
    uint64_t base_address;
    uint64_t size;
    std::string name;
    std::string path;
};

/**
 * Symbol & Structure Resolver - Interpret raw memory.
 * PDB loading, kernel structures, process reconstruction.
 */
class SymbolResolver {
public:
    using ReadCallback = std::function<bool(uint64_t physical_addr, void* buffer, size_t size)>;

    explicit SymbolResolver(ReadCallback read_fn);

    /** Get process list from kernel (requires EPROCESS list head) */
    std::vector<ProcessInfo> get_process_list(uint64_t ps_initial_system_process);

    /** Get module list for process */
    std::vector<ModuleInfo> get_module_list(uint32_t pid,
                                            uint64_t eprocess,
                                            ReadCallback read_fn);

    /** Translate virtual to physical using CR3 */
    std::optional<uint64_t> translate_virtual_to_physical(uint64_t virtual_addr,
                                                         uint64_t cr3);

    /** Load PDB symbols (stub - requires DIA SDK or similar) */
    bool load_pdb(const std::string& path);

    /** Resolve symbol to address */
    std::optional<uint64_t> resolve_symbol(const std::string& name);

private:
    ReadCallback m_read;
};

} // namespace dma
