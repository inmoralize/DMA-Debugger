#pragma once

#include <memory>
#include <string>
#include <vector>
#include <deque>
#include <cstdint>

#include "../../analysis/symbol_resolver/symbol_resolver.hpp"
#include "../../analysis/intelligence/automated_intelligence.hpp"
#include "../../analysis/static_analysis/static_analyzer.hpp"

namespace dma {

class DMAInterface;
class DumpManager;

class App {
public:
    App();
    ~App();

    void run();
    void render();

private:
    void render_menu_bar();
    void render_sidebar();
    void render_main_content();
    void render_process_list();
    void render_module_list();
    void render_suspicious_regions();
    void render_log();

    void log(const std::string& msg);

    // Builds a virtual-address read callback against the live DMA using the
    // configured kernel CR3. Returns nullptr if not connected or CR3 is 0.
    SymbolResolver::ReadCallback make_kernel_va_reader();

    std::unique_ptr<DMAInterface> m_dma;
    std::unique_ptr<DumpManager> m_dump;
    std::unique_ptr<StaticAnalyzer> m_analyzer;

    // UI input buffers
    char m_device_buf[64] = "fpga";
    char m_remote_buf[128] = "";
    char m_dump_path_buf[260] = "memory.dmp";

    // Kernel context (user-supplied — typically obtained out-of-band via PDB)
    uint64_t m_kernel_cr3 = 0;
    uint64_t m_ps_initial_system_process = 0;

    // RWX scan range
    uint64_t m_rwx_start = 0xFFFF800000000000ULL; // kernel VA range default
    uint64_t m_rwx_end   = 0xFFFF810000000000ULL;

    // Suspicious-region scan range (physical, for analyze_regions)
    uint64_t m_susp_start = 0;
    uint64_t m_susp_end   = 0x100000000ULL; // first 4 GB

    uint64_t m_view_address = 0;
    bool m_connected = false;
    bool m_dump_loaded = false;

    // Cached results
    std::vector<ProcessInfo>      m_processes;
    std::vector<PEModule>         m_modules;
    std::vector<ScoredRegion>     m_suspicious;
    std::vector<uint64_t>         m_rwx_pages;

    // Rolling status log (most recent at front)
    std::deque<std::string> m_log_lines;
    static constexpr size_t kMaxLogLines = 200;
};

} // namespace dma
