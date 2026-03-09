#pragma once

#include <memory>
#include <string>

struct ImGuiContext;

namespace dma {

class DMAInterface;
class DumpManager;
class StaticAnalyzer;

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
    void render_memory_viewer();
    void render_analysis_tabs();
    void render_process_list();
    void render_module_list();
    void render_suspicious_regions();

    std::unique_ptr<DMAInterface> m_dma;
    std::unique_ptr<DumpManager> m_dump;
    std::unique_ptr<StaticAnalyzer> m_analyzer;
    std::string m_dump_path;
    uint64_t m_view_address = 0;
    bool m_connected = false;
    bool m_dump_loaded = false;
    int m_selected_tab = 0;
};

} // namespace dma
