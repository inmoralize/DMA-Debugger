#include "dma_capi.hpp"
#include "../../core/dma_interface/dma_interface.hpp"
#include "../../core/memory_dump/dump_manager.hpp"
#include "../../analysis/static_analysis/static_analyzer.hpp"
#include "../../analysis/symbol_resolver/symbol_resolver.hpp"
#include <memory>
#include <cstring>
#include <vector>

static std::unique_ptr<dma::DMAInterface> g_dma;
static std::unique_ptr<dma::DumpManager> g_dump;
static std::unique_ptr<dma::StaticAnalyzer> g_analyzer;
static std::unique_ptr<dma::SymbolResolver> g_resolver;

extern "C" {

dma_handle_t dma_create(void) {
    g_dma = std::make_unique<dma::DMAInterface>();
    return g_dma.get();
}

void dma_destroy(dma_handle_t h) {
    (void)h;
    g_analyzer.reset();
    g_dump.reset();
    g_dma.reset();
}

int dma_initialize(dma_handle_t h, const char* device, const char* remote) {
    if (!h) return 0;
    dma::DMAInterface::Config cfg;
    if (device) cfg.device_type = device;
    if (remote) cfg.remote = remote;
    return static_cast<dma::DMAInterface*>(h)->initialize(cfg) ? 1 : 0;
}

void dma_shutdown(dma_handle_t h) {
    if (h) static_cast<dma::DMAInterface*>(h)->shutdown();
}

int dma_is_initialized(dma_handle_t h) {
    return (h && static_cast<dma::DMAInterface*>(h)->is_initialized()) ? 1 : 0;
}

size_t dma_read(dma_handle_t h, uint64_t addr, void* buf, size_t size) {
    if (!h || !buf) return 0;
    return static_cast<dma::DMAInterface*>(h)->read(addr, buf, size);
}

uint64_t dma_dump(dma_handle_t h, const char* path) {
    if (!h || !path) return 0;
    return static_cast<dma::DMAInterface*>(h)->dump_memory(path);
}

dump_handle_t dump_create(dma_handle_t dma) {
    if (!dma) return nullptr;
    g_dump = std::make_unique<dma::DumpManager>(static_cast<dma::DMAInterface*>(dma));
    return g_dump.get();
}

void dump_destroy(dump_handle_t h) {
    (void)h;
    g_analyzer.reset();
    g_dump.reset();
}

int dump_create_file(dump_handle_t h, const char* path) {
    if (!h || !path) return 0;
    return static_cast<dma::DumpManager*>(h)->create_dump(path) ? 1 : 0;
}

int dump_open(dump_handle_t h, const char* path) {
    if (!h || !path) return 0;
    return static_cast<dma::DumpManager*>(h)->open_dump(path) ? 1 : 0;
}

int dump_read(dump_handle_t h, uint64_t addr, void* buf, size_t size) {
    if (!h || !buf) return 0;
    auto opt = static_cast<dma::DumpManager*>(h)->read(addr, size);
    if (!opt || opt->size() > size) return 0;
    memcpy(buf, opt->data(), opt->size());
    return static_cast<int>(opt->size());
}

void dump_close(dump_handle_t h) {
    if (h) static_cast<dma::DumpManager*>(h)->close();
}

int dump_is_open(dump_handle_t h) {
    return (h && static_cast<dma::DumpManager*>(h)->is_open()) ? 1 : 0;
}

analyzer_handle_t analyzer_create(dma_handle_t dma, dump_handle_t dump) {
    if (!dma) return nullptr;
    g_analyzer = std::make_unique<dma::StaticAnalyzer>(
        static_cast<dma::DMAInterface*>(dma),
        dump ? static_cast<dma::DumpManager*>(dump) : nullptr);
    return g_analyzer.get();
}

void analyzer_destroy(analyzer_handle_t h) {
    (void)h;
    g_analyzer.reset();
}

int analyzer_find_pe(analyzer_handle_t h, uint64_t* bases, uint64_t* sizes, int max_count) {
    if (!h || !bases || !sizes || max_count <= 0) return 0;
    auto mods = static_cast<dma::StaticAnalyzer*>(h)->find_pe_images();
    int n = 0;
    for (const auto& m : mods) {
        if (n >= max_count) break;
        bases[n] = m.base_address;
        sizes[n] = m.size;
        n++;
    }
    return n;
}

int analyzer_scan_pattern(analyzer_handle_t h, const uint8_t* pattern, size_t pattern_len,
                          uint64_t* results, int max_results) {
    if (!h || !pattern || !results || max_results <= 0) return 0;
    std::vector<uint8_t> pat(pattern, pattern + pattern_len);
    auto res = static_cast<dma::StaticAnalyzer*>(h)->scan_pattern("", pat, {});
    int n = 0;
    for (const auto& r : res) {
        if (n >= max_results) break;
        results[n++] = r.address;
    }
    return n;
}

int analyzer_list_processes(analyzer_handle_t h, uint64_t system_eprocess,
                            uint32_t* pids, uint64_t* cr3s, char* names,
                            int max_count, int name_buf_size) {
    (void)h;
    if (!pids || !cr3s || !names || max_count <= 0 || name_buf_size <= 0) return 0;
    if (!g_dma || !g_dma->is_initialized()) return 0;

    g_resolver = std::make_unique<dma::SymbolResolver>(
        [dma = g_dma.get()](uint64_t pa, void* buf, size_t sz) {
            return dma->read(pa, buf, sz) == sz;
        });
    auto procs = g_resolver->get_process_list(system_eprocess);
    int n = 0;
    for (const auto& p : procs) {
        if (n >= max_count) break;
        pids[n] = p.pid;
        cr3s[n] = p.cr3;
        strncpy(names + n * name_buf_size, p.name.c_str(), name_buf_size - 1);
        names[n * name_buf_size + name_buf_size - 1] = '\0';
        n++;
    }
    return n;
}

}
