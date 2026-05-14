#include "dma_capi.hpp"
#include "../../core/dma_interface/dma_interface.hpp"
#include "../../core/memory_dump/dump_manager.hpp"
#include "../../analysis/static_analysis/static_analyzer.hpp"
#include "../../analysis/symbol_resolver/symbol_resolver.hpp"
#include <memory>
#include <cstring>
#include <vector>

struct dma_context {
    std::unique_ptr<dma::DMAInterface>  dma;
    std::unique_ptr<dma::DumpManager>   dump;
    std::unique_ptr<dma::StaticAnalyzer> analyzer;
    std::unique_ptr<dma::SymbolResolver> resolver;
};

extern "C" {

dma_context_t* dma_create(void) {
    auto* ctx = new dma_context();
    ctx->dma      = std::make_unique<dma::DMAInterface>();
    ctx->dump     = std::make_unique<dma::DumpManager>(ctx->dma.get());
    ctx->analyzer = std::make_unique<dma::StaticAnalyzer>(ctx->dma.get(), ctx->dump.get());
    return ctx;
}

void dma_destroy(dma_context_t* ctx) {
    delete ctx;
}

int dma_initialize(dma_context_t* ctx, const char* device, const char* remote) {
    if (!ctx) return 0;
    dma::DMAInterface::Config cfg;
    if (device) cfg.device_type = device;
    if (remote)  cfg.remote     = remote;
    return ctx->dma->initialize(cfg) ? 1 : 0;
}

void dma_shutdown(dma_context_t* ctx) {
    if (ctx) ctx->dma->shutdown();
}

int dma_is_initialized(dma_context_t* ctx) {
    return (ctx && ctx->dma->is_initialized()) ? 1 : 0;
}

size_t dma_read(dma_context_t* ctx, uint64_t addr, void* buf, size_t size) {
    if (!ctx || !buf) return 0;
    return ctx->dma->read(addr, buf, size);
}

uint64_t dma_dump(dma_context_t* ctx, const char* path) {
    if (!ctx || !path) return 0;
    return ctx->dma->dump_memory(path);
}

int dump_create_file(dma_context_t* ctx, const char* path) {
    if (!ctx || !path) return 0;
    return ctx->dump->create_dump(path) ? 1 : 0;
}

int dump_open(dma_context_t* ctx, const char* path) {
    if (!ctx || !path) return 0;
    return ctx->dump->open_dump(path) ? 1 : 0;
}

int dump_read(dma_context_t* ctx, uint64_t addr, void* buf, size_t size) {
    if (!ctx || !buf) return 0;
    auto opt = ctx->dump->read(addr, size);
    if (!opt || opt->size() > size) return 0;
    memcpy(buf, opt->data(), opt->size());
    return static_cast<int>(opt->size());
}

void dump_close(dma_context_t* ctx) {
    if (ctx) ctx->dump->close();
}

int dump_is_open(dma_context_t* ctx) {
    return (ctx && ctx->dump->is_open()) ? 1 : 0;
}

int analyzer_find_pe(dma_context_t* ctx, uint64_t* bases, uint64_t* sizes, int max_count) {
    if (!ctx || !bases || !sizes || max_count <= 0) return 0;
    auto mods = ctx->analyzer->find_pe_images();
    int n = 0;
    for (const auto& m : mods) {
        if (n >= max_count) break;
        bases[n] = m.base_address;
        sizes[n] = m.size;
        n++;
    }
    return n;
}

int analyzer_scan_pattern(dma_context_t* ctx, const uint8_t* pattern, size_t pattern_len,
                          uint64_t* results, int max_results) {
    if (!ctx || !pattern || !results || max_results <= 0) return 0;
    std::vector<uint8_t> pat(pattern, pattern + pattern_len);
    auto res = ctx->analyzer->scan_pattern("", pat, {});
    int n = 0;
    for (const auto& r : res) {
        if (n >= max_results) break;
        results[n++] = r.address;
    }
    return n;
}

int analyzer_list_processes(dma_context_t* ctx, uint64_t system_eprocess,
                            uint32_t* pids, uint64_t* cr3s, char* names,
                            int max_count, int name_buf_size) {
    if (!ctx || !pids || !cr3s || !names || max_count <= 0 || name_buf_size <= 0) return 0;
    if (!ctx->dma->is_initialized()) return 0;

    ctx->resolver = std::make_unique<dma::SymbolResolver>(
        [dma = ctx->dma.get()](uint64_t pa, void* buf, size_t sz) {
            return dma->read(pa, buf, sz) == sz;
        });
    auto procs = ctx->resolver->get_process_list(system_eprocess);
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
