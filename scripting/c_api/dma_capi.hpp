#pragma once

#ifdef _WIN32
    #ifdef DMA_CAPI_EXPORTS
        #define DMA_API __declspec(dllexport)
    #else
        #define DMA_API __declspec(dllimport)
    #endif
#else
    #define DMA_API __attribute__((visibility("default")))
#endif

#include <cstdint>
#include <cstddef>

extern "C" {

/** Opaque context owning DMAInterface, DumpManager, StaticAnalyzer, and SymbolResolver. */
typedef struct dma_context dma_context_t;

DMA_API dma_context_t* dma_create(void);
DMA_API void           dma_destroy(dma_context_t* ctx);
DMA_API int            dma_initialize(dma_context_t* ctx, const char* device, const char* remote);
DMA_API void           dma_shutdown(dma_context_t* ctx);
DMA_API int            dma_is_initialized(dma_context_t* ctx);
DMA_API size_t         dma_read(dma_context_t* ctx, uint64_t addr, void* buf, size_t size);
DMA_API uint64_t       dma_dump(dma_context_t* ctx, const char* path);

DMA_API int            dump_create_file(dma_context_t* ctx, const char* path);
DMA_API int            dump_open(dma_context_t* ctx, const char* path);
DMA_API int            dump_read(dma_context_t* ctx, uint64_t addr, void* buf, size_t size);
DMA_API void           dump_close(dma_context_t* ctx);
DMA_API int            dump_is_open(dma_context_t* ctx);

DMA_API int  analyzer_find_pe(dma_context_t* ctx, uint64_t* bases, uint64_t* sizes, int max_count);
DMA_API int  analyzer_scan_pattern(dma_context_t* ctx, const uint8_t* pattern, size_t pattern_len,
                                   uint64_t* results, int max_results);
DMA_API int  analyzer_list_processes(dma_context_t* ctx, uint64_t system_eprocess,
                                     uint32_t* pids, uint64_t* cr3s, char* names,
                                     int max_count, int name_buf_size);

}
