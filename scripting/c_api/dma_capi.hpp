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

typedef void* dma_handle_t;
typedef void* dump_handle_t;
typedef void* analyzer_handle_t;

DMA_API dma_handle_t dma_create(void);
DMA_API void dma_destroy(dma_handle_t h);
DMA_API int dma_initialize(dma_handle_t h, const char* device, const char* remote);
DMA_API void dma_shutdown(dma_handle_t h);
DMA_API int dma_is_initialized(dma_handle_t h);
DMA_API size_t dma_read(dma_handle_t h, uint64_t addr, void* buf, size_t size);
DMA_API uint64_t dma_dump(dma_handle_t h, const char* path);

DMA_API dump_handle_t dump_create(dma_handle_t dma);
DMA_API void dump_destroy(dump_handle_t h);
DMA_API int dump_create_file(dump_handle_t h, const char* path);
DMA_API int dump_open(dump_handle_t h, const char* path);
DMA_API int dump_read(dump_handle_t h, uint64_t addr, void* buf, size_t size);
DMA_API void dump_close(dump_handle_t h);
DMA_API int dump_is_open(dump_handle_t h);

DMA_API analyzer_handle_t analyzer_create(dma_handle_t dma, dump_handle_t dump);
DMA_API void analyzer_destroy(analyzer_handle_t h);
DMA_API int analyzer_find_pe(analyzer_handle_t h, uint64_t* bases, uint64_t* sizes, int max_count);
DMA_API int analyzer_scan_pattern(analyzer_handle_t h, const uint8_t* pattern, size_t pattern_len,
                                  uint64_t* results, int max_results);
DMA_API int analyzer_list_processes(analyzer_handle_t h, uint64_t system_eprocess,
                                    uint32_t* pids, uint64_t* cr3s, char* names, int max_count, int name_buf_size);

}
