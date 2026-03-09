#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace dma {

struct MemoryRegion {
    uint64_t address;
    uint64_t size;
    std::vector<uint8_t> data;
};

class MemoryDump;

/**
 * Plugin interface for analysis extensions.
 * Implement run() to process memory dumps.
 */
class AnalysisPlugin {
public:
    virtual ~AnalysisPlugin() = default;

    virtual std::string name() const = 0;
    virtual std::string version() const = 0;
    virtual std::string description() const = 0;

    virtual void run(MemoryDump& dump) = 0;
};

/**
 * Memory dump view for plugins.
 */
class MemoryDump {
public:
    virtual ~MemoryDump() = default;
    virtual bool read(uint64_t addr, void* buf, size_t size) = 0;
    virtual uint64_t get_size() const = 0;
    virtual std::vector<MemoryRegion> get_regions() const = 0;
};

} // namespace dma
