#pragma once

#include <cstdint>

namespace dma {

class DMAInterface;
class DumpManager;

class MemoryViewer {
public:
    static void render(DMAInterface* dma, DumpManager* dump, uint64_t& current_address);
};

} // namespace dma
