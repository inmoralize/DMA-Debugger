#pragma once

#include <cstdint>
#include <cstddef>

namespace dma {

class EntropyScanner {
public:
    /** Calculate Shannon entropy (0-8). Higher = more random/compressed. */
    static double calculate(const uint8_t* data, size_t size);
};

} // namespace dma
