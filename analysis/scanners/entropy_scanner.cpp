#include "entropy_scanner.hpp"
#include <cmath>
#include <array>
#include <cstring>

namespace dma {

double EntropyScanner::calculate(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0;

    std::array<uint64_t, 256> freq = {};
    for (size_t i = 0; i < size; ++i) {
        freq[data[i]]++;
    }

    double entropy = 0;
    double inv_size = 1.0 / size;
    for (uint64_t f : freq) {
        if (f == 0) continue;
        double p = f * inv_size;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

} // namespace dma
