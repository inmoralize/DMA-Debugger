#pragma once

#include "static_analyzer.hpp"
#include <string>
#include <vector>
#include <tuple>

namespace dma {

class StaticAnalyzer;

class PatternScanner {
public:
    static std::vector<ScanResult> scan(StaticAnalyzer* analyzer,
                                        const std::string& pattern_name,
                                        const std::vector<uint8_t>& pattern,
                                        const std::vector<uint8_t>& mask);

    static std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> parse_ida_pattern(
        const std::string& ida_pattern);
};

} // namespace dma
