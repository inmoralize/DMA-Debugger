#pragma once

#include "static_analyzer.hpp"
#include <cstdint>
#include <vector>

namespace dma {

class StaticAnalyzer;

class PEScanner {
public:
    static std::vector<PEModule> scan_for_pe(StaticAnalyzer* analyzer);
    static void enrich_module(PEModule& mod, const uint8_t* header_data);
};

} // namespace dma
