#include "pattern_scanner.hpp"
#include "static_analyzer.hpp"
#include <sstream>
#include <cctype>
#include <algorithm>

namespace dma {

std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> PatternScanner::parse_ida_pattern(
    const std::string& ida_pattern) {
    std::vector<uint8_t> pattern, mask;
    std::istringstream iss(ida_pattern);
    std::string token;

    while (iss >> token) {
        if (token == "?" || token == "??") {
            pattern.push_back(0);
            mask.push_back(0);
        } else {
            unsigned int byte = 0;
            if (token.size() == 2 && std::isxdigit(token[0]) && std::isxdigit(token[1])) {
                byte = std::stoul(token, nullptr, 16);
                pattern.push_back(static_cast<uint8_t>(byte));
                mask.push_back(0xFF);
            }
        }
    }
    return {pattern, mask};
}

std::vector<ScanResult> PatternScanner::scan(StaticAnalyzer* analyzer,
                                             const std::string& pattern_name,
                                             const std::vector<uint8_t>& pattern,
                                             const std::vector<uint8_t>& mask) {
    std::vector<ScanResult> result;
    if (!analyzer || pattern.empty()) return result;

    bool use_mask = !mask.empty() && mask.size() == pattern.size();
    const size_t chunk = 16 * 1024 * 1024;
    uint64_t addr = 0;
    uint64_t end = 16ULL * 1024 * 1024 * 1024;

    while (addr < end) {
        auto data = analyzer->read_region(addr, chunk);
        if (data.size() < pattern.size()) break;

        for (size_t i = 0; i + pattern.size() <= data.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < pattern.size(); ++j) {
                uint8_t m = use_mask ? mask[j] : 0xFF;
                if ((data[i + j] & m) != (pattern[j] & m)) {
                    match = false;
                    break;
                }
            }
            if (match) {
                ScanResult sr;
                sr.address = addr + i;
                sr.pattern_name = pattern_name;
                size_t ctx = std::min(size_t(64), data.size() - i);
                sr.context.assign(data.data() + i, data.data() + i + ctx);
                result.push_back(sr);
            }
        }
        addr += chunk - pattern.size();
    }
    return result;
}

} // namespace dma