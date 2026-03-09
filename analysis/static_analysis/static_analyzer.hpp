#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <optional>
#include <memory>

namespace dma {

class DumpManager;
class DMAInterface;

struct PEModule {
    uint64_t base_address;
    uint64_t size;
    std::string name;
    std::string path;
    bool is_64bit;
    bool is_kernel;
};

struct ScanResult {
    uint64_t address;
    std::string pattern_name;
    std::vector<uint8_t> context;
};

struct ExtractedString {
    uint64_t address;
    std::string value;
    size_t length;
};

/**
 * Static Analysis Engine - Analyze memory dumps offline.
 * PE scanning, pattern matching, string extraction, entropy analysis.
 */
class PEScanner;
class PatternScanner;

class StaticAnalyzer {
    friend class PEScanner;
    friend class PatternScanner;
public:
    StaticAnalyzer(DMAInterface* dma, DumpManager* dump_mgr);

    /** Find PE images in memory (MZ header scan) */
    std::vector<PEModule> find_pe_images();

    /** Scan for byte pattern. Returns all matches. */
    std::vector<ScanResult> scan_pattern(const std::string& pattern_name,
                                         const std::vector<uint8_t>& pattern,
                                         const std::vector<uint8_t>& mask = {});

    /** Scan for IDA-style pattern (e.g. "48 8B 05 ?? ?? ?? ??") */
    std::vector<ScanResult> scan_pattern_ida(const std::string& pattern_name,
                                             const std::string& ida_pattern);

    /** Extract ASCII strings from region */
    std::vector<ExtractedString> extract_strings(uint64_t base, size_t size,
                                                  size_t min_length = 4);

    /** Extract Unicode strings from region */
    std::vector<ExtractedString> extract_strings_wide(uint64_t base, size_t size,
                                                       size_t min_length = 4);

    /** Locate loaded modules (PE + metadata) */
    std::vector<PEModule> locate_modules();

    /** Scan with YARA rules (requires yara-cpp) */
    std::vector<ScanResult> scan_yara(const std::string& rules_path);

    /** Get entropy of region (0-8, higher = more random) */
    double get_entropy(uint64_t base, size_t size);

    /** Set scan range (default: full memory) */
    void set_scan_range(uint64_t start, uint64_t end);

    /** Read memory region (from dump or live DMA) */
    std::vector<uint8_t> read_region(uint64_t addr, size_t size);

private:
    DMAInterface* m_dma;
    DumpManager* m_dump_mgr;
    uint64_t m_scan_start = 0;
    uint64_t m_scan_end = 0;

    bool is_pe_header(const uint8_t* data, size_t size);
};

} // namespace dma
