#include "../plugin_interface.hpp"
#include <iostream>
#include <cstring>

namespace {

class ExamplePlugin : public dma::AnalysisPlugin {
public:
    std::string name() const override { return "Example Scanner"; }
    std::string version() const override { return "1.0"; }
    std::string description() const override {
        return "Scans for MZ headers and reports findings";
    }

    void run(dma::MemoryDump& dump) override {
        std::cout << "[ExamplePlugin] Scanning memory dump\n";
        uint64_t count = 0;
        const size_t chunk = 4 * 1024 * 1024;
        uint64_t size = dump.get_size();
        for (uint64_t addr = 0; addr < size; addr += chunk - 0x1000) {
            uint8_t buf[0x1000];
            for (size_t i = 0; i + 64 <= sizeof(buf); i += 0x1000) {
                if (!dump.read(addr + i, buf, 64)) continue;
                if (buf[0] == 'M' && buf[1] == 'Z') {
                    count++;
                    if (count <= 10) {
                        std::cout << "  PE at 0x" << std::hex << (addr + i) << std::dec << "\n";
                    }
                }
            }
        }
        std::cout << "[ExamplePlugin] Found " << count << " PE headers\n";
    }
};

} // namespace

extern "C" {

#ifdef _WIN32
__declspec(dllexport)
#endif
dma::AnalysisPlugin* create_plugin() {
    return new ExamplePlugin();
}

#ifdef _WIN32
__declspec(dllexport)
#endif
void destroy_plugin(dma::AnalysisPlugin* p) {
    delete p;
}

}
