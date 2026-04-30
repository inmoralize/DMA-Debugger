#include "memory_viewer.hpp"
#include "../../core/dma_interface/dma_interface.hpp"
#include "../../core/memory_dump/dump_manager.hpp"
#include "imgui.h"
#include <cstdio>
#include <vector>

namespace dma {

void MemoryViewer::render(DMAInterface* dma_iface, DumpManager* dump, uint64_t& current_address) {
    constexpr size_t bytes_per_row = 16;
    constexpr size_t total_rows = 32;
    constexpr size_t chunk_size = bytes_per_row * total_rows;

    // Zero-init so failed/short reads don't render uninitialized bytes.
    std::vector<uint8_t> buffer(chunk_size, 0);
    size_t bytes_read = 0;

    if (dump && dump->is_open()) {
        if (auto opt = dump->read(current_address, chunk_size); opt) {
            bytes_read = opt->size();
            std::copy(opt->begin(), opt->end(), buffer.begin());
        }
    } else if (dma_iface && dma_iface->is_initialized()) {
        bytes_read = dma_iface->read(current_address, buffer.data(), chunk_size);
    }

    if (bytes_read == 0) {
        ImGui::TextDisabled("No data — connect DMA or open a dump.");
        return;
    }

    // Mouse-wheel scroll moves the address window; useful when the viewport
    // doesn't have its own scrollbar (we only render `total_rows` at a time).
    if (ImGui::IsWindowHovered()) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel > 0) current_address -= bytes_per_row * 4;
        else if (wheel < 0) current_address += bytes_per_row * 4;
    }

    // Use a fixed-pitch layout via a single formatted line per row instead of
    // multiple SameLine() calls (which were positionally broken in the
    // previous implementation).
    ImGui::PushFont(ImGui::GetIO().FontDefault);
    ImGui::BeginChild("HexView", ImVec2(0, 0), true);

    char line[256];
    for (size_t row = 0; row < total_rows; ++row) {
        size_t row_offset = row * bytes_per_row;
        if (row_offset >= bytes_read) break;

        int len = std::snprintf(line, sizeof(line), "%012llX  ",
                                (unsigned long long)(current_address + row_offset));

        for (size_t col = 0; col < bytes_per_row; ++col) {
            size_t idx = row_offset + col;
            if (idx < bytes_read) {
                len += std::snprintf(line + len, sizeof(line) - len, "%02X ", buffer[idx]);
            } else {
                len += std::snprintf(line + len, sizeof(line) - len, "   ");
            }
            if (col == 7) len += std::snprintf(line + len, sizeof(line) - len, " ");
        }

        len += std::snprintf(line + len, sizeof(line) - len, " ");
        for (size_t col = 0; col < bytes_per_row; ++col) {
            size_t idx = row_offset + col;
            char c = '.';
            if (idx < bytes_read) {
                uint8_t b = buffer[idx];
                c = (b >= 32 && b < 127) ? (char)b : '.';
            } else {
                c = ' ';
            }
            if (len + 1 < (int)sizeof(line)) line[len++] = c;
        }
        line[len < (int)sizeof(line) ? len : (int)sizeof(line) - 1] = '\0';
        ImGui::TextUnformatted(line);
    }

    ImGui::EndChild();
    ImGui::PopFont();
}

} // namespace dma
