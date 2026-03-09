#include "memory_viewer.hpp"
#include "../../core/dma_interface/dma_interface.hpp"
#include "../../core/memory_dump/dump_manager.hpp"
#include "imgui.h"
#include <cstdio>
#include <vector>

namespace dma {

void MemoryViewer::render(DMAInterface* dma, DumpManager* dump, uint64_t& current_address) {
    const size_t bytes_per_row = 16;
    const size_t total_rows = 256;
    const size_t chunk_size = bytes_per_row * total_rows;

    std::vector<uint8_t> buffer(chunk_size);
    size_t bytes_read = 0;

    if (dump && dump->is_open()) {
        auto opt = dump->read(current_address, chunk_size);
        if (opt) {
            buffer = std::move(*opt);
            bytes_read = buffer.size();
        }
    } else if (dma && dma->is_initialized()) {
        bytes_read = dma->read(current_address, buffer.data(), chunk_size);
    }

    ImGui::BeginChild("HexView", ImVec2(0, -1), true);

    for (size_t row = 0; row < total_rows && row * bytes_per_row < bytes_read; ++row) {
        uint64_t addr = current_address + row * bytes_per_row;
        ImGui::Text("%08llX:", (unsigned long long)addr);

        ImGui::SameLine(80);
        ImGui::TextDisabled("|");

        for (size_t col = 0; col < bytes_per_row; ++col) {
            size_t idx = row * bytes_per_row + col;
            if (idx >= bytes_read) break;
            ImGui::SameLine(90 + col * 24);
            ImGui::Text("%02X", buffer[idx]);
        }

        ImGui::SameLine(90 + bytes_per_row * 24 + 20);
        ImGui::TextDisabled("| ");
        for (size_t col = 0; col < bytes_per_row; ++col) {
            size_t idx = row * bytes_per_row + col;
            if (idx >= bytes_read) break;
            char c = (buffer[idx] >= 32 && buffer[idx] < 127) ? buffer[idx] : '.';
            ImGui::SameLine();
            ImGui::Text("%c", c);
        }
    }

    ImGui::EndChild();
}

} // namespace dma
