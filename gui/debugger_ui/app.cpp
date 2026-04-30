#include "app.hpp"
#include "memory_viewer.hpp"
#include "../../core/dma_interface/dma_interface.hpp"
#include "../../core/memory_dump/dump_manager.hpp"
#include "../../core/address_translation/page_table_walker.hpp"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>
#include <windows.h>
#include <commdlg.h>
#include <cstdio>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "comdlg32.lib")

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void CreateRenderTarget();
static void CleanupRenderTarget();
static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace dma {

App::App() {
    m_dma = std::make_unique<DMAInterface>();
    m_dump = std::make_unique<DumpManager>(m_dma.get());
    m_analyzer = std::make_unique<StaticAnalyzer>(m_dma.get(), m_dump.get());
}

App::~App() = default;

void App::log(const std::string& msg) {
    m_log_lines.push_front(msg);
    if (m_log_lines.size() > kMaxLogLines) m_log_lines.pop_back();
}

SymbolResolver::ReadCallback App::make_kernel_va_reader() {
    if (!m_connected || m_kernel_cr3 == 0) return nullptr;

    DMAInterface* dma_ptr = m_dma.get();
    uint64_t cr3 = m_kernel_cr3;

    // Physical-memory read callback that the page-table walker uses.
    auto phys_read = [dma_ptr](uint64_t pa, void* buf, size_t size) -> bool {
        return dma_ptr->read(pa, buf, size) == size;
    };

    // Walker is captured by value; constructed once per returned callback.
    auto walker = std::make_shared<PageTableWalker>(phys_read);

    return [walker, dma_ptr, cr3](uint64_t va, void* buf, size_t size) -> bool {
        // Translate page-by-page; reads may cross page boundaries.
        uint8_t* out = static_cast<uint8_t*>(buf);
        size_t done = 0;
        while (done < size) {
            uint64_t cur_va = va + done;
            auto t = walker->translate(cur_va, cr3);
            if (!t || !t->valid) return false;
            size_t page_off = cur_va & 0xFFF;
            size_t can = 0x1000 - page_off;
            size_t want = size - done;
            size_t this_read = can < want ? can : want;
            if (dma_ptr->read(t->physical_address, out + done, this_read) != this_read)
                return false;
            done += this_read;
        }
        return true;
    };
}

void App::run() {
    WNDCLASSEXW wc = {
        sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
        GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
        L"DMA Debugger", nullptr
    };
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"DMA Debugger",
        WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return;
    }
    ShowWindow(hwnd, SW_SHOWDEFAULT);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        render();

        ImGui::Render();
        const float clear_color[4] = {0.1f, 0.1f, 0.12f, 1.0f};
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}

void App::render() {
    render_menu_bar();
    render_sidebar();
    render_main_content();
}

void App::render_menu_bar() {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Connect DMA")) {
                DMAInterface::Config cfg;
                cfg.device_type = m_device_buf;
                cfg.remote = m_remote_buf;
                m_connected = m_dma->initialize(cfg);
                log(m_connected ? std::string("Connected to ") + m_device_buf
                                : std::string("Connect failed (") + m_device_buf + ")");
            }
            if (ImGui::MenuItem("Disconnect", nullptr, false, m_connected)) {
                m_dma->shutdown();
                m_connected = false;
                log("Disconnected DMA");
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Open Dump")) {
                m_dump_loaded = m_dump->open_dump(m_dump_path_buf);
                log(m_dump_loaded ? std::string("Opened dump: ") + m_dump_path_buf
                                  : std::string("Failed to open dump: ") + m_dump_path_buf);
            }
            if (ImGui::MenuItem("Dump Memory", nullptr, false, m_connected)) {
                uint64_t bytes = m_dma->dump_memory(m_dump_path_buf);
                char b[128];
                std::snprintf(b, sizeof(b), "Dumped %llu bytes to %s",
                              (unsigned long long)bytes, m_dump_path_buf);
                log(b);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit")) { PostQuitMessage(0); }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Analysis")) {
            bool has_source = m_connected || m_dump_loaded;
            if (ImGui::MenuItem("Find PE Images", nullptr, false, has_source)) {
                auto images = m_analyzer->find_pe_images();
                char b[64];
                std::snprintf(b, sizeof(b), "Found %zu PE images", images.size());
                log(b);
            }
            if (ImGui::MenuItem("Locate Modules", nullptr, false, has_source)) {
                m_modules = m_analyzer->locate_modules();
                char b[64];
                std::snprintf(b, sizeof(b), "Located %zu modules", m_modules.size());
                log(b);
            }
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }
}

void App::render_sidebar() {
    ImGui::Begin("Connection");

    ImGui::SeparatorText("DMA");
    ImGui::InputText("Device", m_device_buf, sizeof(m_device_buf));
    ImGui::InputText("Remote", m_remote_buf, sizeof(m_remote_buf));
    ImGui::TextDisabled("Status: %s",
        m_connected ? "Connected" : (m_dump_loaded ? "Dump loaded" : "Idle"));

    ImGui::SeparatorText("Dump");
    ImGui::InputText("Path", m_dump_path_buf, sizeof(m_dump_path_buf));

    ImGui::SeparatorText("Kernel context");
    ImGui::InputScalar("Kernel CR3", ImGuiDataType_U64, &m_kernel_cr3, nullptr, nullptr, "%llX");
    ImGui::InputScalar("PsInitialSystemProcess (VA)", ImGuiDataType_U64,
                       &m_ps_initial_system_process, nullptr, nullptr, "%llX");

    ImGui::SeparatorText("Navigation");
    ImGui::InputScalar("Address", ImGuiDataType_U64, &m_view_address, nullptr, nullptr, "%llX");
    if (ImGui::Button("Page +")) m_view_address += 0x1000;
    ImGui::SameLine();
    if (ImGui::Button("Page -")) m_view_address -= 0x1000;

    ImGui::End();
}

void App::render_main_content() {
    ImGui::Begin("Memory View");
    MemoryViewer::render(m_dma.get(), m_dump.get(), m_view_address);
    ImGui::End();

    ImGui::Begin("Analysis");
    if (ImGui::BeginTabBar("AnalysisTabs")) {
        if (ImGui::BeginTabItem("Processes"))   { render_process_list();      ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Modules"))     { render_module_list();       ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Suspicious"))  { render_suspicious_regions();ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Log"))         { render_log();               ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

void App::render_process_list() {
    ImGui::TextDisabled("Walks ActiveProcessLinks via the supplied kernel CR3.");
    bool can_walk = m_connected && m_kernel_cr3 != 0 && m_ps_initial_system_process != 0;

    if (!can_walk) {
        ImGui::TextWrapped("Connect DMA, then enter Kernel CR3 and PsInitialSystemProcess "
                           "(both available via a kernel PDB lookup).");
    }

    if (ImGui::Button("Walk EPROCESS list") && can_walk) {
        auto reader = make_kernel_va_reader();
        if (!reader) {
            log("Process walk: failed to construct VA reader");
        } else {
            SymbolResolver resolver(reader);
            m_processes = resolver.get_process_list(m_ps_initial_system_process);
            char b[64];
            std::snprintf(b, sizeof(b), "Process walk: %zu entries", m_processes.size());
            log(b);
        }
    }

    if (m_processes.empty()) {
        ImGui::TextDisabled("(no processes)");
        return;
    }

    if (ImGui::BeginTable("processes", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("PID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("CR3");
        ImGui::TableSetupColumn("EPROCESS");
        ImGui::TableHeadersRow();
        for (const auto& p : m_processes) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("%u", p.pid);
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(p.name.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::Text("%llX", (unsigned long long)p.cr3);
            ImGui::TableSetColumnIndex(3); ImGui::Text("%llX", (unsigned long long)p.eprocess);
        }
        ImGui::EndTable();
    }
}

void App::render_module_list() {
    bool has_source = m_connected || m_dump_loaded;
    if (ImGui::Button("Scan for modules") && has_source) {
        m_modules = m_analyzer->locate_modules();
        char b[64];
        std::snprintf(b, sizeof(b), "Modules scan: %zu", m_modules.size());
        log(b);
    }
    if (m_modules.empty()) {
        ImGui::TextDisabled("(no modules)");
        return;
    }
    if (ImGui::BeginTable("modules", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Base");
        ImGui::TableSetupColumn("Size");
        ImGui::TableSetupColumn("Name");
        ImGui::TableHeadersRow();
        for (const auto& m : m_modules) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(([&]{
                static char buf[32]; std::snprintf(buf, sizeof(buf), "%llX",
                    (unsigned long long)m.base_address); return buf; }()),
                false, ImGuiSelectableFlags_SpanAllColumns)) {
                m_view_address = m.base_address;
            }
            ImGui::TableSetColumnIndex(1); ImGui::Text("%llu", (unsigned long long)m.size);
            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(m.name.c_str());
        }
        ImGui::EndTable();
    }
}

void App::render_suspicious_regions() {
    ImGui::TextDisabled("Scores PE-without-known-module + high-entropy pages.");

    ImGui::InputScalar("Scan start (PA)", ImGuiDataType_U64, &m_susp_start, nullptr, nullptr, "%llX");
    ImGui::InputScalar("Scan end (PA)",   ImGuiDataType_U64, &m_susp_end,   nullptr, nullptr, "%llX");

    bool has_source = m_connected || m_dump_loaded;
    if (ImGui::Button("Scan suspicious") && has_source) {
        StaticAnalyzer* sa = m_analyzer.get();
        AutomatedIntelligence::ReadCallback rc =
            [sa](uint64_t addr, size_t size) { return sa->read_region(addr, size); };

        auto known = m_analyzer->locate_modules();
        AutomatedIntelligence::ModuleList mods;
        mods.reserve(known.size());
        for (const auto& k : known) mods.emplace_back(k.base_address, k.size);

        AutomatedIntelligence ai;
        m_suspicious = ai.analyze_regions(rc, mods, m_susp_start, m_susp_end);
        char b[64];
        std::snprintf(b, sizeof(b), "Suspicious regions: %zu", m_suspicious.size());
        log(b);
    }

    ImGui::SameLine();
    bool can_rwx = m_connected && m_kernel_cr3 != 0;
    if (ImGui::Button("Find RWX (kernel)") && can_rwx) {
        DMAInterface* dma_ptr = m_dma.get();
        auto phys_read = [dma_ptr](uint64_t pa, void* buf, size_t size) {
            return dma_ptr->read(pa, buf, size) == size;
        };
        AutomatedIntelligence ai;
        m_rwx_pages = ai.find_rwx_pages(phys_read, m_kernel_cr3, m_rwx_start, m_rwx_end);
        char b[64];
        std::snprintf(b, sizeof(b), "RWX pages: %zu", m_rwx_pages.size());
        log(b);
    }

    if (!m_suspicious.empty()) {
        ImGui::SeparatorText("Scored regions");
        if (ImGui::BeginTable("scored", 4,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                ImVec2(0, 200))) {
            ImGui::TableSetupColumn("Address");
            ImGui::TableSetupColumn("Size");
            ImGui::TableSetupColumn("Score");
            ImGui::TableSetupColumn("Reason");
            ImGui::TableHeadersRow();
            for (const auto& r : m_suspicious) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                char addr_buf[32];
                std::snprintf(addr_buf, sizeof(addr_buf), "%llX", (unsigned long long)r.address);
                if (ImGui::Selectable(addr_buf, false, ImGuiSelectableFlags_SpanAllColumns))
                    m_view_address = r.address;
                ImGui::TableSetColumnIndex(1); ImGui::Text("%llu", (unsigned long long)r.size);
                ImGui::TableSetColumnIndex(2); ImGui::Text("%.2f", r.score);
                ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(r.reason.c_str());
            }
            ImGui::EndTable();
        }
    }

    if (!m_rwx_pages.empty()) {
        ImGui::SeparatorText("RWX pages");
        if (ImGui::BeginListBox("##rwx", ImVec2(-1, 200))) {
            for (uint64_t va : m_rwx_pages) {
                char b[32];
                std::snprintf(b, sizeof(b), "%llX", (unsigned long long)va);
                if (ImGui::Selectable(b)) m_view_address = va;
            }
            ImGui::EndListBox();
        }
    }
}

void App::render_log() {
    if (ImGui::Button("Clear")) m_log_lines.clear();
    ImGui::Separator();
    if (ImGui::BeginChild("log_scroll", ImVec2(0, 0), true)) {
        for (const auto& line : m_log_lines) {
            ImGui::TextUnformatted(line.c_str());
        }
    }
    ImGui::EndChild();
}

} // namespace dma

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createFlags,
            featureLevelArray, 2, D3D11_SDK_VERSION, &sd,
            &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;
    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

static void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

static void CleanupRenderTarget() {
    if (g_mainRenderTargetView) {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;
    switch (msg) {
        case WM_SIZE:
            if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
                CleanupRenderTarget();
                g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
                CreateRenderTarget();
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}
