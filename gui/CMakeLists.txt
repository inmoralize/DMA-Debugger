# ImGui-based GUI - set IMGUI_DIR to your imgui clone, or use FetchContent
if(NOT DEFINED IMGUI_DIR)
    set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/imgui CACHE PATH "ImGui source directory")
endif()
if(NOT EXISTS ${IMGUI_DIR}/imgui.h)
    include(FetchContent)
    FetchContent_Declare(imgui GIT_REPOSITORY https://github.com/ocornut/imgui.git GIT_TAG v1.90)
    FetchContent_MakeAvailable(imgui)
    set(IMGUI_DIR ${imgui_SOURCE_DIR})
endif()

add_executable(dma_debugger_gui
    debugger_ui/main.cpp
    debugger_ui/memory_viewer.cpp
    debugger_ui/memory_viewer.hpp
    debugger_ui/analysis_panel.cpp
    debugger_ui/analysis_panel.hpp
    debugger_ui/app.cpp
    debugger_ui/app.hpp
)

target_include_directories(dma_debugger_gui PRIVATE
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/analysis
)

target_sources(dma_debugger_gui PRIVATE
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
)

target_link_libraries(dma_debugger_gui PRIVATE
    dma_debugger_core
    dma_analysis
    d3d11
    d3dcompiler
)

target_compile_definitions(dma_debugger_gui PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    UNICODE
    _UNICODE
)
