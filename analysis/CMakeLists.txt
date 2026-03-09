add_library(dma_analysis STATIC
    static_analysis/static_analyzer.cpp
    static_analysis/static_analyzer.hpp
    static_analysis/pe_scanner.cpp
    static_analysis/pe_scanner.hpp
    static_analysis/pattern_scanner.cpp
    static_analysis/pattern_scanner.hpp
    dynamic_analysis/dynamic_analyzer.cpp
    dynamic_analysis/dynamic_analyzer.hpp
    scanners/entropy_scanner.cpp
    scanners/entropy_scanner.hpp
    symbol_resolver/symbol_resolver.cpp
    symbol_resolver/symbol_resolver.hpp
    intelligence/automated_intelligence.cpp
    intelligence/automated_intelligence.hpp
)

target_include_directories(dma_analysis PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/static_analysis
    ${CMAKE_CURRENT_SOURCE_DIR}/dynamic_analysis
    ${CMAKE_CURRENT_SOURCE_DIR}/scanners
    ${CMAKE_SOURCE_DIR}/core
)

target_link_libraries(dma_analysis PUBLIC
    dma_debugger_core
)

target_compile_definitions(dma_analysis PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
)
