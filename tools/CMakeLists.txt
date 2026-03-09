# CLI Dump Tool
add_executable(dump_tool dump_tool.cpp)
target_include_directories(dump_tool PRIVATE ${CMAKE_SOURCE_DIR}/core)
target_link_libraries(dump_tool PRIVATE dma_debugger_core)
target_compile_definitions(dump_tool PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)

# CLI Analyzer
add_executable(analyzer analyzer.cpp)
target_include_directories(analyzer PRIVATE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/analysis
    ${CMAKE_SOURCE_DIR}/analysis/static_analysis
)
target_link_libraries(analyzer PRIVATE dma_debugger_core dma_analysis)
target_compile_definitions(analyzer PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
