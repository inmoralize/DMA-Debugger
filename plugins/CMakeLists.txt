add_library(plugin_interface INTERFACE)
target_include_directories(plugin_interface INTERFACE
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/analysis
)

# Example plugin - can be built as shared library
add_library(plugin_example MODULE
    example/example_plugin.cpp
)
target_link_libraries(plugin_example PRIVATE plugin_interface dma_debugger_core dma_analysis)
set_target_properties(plugin_example PROPERTIES PREFIX "" OUTPUT_NAME "example_plugin")
