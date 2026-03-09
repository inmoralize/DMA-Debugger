# C API for scripting - build as shared library for Python ctypes
add_library(dma_capi SHARED
    c_api/dma_capi.cpp
    c_api/dma_capi.hpp
)

target_include_directories(dma_capi PUBLIC
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/analysis
)

target_link_libraries(dma_capi PRIVATE
    dma_debugger_core
    dma_analysis
)

target_compile_definitions(dma_capi PRIVATE
    DMA_CAPI_EXPORTS
    _CRT_SECURE_NO_WARNINGS
)

set_target_properties(dma_capi PROPERTIES
    WINDOWS_EXPORT_ALL_SYMBOLS OFF
)

if(BUILD_PYTHON_BINDINGS)
    # Python wrapper using ctypes
    add_custom_target(python_wrapper ALL
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/python
            ${CMAKE_BINARY_DIR}/python
    )
endif()
