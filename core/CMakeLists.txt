# LeechCore is optional - set LEECHCORE_ROOT and link if available
find_path(LEECHCORE_INCLUDE leechcore.h HINTS ${LEECHCORE_ROOT}/include)
find_library(LEECHCORE_LIB leechcore HINTS ${LEECHCORE_ROOT}/lib ${LEECHCORE_ROOT})

add_library(dma_debugger_core STATIC
    dma_interface/dma_interface.cpp
    dma_interface/dma_interface.hpp
    memory_dump/dump_manager.cpp
    memory_dump/dump_manager.hpp
    memory_dump/dump_format.hpp
    address_translation/page_table_walker.cpp
    address_translation/page_table_walker.hpp
    address_translation/address_translation.hpp
)

target_include_directories(dma_debugger_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

if(LEECHCORE_INCLUDE)
    target_include_directories(dma_debugger_core PUBLIC ${LEECHCORE_INCLUDE})
    target_compile_definitions(dma_debugger_core PRIVATE LEECHCORE_AVAILABLE=1)
endif()
if(LEECHCORE_LIB)
    target_link_libraries(dma_debugger_core PUBLIC ${LEECHCORE_LIB})
endif()

target_compile_definitions(dma_debugger_core PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
)
