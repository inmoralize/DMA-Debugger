cmake_minimum_required(VERSION 3.16)
project(DMADebugger VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# LeechCore path - user should set LEECHCORE_ROOT or install to default location
if(NOT DEFINED LEECHCORE_ROOT)
    set(LEECHCORE_ROOT "C:/LeechCore" CACHE PATH "Path to LeechCore installation")
endif()

# Options
option(BUILD_GUI "Build ImGui-based GUI" ON)
option(BUILD_PYTHON_BINDINGS "Build Python scripting API" OFF)
option(BUILD_CLI_TOOLS "Build CLI tools (dump_tool, analyzer)" ON)

# Core library
add_subdirectory(core)

# Analysis engine
add_subdirectory(analysis)

# Scripting
add_subdirectory(scripting)

# GUI (Win32 + DX11 only)
if(BUILD_GUI)
    if(WIN32)
        add_subdirectory(gui)
    else()
        message(STATUS "BUILD_GUI=ON: skipping Win32/DX11 GUI on non-Windows host")
    endif()
endif()

# Plugins
add_subdirectory(plugins)

# CLI Tools
if(BUILD_CLI_TOOLS)
    add_subdirectory(tools)
endif()
