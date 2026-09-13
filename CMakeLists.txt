# Fault Containment Fabric — build configuration.
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

cmake_minimum_required(VERSION 3.25)

project(FaultContainmentFabric
    VERSION 1.0.0
    DESCRIPTION "Vendor-neutral C++20 runtime for failure-containment domains, blast-radius computation, isolation and degraded-mode legality"
    HOMEPAGE_URL "https://github.com/pngen/Fault-Containment-Fabric"
    LANGUAGES CXX)

# --- Options ---------------------------------------------------------------------------

option(FAULT_CONTAINMENT_BUILD_TESTS      "Build the Fault Containment Fabric test suites"      ON)
option(FAULT_CONTAINMENT_BUILD_EXAMPLES   "Build the runnable examples"                          ON)
option(FAULT_CONTAINMENT_BUILD_BENCHMARKS "Build the benchmarks"                                ON)
option(FAULT_CONTAINMENT_BUILD_CLI        "Build the fcf-cli inspection tool"                    ON)
option(FAULT_CONTAINMENT_BUILD_NODES      "Build the fcf-coordinator and fcf-worker node binaries" ON)
option(FAULT_CONTAINMENT_ENABLE_CUDA      "Build the optional CUDA proof surface when a CUDA toolkit is present" ON)
option(FAULT_CONTAINMENT_ENABLE_ASAN      "Build with AddressSanitizer (MSVC /fsanitize=address)" OFF)
option(FAULT_CONTAINMENT_ENABLE_ANALYZE   "Run the MSVC static analyser over first-party code (/analyze)" OFF)
option(FAULT_CONTAINMENT_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors"      ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Tests run without command timeouts by design. A hanging test is a defect to
# diagnose, never something to terminate.
set(DART_TESTING_TIMEOUT 0 CACHE STRING "CTest timeout in seconds; 0 disables the timeout")
set(CTEST_TEST_TIMEOUT 0 CACHE STRING "CTest timeout in seconds; 0 disables the timeout")

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
endif()

# --- Interface library holding first-party compile requirements ------------------------

add_library(fcf_options INTERFACE)
add_library(FaultContainmentFabric::options ALIAS fcf_options)

target_compile_features(fcf_options INTERFACE cxx_std_20)

if(MSVC)
    target_compile_options(fcf_options INTERFACE
        /W4
        /permissive-
        /utf-8
        /Zc:__cplusplus
        /Zc:preprocessor
        /EHsc
        /MP)
    if(FAULT_CONTAINMENT_WARNINGS_AS_ERRORS)
        target_compile_options(fcf_options INTERFACE /WX)
    endif()
    target_compile_definitions(fcf_options INTERFACE
        _WIN32_WINNT=0x0A00
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(fcf_options INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wconversion)
    if(FAULT_CONTAINMENT_WARNINGS_AS_ERRORS)
        target_compile_options(fcf_options INTERFACE -Werror)
    endif()
endif()

if(FAULT_CONTAINMENT_ENABLE_ASAN)
    if(MSVC)
        # MSVC needs the sanitizer runtime that matches the target architecture. Detect
        # it explicitly, so a toolchain that lacks it reports an environment limitation
        # with the exact evidence instead of an opaque linker error.
        get_filename_component(FCF_MSVC_TOOLSET_DIR "${CMAKE_CXX_COMPILER}/../../../.." ABSOLUTE)
        find_file(FCF_ASAN_X64_RUNTIME
            NAMES clang_rt.asan_dynamic-x86_64.lib clang_rt.asan_dynamic_runtime_thunk-x86_64.lib
            PATHS "${FCF_MSVC_TOOLSET_DIR}/lib/x64"
            NO_DEFAULT_PATH)
        if(NOT FCF_ASAN_X64_RUNTIME)
            message(FATAL_ERROR
                "AddressSanitizer was requested but this MSVC toolset does not provide the x64 "
                "sanitizer runtime.\n"
                "  looked in: ${FCF_MSVC_TOOLSET_DIR}/lib/x64\n"
                "  compiler : ${CMAKE_CXX_COMPILER}\n"
                "Install the 'C++ AddressSanitizer' component for the x64 target in the Visual "
                "Studio installer, then reconfigure. Fault Containment Fabric reports this as "
                "UNSUPPORTED rather than claiming sanitizer coverage it does not have.")
        endif()
        unset(FCF_ASAN_X64_RUNTIME CACHE)
        target_compile_options(fcf_options INTERFACE /fsanitize=address /Zi)
        target_link_options(fcf_options INTERFACE /INCREMENTAL:NO)
    else()
        target_compile_options(fcf_options INTERFACE -fsanitize=address -fno-omit-frame-pointer -g)
        target_link_options(fcf_options INTERFACE -fsanitize=address)
    endif()
endif()

if(FAULT_CONTAINMENT_ENABLE_ANALYZE)
    if(MSVC)
        # A genuine supported static analysis pass over first-party code in this
        # environment. Findings are reported as warnings.
        target_compile_options(fcf_options INTERFACE /analyze /analyze:external- /wd6001)
    else()
        message(STATUS "FAULT_CONTAINMENT_ENABLE_ANALYZE applies to MSVC builds only")
    endif()
endif()

# --- Core library ----------------------------------------------------------------------

add_library(fcf_core
    src/actions.cpp
    src/blast_radius.cpp
    src/coordinator.cpp
    src/degraded.cpp
    src/dependency.cpp
    src/engine.cpp
    src/error.cpp
    src/explain.cpp
    src/fault.cpp
    src/net.cpp
    src/persistence.cpp
    src/plan.cpp
    src/policy.cpp
    src/protocol.cpp
    src/state_codec.cpp
    src/wire.cpp
    src/worker_registry.cpp
    src/detail/bytes.cpp
    src/detail/crc32c.cpp
    src/detail/sha256.cpp)

add_library(FaultContainmentFabric::fcf ALIAS fcf_core)

target_include_directories(fcf_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(fcf_core PUBLIC fcf_options)

set_target_properties(fcf_core PROPERTIES
    # Exported as FaultContainmentFabric::fcf
    EXPORT_NAME "fcf"
    OUTPUT_NAME "fcf"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON)

if(WIN32)
    target_link_libraries(fcf_core PRIVATE ws2_32)
endif()

source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${${PROJECT_NAME}_SOURCES})

# --- Optional CUDA proof surface --------------------------------------------------------

if(FAULT_CONTAINMENT_ENABLE_CUDA)
    include(CheckLanguage)
    check_language(CUDA)
    if(CMAKE_CUDA_COMPILER)
        enable_language(CUDA)
        add_library(fcf_cuda_probe STATIC cuda/cuda_probe.cu)
        target_include_directories(fcf_cuda_probe PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
        set_target_properties(fcf_cuda_probe PROPERTIES
            CUDA_STANDARD 17
            CUDA_STANDARD_REQUIRED ON
            CUDA_ARCHITECTURES native
            POSITION_INDEPENDENT_CODE ON)
        # The core library never links CUDA: the probe is a separate, optional surface.
        message(STATUS "CUDA proof surface enabled with ${CMAKE_CUDA_COMPILER}")
    else()
        message(STATUS "CUDA toolkit not found: the CUDA proof surface is UNSUPPORTED here")
    endif()
endif()

# --- Installation ----------------------------------------------------------------------

install(TARGETS fcf_core fcf_options
    EXPORT FaultContainmentFabricTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/fcf
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp")

install(EXPORT FaultContainmentFabricTargets
    FILE FaultContainmentFabricTargets.cmake
    NAMESPACE FaultContainmentFabric::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FaultContainmentFabric)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/FaultContainmentFabricConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/FaultContainmentFabricConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FaultContainmentFabric)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/FaultContainmentFabricConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/FaultContainmentFabricConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/FaultContainmentFabricConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FaultContainmentFabric)

# --- Optional components ---------------------------------------------------------------

if(FAULT_CONTAINMENT_BUILD_CLI OR FAULT_CONTAINMENT_BUILD_NODES)
    add_subdirectory(apps)
endif()

if(FAULT_CONTAINMENT_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(FAULT_CONTAINMENT_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

if(FAULT_CONTAINMENT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
