# Fault Containment Fabric — independent downstream consumer.
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# This is a standalone project. It is deliberately NOT part of the main build: it
# exists to prove that an install tree can be consumed through find_package() with no
# access to the source tree or the build tree.
#
#   cmake -S examples/downstream -B <dir> -DCMAKE_PREFIX_PATH=<install-prefix>
#   cmake --build <dir>
#   <dir>/fcf-downstream-consumer

cmake_minimum_required(VERSION 3.25)

project(FaultContainmentFabricDownstreamConsumer
    VERSION 1.0.0
    DESCRIPTION "Independent consumer of the installed Fault Containment Fabric package"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(FaultContainmentFabric CONFIG REQUIRED)

add_executable(fcf-downstream-consumer main.cpp)
target_link_libraries(fcf-downstream-consumer PRIVATE FaultContainmentFabric::fcf)

if(NOT TARGET FaultContainmentFabric::fcf)
    message(FATAL_ERROR "FaultContainmentFabric::fcf was not provided by the installed package")
endif()
message(STATUS "downstream consumer linked against the installed FaultContainmentFabric::fcf")
