# Fault Containment Fabric — benchmarks.
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

add_executable(fcf-benchmarks bench_main.cpp)
target_link_libraries(fcf-benchmarks PRIVATE FaultContainmentFabric::fcf)
set_target_properties(fcf-benchmarks PROPERTIES OUTPUT_NAME "fcf-benchmarks")
