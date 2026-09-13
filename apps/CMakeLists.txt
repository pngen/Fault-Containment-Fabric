# Fault Containment Fabric — node and inspection binaries.
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

if(FAULT_CONTAINMENT_BUILD_NODES)
    add_executable(fcf-coordinator fcf-coordinator/main.cpp)
    target_link_libraries(fcf-coordinator PRIVATE FaultContainmentFabric::fcf)
    set_target_properties(fcf-coordinator PROPERTIES OUTPUT_NAME "fcf-coordinator")
    install(TARGETS fcf-coordinator RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(fcf-worker fcf-worker/main.cpp)
    target_link_libraries(fcf-worker PRIVATE FaultContainmentFabric::fcf)
    set_target_properties(fcf-worker PROPERTIES OUTPUT_NAME "fcf-worker")
    install(TARGETS fcf-worker RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    if(TARGET fcf_cuda_probe)
        # The same worker source, built with the real CUDA proof surface enabled.
        add_executable(fcf-cuda-worker fcf-worker/main.cpp)
        target_link_libraries(fcf-cuda-worker PRIVATE FaultContainmentFabric::fcf fcf_cuda_probe)
        target_compile_definitions(fcf-cuda-worker PRIVATE FCF_WORKER_CUDA=1)
        set_target_properties(fcf-cuda-worker PROPERTIES OUTPUT_NAME "fcf-cuda-worker")
        install(TARGETS fcf-cuda-worker RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
endif()

if(FAULT_CONTAINMENT_BUILD_CLI)
    add_executable(fcf-cli fcf-cli/main.cpp)
    target_link_libraries(fcf-cli PRIVATE FaultContainmentFabric::fcf)
    set_target_properties(fcf-cli PROPERTIES OUTPUT_NAME "fcf-cli")
    install(TARGETS fcf-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
