# Fault Containment Fabric — test suites.
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# No suite is registered with a timeout. A hanging case is a defect to diagnose,
# never something to terminate.

# AddressSanitizer instrumentation self-test. Registered as a test that is expected
# to fail under instrumentation and to pass (exit 0) without it; the CTest wrapper
# below asserts the instrumentation actually caught the intentional fault.
add_executable(fcf_asan_probe asan_probe.cpp)
target_link_libraries(fcf_asan_probe PRIVATE fcf_options)

add_library(fcf_test_support INTERFACE)
target_include_directories(fcf_test_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fcf_test_support INTERFACE FaultContainmentFabric::fcf)

function(fcf_test_suite name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE fcf_test_support)
    add_test(NAME ${name} COMMAND ${name})
    # TIMEOUT 0 explicitly disables the CTest timeout for this suite.
    set_tests_properties(${name} PROPERTIES TIMEOUT 0)
    set_property(TEST ${name} PROPERTY ENVIRONMENT "FCF_TEST_SUITE=${name}")
endfunction()

if(FAULT_CONTAINMENT_ENABLE_ASAN)
    # Control mode must succeed, and the fault mode must be caught by the runtime.
    add_test(NAME asan_probe_control COMMAND fcf_asan_probe 0)
    set_tests_properties(asan_probe_control PROPERTIES TIMEOUT 0 WILL_FAIL FALSE)
    add_test(NAME asan_selftest_catches_intentional_error
             COMMAND ${CMAKE_COMMAND}
                     -DPROBE=$<TARGET_FILE:fcf_asan_probe>
                     -P ${CMAKE_CURRENT_SOURCE_DIR}/asan_selftest.cmake)
    set_tests_properties(asan_selftest_catches_intentional_error PROPERTIES TIMEOUT 0)
endif()

fcf_test_suite(test_ids_and_codec test_ids_and_codec.cpp)
fcf_test_suite(test_domain_model test_domain_model.cpp)
fcf_test_suite(test_blast_radius test_blast_radius.cpp)
fcf_test_suite(test_containment_lifecycle test_containment_lifecycle.cpp)
fcf_test_suite(test_stale_authority test_stale_authority.cpp)
fcf_test_suite(test_persistence test_persistence.cpp)
fcf_test_suite(test_transport test_transport.cpp)
fcf_test_suite(test_property test_property.cpp)
fcf_test_suite(test_concurrency test_concurrency.cpp)
fcf_test_suite(test_adversarial test_adversarial.cpp)

if(TARGET fcf_cuda_probe)
    add_executable(test_cuda_containment test_cuda_containment.cpp)
    target_link_libraries(test_cuda_containment PRIVATE fcf_test_support fcf_cuda_probe)
    add_test(NAME test_cuda_containment COMMAND test_cuda_containment)
    set_tests_properties(test_cuda_containment PROPERTIES TIMEOUT 0)
    if(FAULT_CONTAINMENT_BUILD_NODES)
        target_compile_definitions(test_cuda_containment PRIVATE
            FCF_COORDINATOR_BINARY="$<TARGET_FILE:fcf-coordinator>"
            FCF_WORKER_BINARY="$<TARGET_FILE:fcf-worker>"
            FCF_CUDA_WORKER_BINARY="$<TARGET_FILE:fcf-cuda-worker>")
        add_dependencies(test_cuda_containment fcf-coordinator fcf-worker fcf-cuda-worker)
    endif()
endif()

if(FAULT_CONTAINMENT_BUILD_NODES)
    fcf_test_suite(test_multiprocess test_multiprocess.cpp)
    target_compile_definitions(test_multiprocess PRIVATE
        FCF_COORDINATOR_BINARY="$<TARGET_FILE:fcf-coordinator>"
        FCF_WORKER_BINARY="$<TARGET_FILE:fcf-worker>")
    add_dependencies(test_multiprocess fcf-coordinator fcf-worker)

    fcf_test_suite(test_coordinator_restart test_coordinator_restart.cpp)
    target_compile_definitions(test_coordinator_restart PRIVATE
        FCF_COORDINATOR_BINARY="$<TARGET_FILE:fcf-coordinator>"
        FCF_WORKER_BINARY="$<TARGET_FILE:fcf-worker>")
    add_dependencies(test_coordinator_restart fcf-coordinator fcf-worker)
endif()
