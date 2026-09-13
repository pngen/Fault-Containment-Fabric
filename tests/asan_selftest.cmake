# Fault Containment Fabric — AddressSanitizer self-test driver.
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# Runs the intentional-fault probe and asserts that the sanitizer runtime actually
# reported it. Without instrumentation the probe would exit with a nonzero status of
# its own, so the probe's own "not detected" exit code is distinguished explicitly.

if(NOT DEFINED PROBE)
    message(FATAL_ERROR "PROBE must point at the fcf_asan_probe executable")
endif()

execute_process(COMMAND "${PROBE}" 1
                RESULT_VARIABLE probe_status
                OUTPUT_VARIABLE probe_output
                ERROR_VARIABLE probe_error)

if(probe_status EQUAL 0)
    message(FATAL_ERROR
        "the intentional memory error was NOT detected; AddressSanitizer is not active. "
        "stdout=${probe_output} stderr=${probe_error}")
endif()

if(probe_status EQUAL 1)
    message(FATAL_ERROR
        "the probe reported that its own intentional fault was not detected, which means "
        "instrumentation is absent. stdout=${probe_output} stderr=${probe_error}")
endif()

string(FIND "${probe_error}" "AddressSanitizer" sanitizer_marker)
if(sanitizer_marker EQUAL -1)
    message(FATAL_ERROR
        "the probe failed but produced no AddressSanitizer report, so the failure is not "
        "evidence of working instrumentation. stderr=${probe_error}")
endif()

message(STATUS "AddressSanitizer self-test passed: the runtime detected the intentional error.")
