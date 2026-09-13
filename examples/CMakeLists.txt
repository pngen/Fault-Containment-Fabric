# Fault Containment Fabric — runnable examples.
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.

set(FCF_EXAMPLES
    01_basic_containment
    02_dependency_blast_radius
    03_worker_death_fencing
    04_degraded_mode
    05_stale_authority_rejection
    06_quarantine_revalidation_release
    07_persistence_restart)

foreach(example ${FCF_EXAMPLES})
    add_executable(fcf-example-${example} ${example}.cpp)
    target_link_libraries(fcf-example-${example} PRIVATE FaultContainmentFabric::fcf)
    set_target_properties(fcf-example-${example} PROPERTIES OUTPUT_NAME "fcf-example-${example}")
endforeach()
