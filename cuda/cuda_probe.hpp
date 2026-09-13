// Fault Containment Fabric — real CUDA containment probe.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// This surface exercises genuine device work: cudaMalloc, host-to-device transfer,
// kernel execution, synchronization, device-to-host copy, CPU parity comparison,
// cudaFree and a device-memory baseline measurement.

#ifndef FCF_CUDA_PROBE_HPP
#define FCF_CUDA_PROBE_HPP

#include <cstddef>
#include <cstdint>
#include <string>

namespace fcf::cuda {

struct DeviceInfo {
    bool available = false;
    std::string name;
    int compute_major = 0;
    int compute_minor = 0;
    std::size_t total_memory_bytes = 0;
    int device_count = 0;
    std::string driver_error;
};

struct WorkloadResult {
    bool ok = false;
    std::string detail;
    std::size_t elements = 0;
    std::uint64_t kernel_milliseconds = 0;
    bool cpu_parity = false;
    std::size_t device_bytes_allocated = 0;
    bool memory_released = false;
};

/// Queries the device without allocating anything.
[[nodiscard]] DeviceInfo query_device();

/// Device memory currently free on device 0, in bytes. Zero when unavailable.
[[nodiscard]] std::size_t free_device_memory_bytes();

/// Runs the real workload: allocate, transfer, execute, synchronize, copy back,
/// compare against a CPU reference and free. Returns what actually happened.
[[nodiscard]] WorkloadResult run_workload(std::size_t elements);

}  // namespace fcf::cuda

#endif  // FCF_CUDA_PROBE_HPP
