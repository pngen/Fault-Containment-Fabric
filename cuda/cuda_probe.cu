// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "cuda/cuda_probe.hpp"

#include <cuda_runtime.h>

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

namespace fcf::cuda {
namespace {

__global__ void scale_and_shift(const float* input, float* output, int count, float scale, float shift) {
    const int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index < count) {
        output[index] = input[index] * scale + shift;
    }
}

[[nodiscard]] std::string cuda_error_text(cudaError_t code) {
    return std::string(cudaGetErrorName(code)) + ": " + cudaGetErrorString(code);
}

}  // namespace

DeviceInfo query_device() {
    DeviceInfo info;
    if (cudaGetDeviceCount(&info.device_count) != cudaSuccess) {
        info.driver_error = cuda_error_text(cudaGetLastError());
        return info;
    }
    if (info.device_count <= 0) {
        info.driver_error = "no CUDA device is present";
        return info;
    }
    cudaDeviceProp properties{};
    if (cudaGetDeviceProperties(&properties, 0) != cudaSuccess) {
        info.driver_error = cuda_error_text(cudaGetLastError());
        return info;
    }
    info.available = true;
    info.name = properties.name;
    info.compute_major = properties.major;
    info.compute_minor = properties.minor;
    info.total_memory_bytes = static_cast<std::size_t>(properties.totalGlobalMem);
    return info;
}

std::size_t free_device_memory_bytes() {
    std::size_t free_bytes = 0;
    std::size_t total_bytes = 0;
    if (cudaMemGetInfo(&free_bytes, &total_bytes) != cudaSuccess) {
        (void)cudaGetLastError();
        return 0;
    }
    return free_bytes;
}

WorkloadResult run_workload(std::size_t elements) {
    WorkloadResult result;
    result.elements = elements;
    if (elements == 0U) {
        result.detail = "no elements requested";
        return result;
    }

    std::vector<float> host_input(elements);
    std::vector<float> host_output(elements, 0.0F);
    std::vector<float> reference(elements, 0.0F);
    for (std::size_t index = 0; index < elements; ++index) {
        host_input[index] = static_cast<float>(index % 97U) * 0.5F - 12.0F;
        reference[index] = host_input[index] * 3.0F + 1.25F;
    }

    float* device_input = nullptr;
    float* device_output = nullptr;
    const std::size_t bytes = elements * sizeof(float);
    cudaError_t status = cudaMalloc(reinterpret_cast<void**>(&device_input), bytes);
    if (status != cudaSuccess) {
        result.detail = "cudaMalloc(input) failed: " + cuda_error_text(status);
        return result;
    }
    status = cudaMalloc(reinterpret_cast<void**>(&device_output), bytes);
    if (status != cudaSuccess) {
        (void)cudaFree(device_input);
        result.detail = "cudaMalloc(output) failed: " + cuda_error_text(status);
        return result;
    }
    result.device_bytes_allocated = bytes * 2U;

    status = cudaMemcpy(device_input, host_input.data(), bytes, cudaMemcpyHostToDevice);
    if (status != cudaSuccess) {
        result.detail = "host-to-device copy failed: " + cuda_error_text(status);
        (void)cudaFree(device_input);
        (void)cudaFree(device_output);
        return result;
    }

    const int count = static_cast<int>(elements);
    const int threads = 256;
    const int blocks = (count + threads - 1) / threads;
    const auto start = std::chrono::steady_clock::now();
    scale_and_shift<<<blocks, threads>>>(device_input, device_output, count, 3.0F, 1.25F);
    status = cudaDeviceSynchronize();
    const auto finish = std::chrono::steady_clock::now();
    if (status != cudaSuccess) {
        result.detail = "kernel execution failed: " + cuda_error_text(status);
        (void)cudaFree(device_input);
        (void)cudaFree(device_output);
        return result;
    }
    result.kernel_milliseconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(finish - start).count());

    status = cudaMemcpy(host_output.data(), device_output, bytes, cudaMemcpyDeviceToHost);
    if (status != cudaSuccess) {
        result.detail = "device-to-host copy failed: " + cuda_error_text(status);
        (void)cudaFree(device_input);
        (void)cudaFree(device_output);
        return result;
    }

    result.cpu_parity = true;
    for (std::size_t index = 0; index < elements; ++index) {
        if (host_output[index] != reference[index]) {
            result.cpu_parity = false;
            result.detail = "device result differs from the CPU reference at element " +
                            std::to_string(index);
            break;
        }
    }

    const cudaError_t free_input = cudaFree(device_input);
    const cudaError_t free_output = cudaFree(device_output);
    result.memory_released = free_input == cudaSuccess && free_output == cudaSuccess;
    if (!result.memory_released) {
        result.detail = "cudaFree failed";
    }
    (void)cudaGetLastError();
    result.ok = result.cpu_parity && result.memory_released;
    if (result.ok && result.detail.empty()) {
        result.detail = "kernel executed, CPU parity confirmed and all device memory released";
    }
    return result;
}

}  // namespace fcf::cuda
