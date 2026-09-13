// Fault Containment Fabric — AddressSanitizer instrumentation self-test.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// This program deliberately performs an out-of-bounds heap write. It exists only to
// prove that the AddressSanitizer runtime is genuinely active in this build
// configuration, and it is never part of the first-party test suite. A correctly
// instrumented build aborts here; an uninstrumented build would exit 0.

#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    const int mode = argc > 1 ? std::atoi(argv[1]) : 1;
    if (mode == 0) {
        // Control mode: no intentional fault, used to confirm the probe runs at all.
        std::printf("asan_probe control mode: no fault injected\n");
        return 0;
    }
    std::printf("asan_probe: injecting an intentional heap-buffer-overflow\n");
    std::fflush(stdout);
    auto* buffer = static_cast<volatile unsigned char*>(std::malloc(16));
    if (buffer == nullptr) {
        return 2;
    }
    for (int index = 0; index < 64; ++index) {
        buffer[index] = static_cast<unsigned char>(index);
    }
    std::printf("asan_probe: the intentional fault was NOT detected\n");
    std::free(const_cast<unsigned char*>(buffer));
    return 1;
}
