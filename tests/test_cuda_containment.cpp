// Fault Containment Fabric — real CUDA containment proof.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// This suite exercises genuine device work (cudaMalloc, H2D, kernel, sync, D2H,
// CPU parity, cudaFree, device-memory baseline) and proves that a quarantined
// incarnation cannot obtain new authorized accelerator work.

#include <cstdint>
#include <string>
#include <vector>

#include "cuda/cuda_probe.hpp"
#include "fcf/engine.hpp"
#include "fcf/net.hpp"
#include "fcf/protocol.hpp"
#include "framework.hpp"
#include "process.hpp"
#include "support.hpp"

using namespace fcf;
using namespace fcf::test;

namespace {

class NullExecutor : public Executor {
public:
    Result<std::string> dispatch(const ContainmentAction& action) override {
        return std::string("cuda-test:") + to_string(action.id);
    }
};

/// Registers a synthetic single-GPU topology around one real device.
struct CudaFixture {
    LogicalClock clock;
    Engine engine;
    ResourceId accelerator{ResourceId::from_value(1)};
    ResourceId cpu_service{ResourceId::from_value(2)};

    CudaFixture() : engine(make_config(clock)) {
        (void)engine.register_worker(WorkerId::from_value(1), WorkerBootId::from_value(11), "cuda-A",
                                     EvidenceSequence::from_value(1));
        (void)engine.register_worker(WorkerId::from_value(2), WorkerBootId::from_value(21), "cpu-B",
                                     EvidenceSequence::from_value(1));
        (void)engine.register_isolation_domain(make_isolation_domain(101, "gpu-iso", {1}));
        (void)engine.register_isolation_domain(make_isolation_domain(102, "cpu-iso", {2}));
        (void)engine.register_failure_domain(make_failure_domain(201, "gpu-fd", {1}));
        (void)engine.register_failure_domain(make_failure_domain(202, "cpu-fd", {2}));
        add_resource(engine, ResourceSpec{1, "cuda-accelerator", ResourceClass::ACCELERATOR,
                                          ProtectionClass::STANDARD, 0, 101, 201, 1, 11});
        add_resource(engine, ResourceSpec{2, "cpu-service", ResourceClass::SERVICE,
                                          ProtectionClass::STANDARD, 0, 102, 202, 2, 21});
    }

    ContainmentGeneration contain_device_failure() {
        FaultEvidence evidence;
        evidence.kind = FaultKind::DEVICE_FAILURE;
        evidence.subject = accelerator;
        evidence.reporter_kind = ReporterKind::COORDINATOR;
        evidence.epoch = engine.epoch();
        evidence.freshness = EvidenceFreshness::FRESH;
        evidence.integrity = IntegrityStatus::VERIFIED;
        const Result<FaultRecord> fault = engine.publish_fault(evidence);
        FCF_REQUIRE_MSG(fault.ok(), fault.ok() ? "" : fault.error().to_string());
        const Result<ContainmentRecord> containment =
            engine.authorize_containment(fault.value().evidence.id, fault.value().evidence.generation);
        FCF_REQUIRE_MSG(containment.ok(), containment.ok() ? "" : containment.error().to_string());
        return containment.value().generation;
    }

    void settle(ContainmentGeneration generation) {
        const Result<ContainmentRecord> record = engine.query_containment(generation);
        FCF_REQUIRE(record.ok());
        NullExecutor executor;
        FCF_REQUIRE(engine.dispatch_containment(generation, &executor).ok());
        for (const ActionId action_id : record.value().actions) {
            const Result<ContainmentAction> action = engine.query_action(action_id);
            FCF_REQUIRE(action.ok());
            ActionAcknowledgment ack;
            ack.action = action_id;
            ack.action_generation = action.value().generation;
            ack.epoch = engine.epoch();
            ack.accepted = true;
            FCF_REQUIRE(engine.record_action_ack(ack).ok());
            ActionResult result;
            result.action = action_id;
            result.action_generation = action.value().generation;
            result.epoch = engine.epoch();
            result.success = true;
            result.mechanism = ContainmentMechanism::LOGICAL_CONTAINMENT;
            FCF_REQUIRE(engine.record_action_result(result).ok());
        }
    }
};

}  // namespace

FCF_TEST(cuda_containment, device_provenance_is_reported_honestly) {
    const cuda::DeviceInfo device = cuda::query_device();
    if (!device.available) {
        std::cout << "  CUDA UNSUPPORTED: " << device.driver_error << std::endl;
        FCF_REQUIRE_MSG(device.driver_error.size() > 0U,
                        "an unavailable device must explain why");
        return;
    }
    std::cout << "  CUDA REAL device=\"" << device.name << "\" compute=" << device.compute_major << "."
              << device.compute_minor << " count=" << device.device_count
              << " total_bytes=" << device.total_memory_bytes << std::endl;
    FCF_REQUIRE(!device.name.empty());
    FCF_REQUIRE(device.device_count >= 1);
    if (device.device_count == 1) {
        std::cout << "  NOTE: exactly one physical GPU is present; multi-GPU containment is NOT "
                     "claimed."
                  << std::endl;
    }
}

FCF_TEST(cuda_containment, real_workload_executes_with_cpu_parity_and_releases_memory) {
    const cuda::DeviceInfo device = cuda::query_device();
    if (!device.available) {
        std::cout << "  CUDA UNSUPPORTED: " << device.driver_error << std::endl;
        return;
    }
    const std::size_t baseline = cuda::free_device_memory_bytes();
    FCF_REQUIRE(baseline > 0U);
    const cuda::WorkloadResult workload = cuda::run_workload(1U << 20);
    FCF_REQUIRE_MSG(workload.ok, workload.detail);
    FCF_REQUIRE(workload.cpu_parity);
    FCF_REQUIRE(workload.memory_released);
    FCF_EQ(workload.elements, static_cast<std::size_t>(1U << 20));
    const std::size_t after = cuda::free_device_memory_bytes();
    std::cout << "  device free bytes baseline=" << baseline << " after=" << after
              << " kernel_us=" << workload.kernel_milliseconds << std::endl;
    // Device memory must return to the baseline within the measurement noise of the
    // driver's own allocations.
    FCF_REQUIRE_MSG(after + (16U * 1024U * 1024U) >= baseline,
                    "device memory did not return to the measured baseline");
}

FCF_TEST(cuda_containment, quarantined_incarnation_cannot_receive_new_accelerator_work) {
    CudaFixture fixture;
    const ContainmentGeneration generation = fixture.contain_device_failure();

    // The accelerator is fenced and cannot receive new authorised work.
    const Result<ResourceStatusView> accelerator =
        fixture.engine.query_resource_status(fixture.accelerator);
    FCF_REQUIRE(accelerator.ok());
    FCF_REQUIRE(accelerator.value().quarantined);
    FCF_REQUIRE(!accelerator.value().operable);

    // Unrelated CPU work is explicitly unaffected and remains operable.
    const Result<ResourceStatusView> cpu = fixture.engine.query_resource_status(fixture.cpu_service);
    FCF_REQUIRE(cpu.ok());
    FCF_REQUIRE(cpu.value().operable);
    FCF_REQUIRE(!cpu.value().quarantined);

    fixture.settle(generation);
    const Result<ContainmentVerification> verification =
        fixture.engine.verify_containment(generation);
    FCF_REQUIRE(verification.ok());
    FCF_EQ(verification.value().outcome, VerificationOutcome::CONTAINED);

    // The degraded contract proves that a quarantined accelerator is not consumed.
    DegradedModeContract contract;
    contract.name = "cpu-only";
    contract.legal_workload_classes = {ResourceClass::SERVICE};
    contract.required_redundancy = 1U;
    const Result<DegradedModeAssessment> degraded = fixture.engine.authorize_degraded_mode(contract);
    FCF_REQUIRE(degraded.ok());
    FCF_REQUIRE(degraded_sets_are_disjoint(degraded.value()));
    FCF_REQUIRE(!claims_full_health(degraded.value().status));
    FCF_REQUIRE(!id_set_contains(degraded.value().permitted, fixture.accelerator));
    FCF_REQUIRE(id_set_contains(degraded.value().prohibited, fixture.accelerator));
    FCF_REQUIRE(id_set_contains(degraded.value().permitted, fixture.cpu_service));
}

FCF_TEST(cuda_containment, a_new_incarnation_cannot_inherit_accelerator_authority) {
    CudaFixture fixture;
    const ContainmentGeneration generation = fixture.contain_device_failure();
    fixture.settle(generation);
    const Result<ContainmentVerification> verified = fixture.engine.verify_containment(generation);
    FCF_REQUIRE(verified.ok());
    FCF_EQ(verified.value().outcome, VerificationOutcome::CONTAINED);

    // The failed incarnation is replaced.
    const Result<WorkerRecord> replacement = fixture.engine.register_worker(
        WorkerId::from_value(1), WorkerBootId::from_value(12), "cuda-A2", EvidenceSequence::from_value(2));
    FCF_REQUIRE(replacement.ok());
    const Result<WorkerRecord> original =
        fixture.engine.query_worker(WorkerId::from_value(1), WorkerBootId::from_value(11));
    FCF_REQUIRE(original.ok());
    FCF_REQUIRE(!holds_live_authority(original.value().state));

    // Fresh evidence from the replacement arrives, but the device stays fenced.
    const Result<ResourceRecord> evidence = fixture.engine.publish_resource_evidence(
        fixture.accelerator, ResourceGeneration{}, EvidenceFreshness::FRESH,
        EvidenceSequence::from_value(9), ContainmentMechanism::LOGICAL_CONTAINMENT, "cuda-A2");
    FCF_REQUIRE(evidence.ok());
    const Result<ResourceStatusView> accelerator =
        fixture.engine.query_resource_status(fixture.accelerator);
    FCF_REQUIRE(accelerator.ok());
    FCF_REQUIRE_MSG(accelerator.value().quarantined,
                    "fresh evidence from a new incarnation must not lift containment");

    // Release is still refused until the containment is proven and the criteria hold.
    ReleaseRequest request;
    request.resource = fixture.accelerator;
    request.containment_generation = generation;
    request.expected_generation = accelerator.value().resource.generation;
    request.evidence_sequence = accelerator.value().resource.evidence_sequence;
    request.authority.clear();
    const Result<ReleaseAssessment> denied = fixture.engine.authorize_release(request);
    FCF_REQUIRE(denied.ok());
    FCF_REQUIRE(!denied.value().granted);

    request.authority = "operator:cuda-release";
    const Result<ReleaseAssessment> granted = fixture.engine.authorize_release(request);
    FCF_REQUIRE(granted.ok());
    FCF_REQUIRE_MSG(granted.value().granted, granted.value().summary);
    const Result<ResourceStatusView> released =
        fixture.engine.query_resource_status(fixture.accelerator);
    FCF_REQUIRE(released.ok());
    FCF_REQUIRE(released.value().operable);

    // Only now may real device work run again, and it must still be correct.
    const cuda::DeviceInfo device = cuda::query_device();
    if (!device.available) {
        std::cout << "  CUDA UNSUPPORTED for the post-release workload: " << device.driver_error
                  << std::endl;
        return;
    }
    const cuda::WorkloadResult workload = cuda::run_workload(1U << 18);
    FCF_REQUIRE_MSG(workload.ok, workload.detail);
    FCF_REQUIRE(workload.cpu_parity);
    FCF_REQUIRE(workload.memory_released);
    std::cout << "  post-release CUDA workload parity confirmed, kernel_us="
              << workload.kernel_milliseconds << std::endl;
}


// --- Real multiprocess CUDA containment proof --------------------------------------------

#if defined(FCF_COORDINATOR_BINARY) && defined(FCF_CUDA_WORKER_BINARY)

namespace {

void require_ok(const Result<ControlResponse>& response, const char* what) {
    FCF_REQUIRE_MSG(response.ok(), std::string(what) + ": " +
                                       (response.ok() ? "" : response.error().to_string()));
    FCF_REQUIRE_MSG(response.value().ok, std::string(what) + ": " + response.value().message);
}

[[nodiscard]] std::uint16_t port_of(const std::string& line) {
    const std::string marker = "LISTENING ";
    const std::size_t position = line.find(marker);
    if (position == std::string::npos) {
        return 0;
    }
    std::uint64_t value = 0;
    for (std::size_t index = position + marker.size(); index < line.size(); ++index) {
        const char c = line[index];
        if (c < '0' || c > '9') {
            break;
        }
        value = value * 10U + static_cast<std::uint64_t>(c - '0');
    }
    return static_cast<std::uint16_t>(value);
}

}  // namespace

FCF_TEST(cuda_containment, real_process_death_of_a_cuda_worker_is_contained) {
    FCF_REQUIRE(initialise_network().ok());
    Result<ChildProcess> coordinator =
        ChildProcess::spawn(FCF_COORDINATOR_BINARY, {"--port", "0", "--no-stdin"});
    FCF_REQUIRE(coordinator.ok());
    const std::string listening = coordinator.value().wait_for("LISTENING ");
    FCF_REQUIRE_MSG(!listening.empty(), "the coordinator produced no listening line");
    const std::uint16_t port = port_of(listening);
    FCF_REQUIRE(port != 0);

    Result<ControlClient> client = ControlClient::connect("127.0.0.1", port);
    FCF_REQUIRE(client.ok());
    ControlClient control = std::move(client.value());

    require_ok(control.send("register-isolation-domain", {"101", "gpu", "LOGICAL_CONTAINMENT", "1"}),
               "register gpu domain");
    require_ok(control.send("register-isolation-domain", {"102", "cpu", "LOGICAL_CONTAINMENT", "2"}),
               "register cpu domain");
    require_ok(control.send("register-resource",
                            {"1", "cuda-accelerator", "ACCELERATOR", "STANDARD", "-", "101", "-", "-", "-"}),
               "register accelerator");
    require_ok(control.send("register-resource",
                            {"2", "cpu-service", "SERVICE", "STANDARD", "-", "102", "-", "-", "-"}),
               "register cpu service");

    const std::string endpoint = std::string("127.0.0.1:") + std::to_string(port);

    // The independent CPU worker stays alive for the whole case.
    Result<ChildProcess> cpu_worker = ChildProcess::spawn(
        FCF_WORKER_BINARY, {"--connect", endpoint, "--id", "2", "--boot", "2001", "--resources", "2",
                            "--name", "cpu-B"});
    FCF_REQUIRE(cpu_worker.ok());
    FCF_REQUIRE(!cpu_worker.value().wait_for("WORKER READY").empty());

    // A real CUDA worker: it runs genuine device work before it is fenced.
    Result<ChildProcess> cuda_worker = ChildProcess::spawn(
        FCF_CUDA_WORKER_BINARY, {"--connect", endpoint, "--id", "1", "--boot", "1001", "--resources",
                                 "1", "--name", "cuda-A", "--cuda-elements", "262144"});
    FCF_REQUIRE(cuda_worker.ok());
    FCF_REQUIRE(!cuda_worker.value().wait_for("WORKER READY").empty());
    const std::string baseline = cuda_worker.value().wait_for("WORKER CUDA BASELINE");
    FCF_REQUIRE_MSG(!baseline.empty(), "the CUDA worker never reported its workload");
    FCF_REQUIRE_MSG(baseline.find("parity=1") != std::string::npos, baseline);
    FCF_REQUIRE_MSG(baseline.find("released=1") != std::string::npos, baseline);

    require_ok(control.send("poll-workers"), "poll workers");
    const Result<ControlResponse> owned = poll_until(control, "resource", {"1"}, [](const ControlResponse& response) {
        return has_line(response, "state=ACTIVE") && has_line(response, "owner_boot=WorkerBootId:1001");
    });
    FCF_REQUIRE_MSG(owned.ok(), owned.ok() ? "" : owned.error().to_string());

    // Real process death during the controlled lifecycle phase.
    (void)cuda_worker.value().kill();

    const Result<ControlResponse> containments =
        poll_until(control, "containments", {}, [](const ControlResponse& response) {
            return !response.lines.empty();
        });
    FCF_REQUIRE(containments.ok());
    const Result<ControlResponse> fenced = poll_until(control, "resource", {"1"}, [](const ControlResponse& response) {
        return has_line(response, "quarantined=1") && has_line(response, "operable=0");
    });
    FCF_REQUIRE_MSG(fenced.ok(), fenced.ok() ? "" : fenced.error().to_string());

    // Unrelated permitted work continues on the independent worker.
    const Result<ControlResponse> cpu_status = control.send("resource", {"2"});
    FCF_REQUIRE(cpu_status.ok());
    FCF_REQUIRE_MSG(has_line(cpu_status.value(), "operable=1"),
                    "independent CPU work must continue after the CUDA worker died");

    // A replacement incarnation must not inherit accelerator authority, so it never
    // receives authorised CUDA work.
    Result<ChildProcess> cuda_worker2 = ChildProcess::spawn(
        FCF_CUDA_WORKER_BINARY, {"--connect", endpoint, "--id", "1", "--boot", "1002", "--resources",
                                 "1", "--name", "cuda-A2", "--cuda-elements", "262144"});
    FCF_REQUIRE(cuda_worker2.ok());
    FCF_REQUIRE(!cuda_worker2.value().wait_for("WORKER READY").empty());
    require_ok(control.send("poll-workers"), "poll workers for the replacement");
    const std::string refusal = cuda_worker2.value().wait_for("WORKER CUDA REFUSED");
    FCF_REQUIRE_MSG(!refusal.empty(),
                    "a quarantined incarnation must be refused new accelerator work");

    const Result<ControlResponse> still_fenced = control.send("resource", {"1"});
    FCF_REQUIRE(still_fenced.ok());
    FCF_REQUIRE(has_line(still_fenced.value(), "quarantined=1"));

    (void)coordinator.value().kill();
    (void)cpu_worker.value().kill();
    (void)cuda_worker2.value().kill();
    control.close();
    shutdown_network();
}

#endif  // FCF_COORDINATOR_BINARY && FCF_CUDA_WORKER_BINARY

int main(int argc, char** argv) { return fcf::test::run(argc, argv); }
