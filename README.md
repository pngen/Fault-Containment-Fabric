# Fault Containment Fabric

Fault Containment Fabric is a vendor-neutral C++20 runtime for defining failure-containment
domains, detecting when faults threaten to cross those boundaries, isolating affected
infrastructure, preventing propagation, and preserving explicitly permitted degraded operation
without confusing containment with recovery.

**Version 1.0.0** — Apache License 2.0, Copyright 2026 Summon Software Labs.

---

## The core question

> When part of accelerator infrastructure becomes faulty, compromised, unreachable, inconsistent,
> or unsafe, what is the smallest authoritative blast radius that must be isolated, what
> dependencies must be fenced with it, what unaffected work may continue, and what degraded mode
> remains legally operable without allowing the failure to propagate?

The defining distinction is between:

> *A failure occurred.*

and:

> *This exact failure, under current evidence and authority, requires this exact containment
> boundary, these resources are fenced, these unaffected resources remain permitted, and this
> degraded operating state is still authoritative.*

Containment happens **before** recovery. Recovery answers what to do after a fault. Fault
Containment Fabric answers what the fault is allowed to damage.

## What this runtime owns

* containment-domain identity, isolation-domain membership, explicit failure-boundary topology;
* fault classification relevant to containment, and fault state;
* dependency edges relevant to propagation, and propagation control;
* deterministic blast-radius computation with a stable explanation;
* containment policy, isolation eligibility, containment actions and their authority;
* dependency-aware fencing, quarantine, degraded-mode eligibility and containment state;
* containment evidence, verification, and release-from-containment eligibility;
* stale-authority rejection and generation-bound containment authority;
* persistence with conservative restart semantics;
* append-only history and audit.

## What this runtime does not own

Scheduling generally; workload placement generally; topology discovery generally; network routing
generally; physical device reset mechanisms; GPU allocation internals; accelerator partition
lifecycle; model lifecycle; SLO definition; cost policy; generic observability; full cluster
orchestration; service replacement and promotion.

It consumes evidence from neighbouring systems and emits typed intents to them. It does not absorb
their responsibilities.

### Neighbouring runtime separation

| System | Owns | Fault Containment Fabric's relationship |
| --- | --- | --- |
| Failure Fabric | failure semantics, ambiguity, retry classification, idempotency, compensation, rollback/recovery ownership | consumes fault evidence; does not classify retries |
| Chaos Lab | injecting and orchestrating reproducible failures | reacts to fault evidence; never injects faults itself |
| Failover Fabric | selecting and promoting replacement service authority | determines what must be isolated before or during promotion |
| Recovery Planner | choosing restore/restart/migrate/rehydrate/promote/failover/recompute | determines what remains legally usable and what must stay fenced while recovery happens |
| SLO Fabric | service obligations | may consume obligations when deciding whether degraded mode is legal; does not own SLOs |
| Topology Fabric / Cluster Fabric / Heterogeneous Accelerator Federation | topology and federation evidence | consumes the structure needed to compute propagation and blast radius |

## Core principles

* **Containment is fail-closed.** UNKNOWN never silently becomes SAFE. A resource that cannot be
  proven outside the blast radius is not treated as unaffected merely because no failure has yet
  been observed on it.
* **Hard containment rules dominate** scores, costs, preferences, utilisation and availability. A
  favourable ranking never rescues a failed mandatory isolation predicate.
* **Containment authority is generation-bound.** A decision made under topology generation N,
  policy generation N, resource generation N, worker incarnation N or coordinator epoch N does not
  silently remain authoritative after relevant state advances.
* **Containment is not recovery.** A resource is not RECOVERED because it was isolated. A service is
  not HEALTHY because propagation stopped. Containment success means the blast radius is bounded
  according to policy and current evidence.
* **Degraded operation is explicit.** Remaining capacity may continue only if a degraded-mode
  contract permits it and current evidence proves its dependencies remain valid.
* **Isolation is dependency-aware.** The point is the smallest correct authoritative blast radius,
  not maximum shutdown. Unrelated resources are not mechanically isolated.
* **Containment is explainable.** Every result exposes the triggering fault, evidence, affected
  domain, computed radius, mandatory inclusions, resources proven outside the radius, selected and
  rejected actions, the degraded-mode determination, the authority envelope and the verification
  status.
* **Actions are transactional where possible.** Planning is not enforcement; enforcement is not
  verification; ACKNOWLEDGED is not CONTAINED.

---

## Architecture

```
include/fcf/       public headers (the only installed surface)
  ids.hpp          strongly typed identities
  error.hpp        typed error codes and context
  result.hpp       Result<T> / Status; policy outcomes are values, not errors
  evidence.hpp     provenance, freshness, integrity, containment mechanism
  domain.hpp       ResourceRecord, containment/isolation/failure domains, Topology
  dependency.hpp   typed dependency edges, propagation outcomes, traversal reasons
  fault.hpp        fault taxonomy, fault state machine, fault evidence and digest
  actions.hpp      containment outcomes, authority envelope, action lifecycle, Executor
  policy.hpp       fault rules, uncertainty behaviour, administrative override
  blast_radius.hpp deterministic result shape
  containment.hpp  committed containment state and release assessment
  degraded.hpp     degraded-mode contracts and assessments
  verification.hpp post-action verification results
  plan.hpp         containment plans
  history.hpp      append-only audit events
  engine.hpp       the runtime
  persistence.hpp  durable snapshot + write-ahead journal
  wire.hpp         framed, bounded, checksummed protocol
  net.hpp          real framed TCP
  protocol.hpp     worker-plane and controller-plane messages
  coordinator.hpp  reference coordinator node
  provenance.hpp   REAL / SYNTHETIC / UNSUPPORTED labelling

src/               implementation (internal headers stay in src/)
apps/              fcf-coordinator, fcf-worker, fcf-cuda-worker, fcf-cli
cuda/              optional real CUDA proof surface
examples/          runnable examples and an independent downstream consumer
benchmarks/        completed-work benchmarks
tests/             proof obligations
```

### Domain model

* **ContainmentDomain** — a logical boundary within which faults may be tolerated or isolated. May
  declare that its members are inseparable.
* **IsolationDomain** — a set of resources that must be fenced together under specified failure
  classes, plus the strongest mechanism actually available for it.
* **FailureDomain** — a physical or logical correlated-failure boundary. The runtime never claims
  discovery of a failure domain the host cannot prove; domains are declared by an operator, an
  import, or a labelled synthetic injection.
* **DependencyEdge** — typed directional dependency with source, destination, type, generation,
  provenance, freshness, integrity, confidence and evidence source. Confidence supplements the
  typed propagation outcome and never replaces mandatory logic.

A resource joins every domain it references, so domain membership and resource placement cannot
drift apart.

### Authority model

Every authoritative plan, action and verification carries an envelope equivalent to:

```
CoordinatorEpoch
FaultId + FaultGeneration
ContainmentGeneration
PolicyGeneration
TopologyGeneration
target ResourceGeneration
WorkerId + WorkerBootId
ActionId + ActionGeneration
required evidence sequence
reservation / lease generations
```

Every field is revalidated immediately before dispatch. A mismatch refuses the dispatch rather than
applying a stale plan. Stale epochs, boots, fault generations, containment generations, policy
generations, topology generations, resource generations and action generations are all rejected.

A process identity and a process incarnation are distinct. Every worker start creates a fresh
`WorkerBootId`; a restarted worker can never reuse stale authority. When Worker A dies, its live
authority is revoked, its dynamic evidence is marked for revalidation, delayed old-boot frames and
old-boot completions are rejected, historical committed records are retained, and fresh evidence
from A′ is required before authority returns.

A coordinator restart advances `CoordinatorEpoch`. Durable history and configuration are
recovered; live process authority is not. Old-epoch traffic is rejected, dynamic evidence becomes
REVALIDATION_REQUIRED, in-flight actions become AMBIGUOUS and are never blindly redispatched, and
fresh evidence is required before current authority is restored.

### Containment lifecycle

```
publish_fault
  -> evaluate_containment      (candidate generation, feasibility, safety, ranking)
  -> authorize_containment     (commit the authoritative radius; generate action candidates)
  -> dispatch_containment      (revalidate every generation, then hand intents to an Executor)
  -> record_action_ack         (ACCEPTED is not CONTAINED)
  -> record_action_result      (what the executor claims is still not proof of effect)
  -> verify_containment        (post-action evidence decides CONTAINED / PARTIAL / BREACHED)
  -> authorize_degraded_mode   (the explicit legal envelope for continued work)
  -> request_release / authorize_release
```

### Blast-radius semantics

The computation is a deterministic function of the fault, the current topology, the dependency
graph, resource generations, failure-domain membership, containment policy, degraded-mode policy,
current evidence and authority state. Inputs are treated as immutable.

Output buckets:

* **mandatory** — must be fenced. Inclusion reasons are typed: fault subject, shared authority,
  state or memory ownership, shared isolation domain, shared failure domain, mandatory
  co-isolation, hard propagation edge, escalated uncertainty, fail-closed on unknown evidence,
  administrative override.
* **precautionary** — conditional propagation. Drained, not fenced.
* **unaffected** — proven outside the radius, each with a recorded proof.
* **unresolved** — evidence could not establish either classification.

Uncertainty behaviour is policy-driven: `CONTAIN_PREEMPTIVELY`, `BOUNDED_EXPOSURE` or
`OBSERVE_ONLY`. Uncertainty never collapses to SAFE or FAILED.

Traversal is deterministic: the frontier is processed in ascending resource identity order and each
resource's edges in ascending dependency identity order, so identical canonical input produces a
byte-identical explanation. Broad actions such as `FULL_DOMAIN_ISOLATION` are reported as illegal
when a narrower scope suffices; PROTECTED and CRITICAL resources escalate instead of being fenced
silently, and safety still wins.

### Degraded-mode semantics

A degraded-mode contract declares permitted and prohibited resources, reduced capacity, required
redundancy, disabled features, legal workload classes, hard safety constraints, evidence
requirements, generation binding, expiry/revalidation conditions and exit preconditions.

Statuses: `NORMAL`, `DEGRADED_AUTHORIZED`, `DEGRADED_REVALIDATION_REQUIRED`, `DEGRADED_UNSAFE`,
`NO_LEGAL_DEGRADED_MODE`. Permitted and prohibited sets are computed independently and are never
allowed to overlap, so a degraded mode cannot consume a quarantined resource. A degraded-mode
result never claims full health.

### Release from containment

Quarantine never disappears because time passed. Release requires current resource generation,
current topology, fresh health/capability evidence, a containment verified as `CONTAINED`, policy
satisfaction, dependency validity, no unresolved propagation and explicit release authority. A
restarted process is not automatically rehabilitated; a reset device is not automatically healthy;
a reconnecting node is not automatically trusted.

### Persistence

Two durable artifacts under one state directory:

* `state.fcfsnap` — magic, format version, checked payload length, header CRC32C and payload
  CRC32C, then the encoded state. Trailing bytes are rejected.
* `journal.fcf` — a write-ahead journal of ordered records, each with magic, length, CRC32C and a
  sequence number. Records are ordered by sequence on replay.

A mutation is appended and flushed past the durability boundary before it is acknowledged. Snapshots
are written to a temporary file, flushed, closed and then atomically replaced. On Windows the
replacement uses `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`; POSIX
semantics are not assumed. A crash may leave a torn final record: those bytes are reported and
discarded. A torn record followed by further valid data, a sequence gap, bad magic, an unsupported
version, a length mismatch, a checksum mismatch, an absurd count and an unresolvable graph reference
are all reported as corruption rather than repaired.

### Transport

A frame is `magic(4) version(2) kind(2) payload_len(4) header_crc(4) payload_crc(4) payload`. The
header checksum covers bytes `[0,12)`, so the checksum field itself is deliberately excluded and no
canonical zeroing is required. The length field is inside the checksummed region, so a corrupted
length can never size an allocation. Reads are partial-read safe and every connection buffer is
bounded.

Bad magic, unsupported versions, oversized declared lengths, truncated headers and payloads,
checksum mismatches, unknown mandatory message types and trailing bytes are all rejected. Socket
reads never assume that one send equals one receive.

---

## REAL / SYNTHETIC / UNSUPPORTED capabilities

This section is the authoritative capability statement for the release environment
(Windows 11 Pro 26200, x64, MSVC 19.44, AMD Ryzen 7 9800X3D, NVIDIA GeForce RTX 5090,
compute capability 12.0, CUDA 12.9, driver 616.92).

### REAL — proven by execution in this environment

* Independent Windows x64 processes communicating over real Winsock TCP.
* Real process termination, observed as connection loss, driving authority revocation.
* Real coordinator process kill and restart with durable recovery and epoch advance.
* Versioned, CRC32C-checked snapshot plus write-ahead journal on NTFS with atomic replacement.
* Logical containment: authority revocation, admission denial, quarantine, dispatch rejection.
* Process containment of a worker incarnation the coordinator observed dying.
* Genuine CUDA work: `cudaMalloc`, host-to-device transfer, kernel execution,
  `cudaDeviceSynchronize`, device-to-host copy, CPU parity comparison, `cudaFree`, and a
  device-memory baseline measured with `cudaMemGetInfo` before and after. Measured baseline
  restoration was exact (32,496,418,816 free bytes before and after).
* A real CUDA worker process terminated during its lifecycle, with containment committed, an
  independent CPU worker continuing, and the replacement incarnation refused new accelerator work.

### SYNTHETIC — modelled, explicitly labelled, not claimed as hardware proof

* Multi-device, multi-host, multi-rack and correlated power/NUMA failure domains. The runtime
  represents them, and tests exercise them, but this environment has one GPU, one host and no
  partitionable fabric. Such domains are declared with `SYNTHETIC_CORRELATED_GROUP` or operator
  provenance and are never presented as discovered physical structure.
* Accelerator partition lifecycle and rack-level correlated power failure.

### UNSUPPORTED — genuinely unavailable in this environment

* **AddressSanitizer for x64.** The installed MSVC 14.44.35207 toolset ships only the i386
  sanitizer runtime: `lib/x64` contains no `clang_rt.asan*` file, while `lib/x86` contains
  `clang_rt.asan_dynamic-i386.lib` and `clang_rt.asan_dynamic_runtime_thunk-i386.lib`. No LLVM or
  `clang-cl` toolchain is installed. Requesting `FAULT_CONTAINMENT_ENABLE_ASAN` therefore fails
  configuration with the exact evidence instead of producing a link error. The sanitizer self-test
  (`tests/asan_probe.cpp` plus `tests/asan_selftest.cmake`) is present and will assert that
  instrumentation genuinely catches an intentional memory error on a toolchain that provides the
  x64 runtime. **No sanitizer coverage is claimed for this release.**
* GPU reset isolation, MIG isolation, NVLink/NVSwitch fault containment, PCIe fault isolation,
  CP/ECC fault handling, RDMA device isolation, DPU/SmartNIC containment, physical rack or power
  fault injection.

`fcf-cli --connect <host:port> capabilities`, `fcf-coordinator --capabilities` and the runtime's own `capability report print these labels.

**A SYNTHETIC capability is never silently upgraded to REAL.**

---

## Build

Requirements: CMake 3.25 or newer, a C++20 compiler, and on Windows the MSVC toolset. CUDA is
optional and the core library never links it.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

| Option | Default | Effect |
| --- | --- | --- |
| `FAULT_CONTAINMENT_BUILD_TESTS` | ON | build the test suites |
| `FAULT_CONTAINMENT_BUILD_EXAMPLES` | ON | build the runnable examples |
| `FAULT_CONTAINMENT_BUILD_BENCHMARKS` | ON | build the benchmarks |
| `FAULT_CONTAINMENT_BUILD_CLI` | ON | build `fcf-cli` |
| `FAULT_CONTAINMENT_BUILD_NODES` | ON | build `fcf-coordinator`, `fcf-worker` and, when CUDA is present, `fcf-cuda-worker` |
| `FAULT_CONTAINMENT_ENABLE_CUDA` | ON | build the CUDA proof surface when a CUDA toolkit is present |
| `FAULT_CONTAINMENT_ENABLE_ASAN` | OFF | build with AddressSanitizer, or fail with the toolchain evidence |
| `FAULT_CONTAINMENT_ENABLE_ANALYZE` | OFF | run the MSVC static analyser over first-party code |
| `FAULT_CONTAINMENT_WARNINGS_AS_ERRORS` | ON | treat first-party warnings as errors |

First-party code compiles clean at `/W4 /WX /permissive-` with no global warning suppression, no
machine-specific absolute paths and no generated junk.

## Tests

Every suite is independently addressable and every case has a stable name.

```
build/bin/test_blast_radius --list              # list cases
build/bin/test_blast_radius --case chain_propagation_includes_every_reachable_resource
build/bin/test_blast_radius --suite blast_radius
```

Progress is printed and flushed as it happens, so a blocked case is never opaque. **No suite uses a
test timeout of any kind.** CTest is configured with `TIMEOUT 0` and the harness contains no
watchdog, deadline or forced-kill timer. A hanging test would be a defect to diagnose.

| Suite | Proves |
| --- | --- |
| `test_ids_and_codec` | identity typing and parsing, bounded codec rejection paths, CRC32C and SHA-256 against published test vectors |
| `test_domain_model` | topology registration, generation advance, impossible graph references, worker reincarnation, policy validation |
| `test_blast_radius` | deterministic radius over chains, stars, diamonds, cycles, disconnected components, shared and correlated domains, conditional and non-propagating edges, fail-closed uncertainty, protected-resource escalation, illegal broad actions |
| `test_containment_lifecycle` | authorization fencing without touching unaffected work, ACKNOWLEDGED is not CONTAINED, executor refusal, degraded contracts, release criteria |
| `test_stale_authority` | stale epoch, stale boot, stale generations, acknowledgment before dispatch, idempotent but single-commit completion, superseded faults |
| `test_persistence` | snapshot and journal durability, torn tail, checksum, magic, version, truncation, trailing garbage |
| `test_transport` | frame round trips, every malformed-frame rejection, byte-at-a-time fragmentation, real TCP in both directions, repeated connect/disconnect |
| `test_property` | seeded randomized graphs and faults with invariant checks and reproducibility |
| `test_concurrency` | readers and a writer, concurrent acknowledgments, shutdown with active containment, repeated start/stop, concurrent epoch advance |
| `test_adversarial` | delayed completion after death, acknowledgment after target movement, healthy-while-contained, stale degraded requests, repeated contain/release, identity collisions and sentinels, secondary failure, overlapping containments |
| `test_multiprocess` | coordinator, Worker A, Worker B and a controller as real processes; real kill; fencing; stale replay rejection; reincarnation; fresh evidence; release |
| `test_coordinator_restart` | real coordinator crash; epoch advance; durable containment survival; old-epoch rejection; conservative recovery; reattachment |
| `test_cuda_containment` | real CUDA workload with CPU parity and memory baseline, quarantined incarnation refused accelerator work, no inherited authority after reincarnation, and real process death of a CUDA worker |

## Examples

```
build/bin/fcf-example-01_basic_containment
build/bin/fcf-example-02_dependency_blast_radius
build/bin/fcf-example-03_worker_death_fencing
build/bin/fcf-example-04_degraded_mode
build/bin/fcf-example-05_stale_authority_rejection
build/bin/fcf-example-06_quarantine_revalidation_release
build/bin/fcf-example-07_persistence_restart
```

Each compiles against the public API only and exercises behaviour that is actually implemented.

## CLI and nodes

```
fcf-coordinator --port 0 --state-dir ./state        # start a coordinator node
fcf-worker --connect 127.0.0.1:PORT --id 1 --boot 1001 --resources 1,2
fcf-cuda-worker --connect 127.0.0.1:PORT --id 1 --boot 1001 --resources 1 --cuda-elements 262144
fcf-cli --connect 127.0.0.1:PORT status
fcf-cli --state-dir ./state containments             # inspect durable state offline
fcf-cli --connect 127.0.0.1:PORT explain 1
```

Commands: `status`, `faults`, `containments`, `workers`, `snapshot-info`, `resource`, `action`,
`containment`, `explain`, `evaluate`, `contain`, `verify`, `degraded`, `release`, `history`,
`register-domain`, `register-isolation-domain`, `register-failure-domain`, `register-resource`,
`register-dependency`, `set-resource-owner`, `publish-fault`, `worker-lost`, `poll-workers`,
`shutdown`. CLI output reflects actual runtime state; there are no fake controls.

## Install and consume

```
cmake --install build --prefix /path/to/prefix
```

The install tree contains the library, the public headers, the exported targets, the package config
and the version file. An independent consumer links only against the installed package:

```
cmake -S examples/downstream -B downstream-build -DCMAKE_PREFIX_PATH=/path/to/prefix
cmake --build downstream-build
downstream-build/fcf-downstream-consumer
```

```cmake
find_package(FaultContainmentFabric CONFIG REQUIRED)
target_link_libraries(my_target PRIVATE FaultContainmentFabric::fcf)
```

The consumer project is deliberately outside the main build so it cannot reach back into the source
tree or the build tree.

## Benchmarks

```
build/bin/fcf-benchmarks
```

Benchmarks measure completed work, never asynchronous submission. Representative results on the
release environment (Release, MSVC 19.44, single socket):

| Benchmark | Count | Total | Per operation |
| --- | --- | --- | --- |
| blast radius @ 100 resources | 500 evaluations | 0.052 s | 104 µs |
| blast radius @ 1,000 resources | 100 evaluations | 0.129 s | 1.29 ms |
| blast radius @ 10,000 resources | 20 evaluations | 0.365 s | 18.2 ms |
| fault ingestion | 2,000 faults | 0.008 s | 4.0 µs |
| dependency graph update | 1,000 registrations | 0.003 s | 2.6 µs |
| snapshot creation @ 10,000 resources | 20 snapshots | 0.130 s | 6.5 ms |
| deterministic explanation @ 10,000 resources | 200 renderings | 0.096 s | 478 µs |
| containment verification | 100 verifications | 0.163 s | 1.63 ms |
| concurrent evaluation (all threads) | 3,200 evaluations | 0.544 s | 170 µs |
| persistence save @ 1,000 resources | 20 snapshots | 0.125 s | 6.2 ms |
| persistence load @ 1,000 resources | 20 recoveries | 0.188 s | 9.4 ms |

These are honest measurements of one machine, not manufactured precision.

## Concurrency model

Every public `Engine` method is safe to call concurrently. Reads take a shared lock; mutations take
an exclusive lock. Internal locks are never held across executor calls, persistence I/O, network
waits or user callbacks. Drainable socket pointers are owned by the connection thread so shutdown
closes exactly the socket a thread is blocked on. Every accepted socket takes its own Winsock
reference, so the network stack is never torn down under a live socket.

## Platform

Validated: **Windows 11 Pro x64 with MSVC 19.44 and the Windows SDK 10.0.26100**. The durable store
uses Windows atomic-replacement and flush semantics directly; a POSIX implementation of the same
contract is present but **has not been validated in this release environment** and is not claimed.

## Security and trust boundaries

All external evidence is untrusted. The codec validates every length before allocating, uses checked
arithmetic, bounds every collection, rejects invalid enumerations, unsorted or duplicate identity
sets, invalid UTF-8, oversized strings and trailing bytes, and verifies CRC32C at every durable and
wire boundary. Durable paths are refused when they are reparse points or symlinks, so substitution
cannot redirect durable state. Payload lengths are never trusted. The control plane is bound to
loopback by default and exposes a closed command vocabulary, not generic remote execution.

## Limitations

* One physical GPU is present, so multi-GPU, MIG, NVLink/NVSwitch, PCIe and ECC containment paths are
  SYNTHETIC or UNSUPPORTED and are labelled as such.
* No sanitizer coverage is claimed for this release (see UNSUPPORTED above).
* The POSIX durable-store path is implemented but unvalidated here.
* In-memory history is a bounded tail; the complete audit trail is the durable journal.
* Logical and process containment are the enforcement mechanisms available; hardware isolation
  primitives are not present and are never described as if they were.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
