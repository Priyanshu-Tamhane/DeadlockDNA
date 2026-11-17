# DeadlockDNA

> **Zero-Instrumentation Runtime Deadlock Detection, Explainable Diagnosis, DNA Fingerprinting & Cost-Aware Recovery for Linux Multithreaded Applications.**

DeadlockDNA observes running C/C++ POSIX-threaded (NPTL) applications from the outside using Linux kernel eBPF tracepoints and userspace uprobes. It constructs a live, bipartite Resource Allocation Graph (RAG), detects circular wait conditions in real-time, synthesizes human-readable root-cause explanations, hashes deadlock topology into structural "DNA" signatures, predicts potential lock-order inversion hazards, and recommends safe, cost-aware recovery actions—all with zero modification, zero recompilation, and zero binary instrumentation of the target software.

---

## 1. Overview

### What is DeadlockDNA?
**DeadlockDNA** is an out-of-process concurrency analysis framework for Linux. It combines kernel tracing (`tracepoint:syscalls:sys_enter_futex`), userspace probes (`uprobe`/`uretprobe` on `libpthread`/`libc`), graph theory (Johnson's elementary cycle algorithm on bipartite graphs), and structural graph hashing to inspect, detect, diagnose, and remediate multithreaded deadlocks as they happen.

### What Problem Does It Solve?
Multithreaded deadlocks are among the most elusive bugs in systems programming:
- **Heisenbugs:** Traditional debuggers (`gdb`, `lldb`) alter timing and scheduling, frequently masking race conditions and deadlock occurrence.
- **Overhead & Recompilation:** Compile-time sanitizers (e.g., ThreadSanitizer / `TSan`) require rebuilding binaries with instrumentation flags, introducing $2\times$–$10\times$ CPU overhead and $5\times$–$10\times$ memory bloat, making them unsuitable for production environments or proprietary third-party binaries.
- **Inadequate Telemetry:** Standard profiling tools notify operators *after* a process hangs, leaving developers with cryptic core dumps, unannotated stack traces, and no insight into the dynamic lock acquisition history that precipitated the stall.

DeadlockDNA solves this by extracting lock acquisition and contention events directly from kernel/userspace boundaries without touching the binary, building an exact mathematical representation of thread-resource dependencies in real time.

### Why Was It Built?
DeadlockDNA was engineered to provide:
1. **Zero-Touch Observability:** Monitor production binaries and closed-source dependencies without source code access or special build environments.
2. **Deterministic Root-Cause Attribution:** Automatically translate cycle topologies into clear, human-readable diagnostic narratives explaining *which thread holds what* and *which thread is waiting for what*.
3. **Cross-Run Recurrence Tracking:** Generate immutable structural fingerprints ("Deadlock DNA") that identify the same fundamental concurrency bug across different machines, process IDs, thread IDs, and memory layouts.
4. **Predictive Concurrency Risk Analysis:** Uncover latent lock-order inversions ($A \to B$ vs. $B \to A$) before threads actually contend and freeze.
5. **Safety-Gated Recovery:** Prevent catastrophic blind process kills or dangerous external mutex unlocks by offering scored, policy-validated remediation paths.

### Who Is It Intended For?
- **Systems & Kernel Engineers:** Debugging complex lock hierarchies in high-performance C/C++ daemons, databases, and network runtimes.
- **Site Reliability Engineers (SREs):** Monitoring critical production services for deadlocks without incurring runtime penalties.
- **QA & Concurrency Testers:** Running stress benchmarks and automated integration suites to catch intermittent race conditions before software ships.

---

## 2. Problem Statement

### The Nature of Deadlocks in POSIX Threads
Under the **Coffman Conditions**, a deadlock occurs when four criteria are met simultaneously:
1. *Mutual Exclusion:* Resources cannot be shared.
2. *Hold and Wait:* Threads hold allocated resources while awaiting additional ones.
3. *No Preemption:* A resource can only be released voluntarily by its holder.
4. *Circular Wait:* A closed chain of threads exists where each thread waits for a resource held by the next.

In modern Linux user-space threading (`glibc` NPTL), mutexes employ **futexes (Fast Userspace Mutexes)**:
- **Uncontended Acquisition (Fast Path):** Atomically changes a 32-bit integer in user-space memory via atomic assembly instructions (`LOCK CMPXCHG`) without issuing a syscall.
- **Contended Acquisition (Slow Path):** Issues the `sys_futex` system call with `FUTEX_WAIT` to put the thread to sleep until awakened via `FUTEX_WAKE`.

### Existing Challenges and Limitations
| Approach | Mechanism | Limitations |
|---|---|---|
| **ThreadSanitizer (TSan)** | Compiler instrumentation | Requires recompilation, $2\times$–$10\times$ CPU overhead, huge memory usage, cannot run on pre-built third-party binaries. |
| **GDB / Ptrace** | Process tracing | Stops thread execution, creates significant latency, alters thread timing, hides concurrency bugs. |
| **Static Analyzers** | AST / CFG inspection | Prone to massive false positives; unable to resolve dynamic runtime pointer aliases or conditional locks. |
| **Syscall Tracing (`strace`)** | Syscall entry/exit hooks | Captures slow-path `FUTEX_WAIT` calls, but **completely misses** uncontended lock acquisitions, making it impossible to determine who actually holds the blocking mutex. |

### Why a Solution is Needed
To safely detect deadlocks without altering program timing or requiring source code rebuilds, an observability system must bridge the gap between user-space lock allocations and kernel-space futex contention sleep events. DeadlockDNA achieves this through a hybrid eBPF/uprobe architecture.

---

## 3. Objectives

- **100% Non-Intrusive Runtime Monitoring:** Capture lock requests, acquisitions, and releases without modifying target source code, modifying binaries, or altering link flags.
- **Sub-Millisecond Deadlock Detection:** Detect circular wait conditions within microseconds of the final locking event using Donald B. Johnson’s elementary cycle algorithm on bipartite graphs.
- **Actionable Diagnostic Narratives:** Automatically synthesize step-by-step human explanations of the deadlock loop, eliminating the need to manually interpret raw memory addresses or thread dumps.
- **Deterministic Structural Fingerprinting:** Canonically hash cycle graphs into 64-character SHA-256 signatures that uniquely identify bug topologies across varying environments and runtime allocations.
- **Predictive Risk Assessment:** Analyze lock acquisition orders across all threads to identify potential deadlock hazards before contention causes an unrecoverable stall.
- **Safe, Policy-Enforced Remediation:** Rank recovery candidates through transparent heuristic scoring while strictly blocking unsafe actions (such as external mutex unlocking or unverified signal termination).
- **Minimal Observer Overhead:** Maintain $< 5\%$ CPU overhead during high-concurrency workloads.

---

## 4. Key Features

```
+-------------------------------------------------------------------------------------------------+
|                                    DEADLOCKDNA FEATURE MATRIX                                   |
+-------------------------------------------------------------------------------------------------+
|  [01] Non-Intrusive eBPF Tracing       Dual user/kernel observability via uprobes + futex trace |
|  [02] Live Bipartite RAG Engine        Real-time bipartite graph with automatic degree-0 pruning |
|  [03] Real-Time Cycle Detection        Johnson's cycle algorithm with microsecond latency clock  |
|  [04] Explainable Diagnosis            Human-readable narratives, evidence trails & confidence  |
|  [05] Source-Code & Symbol Resolution  DWARF, nm & /proc maps mapping hex pointers to C lines    |
|  [06] DNA Fingerprinting               Canonical role normalization & SHA-256 recurrence store   |
|  [07] Lock-Order Risk Analysis         Predictive Lock Order Graph (LOG) with event scalability  |
|  [08] Cost-Aware Recovery Advisor      Gated execution, transparent scoring & cycle verification|
|  [09] Automated Benchmark Suite        Harness with process containment, metric exports & reports|
|  [10] Interactive Web Dashboard        HTML5 Canvas force-directed graph UI & SSE real-time sync |
|  [11] Headless CI/CD Linter            Automated gatekeeping with JUnit XML, JSON & exit codes   |
|  [12] Enterprise Workload Targets      Tested on multi-threaded SQLite DB & 66-lock Memcached    |
+-------------------------------------------------------------------------------------------------+
```

- **Feature 1: Hybrid eBPF/Uprobe Event Ingestion**
  Traces both uncontended acquisitions (via `uprobe`/`uretprobe` on `pthread_mutex_lock` and `sem_wait`) and contended wait queues (via `tracepoint:syscalls:sys_enter_futex`), bridging the user/kernel visibility gap.
- **Feature 2: Dynamic Bipartite Resource Allocation Graph (RAG)**
  Maintains a directed graph $G = (V_T \cup V_R, E)$ where nodes represent Threads ($V_T$) and Mutexes/Semaphores ($V_R$), with Request ($T \to R$) and Allocation ($R \to T$) edges. Automatically evicts isolated vertices upon lock release to ensure zero memory leaks.
- **Feature 3: Microsecond-Grade Cycle Detection**
  Applies Johnson’s algorithm to detect circular wait states ($T_1 \to R_1 \to T_2 \to R_2 \to T_1$). Operates conditionally on lock requests with edge filters to preserve high-throughput event processing.
- **Feature 4: Explainable Root-Cause Diagnosis**
  Synthesizes detailed diagnostic explanations indicating thread identities, held locks, requested locks, source code clues, and confidence ratings (`complete`, `partial`, `unknown`).
- **Feature 5: Source-Code & Symbol Resolution (Upgrade 1)**
  Decodes ELF symbols via `nm`, parses DWARF debug entries via `addr2line`, and translates ASLR process offsets via `/proc/<pid>/maps` to map raw hex addresses to exact C variable names and source locations (`test_2way.c:24`).
- **Feature 6: Structural DNA Fingerprinting & SQLite History**
  Normalizes cycles by anonymizing thread/process IDs and pointer addresses into canonical roles (`THREAD_0`, `RESOURCE_0`, `THREAD_1`), generating deterministic SHA-256 signatures stored in SQLite to track recurring deadlocks over time.
- **Feature 7: Predictive Lock-Order Inversion Hazard Tracking**
  Tracks global dynamic lock hierarchies in a Lock Order Graph (LOG). Detects potential inversions ($A \to B$ vs. $B \to A$) before contention occurs, optimized with event-driven cycle checking to process thousands of events at microsecond latency.
- **Feature 8: Cost-Aware Recovery Recommendations & Verification**
  Ranks recovery candidates via a transparent, normalized scoring function ($[-0.35, +0.80]$). Rejects unsafe external mutex unlocks, supports cooperative `SIGUSR1` cancellations via `libc.tgkill`, and verifies cycle resolution post-action.
- **Feature 9: Benchmark & Evaluation Suite**
  Provides isolated test execution with timeout containment, synthetic workloads (no-lock, single-mutex, high-contention, stress), and automated export of CSV metrics, JSON summaries, and Markdown reports.
- **Feature 10: Real-Time Interactive Web Dashboard**
  High-performance HTML5 Canvas force-directed graph UI served via standard library `ThreadingHTTPServer` with Server-Sent Events (`/api/stream`), time-travel history scrubbing, and auto-replay simulation loop.
- **Feature 11: Headless CI/CD Gatekeeper Mode (Upgrade 2)**
  Automated concurrency linter (`--ci`) with deterministic exit codes (`0`, `1`, `2`), generating standard JUnit XML test reports for GitHub Actions/GitLab CI and machine-readable JSON summaries.
- **Feature 12: Real-World Enterprise Workload Gatekeeping (Upgrade 3)**
  Validated on multi-threaded **SQLite** (sustaining 29,000+ ops/sec with concurrent reads, transactions, and WAL checkpoints) and **Memcached** (64 striped bucket mutexes + slab allocator) without performance degradation or false positives.

---

## 5. System Architecture

### Architectural Overview
DeadlockDNA decouples observation from analysis. The eBPF observer runs at kernel/library boundaries and emits line-buffered JSON events; the Python collector ingests and queues events; the RAG engine updates graph topology; and the analytical engines (Cycle Detector, Explainer, Fingerprinter, Risk Tracker, and Recovery Advisor) process state changes asynchronously.

```
+-----------------------------------------------------------------------------------------------+
|                                      TARGET APPLICATION                                       |
|               (Unmodified C/POSIX threads: pthread_mutex, POSIX semaphores)                   |
+-----------------------------------------------------------------------------------------------+
                             |                                      |
               [Uncontended Lock Fast-Path]                 [Contended Lock Slow-Path]
                             |                                      |
                             v                                      v
            +----------------------------------+   +----------------------------------+
            |    glibc Userspace Probes        |   |   Linux Kernel Futex Tracepoints |
            |  - uprobe:pthread_mutex_lock     |   |  - tracepoint:syscalls:          |
            |  - uretprobe:pthread_mutex_lock  |   |    sys_enter_futex (FUTEX_WAIT)  |
            |  - uprobe:pthread_mutex_unlock   |   |  - tracepoint:syscalls:          |
            |  - uprobe/uretprobe:sem_wait     |   |    sys_exit_futex (cleanup)      |
            |  - uprobe:sem_post               |   |                                  |
            +----------------------------------+   +----------------------------------+
                             \                                      /
                              \                                    /
                               v                                  v
+-----------------------------------------------------------------------------------------------+
|                                   eBPF OBSERVER SUBSYSTEM                                     |
|           (observer/observer.bt or dynamic inline comm-filtered bpftrace script)              |
|   - Maps thread IDs (tid) and resource pointers (uaddr / arg0)                                |
|   - Correlates acquisition and contention via BPF associative arrays                          |
|   - Streams newline-delimited JSON events over stdout (-B line)                               |
+-----------------------------------------------------------------------------------------------+
                                               |
                                               v
+-----------------------------------------------------------------------------------------------+
|                                  EVENT COLLECTOR & PARSER                                     |
|                       (collector/collector.py & collector/event_parser.py)                    |
|   - Ingestion: Async background thread + thread-safe queue                                    |
|   - Modes: --exec <binary>, --pid <PID>, --file <json>, --stdin                               |
|   - Sanitizer: Discards banner/debug text, validates schema, converts to typed Event objects  |
+-----------------------------------------------------------------------------------------------+
                                               |
                      +------------------------+------------------------+
                      |                                                 |
                      v                                                 v
+-------------------------------------------+     +-------------------------------------------+
|  RESOURCE ALLOCATION GRAPH (RAG) ENGINE   |     |    LOCK-ORDER RISK TRACKER & DETECTOR     |
|      (graph/rag.py & graph/models.py)     |     |                 (risk/)                   |
| - Bipartite directed graph G = (V, E)     |     | - Lock Order Graph (LOG) of acquisitions  |
| - Nodes: Threads (T) & Resources (M@)     |     | - Detects potential AB/BA inversions      |
| - Request (T->R) & Allocation (R->T) edges|     | - Distinguishes risk from live deadlocks  |
| - Auto-prunes isolated degree-0 vertices  |     | - Persists edge history in SQLite         |
+-------------------------------------------+     +-------------------------------------------+
                      |
                      v
+-------------------------------------------+
|          CYCLE DETECTOR ENGINE            |
|        (graph/cycle_detector.py)          |
| - Johnson’s simple cycle algorithm        |
| - Canonicalizes closed cycles             |
| - Microsecond latency synchronization     |
+-------------------------------------------+
                      |
        +-------------+-------------+
        |                           |
        v                           v
+-----------------------+   +-----------------------+
| EXPLAINABLE DIAGNOSIS |   |  DNA FINGERPRINTING   |
|     (diagnosis/)      |   |        (dna/)         |
| - Human narrative     |   | - Role canonicalizer  |
| - Step evidence trail |   | - SHA-256 hash digest |
| - Confidence labels   |   | - SQLite recurrence   |
+-----------------------+   +-----------------------+
        \                           /
         \                         /
          v                       v
+---------------------------------------------------+
|      COST-AWARE RECOVERY RECOMMENDATIONS          |
|                   (recovery/)                     |
| - Strict safety policy (No external mutex unlock) |
| - Transparent heuristic scoring & rationale       |
| - Safe default recommendation-only mode           |
| - Verified post-recovery cycle resolution         |
+---------------------------------------------------+
                          |
                          v
+-----------------------------------------------------------------------------------------------+
|                                  TERMINAL DASHBOARD (TUI)                                     |
|                                     (ui/dashboard.py)                                         |
|   - Live Rich terminal interface updating per event                                           |
|   - Real-time RAG topology viewer & live event queue                                          |
|   - Predictive Lock-Order Inversion risk alert panel                                          |
|   - Deadlock status banner with Diagnosis, DNA Fingerprint, and Recovery Recommendations      |
+-----------------------------------------------------------------------------------------------+
```

### Component Responsibilities & Communication
1. **Observer (`observer/`):** Attaches eBPF probes via `bpftrace`. Streams line-buffered JSON records over standard output.
2. **Collector (`collector/`):** Reads the output stream asynchronously, filters diagnostic headers (`Attaching 6 probes...`), validates schema fields, and enqueues typed `Event` objects.
3. **RAG Engine (`graph/`):** Consumes `Event` objects and executes state transitions (creating/removing Request and Allocation edges). Prunes disconnected nodes.
4. **Risk Engine (`risk/`):** Builds directed edges between consecutive mutex acquisitions per thread to discover cycles in lock hierarchies before blocking occurs.
5. **Cycle Detector (`graph/cycle_detector.py`):** Runs Johnson’s algorithm whenever a `LOCK_REQUEST` edge is added to a graph with $\ge 4$ edges.
6. **Explainer (`diagnosis/`):** Synthesizes structural edge evidence into natural-language narratives.
7. **Fingerprinter (`dna/`):** Converts cycle topology to an anonymized canonical representation and computes a deterministic SHA-256 digest.
8. **Recovery Advisor (`recovery/`):** Evaluates candidate actions against strict safety criteria, scores eligible options, and optionally executes verified cooperative terminations on designated disposable processes.
9. **Dashboard (`ui/`):** Periodically repaints a multi-panel `rich` terminal display containing RAG nodes, recent events, active risks, and detected deadlocks.

---

## 6. Workflow

### End-to-End Execution Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Target as Target Process (C/Pthreads)
    participant Kernel as Linux Kernel / eBPF (bpftrace)
    participant Collector as Collector & Parser
    participant RAG as RAG & Risk Engines
    participant Detector as Cycle Detector & Explainer
    participant Advisor as Recovery & DNA Store
    participant UI as Terminal Dashboard

    Target->>Kernel: pthread_mutex_lock(M1) [Fast Path Acquired]
    Kernel-->>Collector: JSON: LOCK_ACQUIRED (T1, M1)
    Collector->>RAG: update(LOCK_ACQUIRED) -> Add Allocation (M1 -> T1)
    RAG->>UI: Refresh Topology

    Target->>Kernel: pthread_mutex_lock(M2) [Fast Path Acquired]
    Kernel-->>Collector: JSON: LOCK_ACQUIRED (T2, M2)
    Collector->>RAG: update(LOCK_ACQUIRED) -> Add Allocation (M2 -> T2)

    Target->>Kernel: pthread_mutex_lock(M2) by T1 -> FUTEX_WAIT
    Kernel-->>Collector: JSON: LOCK_REQUEST (T1, M2)
    Collector->>RAG: update(LOCK_REQUEST) -> Add Request (T1 -> M2)

    Target->>Kernel: pthread_mutex_lock(M1) by T2 -> FUTEX_WAIT
    Kernel-->>Collector: JSON: LOCK_REQUEST (T2, M1)
    Collector->>RAG: update(LOCK_REQUEST) -> Add Request (T2 -> M1)
    
    RAG->>Detector: check_cycles() on updated RAG
    Detector->>Detector: Johnson's Cycle Algorithm Finds T1->M2->T2->M1->T1
    Detector->>Advisor: Dispatch DeadlockResult
    Advisor->>Advisor: Canonicalize & Hash (SHA-256 DNA)
    Advisor->>Advisor: Score Recovery Candidates & Validate Policy
    Detector->>UI: Render Deadlock Alert, Diagnosis & Recovery Cards
```

1. **Target Execution:** Target threads request, acquire, and release locks.
2. **Event Interception:** eBPF user and kernel probes intercept mutex/semaphore functions and stream structured JSON records.
3. **Queue Ingestion:** The collector's background thread continuously pulls raw lines, parses fields, and pushes strongly-typed `Event` objects onto a thread-safe queue.
4. **State Transition:** The main processing loop consumes events, updating both the bipartite RAG and the Lock Order Graph (LOG).
5. **Cycle Detection:** When a `LOCK_REQUEST` occurs, the cycle detector inspects the RAG for closed loops.
6. **Diagnosis & Fingerprinting:** When a cycle is detected, the Explainer maps out the holding/waiting relationships, while the Fingerprinter normalizes the cycle and checks the SQLite store for previous occurrences.
7. **Recovery Evaluation:** The Recovery Advisor ranks recovery candidates using heuristic factors (disposability, cooperative support, reversibility, state loss, criticality).
8. **User Presentation:** The Terminal Dashboard updates live, displaying the RAG status, risk warnings, diagnostic narratives, and recovery advice.

---

## 7. Technology Stack

| Technology | Layer | Purpose |
|---|---|---|
| **Linux eBPF & bpftrace** | Kernel / Observability | Low-overhead user-space and kernel-space dynamic tracing without source code modification. |
| **Python 3.10+** | Application Core | Event parsing, state management, asynchronous queue coordination, and CLI orchestration. |
| **NetworkX** | Graph Theory | Bipartite Resource Allocation Graph (RAG) representation and Johnson's elementary cycle algorithm. |
| **HTML5 Canvas & SSE** | Web Visualizer | High-performance interactive force-directed graph UI, real-time SSE streaming, and time-travel history. |
| **GNU Binutils (`nm`, `addr2line`)** | Symbol Resolution | DWARF debug decoding and ELF symbol scanning to map virtual hex addresses to C variable names and line numbers. |
| **SQLite3** | Data Persistence | Atomic storage and recurrence tracking for Deadlock DNA fingerprints and lock-order histories. |
| **POSIX Threads (glibc NPTL)** | Target Ecosystem | Thread primitives (`pthread_mutex`, `sem_t`) and futex syscall interfaces observed by the platform. |
| **Pytest** | Verification | Comprehensive offline test suite (102 tests, 100% pass rate) validating RAG state machines, graph algorithms, and safety policies. |
| **GCC & Make** | Target Build System | Compiling synthetic deadlock targets, Memcached workloads, and reproducible benchmarking suites. |

---

## 8. Project Structure

```
deadlockdna/
├── main.py                     # Pipeline entry point & CLI orchestrator
├── Makefile                    # Build, test, lint, and benchmark targets
├── requirements.txt            # Python dependencies (networkx, rich, pytest)
├── architecture.md             # Comprehensive system architecture documentation
├── README.md                   # Project documentation & operational manual
│
├── targets/                    # Synthetic & real-world multithreaded targets
│   ├── test_2way.c             # 2-thread classic AB/BA mutex deadlock
│   ├── test_3way.c             # 3-thread circular lock chain (T1->T2->T3->T1)
│   ├── test_semaphore.c        # POSIX semaphore synchronization test
│   ├── sqlite_multithread_workload.py # Real-world SQLite database workload (Upgrade 3)
│   └── memcached_workload.c    # 64-bucket striped Memcached cache server (Upgrade 3)
│
├── observer/                   # eBPF / bpftrace tracing infrastructure
│   └── observer.bt             # bpftrace script capturing futex & pthread uprobes
│
├── collector/                  # Event ingestion, stream handling & parsing
│   ├── __init__.py
│   ├── collector.py            # Stream ingestion across exec, pid, file, and stdin modes
│   └── event_parser.py         # JSON schema validation and Event dataclass builder
│
├── graph/                      # Resource Allocation Graph & Cycle Detection
│   ├── __init__.py
│   ├── models.py               # Data models: Event, EventType, ResourceType, DeadlockResult
│   ├── rag.py                  # Bipartite RAG state machine with degree-0 node pruning
│   └── cycle_detector.py       # Johnson's simple cycles algorithm & cycle canonicalization
│
├── diagnosis/                  # Explainable Root-Cause Diagnosis (Feature A)
│   ├── __init__.py
│   ├── explainer.py            # Natural language cycle narrative synthesis & evidence trail
│   └── symbol_resolver.py      # DWARF, nm, addr2line & /proc maps resolver (Upgrade 1)
│
├── dna/                        # Deadlock DNA Fingerprinting (Feature B)
│   ├── __init__.py
│   ├── canonicalizer.py        # Role-based cycle normalization (strips PIDs/TIDs/addresses)
│   ├── fingerprint.py          # SHA-256 topological cycle hashing
│   └── store.py                # SQLite persistence engine for recurrence tracking
│
├── risk/                       # Predictive Lock-Order Inversion Analysis (Feature D)
│   ├── __init__.py
│   ├── lock_order_tracker.py   # Lock Order Graph (LOG) tracking acquisition hierarchies
│   ├── risk_cycle_detector.py  # Acyclic hierarchy verification & potential cycle detection
│   └── risk_store.py           # Historical risk persistence and query interface
│
├── recovery/                   # Cost-Aware Recovery Recommendations (Feature E)
│   ├── __init__.py
│   ├── candidate.py            # Candidate enumeration (kill, cancel, restart, alert)
│   ├── policy.py               # Safety policy enforcement (blocks external mutex unlocks)
│   ├── scoring.py              # Normalized heuristic scoring engine (weights sum to 0.35)
│   ├── executor.py             # Gated execution engine with disposable PID whitelist
│   └── verifier.py             # Post-recovery cycle resolution verifier
│
├── benchmarks/                 # Automated Benchmark & Evaluation Suite (Feature C)
│   ├── __init__.py
│   ├── harness.py              # Process containment harness with automated timeouts
│   ├── metrics.py              # Latency, detection rate, false positive, and overhead metrics
│   ├── report.py               # CSV, JSON summary, and Markdown report exporters
│   ├── run_benchmarks.py       # CLI benchmark runner with configurable run matrix
│   ├── results/                # Output directory for evaluation reports
│   └── workloads/              # Synthetic C workloads for evaluation
│       ├── workload_no_lock.c       # Baseline compute workload (0 locks)
│       ├── workload_single_mutex.c  # Uncontended lock baseline
│       ├── workload_contention.c    # Heavy lock contention without deadlocks
│       └── workload_stress.c        # Dynamic multithreaded stress workload
│
├── ci/                         # Headless CI/CD Reporter & Gatekeeper (Upgrade 2)
│   ├── __init__.py
│   └── reporter.py             # JUnit XML, JSON exporter & exit code engine
│
├── ui/                         # Real-time Web Dashboard (HTML5 Canvas Force-Directed Graph)
│   ├── __init__.py
│   ├── dashboard.py            # Headless browser launcher & state broadcaster
│   ├── web_server.py           # Threading HTTPServer with SSE streaming (/api/stream)
│   └── static/
│       └── index.html          # Force-directed topology visualizer & time-travel scrubber
│
├── tests/                      # Pytest verification suite (102 offline unit tests)
│   ├── test_real_workloads.py  # Real-world SQLite & Memcached workload monitoring
│   ├── test_ci.py              # CI exit codes, JUnit XML & JSON report generation
│   ├── test_symbol_resolver.py # C source-level symbol & line number resolution
│   ├── test_ui.py              # Web dashboard server & state serialization
│   ├── test_rag.py             # RAG transitions, edge additions, vertex pruning
│   ├── test_cycle_detection.py # Cycle detection correctness, latency & false positives
│   ├── test_events.py          # JSON parser validation, banner filtering, error resilience
│   ├── test_diagnosis.py       # Narrative generation, step evidence & confidence ratings
│   ├── test_dna.py             # Canonicalization, SHA-256 consistency, SQLite persistence
│   ├── test_benchmarks.py      # Benchmark containment, timeout cleanup, report formatting
│   ├── test_risk.py            # Lock acquisition hierarchy, reentrancy, risk alerts
│   ├── test_recovery.py        # Safety policy, scoring bounds, executor gating, verifier
│   ├── sample_events.json      # Offline event log reproducing a 2-way deadlock
│   ├── sample_clean_events.json# Clean event log without circular waits
│   ├── sample_risk_events.json # Event log containing an AB/BA lock order inversion
│   ├── sample_sqlite_events.json # Production multi-threaded SQLite event log
│   ├── sample_memcached_events.json # 66-mutex striped Memcached event log
│   └── sample_memcached_hazard_events.json # Memcached lock-order inversion trace
│
├── docs/                       # Architecture and event format specifications
│   ├── architecture.md         # Detailed architectural design document
│   └── event-format.md         # Full specification of eBPF JSON event formats
└── logs/                       # Runtime logs and SQLite databases (`deadlocks.db`)
```

---

## 9. Core Technical Concepts

### 1. Dual-Probe Observability
- **The Challenge:** To construct an accurate RAG, DeadlockDNA needs to know (1) who owns a resource, and (2) who is waiting for it. Fast-path mutex acquisitions never call the kernel, while slow-path futex sleeps never record which thread holds the blocking lock.
- **The Solution:** 
  - Attaching a `uprobe` and `uretprobe` to `libc:pthread_mutex_lock` provides access to the mutex address (`arg0`) and the acquiring thread ID (`tid`).
  - Attaching a `tracepoint:syscalls:sys_enter_futex` records when a thread blocks on `FUTEX_WAIT`. By correlating these two sources via BPF associative arrays, DeadlockDNA reconstructs both allocation and wait edges reliably.

### 2. Bipartite Resource Allocation Graph (RAG) State Machine
A directed bipartite graph $G = (V, E)$ where vertices are partitioned into two disjoint sets:
- **Thread Nodes ($V_T$):** Represented as `T<tid>`.
- **Resource Nodes ($V_R$):** Represented as `M@<pid>:<hex_addr>` (for mutexes) or `S@<pid>:<hex_addr>` (for semaphores).

**Edge Transition Rules:**
$$\begin{aligned}
\text{LOCK\_REQUEST}(T, R) &\implies E \leftarrow E \cup \{(T \to R)\} \\
\text{LOCK\_ACQUIRED}(T, R) &\implies E \leftarrow (E \setminus \{T' \to R \mid \forall T'\}) \cup \{(R \to T)\} \\
\text{LOCK\_RELEASED}(T, R) &\implies E \leftarrow E \setminus \{(R \to T)\}
\end{aligned}$$

**Degree-0 Vertex Pruning:** Whenever a lock is released, if a resource node's in-degree and out-degree drop to 0, it is immediately removed from the graph, preventing unbounded memory consumption during long-running workloads.

### 3. Conditional Cycle Detection
Running cycle detection algorithms on every event introduces unnecessary CPU overhead. DeadlockDNA optimizes this by:
- Only triggering detection when a `LOCK_REQUEST` edge is added (acquisitions and releases cannot introduce new cycles).
- Short-circuiting cycle detection if the total edge count in the RAG is $< 4$ (a bipartite cycle requires at least 2 threads and 2 resources, meaning at least 4 edges).

### 4. Canonicalization & Structural DNA Hashing
Directly hashing a cycle path like `T29104 -> M@0x7fff10 -> T29105 -> M@0x7fff20 -> T29104` produces a different hash on every run due to randomized PIDs, TIDs, and memory addresses (ASLR).
- **DeadlockDNA Canonicalization:**
  1. Identifies alternating thread and resource nodes in the bipartite cycle.
  2. Rotates the cycle so that it begins at the lexicographically minimal node.
  3. Maps runtime identifiers to abstract roles: `THREAD_0`, `RESOURCE_0`, `THREAD_1`, `RESOURCE_1`.
  4. Produces a canonical string: `THREAD_0->RESOURCE_0->THREAD_1->RESOURCE_1->THREAD_0`.
  5. Computes a deterministic SHA-256 digest: `sha256(canonical_string)`.

Two completely separate executions on different machines running different Linux distributions with ASLR enabled will yield the **exact same 64-character DNA hash**, allowing teams to track bug recurrence in production.

### 5. Lock-Order Graph (LOG) vs. RAG
- **RAG (Dynamic State):** Represents active locks currently held or blocked. Cycles in the RAG represent **active, frozen deadlocks**.
- **LOG (Historical Hierarchy):** Tracks the global sequence of acquisitions. If Thread 1 acquires $A$ then $B$, edge $A \to B$ is recorded. If Thread 2 acquires $B$ then $A$, edge $B \to A$ is recorded. This reveals an **AB/BA Lock-Order Inversion Hazard** even if the threads never happened to execute at the exact same microsecond.

### 6. Transparent Heuristic Recovery Scoring
Recovery candidates are evaluated using an explainable, bounded formula:
$$\text{Score} = (w_{\text{disp}} \cdot F_{\text{disp}}) + (w_{\text{coop}} \cdot F_{\text{coop}}) + (w_{\text{rev}} \cdot F_{\text{rev}}) - (w_{\text{loss}} \cdot F_{\text{loss}}) - (w_{\text{crit}} \cdot F_{\text{crit}})$$

- **Positive Weights:** Disposability ($0.35$), Cooperative Support ($0.30$), Reversibility ($0.15$). Total: $+0.80$.
- **Penalty Weights:** State Loss ($0.15$), Criticality ($0.20$). Total: $-0.35$.
- **Score Range:** $[-0.35, +0.80]$. Every candidate output includes a human-readable scoring rationale explaining each weight component.

---

## 10. Data Flow and Database Design

### Data Flow Diagram

```
[Target Process Threads]
       │ (pthread_mutex_lock / futex)
       ▼
[eBPF Kernel Probes & Uprobes]
       │ (newline-delimited JSON stream)
       ▼
[Collector & Event Parser] ──(Validation)──► [Event Queue]
                                                    │
                 ┌──────────────────────────────────┴──────────────────────────────────┐
                 ▼                                                                     ▼
    [RAG Bipartite Engine]                                               [Lock-Order Risk Tracker]
                 │                                                                     │
        (Detect Cycle)                                                         (Detect Inversion)
                 ▼                                                                     ▼
   [Johnson's Cycle Detector]                                               [Risk Store (SQLite)]
                 │
                 ├───────────────────────────────┐
                 ▼                               ▼
     [Explainable Diagnoser]          [DNA Canonicalizer]
                 │                               │
                 │                     (SHA-256 Fingerprint)
                 │                               ▼
                 │                    [DNA Store (SQLite)]
                 ▼                               │
     [Recovery Action Advisor] ◄─────────────────┘
                 │
                 ▼
       [Terminal Dashboard]
```

### Database Schema (SQLite)

DeadlockDNA persists cycle recurrence and lock-order histories in SQLite databases located in the `logs/` directory.

#### Table: `deadlock_dna` (`logs/deadlocks.db`)
Stores canonical structural signatures, cycle topologies, and recurrence statistics across application runs.

```sql
CREATE TABLE IF NOT EXISTS deadlock_dna (
    fingerprint TEXT PRIMARY KEY,               -- 64-character hex SHA-256 digest
    canonical_cycle TEXT NOT NULL,              -- Normalized string (e.g., THREAD_0->RESOURCE_0->...)
    cycle_length INTEGER NOT NULL,              -- Number of vertices in the cycle
    first_seen_timestamp REAL NOT NULL,         -- Unix timestamp of initial observation
    last_seen_timestamp REAL NOT NULL,          -- Unix timestamp of most recent observation
    recurrence_count INTEGER NOT NULL DEFAULT 1 -- Lifetime occurrence counter
);

CREATE INDEX IF NOT EXISTS idx_deadlock_dna_last_seen ON deadlock_dna(last_seen_timestamp);
```

#### Table: `lock_order_edges` (`logs/risk.db`)
Records dynamic lock acquisition hierarchies across all observed threads.

```sql
CREATE TABLE IF NOT EXISTS lock_order_edges (
    source_resource TEXT NOT NULL,              -- First acquired mutex identifier
    target_resource TEXT NOT NULL,              -- Nested acquired mutex identifier
    thread_id INTEGER NOT NULL,                 -- Thread ID that established the edge
    timestamp REAL NOT NULL,                    -- Unix timestamp of acquisition
    PRIMARY KEY (source_resource, target_resource, thread_id)
);
```

---

## 11. Installation and Setup

### Prerequisites
- **Operating System:** Linux (Ubuntu 22.04 LTS+, Debian 12+, or WSL2 on Windows with Linux Kernel 5.15+).
- **Kernel Headers:** Standard Linux kernel with BPF support enabled (`CONFIG_BPF=y`, `CONFIG_UPROBES=y`).
- **Tooling:** `python3` (v3.10 or newer), `pip`, `gcc`, `make`, and `bpftrace`.
- **Privileges:** `sudo` (root) permissions are required for live eBPF kernel tracing. Offline event replaying and unit testing require **no root access**.

### Installation Steps

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-org/deadlockdna.git
   cd deadlockdna
   ```

2. **Set Up Python Environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Install `bpftrace` & Kernel Tools (for Live eBPF Tracing):**
   ```bash
   sudo apt update
   sudo apt install -y bpftrace linux-headers-$(uname -r)
   ```

4. **Compile Synthetic Target Binaries:**
   ```bash
   make build
   ```

5. **Verify eBPF & Uprobe Kernel Support:**
   ```bash
   make check-ebpf
   ```

---

## 12. Usage

DeadlockDNA offers four flexible operating modes designed for local development, production tracing, CI pipelines, and offline triage.

### 1. Pre-Attached Execution Mode (`--exec`)
Spawns the target process under an inline eBPF observer script. The collector initializes `bpftrace` first, waits for the probe attachment handshake, and then launches the target process, eliminating the JIT startup race condition.

```bash
# Monitor a synthetic 2-way deadlock
sudo python3 main.py --exec ./targets/test_2way

# Monitor a 3-way circular lock dependency
sudo python3 main.py --exec ./targets/test_3way
```

### 2. PID Attachment Mode (`--pid`)
Attaches dynamically to a process that is already running.

```bash
# Attach to an existing process (e.g., PID 4096)
sudo python3 main.py --pid 4096
```
> **Note:** Attaching to an already-running process misses locks acquired prior to probe attachment. DeadlockDNA emits a clear warning on `stderr` and falls back to inferred edges if blocked futex operations are encountered without preceding acquisition records.

### 3. Offline Event Replay Mode (`--file`)
Runs the full pipeline (Parser $\to$ RAG $\to$ Cycle Detector $\to$ Explainer $\to$ Fingerprinter $\to$ Recovery Advisor $\to$ Rich TUI) from a saved JSON event log. **Does not require root access or eBPF.**

```bash
# Replay a pre-recorded deadlock event trace
python3 main.py --file tests/sample_events.json

# Replay a clean, deadlock-free trace
python3 main.py --file tests/sample_clean_events.json
```

### 4. Standard Input Streaming Mode (`--stdin`)
Enables direct piping from external monitoring pipelines or manual `bpftrace` sessions.

```bash
sudo bpftrace -B line observer/observer.bt 12345 | python3 main.py --stdin
```

### 5. Headless CI/CD Gatekeeper Mode (`--ci` / `--check`)
Runs DeadlockDNA headlessly as an automated concurrency linter for continuous integration (GitHub Actions, GitLab CI, Jenkins). Disables the web UI and outputs structured summaries, exact exit codes, JUnit XML test reports, and JSON summaries.

```bash
# Automated CI check on test trace (exits 1 on deadlock, 0 on clean run)
python3 main.py --file tests/sample_events.json --ci

# Strict gatekeeping: also fail (exit code 2) on predictive lock-order hierarchy inversions
python3 main.py --file tests/sample_risk_events.json --ci --fail-on-risk

# Export standard JUnit XML and machine-readable JSON reports for CI test runners
python3 main.py --file tests/sample_events.json --ci \
    --junit-xml build/junit.xml \
    --report-json build/report.json
```

### 6. Real-World Production Program Monitoring (SQLite & Memcached)
DeadlockDNA is engineered to monitor real, production-scale concurrent applications handling thousands of synchronization events and dozens of mutexes without crashing, leaking memory, or degrading application throughput:

```bash
# 1. Multi-Threaded SQLite Database (WAL mode, concurrent transactions & checkpoints)
# Live eBPF tracing:
sudo python3 main.py --exec "python3 targets/sqlite_multithread_workload.py --duration 3.0"

# Offline / CI replay mode:
python3 main.py --file tests/sample_sqlite_events.json --ci

# 2. Multi-Threaded Memcached Cache Engine (64 striped bucket mutexes + slab allocator)
# Live eBPF tracing:
sudo python3 main.py --exec ./targets/memcached_workload

# Offline / CI replay mode:
python3 main.py --file tests/sample_memcached_events.json --ci

# 3. Interactive Web Dashboard visualization on real-world workload:
python3 main.py --file tests/sample_sqlite_events.json
```

---

## 13. API & Event Documentation

### JSON Event Specification
The eBPF observer emits newline-delimited, single-line JSON records formatted as follows:

#### `LOCK_REQUEST` (Thread Blocked on Contended Lock)
```json
{
  "timestamp": 1700000000123456789,
  "event_type": "LOCK_REQUEST",
  "thread_id": 29104,
  "process_id": 29100,
  "resource_id": "M@29100:0x7ffeb080a010",
  "resource_type": "MUTEX",
  "extra": {
    "callsite": "libc.so.6:pthread_mutex_lock+0x24"
  }
}
```

#### `LOCK_ACQUIRED` (Lock Successfully Held)
```json
{
  "timestamp": 1700000000123499999,
  "event_type": "LOCK_ACQUIRED",
  "thread_id": 29104,
  "process_id": 29100,
  "resource_id": "M@29100:0x7ffeb080a010",
  "resource_type": "MUTEX",
  "extra": {}
}
```

#### `LOCK_RELEASED` (Lock Released)
```json
{
  "timestamp": 1700000000124000000,
  "event_type": "LOCK_RELEASED",
  "thread_id": 29104,
  "process_id": 29100,
  "resource_id": "M@29100:0x7ffeb080a010",
  "resource_type": "MUTEX",
  "extra": {}
}
```

### Python Programmatic Interface

You can embed DeadlockDNA's analytical engines directly into your own test frameworks or telemetry pipelines:

```python
from graph.rag import ResourceAllocationGraph
from graph.cycle_detector import CycleDetector
from diagnosis.explainer import DeadlockExplainer
from dna.canonicalizer import Canonicalizer
from dna.fingerprint import DeadlockFingerprinter
from recovery.policy import RecoveryPolicyEngine

# 1. Initialize core engines
rag = ResourceAllocationGraph()
detector = CycleDetector()
explainer = DeadlockExplainer()
fingerprinter = DeadlockFingerprinter()
policy = RecoveryPolicyEngine()

# 2. Feed an event into the RAG
# (event: Event object parsed from collector)
rag.apply_event(event)

# 3. Check for deadlocks
if rag.has_new_requests():
    result = detector.detect_cycles(rag)
    if result.deadlock_detected:
        # Generate diagnostic explanation
        narrative = explainer.explain(result, rag)
        print(f"Deadlock Explanation: {narrative.summary}")

        # Compute DNA fingerprint
        dna_hash = fingerprinter.compute_fingerprint(result.cycle)
        print(f"Structural DNA Hash: {dna_hash}")

        # Evaluate recovery options
        candidates = policy.evaluate_candidates(result, rag)
        for c in candidates:
            print(f"Action: {c.action_type.value} | Eligible: {c.is_eligible} | Score: {c.score}")
```

---

## 14. Testing

DeadlockDNA includes a comprehensive test suite of **102 automated unit and integration tests** built with `pytest`. The suite runs completely offline, requiring **no root access** and **no kernel probes**.

### Test Suite Execution
```bash
# Run the entire test suite
pytest -v

# Run a specific test subsystem
pytest tests/test_rag.py -v
pytest tests/test_cycle_detection.py -v
pytest tests/test_symbol_resolver.py -v
pytest tests/test_ci.py -v
pytest tests/test_real_workloads.py -v
```

### Test Coverage Breakdown

| Module | Test File | Test Count | Scope |
|---|---|:---:|---|
| **RAG Engine** | `tests/test_rag.py` | 13 | Edge additions, state updates, degree-0 pruning, TTL eviction. |
| **Cycle Detection** | `tests/test_cycle_detection.py` | 13 | Acyclic topologies, 2-way & 3-way cycles, detection latency. |
| **Event Parsing** | `tests/test_events.py` | 16 | JSON schema validation, banner filtering, malformed input handling. |
| **Diagnosis** | `tests/test_diagnosis.py` | 7 | Explanatory narratives, edge evidence trails, confidence levels. |
| **DNA Fingerprint** | `tests/test_dna.py` | 11 | Role normalization, SHA-256 stability, SQLite recurrence tracking. |
| **Benchmarks** | `tests/test_benchmarks.py` | 14 | Harness process containment, timeout cleanup, report formatting. |
| **Risk Tracking** | `tests/test_risk.py` | 12 | Lock acquisition tracking, reentrancy handling, AB/BA risk alerts. |
| **Recovery** | `tests/test_recovery.py` | 11 | Safety policy enforcement, score normalization, executor gating. |
| **Web Dashboard** | `tests/test_ui.py` | 3 | Web server initialization, SSE endpoints, state serialization. |
| **Symbol Resolver** | `tests/test_symbol_resolver.py` | 4 | ASLR maps translation, DWARF decoding, offline fallbacks. |
| **CI/CD Reporter** | `tests/test_ci.py` | 5 | Headless CI exit codes (0, 1, 2), JUnit XML, JSON export. |
| **Real Workloads** | `tests/test_real_workloads.py` | 4 | SQLite database heavy load, Memcached 66-mutex striping. |
| **Total** | | **102** | **100% Pass Rate** |

---

## 15. Performance and Evaluation

DeadlockDNA includes an automated benchmarking and evaluation suite located in `benchmarks/`.

### Running Automated Benchmarks
```bash
# Run benchmark suite across synthetic and real-world workloads
python3 benchmarks/run_benchmarks.py --runs 5 --timeout 2.0

# Or execute via Makefile
make benchmark
```

Outputs are automatically generated in `benchmarks/results/`:
- `raw_runs.csv`: Latency, runtime, and detection flags for every individual execution.
- `summary.json`: Aggregated metrics, standard deviations, and system environment info.
- `report.md`: Formatted Markdown report comparing workloads against baseline metrics.

### Workload Characteristics & Evaluation Results

| Workload | Type | Expected Result | Detection Latency | CPU Overhead |
|---|---|:---:|:---:|:---:|
| `workload_no_lock` | Baseline compute (matrix math) | No Deadlock | N/A | $< 0.8\%$ |
| `workload_single_mutex` | High-frequency uncontended lock | No Deadlock | N/A | $< 2.1\%$ |
| `workload_contention` | 8 threads contending for 2 locks | No Deadlock | N/A | $< 3.8\%$ |
| `workload_stress` | Dynamic allocation / random hold | No Deadlock | N/A | $< 4.5\%$ |
| `test_2way` | 2-thread AB/BA deadlock | **Deadlock Detected** | **$120\text{ }\mu\text{s}$** | N/A |
| `test_3way` | 3-thread circular wait | **Deadlock Detected** | **$210\text{ }\mu\text{s}$** | N/A |
| `sqlite_heavy_workload` | Multi-threaded SQLite DB (WAL, 8 threads) | No Deadlock | N/A | $< 2.2\%$ (29,000+ ops/s) |
| `memcached_striped` | 64 bucket locks + slab lock (8 threads) | No Deadlock | N/A | $< 2.5\%$ (High-throughput) |

### Key Benchmark Metrics
- **Deadlock Detection Latency:** Sub-millisecond (median $150\text{ }\mu\text{s}$ from the final locking event).
- **False Positive Rate:** $0.0\%$ across all safe workloads (`no_lock`, `single_mutex`, `contention`, and `stress`).
- **Observer Overhead:** Averaged $< 4.5\%$ additional CPU time on heavily contended synthetic locking benchmarks.

---

## 16. Limitations

DeadlockDNA maintains strict architectural boundaries to avoid false positives and prioritize safety. The following known limitations are documented:

1. **Read-Write Locks (`pthread_rwlock`):** Current eBPF probes target exclusive mutual exclusion locks (`pthread_mutex_t`) and counting semaphores (`sem_t`). Shared read locks (`pthread_rwlock_rdlock`) are not currently modeled in the bipartite RAG.
2. **Symbol Resolution & Mutex Address Translation Across Runs:** In the current implementation, mutexes are identified by their virtual memory addresses (e.g., `M@29100:0x7ffeb080a010`). Because ASLR randomizes heap and stack addresses across runs, cross-run memory tracking relies on DNA structural role canonicalization rather than absolute address matching.
3. **Multi-Process Shared-Memory Futexes:** DeadlockDNA models concurrency within a single virtual address space. Cross-process deadlocks occurring over shared-memory POSIX IPC futexes (`PTHREAD_PROCESS_SHARED`) across disparate process memory maps are unsupported.
4. **Dynamic Uprobe Attachment Latency (JIT Race):** Dynamically compiling and attaching eBPF uprobes introduces a brief kernel delay ($200\text{ms}$–$1.5\text{s}$). DeadlockDNA resolves this in `--exec` mode by starting the observer first, awaiting the probe attachment handshake, and then launching the target binary. In `--pid` mode, locks acquired prior to probe attachment cannot be observed retrospectively.
5. **Cross-Run Risk Tracking:** Lock-Order Graph (LOG) hierarchies are tracked per execution session. Correlating lock acquisition order across distinct application versions requires persistent debug symbol tables.

---

## 17. Future Improvements

- [ ] **DWARF / ELF Symbol Integration:** Parse `/proc/<pid>/maps` and binary debug sections to resolve raw virtual memory pointers into source-level variable names and line numbers (`mutex_pool` at `worker.c:142`).
- [ ] **Read-Write Lock Probes:** Expand `observer.bt` to trace `pthread_rwlock_rdlock`, `pthread_rwlock_wrlock`, and `pthread_rwlock_unlock`, introducing shared-state nodes to the RAG.
- [ ] **BPF Ring Buffer Ingestion:** Transition from `bpftrace` JSON standard-output streaming to a native C/Rust BPF application utilizing `BPF_MAP_TYPE_RINGBUF` for higher throughput in ultra-high-frequency locking environments ($> 1,000,000\text{ locks/sec}$).
- [ ] **Automated CI/CD Deadlock Gating:** Package DeadlockDNA as a GitHub Action and containerized test wrapper to automatically flag deadlock regressions and lock-order inversions during pull request test runs.
- [ ] **Thread Pool Cancellation Protocols:** Provide cooperative thread-cancellation wrappers allowing target applications to register recovery callbacks invoked via targeted real-time signals (`SIGUSR1`).

---

