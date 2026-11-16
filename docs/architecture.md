# DeadlockDNA — System Architecture & Design Specification

> **Project:** DeadlockDNA — Non-Intrusive Runtime Deadlock Detection, Diagnosis & Recovery Framework for Linux Multithreaded Applications  
> **Status:** Fully Implemented & Verified (**97/97 Unit Tests Passing**, 100% Pass Rate)  
> **Target OS:** Linux (Ubuntu 22.04+ / Debian x86_64, WSL2 with Linux Kernel 5.15+)  
> **Technology Stack:** Linux eBPF / bpftrace, Python 3.10+, NetworkX, Rich TUI, SQLite, POSIX Threads (glibc / NPTL)  

---

## 1. Executive Summary & Vision

**DeadlockDNA** is an out-of-process, zero-instrumentation runtime deadlock detection, diagnosis, fingerprinting, benchmarking, risk analysis, and advisory recovery platform for Linux C/C++ multithreaded applications.

Unlike traditional debugging tools:
* **No code instrumentation:** Does not require modifying target source code.
* **No recompilation:** Works on standard binaries without debug flags or compiler sanitizers (`-fsanitize=thread`).
* **No intrusive injection:** Does not use `LD_PRELOAD`, debugger traps (`ptrace`), or binary rewriting.
* **True Non-Intrusiveness:** Observes processes from the outside using Linux kernel eBPF tracepoints and user-space probes (`uprobes`).

---

## 2. End-to-End Architectural Pipeline

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
|   - 4 Modes: --exec <prog> (pre-attached to prevent JIT race), --pid <PID>, --file, --stdin   |
|   - Ingestion: Asynchronous reader thread + thread-safe queue                                 |
|   - Parser: Discards banner/debug text, validates schema, converts to typed Event objects     |
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

---

## 3. Subsystem Breakdown

### 3.1. Layer 1: Hybrid eBPF/Uprobe Observer (`observer/`)
* **Fast-Path Problem:** Uncontended mutexes are acquired via atomic CPU instructions in user space without issuing system calls. Tracing futex syscalls alone misses who holds uncontended locks.
* **Dual Observation:**
  * `uprobe` & `uretprobe` on `libc.so.6:pthread_mutex_lock` and `sem_wait` capture lock acquisitions and pointers.
  * `tracepoint:syscalls:sys_enter_futex` captures threads blocked on `FUTEX_WAIT`.
  * `uprobe` on `pthread_mutex_unlock` and `sem_post` captures lock releases.
* Emits newline-delimited, line-buffered JSON records (`LOCK_REQUEST`, `LOCK_ACQUIRED`, `LOCK_RELEASED`).

### 3.2. Layer 2: Event Ingestion & Collector (`collector/`)
* **Modes:** `--exec <binary>`, `--pid <PID>`, `--file <json>`, `--stdin`.
* **JIT Startup Race Barrier:** Generates an inline comm-filtered bpftrace script, launches the observer first, awaits the `BEGIN` handshake signal, and only then spawns the target program.
* **Parser:** Filters diagnostic banners (`Attaching 6 probes...`), validates JSON schema, and normalizes into typed `Event` objects.

### 3.3. Layer 3: Resource Allocation Graph (RAG) (`graph/`)
* **Representation:** NetworkX directed bipartite graph $G = (V_T \cup V_R, E)$.
* **Nodes:** Threads `T<tid>` and Scoped Resources `M@<pid>:<hex_addr>`.
* **State Machine:**
  * `LOCK_REQUEST`: Adds request edge $T \to R$.
  * `LOCK_ACQUIRED`: Removes request $T \to R$, evicts previous holder, adds allocation $R \to T$.
  * `LOCK_RELEASED`: Removes allocation $R \to T$.
* **Automatic Compaction:** Disconnected degree-0 nodes are pruned immediately after lock release to prevent memory growth.

### 3.4. Layer 4: Cycle Detection (`graph/cycle_detector.py`)
* **Algorithm:** Donald B. Johnson’s elementary cycle finder (`networkx.simple_cycles`).
* **Canonicalization:** Rotates cycles to start at the lexicographically minimal node and appends the root to close the loop.
* **Latency Calculation:** Measures nanosecond detection latency from kernel timestamp (`bpf_ktime_get_ns`) to cycle discovery.

### 3.5. Feature A: Explainable Deadlock Diagnosis (`diagnosis/`)
* Translates detected cycles into human-readable narratives.
* Identifies for each thread what it holds ($R_{\text{held}} \to T$) and what it is waiting for ($T \to R_{\text{wait}}$).
* Determines observation confidence (`complete`, `partial`, `unknown`) and records explicit limitations.

### 3.6. Feature B: Deadlock DNA Fingerprinting & History Store (`dna/`)
* **Canonicalizer:** Strips runtime PIDs, TIDs, and virtual memory addresses, converting the cycle into a role-based structure (`THREAD_0 -> RESOURCE_0 -> THREAD_1 -> RESOURCE_1 -> THREAD_0`).
* **Hasher:** Generates deterministic 64-character SHA-256 digests. Structurally identical deadlocks across different runs/machines produce identical fingerprints.
* **SQLite Store:** Stores recurrence counts in `logs/deadlocks.db` via atomic transactions.

### 3.7. Feature C: Automated Benchmark Suite (`benchmarks/`)
* Safe benchmark harness with process containment and automatic timeouts.
* Measures detection success rate, false positive rate, latency percentiles (median, p95), runtime overhead, and event loss.
* Automatically exports CSV raw run data, JSON summaries, and Markdown reports.

### 3.8. Feature D: Lock-Order Risk Analysis (`risk/`)
* **Lock-Order Graph (LOG):** Tracks dynamic lock acquisition sequences per thread. When thread $T$ acquires $B$ while holding $A$, records directed edge $A \to B$.
* **Predictive Detection:** Detects circular lock-order dependencies (e.g. $A \to B$ and $B \to A$) before a deadlock occurs.
* **Predictive vs. Live:** Explicitly flags risks with `is_live_deadlock = False`, distinguishing architectural hierarchy violations from active deadlocks.

### 3.9. Feature E: Cost-Aware Recovery Recommendations (`recovery/`)
* **Safety Boundaries:** External mutex unlocking is unconditionally rejected (violates POSIX invariants). Non-disposable / production targets block destructive terminations.
* **Transparent Heuristic Scoring:** Ranks actions using documented weights:
  $$\text{score} = w_1 \cdot \text{disposability} + w_2 \cdot \text{cooperative\_support} + w_3 \cdot \text{reversibility} - w_4 \cdot \text{state\_loss} - w_5 \cdot \text{criticality}$$
* **Default Safe Mode:** Defaults to recommendation-only mode (`execution_enabled = False`).
* **Verification:** `RecoveryVerifier` confirms post-recovery cycle resolution and logs side effects.

---

## 4. Verification Suite & Metrics

The complete test suite runs under pytest in **< 2.0 seconds**:

| Test Module | Coverage Area | Tests | Status |
|---|---|:---:|:---:|
| `tests/test_rag.py` | RAG graph transitions, edge creation, node pruning | 13 | Passing |
| `tests/test_cycle_detection.py` | Acyclic graphs, 2-way & 3-way cycles, latency | 13 | Passing |
| `tests/test_events.py` | JSON stream parsing, banner filtering, type safety | 16 | Passing |
| `tests/test_diagnosis.py` | Human-readable explanation, evidence trail, confidence | 7 | Passing |
| `tests/test_dna.py` | Role canonicalization, SHA-256 hashing, SQLite store | 11 | Passing |
| `tests/test_benchmarks.py` | Workload containment, timeout cleanup, report generation | 14 | Passing |
| `tests/test_risk.py` | Lock-order acquisition graph, reentrancy, predictive risks | 12 | Passing |
| `tests/test_recovery.py` | Transparent scoring, safety policy, executor gating, verifier | 11 | Passing |
| **Total** | **Full System Integration & Unit Test Suite** | **97** | **100% Pass** |
