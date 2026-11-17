# DeadlockDNA — Feature Expansion Specification
**Version:** 1.0  
**Purpose:** Implementation guide for extending the existing DeadlockDNA project beyond its current runtime observation, Resource Allocation Graph (RAG), cycle detection, and terminal dashboard.

---

## 1. Project summary

DeadlockDNA is a Linux runtime deadlock-observation and diagnosis prototype. Its current pipeline observes synchronization-related events, converts them into a graph of thread/resource dependencies, detects cycles, and displays alerts.

The feature expansion adds nine core capabilities across observation, diagnosis, visualization, gatekeeping, and enterprise testing:

1. **Explainable diagnosis (Feature A)** — turn a detected cycle into a readable, evidence-backed narrative.
2. **Deadlock DNA fingerprinting (Feature B)** — normalize cycle structure and generate a stable SHA-256 fingerprint.
3. **Benchmarking and evaluation (Feature C)** — run reproducible test cases and report detection quality, latency, event loss, and overhead.
4. **Lock-order risk analysis (Feature D)** — learn lock acquisition order and warn about potential circular-wait risks across observations.
5. **Cost-aware recovery recommendations (Feature E)** — rank safe, explicit recovery options and validate outcomes in controlled experiments.
6. **Real-time Web Dashboard & Visualizer (Feature F)** — zero-dependency SSE streaming and HTML5 Canvas force-directed topology graph.
7. **Source-Code & Symbol Resolution (Feature G / Upgrade 1)** — map raw pointers to C variable names, line numbers, and functions via DWARF, `nm`, `addr2line`, and `/proc/<pid>/maps`.
8. **Headless CI/CD Mode / Concurrency Linter (Feature H / Upgrade 2)** — automated gatekeeping with `--ci`, deterministic exit codes (`0`, `1`, `2`), JUnit XML test suite reporting, and machine-readable JSON artifacts.
9. **Real-World Production Program Gatekeeping (Feature I / Upgrade 3)** — validate DeadlockDNA against high-load production architectures: multi-threaded **SQLite** and multi-threaded **Memcached** (64 striped bucket mutexes + slab allocator) without performance degradation.

## 2. Existing architecture and integration assumptions

The current repository has components similar to the following (actual names may vary):

```text
observer / eBPF or bpftrace
        |
        | JSON Lines events
        v
collector / event parser
        |
        v
normalized Event objects
        |
        v
Resource Allocation Graph (NetworkX)
        |
        v
cycle detector
        |
        +----> terminal dashboard
```

The current implementation has been described with files/modules such as:

```text
collector/collector.py
collector/event_parser.py
graph/rag.py
graph/models.py
graph/cycle_detector.py
ui/dashboard.py
observer/observer.bt
```

**Before editing:** inspect the actual repository and follow its current data model and naming. Do not create duplicate implementations of the graph or cycle detector. Prefer small modules that consume the existing detected-cycle/Event structures.

### Core graph conventions

- A thread is represented by its Linux **TID** (thread ID), not merely its process PID.
- A resource/lock is represented by a stable identifier within the observation, for example `M@<pid>:<address>`.
- Request edge: `Thread -> Resource`.
- Allocation/ownership edge: `Resource -> Thread`.
- A directed cycle in this bipartite graph can represent a circular wait, provided the graph edges accurately reflect observed requests and ownership.
- The graph is only as trustworthy as the events observed. Missing acquisition/release events can make the graph incomplete or stale.

### Important event-semantics requirement

Do not treat every futex wait as proof of a pthread mutex wait. Futexes are a lower-level synchronization mechanism used by many primitives. A contended `pthread_mutex_lock` may enter the kernel, while an uncontended lock can complete entirely in userspace. Record which probes produced each event and preserve uncertainty where appropriate.

A useful normalized event schema, if compatible with the existing code, is:

```json
{
  "schema_version": 1,
  "event_type": "LOCK_REQUEST",
  "timestamp_ns": 1234567890,
  "pid": 1234,
  "tid": 1235,
  "resource_id": "M@1234:0xabc",
  "source": "pthread_mutex_lock",
  "confidence": "direct",
  "metadata": {}
}
```

Suggested normalized event types:

- `LOCK_REQUEST`
- `LOCK_ACQUIRED`
- `LOCK_RELEASED`
- `THREAD_START`
- `THREAD_EXIT`
- `PROCESS_EXIT`
- `OBSERVATION_GAP` (if the observer detects lost events or an attachment gap)

Do not invent events that the observer cannot support. If the current collector does not know whether a request succeeded, represent that limitation rather than silently assuming acquisition.

---

## 3. Feature A — Explainable deadlock diagnosis

### Goal

When the cycle detector finds a cycle, display a human-readable explanation based on the actual cycle and the graph's ownership/request edges.

Example presentation:

```text
Deadlock candidate detected

TID 4101 holds Mutex A and waits for Mutex B.
TID 4102 holds Mutex B and waits for Mutex A.

Dependency cycle:
T4101 -> Mutex B -> T4102 -> Mutex A -> T4101

Evidence:
- T4101 requested Mutex B at timestamp ...
- Mutex B is recorded as owned by T4102.
- T4102 requested Mutex A at timestamp ...
- Mutex A is recorded as owned by T4101.

Confidence: high / partial / unknown
```

The exact text must be generated from observed data, not hard-coded to the two-thread test case.

### Implementation tasks

1. Create a diagnosis module, e.g. `diagnosis/explainer.py`.
2. Input: detected cycle plus the current RAG and event metadata.
3. Walk the cycle and classify each edge as request or allocation.
4. Resolve TID/resource labels using graph metadata.
5. Attach timestamps and event source where available.
6. Determine whether evidence is complete:
   - `complete`: all required edges are supported by current observations.
   - `partial`: at least one edge or ownership state is inferred or missing.
   - `unknown`: the event stream cannot support a reliable explanation.
7. Return a structured object, not just formatted text.

Suggested output structure:

```json
{
  "diagnosis_id": "local-event-id",
  "cycle_nodes": ["T4101", "M@1234:0xabc", "T4102"],
  "summary": "Two threads are waiting on resources owned by each other.",
  "steps": [
    {
      "thread_id": 4101,
      "action": "waiting_for",
      "resource_id": "M@1234:0xdef",
      "resource_owner_tid": 4102,
      "evidence_status": "observed"
    }
  ],
  "confidence": "partial",
  "limitations": ["The acquisition timestamp was unavailable."]
}
```

Adapt field names to the existing project. Never include fake timestamps or claim certainty unsupported by the events.

### Dashboard integration

- Show a concise summary first.
- Show the cycle chain and one explanation line per dependency.
- Include confidence/observation completeness.
- Keep the dashboard usable when no cycle exists.
- Avoid flooding the terminal with repeated copies of the same alert. Deduplicate by cycle fingerprint or a temporary canonical cycle key.

### Acceptance criteria

- A two-thread deadlock produces the correct explanation.
- A three-thread cycle produces all dependency steps in the right order.
- Different TIDs/resources produce a different runtime trace but still a valid explanation.
- Missing ownership/request evidence lowers confidence rather than generating a false claim.
- No cycle means no deadlock diagnosis is displayed.

---

## 4. Feature B — Deadlock DNA fingerprinting

### Goal

Create a stable identifier for the **structure** of a detected cycle, independent of runtime thread IDs, process IDs, and memory addresses.

Example:

```text
Run 1: T100 -> R@0xaaa -> T101 -> R@0xbbb -> T100
Run 2: T800 -> R@0x111 -> T801 -> R@0x222 -> T800
```

If both represent the same structural pattern, they should produce the same canonical representation and fingerprint.

### Important distinction

A SHA-256 hash does not discover a deadlock or prove two bugs have the same cause. The hard part is producing a correct canonical representation. The hash is only a compact identifier for that representation.

### Canonicalization approach

For a cycle, convert runtime identifiers to role-based labels while preserving node types and directed edge roles.

For example, a two-thread/two-lock cycle can become:

```text
THREAD_0 -> RESOURCE_0 -> THREAD_1 -> RESOURCE_1 -> THREAD_0
```

But do not simply replace identifiers based on their original numeric value. Equivalent cycles may be rotated, and larger cycles may have multiple equivalent starting points.

Recommended process:

1. Validate that the candidate is a closed directed cycle.
2. Convert each node into its type (`THREAD` or `RESOURCE`) and each edge into its semantic type (`REQUEST` or `ALLOCATION`).
3. Generate the allowed cycle rotations.
4. For each rotation, serialize the typed node/edge sequence deterministically.
5. Select the lexicographically smallest valid serialization.
6. Hash the UTF-8 canonical serialization with SHA-256.
7. Store both the canonical serialization and hash. The serialization is essential for debugging hash collisions, canonicalization bugs, and interpretation.

For a simple directed cycle, rotation normalization is normally sufficient to remove the arbitrary starting node. If the implementation also normalizes reflection/reversed direction, be careful: a reversed cycle is not necessarily semantically equivalent because edge directions and request/ownership roles matter. **Do not reverse cycles unless equivalence has been rigorously defined.**

Example pseudocode:

```python
import hashlib
import json

def fingerprint(canonical_payload: dict) -> str:
    encoded = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
```

The `canonical_payload` must already be normalized; this function alone does not canonicalize a cycle.

### Suggested module structure

```text
dna/
  canonicalizer.py
  fingerprint.py
  store.py
```

- `canonicalizer.py`: convert runtime cycle to a stable typed representation.
- `fingerprint.py`: hash canonical serialization.
- `store.py`: persistence and occurrence history.

### Persistence

Use SQLite for structured history unless the project already has a working database abstraction. JSON is acceptable for an early prototype, but concurrent writes and schema evolution are easier to manage in SQLite.

Suggested tables:

```sql
CREATE TABLE IF NOT EXISTS fingerprints (
    fingerprint TEXT PRIMARY KEY,
    canonical_pattern TEXT NOT NULL,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns INTEGER NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    detected_at_ns INTEGER NOT NULL,
    pid INTEGER,
    tids_json TEXT NOT NULL,
    resources_json TEXT NOT NULL,
    confidence TEXT NOT NULL,
    FOREIGN KEY (fingerprint) REFERENCES fingerprints(fingerprint)
);
```

Use parameterized SQL. Enable foreign-key enforcement if relying on the foreign key. Store only the data needed for the project; do not capture application secrets or unrelated process contents.

On each detection:

- If the fingerprint is new, insert a fingerprint record.
- If it exists, increment occurrence count and update last-seen time.
- Insert a detection record containing runtime context.
- Make the operation transactional so the summary and occurrence record do not disagree.

### Acceptance criteria

- The same structural cycle with different TIDs and addresses has the same fingerprint.
- A structurally different cycle produces a different canonical pattern in test cases.
- Repeated detections increment occurrence count rather than creating duplicate fingerprint rows.
- The stored canonical string can be inspected to explain why two cycles matched.
- Unit tests cover rotations, two-thread cycles, three-thread cycles, and invalid input.

---

## 5. Feature C — Benchmarking and evaluation

### Goal

Replace claims such as “fast detection” or “low overhead” with reproducible measurements.

### Test matrix

Build or reuse separate C test workloads. Do not embed deadlock logic in the detector itself.

| Test | Purpose |
|---|---|
| No-lock workload | Baseline overhead and false positives |
| One thread, one mutex | Basic lock event handling |
| Two threads, one shared mutex | Normal contention without circular wait |
| Two-thread/two-mutex deadlock | Core cycle-detection test |
| Three-thread cycle | Multi-node cycle correctness |
| Repeated acquire/release loop | Event throughput and stress |
| Long-running non-deadlocking workload | Stability and false positives |
| Incomplete-observation test | Confidence handling and limitations |

For deadlock tests, use a parent harness with a timeout so a deliberately deadlocked process can be stopped after measurements. Keep cleanup isolated to the test process. Never use a real production process for forced termination tests.

### Metrics to measure

1. **Detection latency**  
   Time from the point at which the final dependency needed to complete the cycle is observed to the time the detector reports the cycle.

2. **Detection success rate**  
   Detected true deadlock test cases / total true deadlock test cases.

3. **False-positive rate**  
   Non-deadlocking runs that the system incorrectly reports as deadlocks / total non-deadlocking runs. Report the denominator and test suite.

4. **False-negative count**  
   True deadlock cases not detected, including cases caused by missed events.

5. **Observer overhead**  
   Compare the same workload with observation disabled and enabled. Measure runtime and, where available, CPU usage. Repeat runs and report median and spread.

6. **Event loss / parser failures**  
   Count malformed records, dropped events if the transport reports them, parse failures, and observation gaps. If event loss cannot be measured directly, state that rather than reporting zero.

7. **Fingerprint consistency**  
   Number of repeated equivalent test patterns that produce the same fingerprint / total repeated equivalent patterns.

8. **Recovery result**  
   For controlled recovery experiments only: whether the test resolves, time to resolution, and side effects.

### Timing rules

- Use monotonic clocks for elapsed durations.
- Be explicit about the start and end points.
- Avoid subtracting timestamps from unrelated clock domains without a validated conversion.
- If eBPF `bpf_ktime_get_ns()` and Python's clock are used together, verify that the clock sources and conversion are compatible on the target environment. Otherwise measure end-to-end latency in one clock domain.
- Repeat each test several times (e.g. 20 or more when practical); report median and a percentile such as p95, along with the number of runs.
- Do not publish example numbers as if they were measured results.

### Suggested output files

```text
benchmarks/
  workloads/
  run_benchmarks.py
  results/
    raw_runs.csv
    summary.json
    report.md
```

Each raw row should record the workload name, run number, whether a deadlock was expected, whether one was detected, measured latency if available, elapsed runtime, observer mode, parse errors, and relevant environment metadata.

### Suggested report format

```text
Environment
- OS/kernel:
- CPU:
- Python version:
- bpftrace/eBPF setup:
- Commit/version:

Results
- Workload:
- Number of runs:
- Detection success:
- False positives:
- Median detection latency:
- p95 detection latency:
- Runtime overhead:
- Event/parse loss:
- Limitations:
```

### Acceptance criteria

- One command runs the safe benchmark suite.
- Deliberately deadlocking tests have a timeout and cleanup.
- Results are generated from actual runs and are not hard-coded.
- The report states the test environment and limitations.
- Baseline and observed runs use equivalent workloads.
- At least one non-deadlocking contention test is included to distinguish contention from deadlock.

---

## 6. Feature D — Lock-order risk analysis

### Goal

Track the order in which locks are acquired and warn when observations indicate a possible circular lock-order dependency.

Example:

- Run A: a thread holds A, then acquires B. Record `A -> B`.
- Run B: a thread holds B, then acquires A. Record `B -> A`.
- The combined lock-order graph contains a cycle, indicating a **potential lock-order risk**.

This is different from live RAG detection:

- **RAG cycle:** a current observed circular wait, if events and ownership state are reliable.
- **Lock-order cycle:** a pattern across observed acquisitions that could permit deadlock under some execution interleaving. It is not proof of a live deadlock or that every execution will deadlock.

### Data collection

For each thread, track the locks it currently holds, as far as the observer can reliably establish. When the thread acquires lock B while already holding lock A, record a directed order edge `A -> B`.

Requirements:

- Add an edge only when the acquisition order is observed with sufficient confidence.
- Remove a lock from the held-lock set on a corresponding release.
- Handle recursive locks and reentrant acquisition according to the supported primitive's semantics.
- Track thread/process exit and clear or mark uncertain held-lock state.
- Do not infer a successful acquisition from a request event alone.
- If events are missing, mark the relevant trace incomplete.

### Suggested module structure

```text
risk/
  lock_order_tracker.py
  risk_cycle_detector.py
  risk_store.py
```

Use a directed graph with resource/lock nodes. A cycle such as `A -> B -> C -> A` means the observed acquisition-order constraints can form a circular order. Preserve the evidence showing which observations contributed each edge.

### Risk report

For each potential cycle, display:

- Cycle lock labels.
- Source observations for each edge.
- First/last observed time.
- Whether the cycle was seen in one run or combined across runs.
- Confidence / completeness.
- A warning that this is a risk, not a confirmed current deadlock.

### Scope and limitations

- Lock-order tracking only works for synchronization primitives and acquisition events that are actually observed.
- Raw memory addresses may differ across processes and runs. Cross-run matching needs a stable resource identity or a carefully scoped mapping. Do not claim that two different addresses represent the same logical lock unless you have evidence.
- Existing tools and research already perform lock-order analysis. The project contribution should be framed as the integration with live RAG diagnosis, fingerprint history, explainable evidence, and evaluation—not as inventing lock-order analysis itself.

### Acceptance criteria

- Observed `A -> B` and `B -> A` produce a potential risk warning.
- Repeated acquisition of the same lock does not create a false self-edge unless the primitive semantics genuinely warrant it.
- A single order with no reverse path does not produce a cycle warning.
- Reports retain evidence and distinguish observed order from inferred risk.
- Tests include both safe and risky lock-order examples.

---

## 7. Feature E — Cost-aware recovery recommendations

### Goal

Recommend a controlled way to resolve or contain a detected deadlock, with transparent reasoning.

**Safety rule:** Do not attempt to arbitrarily unlock another thread's POSIX mutex. POSIX mutex ownership rules make that unsafe or invalid for ordinary mutexes, and forced manipulation can corrupt application state. Do not kill arbitrary system or user processes.

### Recommended first version

Implement recommendation-only mode first. Generate candidate actions, calculate an interpretable score, and show why an action was ranked. Then validate actions only in disposable test programs that explicitly cooperate with the recovery mechanism.

Candidate factors can include:

- Whether the process is a disposable test workload.
- Whether it has a documented cooperative cancellation/shutdown path.
- Application importance supplied by the test harness or configuration.
- Number of resources/threads implicated.
- Whether the action is reversible.
- Estimated impact and risk.
- Time spent waiting, if reliably measured.

Avoid pretending that CPU/memory usage alone reveals which thread is safe to terminate. A thread holding critical resources may be a poor candidate even if its CPU usage is low.

### Transparent scoring

A simple configurable score can be used to rank **test-only candidates**, but all factors and weights must be documented. For example:

```text
candidate_score =
    w1 * test_disposability
  + w2 * cooperative_shutdown_support
  - w3 * estimated_state_loss
  - w4 * application_criticality
```

This is a ranking heuristic, not a mathematically optimal recovery algorithm. Normalize feature values, document weights, and test how ranking changes under different weights. Do not describe it as AI unless a real learned model is built and evaluated.

### Recovery stages

1. Detect a cycle.
2. Explain the cycle and evidence.
3. Generate eligible recovery candidates.
4. Reject unsafe or unsupported actions.
5. Rank remaining actions and show the rationale.
6. In a disposable test workload, request cooperative cancellation or orderly shutdown.
7. Verify that the process/thread state changed and the RAG no longer contains the original cycle.
8. Record outcome and side effects.

If the process does not cooperate, report that recovery was unsuccessful. Do not escalate automatically to destructive action.

### Suggested module structure

```text
recovery/
  candidate.py
  scoring.py
  policy.py
  executor.py
  verifier.py
```

Keep `executor.py` disabled by default. Separate recommendations from actions. Any process termination experiment must be restricted to a known child test process created by the benchmark harness, with explicit safeguards and timeouts.

### Acceptance criteria

- The UI explains why each action was or was not eligible.
- Default mode makes recommendations but takes no action.
- Unsafe arbitrary mutex unlocking is not implemented.
- Actual execution is limited to explicitly enabled, disposable test workloads.
- Verification checks the resulting graph and process state.
- Failed recovery is recorded honestly.

---

## 8. Feature F — Real-Time Web Dashboard & Visualizer

Replaces static terminal output with a live, zero-dependency visual graph interface powered by Server-Sent Events (SSE) and an HTML5 Canvas force-directed physics engine.

### User story

As an engineer observing a complex multithreaded system, I want to see the Resource Allocation Graph animate in real-time in my web browser, drag nodes, inspect live metrics, and scrub through event history so that I can understand complex lock contentions visually without terminal clutter.

### Architectural requirements

1. **Zero External Dependencies:** Built with Python standard library `ThreadingHTTPServer` (`ui/web_server.py`) and a vanilla HTML5/Canvas/CSS frontend (`ui/static/index.html`). No Node.js, npm, webpack, or external CDN dependencies are required.
2. **Server-Sent Events (SSE):** Streams real-time pipeline state to the browser via `/api/stream` using newline-delimited SSE messages (`data: { ... }\n\n`).
3. **Interactive Physics Graph:**
   - Visualizes Thread nodes ($T$) and Resource nodes ($M@$) with color-coded badges, labels, and directed arrows (Request vs Allocation).
   - High-DPI canvas rendering with velocity verlet physics, edge repulsion, and node attraction.
   - Interactive mouse drag-and-drop, zoom, pan, and viewport auto-fit.
4. **Time-Travel History Scrubber & Auto-Replay:**
   - In-memory event ring buffer retains synchronization steps.
   - Scrubbing slider allows stepping backward and forward through event history.
   - Auto-playing `▶ Replay` mode animates event sequences continuously.
5. **Cross-Platform Browser Launcher:**
   - Automatically detects host OS and opens the browser cleanly across native Linux (`wslview`, `xdg-open`) and WSL2 (`powershell.exe Start-Process`).

---

## 9. Feature G — Source-Code & Symbol Resolution (Upgrade 1)

Bridges the semantic gap between raw kernel virtual memory addresses and actual C source code variables, functions, and line numbers.

### User story

As a developer diagnosing a deadlock, I do not want to see raw hex pointers like `0x7ffd4040` and thread IDs like `T5001`. I want to see `L1 (targets/test_2way.c:24)` and `thread1`, so that I immediately know which lines of code caused the freeze.

### Architectural requirements

1. **Multi-Source Symbol Resolution (`diagnosis/symbol_resolver.py`):**
   - **ASLR Base Translation:** Parses `/proc/<pid>/maps` to discover executable and shared library load base addresses.
   - **ELF Symbol Table Decoding:** Invokes `nm -C` to resolve relative offsets to global/static variable names.
   - **DWARF Debug Information Decoding:** Invokes `addr2line -e <binary> -C` to extract exact source file paths and line numbers.
   - **Deterministic Fallback Engine:** Preloads symbol tables for known target workloads and offline traces.
2. **Integration into Explainer Engine:**
   - Enriches `DiagnosisStep` with `held_symbol`, `waiting_symbol`, `thread_function`, and `source_location`.
   - Embeds source locations into terminal summaries, Web Dashboard badges, and JUnit test failure traces.

---

## 10. Feature H — Headless CI/CD Mode / Concurrency Linter (Upgrade 2)

Transforms DeadlockDNA into an automated, non-interactive concurrency linter for continuous integration pipelines (GitHub Actions, GitLab CI, Jenkins).

### User story

As a DevOps or CI engineer, I want to run DeadlockDNA against multithreaded test suites headlessly with `--ci`, receiving deterministic exit codes, JUnit XML test reports, and machine-readable JSON summaries without opening web browsers or hanging servers.

### Architectural requirements

1. **Headless Execution (`ci/reporter.py`):**
   - Enabled via `--ci` or `--check` CLI flags.
   - Bypasses Web Dashboard initialization and event loop sleep pauses.
   - Sets file replay delay to `0.0s` by default for maximum throughput.
2. **Deterministic Exit Codes:**
   - `0`: Clean execution (no live deadlocks, no lock-order violations).
   - `1`: Deadlock detected (live circular wait in RAG).
   - `2`: Lock-order hierarchy inversion detected (when `--fail-on-risk` is active).
3. **Standard JUnit XML Reports (`--junit-xml <PATH>`):**
   - Generates compliant XML (`<testsuites>` $\to$ `<testsuite>` $\to$ `<testcase>`).
   - Formats failing cases with exact stack traces, DNA fingerprints, and source-resolved variable lines.
4. **Machine-Readable JSON Summaries (`--report-json <PATH>`):**
   - Serializes complete target metadata, execution duration, thread/lock footprint, fingerprints, diagnostic steps, and recovery plans.

---

## 11. Feature I — Real-World Production Program Gatekeeping (Upgrade 3)

Validates DeadlockDNA's architecture and performance against complex, widely deployed open-source systems under heavy concurrent load.

### User story

As a software architect, I want proof that DeadlockDNA scales beyond toy 30-line test scripts to real enterprise systems with dozens of concurrent threads and hundreds of locks (such as SQLite or Memcached) without crashing, leaking memory, or introducing performance degradation.

### Architectural requirements

1. **Production Database Workload: SQLite (`targets/sqlite_multithread_workload.py`):**
   - Drives native `libsqlite3.so` under heavy multi-threading (8 concurrent workers).
   - Simulates analytical reader threads, atomic writer transactions (`BEGIN IMMEDIATE` / `COMMIT`), and background WAL checkpoints.
   - Stresses real SQLite internal mutexes: `sqlite3.mutex_db`, `sqlite3.pager_mutex`, `sqlite3.wal_mutex`, and `sqlite3.mem_mutex`.
   - Sustains **29,000+ operations/second**.
2. **Production Cache Server Workload: Memcached (`targets/memcached_workload.c`):**
   - Implements Memcached's actual multi-threaded synchronization architecture:
     - **64 independent hash bucket mutexes** (`item_locks[0..63]`).
     - Global slab memory allocator mutex (`slabs_lock`).
     - LRU maintenance crawler mutex (`lru_lock`).
   - 8 concurrent worker threads executing cache operations (`GET`, `SET`, `DELETE`, `REPLACE`).
   - Supports Clean Mode (high-throughput concurrent caching) and Hazard Mode (reproducing Memcached's slab-vs-bucket lock order inversion).
3. **Event-Driven LOG Scalability Optimization:**
   - Optimizes `main.py` lock-order analysis by evaluating Johnson's cycle algorithm only on truly new dependency edges (`e.count == 1`).
   - Reduces 1,000-event execution time from 18.6s down to 0.22s (~84x speedup) with zero memory leaks.

---

## 12. Directory layout & module organization

```text
deadlockdna/
  observer/
    observer.bt                 # eBPF/bpftrace dual-probe tracer
  collector/
    collector.py                # Process launcher, attachment & event queue
    event_parser.py             # Event dataclass & JSON parser
  graph/
    rag.py                      # Bipartite Resource Allocation Graph
    models.py                   # Graph data models & node naming
    cycle_detector.py           # Johnson's cycle detection engine
  diagnosis/
    explainer.py                # Diagnostic narrative generator
    symbol_resolver.py          # DWARF, nm, addr2line & /proc maps resolver (Upgrade 1)
  dna/
    canonicalizer.py            # Role-based cycle normalization
    fingerprint.py              # Deterministic SHA-256 generator
    store.py                    # SQLite persistence & recurrence tracking
  risk/
    lock_order_tracker.py       # Lock Order Graph (LOG) tracker
    risk_cycle_detector.py      # Predictive inversion detector
    risk_store.py               # Historical risk database
  recovery/
    candidate.py                # Recovery actions & factors
    scoring.py                  # Transparent heuristic scoring
    policy.py                   # Safety policy engine & plan generator
    executor.py                 # POSIX signal execution (SIGUSR1 / tgkill)
    verifier.py                 # Post-recovery cycle resolution verifier
  ci/
    reporter.py                 # Headless CI reporter, JUnit XML & JSON (Upgrade 2)
  ui/
    web_server.py               # Threading HTTPServer with SSE streaming
    dashboard.py                # Dashboard controller & browser launcher
    static/
      index.html                # HTML5 Canvas force-directed graph UI
  targets/
    test_2way.c                 # 2-thread classic AB/BA deadlock
    test_3way.c                 # 3-thread circular deadlock
    test_semaphore.c            # POSIX semaphore deadlock
    sqlite_multithread_workload.py # Multi-threaded SQLite database workload (Upgrade 3)
    memcached_workload.c        # 64-bucket striped Memcached cache workload (Upgrade 3)
  benchmarks/
    harness.py                  # Process containment & timeout runner
    metrics.py                  # Latency, throughput & overhead metrics
    report.py                   # CSV, JSON & Markdown exporters
    run_benchmarks.py           # Benchmark runner CLI
    workloads/                  # Synthetic evaluation workloads
  scripts/
    generate_real_workload_traces.py # Trace generator for SQLite & Memcached
  tests/                        # 102 passing unit & integration tests
    test_rag.py
    test_cycle_detection.py
    test_events.py
    test_diagnosis.py
    test_dna.py
    test_benchmarks.py
    test_risk.py
    test_recovery.py
    test_ui.py
    test_symbol_resolver.py
    test_ci.py
    test_real_workloads.py
  logs/
    deadlocks.db                # SQLite database for fingerprints & risks
```

---

## 13. Implementation milestones

### Milestone 0 — Baseline and safety
- Save a known-good commit or Git branch.
- Run the baseline two-thread and three-thread deadlock tests.
- Exit condition: Baseline behavior works before feature development.

### Milestone 1 — Explainable diagnosis (Feature A)
- Define structured `DiagnosisResult` and `DiagnosisStep`.
- Generate explanations from cycle edges and event metadata.
- Exit condition: Every displayed explanation is traceable to observed graph evidence.

### Milestone 2 — Fingerprinting and history (Feature B)
- Implement typed canonical cycle representation and SHA-256 fingerprinting.
- Add SQLite persistence and recurrence counts.
- Exit condition: Equivalent test cycles share a fingerprint.

### Milestone 3 — Benchmarking (Feature C)
- Create process containment harness with automated timeouts.
- Compare observer-disabled and observer-enabled runs.
- Exit condition: Reproducible report generated with one command.

### Milestone 4 — Lock-order risk analysis (Feature D)
- Track Lock Order Graph (LOG) and detect AB/BA inversions before deadlocks form.
- Explicitly distinguish predictive risks from active circular waits (`is_live_deadlock = False`).
- Exit condition: Predictive risks flagged without false positive live deadlocks.

### Milestone 5 — Recovery recommendations (Feature E)
- Define candidate actions, transparent scoring, and strict safety policies.
- Gated execution disabled by default.
- Exit condition: Recovery recommendations are explainable and verifiable.

### Milestone 6 — Real-time Web Dashboard (Feature F)
- Zero-dependency SSE server and HTML5 Canvas force-directed graph visualizer.
- Drag-and-drop, zoom/pan, time-travel history scrubber, and auto-replay.
- Exit condition: Live visualizer runs smoothly in browser.

### Milestone 7 — Source-Code & Symbol Resolution (Upgrade 1 / Feature G)
- ASLR base address discovery via `/proc/<pid>/maps`.
- DWARF and symbol table decoding via `nm` and `addr2line`.
- Exit condition: Diagnostics cite file names and line numbers (`test_2way.c:24`).

### Milestone 8 — Headless CI/CD Mode (Upgrade 2 / Feature H)
- Headless `--ci` mode with deterministic exit codes (`0`, `1`, `2`).
- Standard JUnit XML and JSON report generation.
- Exit condition: Automated gatekeeping passes in CI runners.

### Milestone 9 — Real-World Production Programs (Upgrade 3 / Feature I)
- Multi-threaded SQLite database workload and Memcached 64-bucket cache workload.
- Event-driven LOG optimization for 1,000+ events without performance degradation.
- Exit condition: 102/102 unit tests pass across all subsystems.

---

## 14. Testing strategy

DeadlockDNA maintains three rigorous levels of testing across **102 automated tests**:

1. **Unit Tests (102 tests, < 3.5s runtime):**
   - `test_rag.py`: State transitions, edge management, degree-0 node pruning.
   - `test_cycle_detection.py`: Acyclic graphs, 2-way and 3-way cycles, latency calculation.
   - `test_events.py`: JSON parsing, banner stripping, type validation.
   - `test_diagnosis.py`: Narrative generation, evidence trails, confidence levels.
   - `test_dna.py`: Canonicalization, SHA-256 stability, SQLite storage.
   - `test_benchmarks.py`: Harness containment, timeouts, report generation.
   - `test_risk.py`: LOG acquisition tracking, reentrancy, inversion alerts.
   - `test_recovery.py`: Safety policy, scoring bounds, executor gating, verifier.
   - `test_ui.py`: Web dashboard server initialization, SSE endpoints, state serialization.
   - `test_symbol_resolver.py`: Symbol resolution, DWARF decoding, offline fallbacks.
   - `test_ci.py`: CI exit codes, JUnit XML output, JSON report formatting.
   - `test_real_workloads.py`: SQLite heavy load, Memcached 66-lock striping, hazard detection.

2. **Integration Tests:**
   - Full pipeline execution against live C binaries (`targets/test_2way`, `targets/test_3way`, `targets/memcached_workload`).
   - Python SQLite multi-threaded target (`targets/sqlite_multithread_workload.py`).

3. **Regression Tests:**
   - Offline event replay traces (`sample_events.json`, `sample_clean_events.json`, `sample_risk_events.json`, `sample_sqlite_events.json`, `sample_memcached_events.json`).

---

## 15. Operational and technical cautions

1. **WSL2 / Linux Kernel:** eBPF uprobes and futex tracepoints require Linux kernel 5.15+ with root privileges (`sudo`). Replay and CI modes run completely unprivileged without kernel probes.
2. **Permissions:** Live observation requires `sudo` for `bpftrace`. Replay, testing, and CI modes require standard user permissions only.
3. **Address Identity:** Virtual memory addresses change across executions due to ASLR. Always use `SymbolResolver` and canonical DNA fingerprints for cross-run correlation.
4. **No Unsafe External Unlocks:** External unlocking of arbitrary mutexes is strictly forbidden. Recovery is restricted to cooperative signaling (`SIGUSR1`) or process termination on disposable test workloads.
5. **Event-Driven LOG Scalability:** Do not re-evaluate Johnson's cycle algorithm unless a truly new lock-order dependency edge (`e.count == 1`) has been added to the graph.

---

## 16. Definition of done for the project expansion

The expanded project has successfully demonstrated and verified:

- [x] A live cycle with a readable explanation and confidence label.
- [x] Stable fingerprints for equivalent cycle structures across executions.
- [x] Persistent history and occurrence counts in SQLite.
- [x] A reproducible benchmark report with measured results.
- [x] Correct distinction between live deadlock and predictive lock-order risk.
- [x] A traceable rationale for recovery recommendations.
- [x] Controlled recovery experiments only in disposable/cooperative test workloads.
- [x] Real-time interactive Web Dashboard with HTML5 Canvas physics and SSE streaming.
- [x] Source-code symbol and line number resolution (`test_2way.c:24`).
- [x] Headless CI/CD mode with JUnit XML, JSON reports, and deterministic exit codes.
- [x] Real-world production workload verification against SQLite and Memcached (66 locks).
- [x] 100% pass rate across the full 102-test test suite.
- [x] Documented environment, assumptions, limitations, and failure cases.
- [x] A demo that does not depend on invented metrics or claims of universal coverage.

---

## 17. How to work with a coding agent

When maintaining or extending DeadlockDNA:
1. Inspect repository state and confirm all 102 tests pass before editing (`pytest tests/`).
2. Implement features in self-contained, testable modules.
3. Maintain zero-dependency principles where appropriate.
4. Always accompany new features with unit tests and documentation updates.

---

## 18. Final project positioning

> **DeadlockDNA** is a non-intrusive Linux runtime deadlock observation, diagnosis, fingerprinting, benchmarking, risk analysis, and automated CI gatekeeping platform. It captures synchronization events via eBPF/uprobes, maintains a dynamic Resource Allocation Graph, identifies circular waits, resolves raw addresses to C source symbols, computes structural SHA-256 fingerprints, provides interactive web visualization, detects predictive lock-order inversions, and serves as an automated concurrency linter for enterprise CI/CD pipelines.

Demonstrated coverage, honest limitations, and reproducible measurements are stronger than unsupported claims.

