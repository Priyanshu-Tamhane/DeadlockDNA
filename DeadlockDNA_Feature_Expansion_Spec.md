# DeadlockDNA — Feature Expansion Specification
**Version:** 1.0  
**Purpose:** Implementation guide for extending the existing DeadlockDNA project beyond its current runtime observation, Resource Allocation Graph (RAG), cycle detection, and terminal dashboard.

---

## 1. Project summary

DeadlockDNA is a Linux runtime deadlock-observation and diagnosis prototype. Its current pipeline observes synchronization-related events, converts them into a graph of thread/resource dependencies, detects cycles, and displays alerts.

The next development phase should add four capabilities:

1. **Explainable diagnosis** — turn a detected cycle into a readable, evidence-backed explanation.
2. **Deadlock DNA fingerprinting** — normalize cycle structure and generate a stable SHA-256 fingerprint.
3. **Benchmarking and evaluation** — run reproducible test cases and report detection quality, latency, event loss, and overhead.
4. **Lock-order risk analysis** — learn lock acquisition order and warn about potential circular-wait risks across observations.
5. **Cost-aware recovery recommendations** — rank safe, explicit recovery options and validate outcomes in controlled experiments.

**Out of scope for this milestone:** monitoring arbitrary running applications. Keep the existing tested target-launch / selected-PID workflows as they are. Do not claim universal application support.

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

## 8. Suggested directory layout

Adapt this to the repository rather than forcing a large refactor.

```text
deadlockdna/
  observer/
  collector/
  graph/
  ui/
  diagnosis/
    explainer.py
  dna/
    canonicalizer.py
    fingerprint.py
    store.py
  risk/
    lock_order_tracker.py
    risk_cycle_detector.py
    risk_store.py
  benchmarks/
    workloads/
    run_benchmarks.py
    results/
  recovery/
    candidate.py
    scoring.py
    policy.py
    executor.py
    verifier.py
  tests/
    unit/
    integration/
  docs/
    FEATURE_EXPANSION_SPEC.md
```

---

## 9. Recommended implementation order

Build in small, testable steps. Keep the current working pipeline green after each step.

### Milestone 0 — Baseline and safety

- Save a known-good commit or Git branch.
- Run the current two-thread and three-thread deadlock tests.
- Save baseline logs and record the exact environment.
- Add/confirm tests for the current RAG and cycle detector.
- Document known observer limitations.

**Exit condition:** Existing behavior still works before feature development begins.

### Milestone 1 — Explainable diagnosis

- Define a structured diagnosis result.
- Generate explanations from cycle edges and event metadata.
- Add completeness/confidence labels.
- Integrate with the dashboard.
- Add two-thread, three-thread, and incomplete-evidence tests.

**Exit condition:** Every displayed explanation is traceable to observed graph evidence.

### Milestone 2 — Fingerprinting and history

- Implement typed canonical cycle representation.
- Normalize rotation and runtime identifiers.
- Generate SHA-256.
- Add SQLite persistence and occurrence counts.
- Add unit tests for equivalent and different patterns.

**Exit condition:** Equivalent test cycles share a fingerprint, and history is persistent.

### Milestone 3 — Benchmarking

- Create a safe benchmark harness.
- Include deadlock and non-deadlock workloads.
- Add timeouts and cleanup.
- Record actual raw data and generate a summary report.
- Compare observer-disabled and observer-enabled runs.

**Exit condition:** A reproducible report can be generated with one documented command.

### Milestone 4 — Lock-order risk analysis

- Track held locks per thread where events permit.
- Record observed lock-order edges.
- Find cycles in the lock-order graph.
- Preserve evidence for each edge.
- Distinguish risk warnings from live deadlock alerts.

**Exit condition:** The safe and risky test suites produce the expected outcomes with evidence.

### Milestone 5 — Recovery recommendations

- Define eligible candidates and policies.
- Add transparent scoring and reasons.
- Keep execution disabled by default.
- Test cooperative recovery in disposable programs.
- Verify whether the cycle actually resolved.

**Exit condition:** Recommendations are explainable, unsafe actions are blocked, and experimental outcomes are measured.

---

## 10. Testing strategy

Use three levels of testing.

### Unit tests

Test pure logic without eBPF or a running deadlock:

- Canonicalization and fingerprint generation.
- Cycle rotation normalization.
- Diagnosis formatting and evidence completeness.
- Lock-order edge insertion/removal.
- Risk-cycle detection.
- Recovery scoring and eligibility policies.
- Database insert/update/transaction behavior.

### Integration tests

Run the actual observer, collector, RAG, detector, and dashboard/backend together against controlled workloads:

- Two-thread deadlock.
- Three-thread deadlock.
- Normal mutex contention without a deadlock.
- No-lock workload.
- Thread/process exit while being observed.
- Repeated lock/unlock operations.
- Missing or malformed event records where safely simulatable.

### Regression tests

Every feature change should preserve the existing behavior. Keep representative event fixtures so parsing, graph updates, and cycle detection can be tested without relying on timing-sensitive eBPF execution for every unit test.

---

## 11. Operational and technical cautions

1. **WSL2:** The current WSL2 environment may support the current setup but can differ from native Linux in kernel capabilities and tracing behavior. Record the exact kernel and tool versions. If a feature cannot be validated in WSL2, use a compatible native Linux VM or machine for that test.
2. **Permissions:** eBPF/bpftrace often requires elevated privileges and kernel support. Do not run more privileged than necessary.
3. **Missed events:** Lost events can invalidate lock ownership and graph state. Surface gaps; do not treat an incomplete graph as definitive.
4. **Clock domains:** Only compare timestamps after confirming their clock source and conversion.
5. **TID/PID lifecycle:** TIDs can exit and numeric identifiers can be reused. Remove stale graph state and associate events with a process lifetime/session.
6. **Address identity:** A mutex pointer is useful within an observation but is not automatically a stable logical identity across executions.
7. **Cycle detection complexity:** Enumerating all simple cycles can become expensive on larger graphs. Start with the existing implementation and measure; optimize only if benchmarks show a problem.
8. **No universal claim:** Probes for glibc pthread mutexes do not cover every language runtime, synchronization primitive, or application.
9. **No unsafe unlock:** Do not directly unlock arbitrary mutexes from the monitoring process.
10. **No unsupported AI claims:** A heuristic is a heuristic. Only call a feature machine learning/AI if a model is actually trained or used and evaluated.

---

## 12. Definition of done for the project expansion

The expanded project should be able to demonstrate:

- [ ] A live cycle with a readable explanation and confidence label.
- [ ] Stable fingerprints for equivalent cycle structures.
- [ ] Persistent history and occurrence counts.
- [ ] A reproducible benchmark report with measured results.
- [ ] Correct distinction between live deadlock and lock-order risk.
- [ ] A traceable rationale for recovery recommendations.
- [ ] Controlled recovery experiments only in disposable/cooperative test workloads.
- [ ] Unit, integration, and regression tests.
- [ ] Documented environment, assumptions, limitations, and failure cases.
- [ ] A demo that does not depend on invented metrics or claims of universal coverage.

## 13. How to work with a coding agent

Use this spec as the overall project contract, but do **not** ask an agent to implement everything in one pass.

For each milestone, give it these instructions:

1. Inspect the repository and summarize the existing interfaces before editing.
2. Identify the smallest set of files that need changes.
3. Preserve the current observer/collector/RAG/cycle-detection behavior.
4. Implement one milestone only.
5. Add tests and run the relevant existing tests.
6. Report the exact files changed, commands run, test results, known failures, and assumptions.
7. Do not claim a test passed unless it was actually executed.
8. Stop and ask before making a breaking architecture change or introducing a new external dependency.

**First coding-agent task:** implement Feature A (explainable diagnosis) only. Once it passes tests and works with the current dashboard, move to DNA fingerprinting.

---

## 14. Final project positioning

A defensible project description is:

> DeadlockDNA is a Linux runtime prototype that observes supported synchronization events, constructs a thread-resource dependency graph, detects observed circular-wait candidates, explains their dependency chains, fingerprints recurring cycle structures, and evaluates detection quality. It also explores lock-order risk analysis and safe, cooperative recovery recommendations. Its coverage depends on the synchronization primitives and events the observer can reliably capture.

Do not claim that it detects every deadlock in every application, predicts all deadlocks, or safely repairs arbitrary mutex deadlocks. Demonstrated coverage, honest limitations, and reproducible measurements are stronger than unsupported claims.
