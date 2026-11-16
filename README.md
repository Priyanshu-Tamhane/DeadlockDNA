# DeadlockDNA

> Runtime deadlock detection for Linux multithreaded programs using eBPF.

Observes a running C+pthread process from outside (no instrumentation code in the target), builds a live Resource Allocation Graph (RAG), detects circular wait conditions in real-time, and displays results in a terminal dashboard.

---

## Directory Structure

```
deadlockdna/
├── main.py             ← Pipeline entry point
├── Makefile            ← Build, test, and check targets
├── requirements.txt    ← Python dependencies (networkx, rich, pytest)
│
├── targets/            ← C target programs that create real deadlocks
│   ├── test_2way.c     ← 2-thread mutex deadlock (T1<->T2)
│   ├── test_3way.c     ← 3-thread mutex deadlock (T1->T2->T3->T1)
│   └── test_semaphore.c← POSIX semaphore synchronization test
│
├── observer/           ← eBPF tracing script (bpftrace)
│   └── observer.bt     ← Captures futex and uprobe lock/unlock tracepoints
│
├── collector/          ← Event ingestion & parsing module
│   ├── collector.py    ← Streams raw eBPF JSON into typed Event objects
│   └── event_parser.py ← Parses and validates JSON event payloads
│
├── graph/              ← RAG Engine & Cycle Detection
│   ├── models.py       ← Event & DeadlockResult dataclasses
│   ├── rag.py          ← Resource Allocation Graph manager
│   └── cycle_detector.py← Cycle detection algorithm (NetworkX DFS)
│
├── diagnosis/          ← Explainable Deadlock Diagnosis (Feature A)
│   └── explainer.py    ← Analyzes RAG cycle edges and outputs human explanation
│
├── dna/                ← Deadlock DNA Fingerprinting (Feature B)
│   ├── canonicalizer.py← Normalizes cycle rotation & anonymous role labels
│   ├── fingerprint.py  ← SHA-256 structural cycle hashing
│   └── store.py        ← SQLite persistence & recurrence tracking
│
├── benchmarks/         ← Benchmark & Evaluation Suite (Feature C)
│   ├── workloads/      ← Synthetic C workloads (no-lock, contention, stress)
│   ├── harness.py      ← Isolated process execution with timeout containment
│   ├── metrics.py      ← Latency stats, detection rates, false positive tracking
│   ├── report.py       ← CSV, JSON summary, and Markdown report exporters
│   ├── run_benchmarks.py← CLI runner orchestrating evaluation runs
│   └── results/        ← Generated raw_runs.csv, summary.json, and report.md
│
├── ui/                 ← Terminal Dashboard Visualizer
│   └── dashboard.py    ← Rich TUI displaying events, RAG, and cycle status
│
├── tests/              ← Pytest suite (offline validation)
│   ├── test_rag.py
│   ├── test_cycle_detection.py
│   ├── test_events.py
│   ├── test_diagnosis.py
│   ├── test_dna.py
│   ├── test_benchmarks.py
│   ├── sample_events.json
│   └── sample_clean_events.json
│
├── docs/               ← Architectural design documentation
│   ├── architecture.md
│   └── event-format.md
└── logs/               ← Runtime application logs
```

---

## 🚀 Step-by-Step Instructions: Running the Project

> **IMPORTANT**: Make sure to execute all commands **inside your WSL2 Ubuntu terminal**!

### 1. Environment Setup

Open your WSL terminal and navigate to the project directory:

```bash
# Open WSL Ubuntu terminal
wsl -d Ubuntu

# Navigate to project root
cd /home/priyanshu/deadlockdna

# (Optional) Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

---

### 2. Build the C Target Programs

Compile the synthetic deadlock C applications (`test_2way`, `test_3way`, `test_semaphore`):

```bash
make build
```

---

### 3. Run the Unit Test Suite

Run the offline pytest suite (no root privileges or eBPF required):

```bash
make test
```
*or directly:*
```bash
python3 -m pytest tests/ -v
```

---

### 4. Run Offline Event Replay (No Root / No eBPF Required)

To test the entire pipeline (Collector → RAG → Cycle Detector → Rich Dashboard UI) without needing root privileges or eBPF tracepoints:

```bash
python3 main.py --file tests/sample_events.json
```

---

### 5. Run the Automated Benchmark & Evaluation Suite (Milestone 3)

To execute reproducible evaluation across safe non-deadlocking workloads, contention tests, and deadlock targets:

```bash
# Execute benchmark suite via Makefile
make benchmark

# Or run directly with custom parameters
python3 benchmarks/run_benchmarks.py --runs 5 --timeout 2.0
```

Results and reports are generated in `benchmarks/results/`:
- `raw_runs.csv`: Latency, runtime, and detection status per run
- `summary.json`: Aggregate metrics and system metadata
- `report.md`: Human-readable evaluation report

---

### 6. Run Live eBPF Deadlock Tracing (Full Mode)

To trace a live C process and detect deadlocks in real-time as they occur:

#### Step 5a. Install `bpftrace` (if not already installed)
```bash
sudo apt update
sudo apt install -y bpftrace
```

#### Step 5b. Verify eBPF kernel tracepoints
```bash
make check-ebpf
```

#### Step 5c. Launch and observe target program
```bash
sudo python3 main.py --exec ./targets/test_2way
```

---

### 6. Attach to an Existing Running Process PID

If a target process is already running in another terminal:

```bash
# Attach to PID (e.g., PID 5000)
sudo python3 main.py --pid 5000
```

---

### 7. Standalone Target Program Testing

You can also run target programs individually to see them deadlock:

```bash
./targets/test_2way       # 2-thread mutex deadlock
./targets/test_3way       # 3-thread mutex deadlock
./targets/test_semaphore  # semaphore deadlock
```

---

## 🛠️ CLI Reference Summary

| Command | Description | Root Required? |
|---|---|:---:|
| `make build` | Compiles target C programs & benchmark workloads | ❌ |
| `make test` | Runs offline Pytest unit test suite | ❌ |
| `make benchmark` | Runs automated evaluation suite & generates reports | ❌ |
| `python3 benchmarks/run_benchmarks.py` | Custom benchmark runner (`--runs`, `--timeout`) | ❌ |
| `python3 main.py --file <json>` | Replays recorded event log | ❌ |
| `sudo python3 main.py --exec <bin>` | Launches program + monitors live via eBPF | ✅ |
| `sudo python3 main.py --pid <PID>` | Attaches to running PID via eBPF | ✅ |
| `sudo bpftrace -B line observer/observer.bt <PID> \| python3 main.py --stdin` | Pipes raw bpftrace JSON directly | ✅ |

---

## 💡 Troubleshooting & WSL2 Notes

* **Terminal Environment**: Always ensure commands are executed inside the WSL environment (`wsl -d Ubuntu`) and that your Python virtual environment is activated (`source .venv/bin/activate`).
* **Sudo Environment**: If running `sudo python3 main.py`, ensure dependencies are installed globally or use `sudo .venv/bin/python3 main.py`.
* **eBPF Tracepoint Support**: WSL2 runs a genuine Linux kernel. If `futex` tracepoints are unavailable, run `wsl --update` from Windows PowerShell to update the WSL kernel.
