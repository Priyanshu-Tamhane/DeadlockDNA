# DeadlockDNA Architecture & Design

DeadlockDNA is an out-of-process, non-intrusive runtime deadlock detection engine for Linux multithreaded applications (C / POSIX threads).

```
+--------------------+        +---------------------+        +-------------------------+
| Target Application | -----> | bpftrace Observer   | -----> | Collector & Parser      |
| (pthreads, mutex,  |        | (futex tracepoints, |        | (collector.py,          |
|  POSIX semaphores) |        |  glibc uprobes)     |        |  event_parser.py)       |
+--------------------+        +---------------------+        +-------------------------+
                                                                          |
                                                                          v
+--------------------+        +---------------------+        +-------------------------+
| Terminal Dashboard | <----- | Cycle Detector      | <----- | Resource Allocation     |
| (Rich live UI)     |        | (Johnson's simple   |        | Graph (RAG) (rag.py)    |
|                    |        |  cycle algorithm)   |        |                         |
+--------------------+        +---------------------+        +-------------------------+
```

## Core Components

### 1. eBPF Observer (`observer/observer.bt`)
- **Fast-path tracking**: Uncontended mutexes and semaphores are acquired directly in user space without entering the kernel. DeadlockDNA places user-space probes (`uprobe`/`uretprobe`) on `pthread_mutex_lock`, `pthread_mutex_unlock`, `sem_wait`, and `sem_post` in `libc.so.6`.
- **Contention tracking**: Thread blocking is detected via the kernel `tracepoint:syscalls:sys_enter_futex` with `FUTEX_WAIT`.
- **Streaming Output**: Events are streamed to stdout as single-line JSON records.

### 2. Event Collector & Parser (`collector/`)
- Normalizes raw JSON stream lines into strongly typed `Event` objects.
- Resiliently ignores bpftrace diagnostic/banner messages, comment headers, and malformed inputs.
- Supports 4 input modes:
  - `--exec <binary>`: Pre-attaches bpftrace, then launches target program to avoid startup race conditions.
  - `--pid <PID>`: Attaches live observer to an existing running process.
  - `--file <path>`: Replays recorded JSON events for offline analysis/demos.
  - `--stdin`: Reads live event stream piped directly from bpftrace.

### 3. Resource Allocation Graph (`graph/rag.py`)
- Directed bipartite graph `G = (V, E)` using NetworkX:
  - Nodes: Threads (`T<tid>`) and Resources (`M@<pid>:<hex_addr>`).
  - Request edge `T -> R`: Thread `T` is blocked waiting for resource `R`.
  - Allocation edge `R -> T`: Resource `R` is held by thread `T`.
- Dynamically prunes isolated nodes to prevent graph bloating during long execution runs.

### 4. Cycle Detector (`graph/cycle_detector.py`)
- Executes Johnson's algorithm (`networkx.simple_cycles`) over the directed RAG.
- A directed cycle represents a circular wait condition (Coffman condition #4), proving a deadlock.
- Calculates precise detection latency in microseconds (`latency_us`), synchronizing against kernel monotonic timestamps in live tracing mode and algorithmic execution time in replay mode.

### 5. Terminal Dashboard (`ui/dashboard.py`)
- Built with Python `rich` library.
- Displays target metadata, recent live event log, live RAG edge state, and visual deadlock cycle reporting.
