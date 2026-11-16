# DeadlockDNA — Makefile
# Run from /home/priyanshu/deadlockdna

CC     = gcc
CFLAGS = -Wall -Wextra -pthread -O0 -g

.PHONY: all build test benchmark clean help

all: build

## Build all target programs and benchmark workloads
build:
	$(CC) $(CFLAGS) targets/test_2way.c     -o targets/test_2way
	$(CC) $(CFLAGS) targets/test_3way.c     -o targets/test_3way
	$(CC) $(CFLAGS) targets/test_semaphore.c -o targets/test_semaphore
	@mkdir -p benchmarks/workloads
	$(CC) $(CFLAGS) benchmarks/workloads/workload_no_lock.c      -o benchmarks/workloads/workload_no_lock
	$(CC) $(CFLAGS) benchmarks/workloads/workload_single_mutex.c  -o benchmarks/workloads/workload_single_mutex
	$(CC) $(CFLAGS) benchmarks/workloads/workload_contention.c    -o benchmarks/workloads/workload_contention
	$(CC) $(CFLAGS) benchmarks/workloads/workload_stress.c        -o benchmarks/workloads/workload_stress
	@echo ""
	@echo "Built targets and benchmark workloads successfully."

## Run unit tests (no root, no eBPF needed)
test:
	python3 -m pytest tests/ -v

## Run benchmark and evaluation suite (generates CSV, JSON, Markdown reports)
benchmark:
	python3 benchmarks/run_benchmarks.py --runs 3

## Install Python dependencies
install:
	pip install -r requirements.txt

## Check eBPF / bpftrace availability
check-ebpf:
	@echo "bpftrace version:"
	@bpftrace --version 2>/dev/null || echo "  bpftrace not found — install: sudo apt install bpftrace"
	@echo ""
	@echo "Available futex tracepoints:"
	@sudo bpftrace -l 'tracepoint:syscalls:*futex*' 2>/dev/null || echo "  (need sudo)"

clean:
	rm -f targets/test_2way targets/test_3way targets/test_semaphore
	rm -f benchmarks/workloads/workload_no_lock benchmarks/workloads/workload_single_mutex benchmarks/workloads/workload_contention benchmarks/workloads/workload_stress
	rm -rf benchmarks/results
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null; true
	find . -name '*.pyc'      -delete 2>/dev/null; true

help:
	@echo "DeadlockDNA — Available targets:"
	@echo "  make build       — compile all target C programs & benchmark workloads"
	@echo "  make test        — run Python unit tests"
	@echo "  make benchmark   — run automated benchmark suite and generate reports"
	@echo "  make install     — pip install requirements.txt"
	@echo "  make check-ebpf  — verify bpftrace + futex tracepoints"
	@echo "  make clean       — remove binaries and caches"
	@echo ""
	@echo "Run the full pipeline:"
	@echo "  sudo python3 main.py --exec ./targets/test_2way"
	@echo "  sudo python3 main.py --pid <PID>"
	@echo "  python3 main.py --file tests/sample_events.json"
