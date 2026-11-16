"""
collector.py — DeadlockDNA Event Collector (collector/)

Runs the bpftrace observer as a subprocess and yields Event objects.
Supports 4 modes: --pid, --exec, --file, --stdin.

Does NOT perform deadlock detection — only collects and normalizes events.
"""

import argparse
import logging
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Generator, Optional

_HERE = Path(__file__).parent
_OBSERVER_BT = _HERE.parent / "observer" / "observer.bt"

sys.path.insert(0, str(_HERE))
from event_parser import Event, parse_line

logger = logging.getLogger(__name__)


class CollectorError(Exception):
    pass


# Standard library paths for pthread / libc on Ubuntu/Debian x86_64
_LIBPTHREAD = "/lib/x86_64-linux-gnu/libpthread.so.0"
_LIBC       = "/lib/x86_64-linux-gnu/libc.so.6"


def _build_comm_script(prog_name: str) -> str:
    """
    Build an inline bpftrace script that filters by comm name (process basename).
    Used in --exec mode so bpftrace can be started BEFORE the target process,
    avoiding the race where the target deadlocks before bpftrace JIT-compiles.

    Includes futex tracepoints (for LOCK_REQUEST/blocking waits), uprobes on
    pthread_mutex_lock/unlock, and uprobes on sem_wait/sem_post (for POSIX semaphores).
    Truncates prog_name to 15 chars to match Linux TASK_COMM_LEN.
    """
    p = prog_name[:15]
    lp = _LIBPTHREAD
    lc = _LIBC
    lines = [
        f'BEGIN {{ printf("# deadlockdna observer started — watching comm={p}\\n"); }}',
        f'tracepoint:syscalls:sys_enter_futex /comm == "{p}" && ((args->op & 0x7f) == 0)/ {{',
        '    @pending[tid] = (uint64)args->uaddr;',
        r'    printf("{\"timestamp_ns\":%llu,\"pid\":%d,\"tid\":%d,\"resource\":\"0x%llx\",\"operation\":\"LOCK_REQUEST\"}\n", nsecs, pid, tid, (uint64)args->uaddr);',
        '}',
        f'tracepoint:syscalls:sys_exit_futex /comm == "{p}" && @pending[tid] != 0/ {{',
        '    delete(@pending[tid]);',
        '}',
        f'uprobe:{lp}:pthread_mutex_lock, uprobe:{lc}:pthread_mutex_lock /comm == "{p}"/ {{',
        '    @mu_arg[tid] = (uint64)arg0;',
        '}',
        f'uretprobe:{lp}:pthread_mutex_lock, uretprobe:{lc}:pthread_mutex_lock /comm == "{p}" && @mu_arg[tid] != 0 && retval == 0/ {{',
        r'    printf("{\"timestamp_ns\":%llu,\"pid\":%d,\"tid\":%d,\"resource\":\"0x%llx\",\"operation\":\"LOCK_ACQUIRED\"}\n", nsecs, pid, tid, @mu_arg[tid]);',
        '    delete(@mu_arg[tid]);',
        '}',
        f'uretprobe:{lp}:pthread_mutex_lock, uretprobe:{lc}:pthread_mutex_lock /comm == "{p}" && @mu_arg[tid] != 0 && retval != 0/ {{',
        '    delete(@mu_arg[tid]);',
        '}',
        f'uprobe:{lp}:pthread_mutex_unlock, uprobe:{lc}:pthread_mutex_unlock /comm == "{p}"/ {{',
        r'    printf("{\"timestamp_ns\":%llu,\"pid\":%d,\"tid\":%d,\"resource\":\"0x%llx\",\"operation\":\"LOCK_RELEASED\"}\n", nsecs, pid, tid, (uint64)arg0);',
        '}',
        f'uprobe:{lc}:sem_wait /comm == "{p}"/ {{',
        '    @sem_arg[tid] = (uint64)arg0;',
        '}',
        f'uretprobe:{lc}:sem_wait /comm == "{p}" && @sem_arg[tid] != 0 && retval == 0/ {{',
        r'    printf("{\"timestamp_ns\":%llu,\"pid\":%d,\"tid\":%d,\"resource\":\"0x%llx\",\"operation\":\"LOCK_ACQUIRED\"}\n", nsecs, pid, tid, @sem_arg[tid]);',
        '    delete(@sem_arg[tid]);',
        '}',
        f'uretprobe:{lc}:sem_wait /comm == "{p}" && @sem_arg[tid] != 0 && retval != 0/ {{',
        '    delete(@sem_arg[tid]);',
        '}',
        f'uprobe:{lc}:sem_post /comm == "{p}"/ {{',
        r'    printf("{\"timestamp_ns\":%llu,\"pid\":%d,\"tid\":%d,\"resource\":\"0x%llx\",\"operation\":\"LOCK_RELEASED\"}\n", nsecs, pid, tid, (uint64)arg0);',
        '}',
        r'END { printf("# deadlockdna observer stopped.\n"); clear(@pending); clear(@mu_arg); clear(@sem_arg); }',
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Collection modes
# ---------------------------------------------------------------------------

def collect_from_pid(pid: int) -> Generator[Event, None, None]:
    """Attach bpftrace observer to a running process. Requires root."""
    if not _OBSERVER_BT.exists():
        raise CollectorError(f"Observer not found: {_OBSERVER_BT}")

    cmd = ["bpftrace", "-B", "line", str(_OBSERVER_BT), str(pid)]
    logger.info("bpftrace: %s", " ".join(cmd))

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
    except FileNotFoundError:
        raise CollectorError("bpftrace not found. Install: sudo apt install bpftrace")
    except PermissionError:
        raise CollectorError("Permission denied. Run with sudo.")

    # Drain stderr in background to prevent pipe from blocking
    threading.Thread(target=lambda: proc.stderr.read(), daemon=True).start()

    logger.info("bpftrace running (pid=%d), watching target pid=%d", proc.pid, pid)

    event_queue: queue.Queue = queue.Queue()

    def _reader():
        try:
            for line in proc.stdout:
                ev = parse_line(line)
                if ev is not None:
                    event_queue.put(ev)
        except Exception as exc:
            logger.error("reader thread error: %s", exc)
        finally:
            event_queue.put(None)

    threading.Thread(target=_reader, daemon=True).start()

    try:
        while True:
            try:
                ev = event_queue.get(timeout=0.2)
                if ev is None:
                    break
                yield ev
            except queue.Empty:
                if proc.poll() is not None:
                    while not event_queue.empty():
                        ev = event_queue.get_nowait()
                        if ev is not None:
                            yield ev
                    break
    except KeyboardInterrupt:
        pass
    finally:
        _kill(proc)


def collect_from_exec(program: str, args: Optional[list] = None) -> Generator[Event, None, None]:
    """
    Launch a target program and observe it. Requires root.

    Key design: bpftrace is started FIRST using a comm-based filter, then we
    wait for its BEGIN signal before launching the target. This prevents the
    race condition where the target deadlocks before bpftrace finishes
    JIT-compiling its probes (which can take 1–3 seconds).
    """
    prog_name = Path(program).name
    bt_script = _build_comm_script(prog_name)

    cmd = ["bpftrace", "-B", "line", "-e", bt_script]
    logger.info("bpftrace (comm=%s): %s", prog_name, " ".join(cmd[:3]) + " -e <inline>")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
    except FileNotFoundError:
        raise CollectorError("bpftrace not found. Install: sudo apt install bpftrace")
    except PermissionError:
        raise CollectorError("Permission denied. Run with sudo.")

    # Drain stderr in background
    threading.Thread(target=lambda: proc.stderr.read(), daemon=True).start()

    event_queue: queue.Queue = queue.Queue()
    ready_event = threading.Event()

    def _reader():
        """Read bpftrace stdout, signal when BEGIN fires, then queue events."""
        try:
            for line in proc.stdout:
                if not ready_event.is_set() and "observer started" in line:
                    ready_event.set()
                    continue
                ev = parse_line(line)
                if ev is not None:
                    event_queue.put(ev)
        except Exception as exc:
            logger.error("reader thread error: %s", exc)
        finally:
            event_queue.put(None)  # sentinel — signals generator to stop

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    # Wait for bpftrace to be ready (max 8 seconds for slow kernels / WSL2)
    if not ready_event.wait(timeout=8.0):
        _kill(proc)
        raise CollectorError(
            "bpftrace did not start within 8 seconds.\n"
            "  → Check that futex tracepoints exist: sudo bpftrace -l 'tracepoint:syscalls:*futex*'\n"
            "  → If missing, run: wsl --update  (from Windows PowerShell)"
        )

    # bpftrace is now attached — launch the target
    target_cmd = [program] + (args or [])
    logger.info("launching target: %s", " ".join(target_cmd))
    try:
        target = subprocess.Popen(target_cmd,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        _kill(proc)
        raise CollectorError(f"program not found: {program}")

    logger.info("target launched with pid=%d", target.pid)

    # Yield events from the queue until bpftrace exits
    try:
        while True:
            try:
                ev = event_queue.get(timeout=0.2)
                if ev is None:   # sentinel from reader thread
                    break
                yield ev
            except queue.Empty:
                if proc.poll() is not None:
                    # Drain any remaining events
                    while not event_queue.empty():
                        ev = event_queue.get_nowait()
                        if ev is not None:
                            yield ev
                    break
    except KeyboardInterrupt:
        pass
    finally:
        _kill(proc)
        if target.poll() is None:
            target.terminate()
            try:
                target.wait(timeout=3)
            except subprocess.TimeoutExpired:
                target.kill()


def collect_from_file(filepath: str, delay: float = 0.5) -> Generator[Event, None, None]:
    """Replay events from a saved JSON file with a delay for visual demonstration. No root needed."""
    path = Path(filepath)
    if not path.exists():
        raise CollectorError(f"file not found: {filepath}")
    logger.info("replaying events from %s (delay=%.2fs)", filepath, delay)
    with open(path) as f:
        for line in f:
            ev = parse_line(line)
            if ev is not None:
                if delay > 0:
                    time.sleep(delay)
                yield ev


def collect_from_stdin() -> Generator[Event, None, None]:
    """Read JSON events from stdin."""
    logger.info("reading events from stdin")
    try:
        for line in sys.stdin:
            ev = parse_line(line)
            if ev is not None:
                yield ev
    except KeyboardInterrupt:
        pass


def _kill(proc: subprocess.Popen, timeout: float = 3.0) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="DeadlockDNA Collector")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pid",   type=int)
    mode.add_argument("--exec",  dest="exec_path")
    mode.add_argument("--file",  dest="file_path")
    mode.add_argument("--stdin", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, stream=sys.stderr,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    logs_dir = _HERE.parent / "logs"
    logs_dir.mkdir(exist_ok=True)

    print(f"\n{'TIME':<13} {'TID':<8} {'RESOURCE':<24} {'OPERATION'}")
    print("-" * 62)

    try:
        if args.pid:
            events = collect_from_pid(args.pid)
        elif args.exec_path:
            events = collect_from_exec(args.exec_path)
        elif args.file_path:
            events = collect_from_file(args.file_path)
        else:
            events = collect_from_stdin()

        from datetime import datetime
        for ev in events:
            ts = datetime.fromtimestamp(ev.timestamp_ns / 1e9).strftime("%H:%M:%S.%f")[:13]
            print(f"{ts:<13} {ev.tid:<8} {ev.resource:<24} {ev.operation.name}")

    except CollectorError as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[deadlockdna] collector stopped.")


if __name__ == "__main__":
    main()
