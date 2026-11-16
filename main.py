"""
main.py — DeadlockDNA Pipeline Entry Point

Complete detection pipeline run from project root:
  Target program → eBPF observer → Collector → RAG → Cycle Detector → Explainer → DNA → Risk → Recovery → Dashboard

Usage (from /home/priyanshu/deadlockdna):

  # Live: launch target + observe (requires root + bpftrace)
  sudo python3 main.py --exec ./targets/test_2way

  # Live: attach to running process
  sudo python3 main.py --pid 5000

  # Test: replay saved event file (no root needed)
  python3 main.py --file tests/sample_events.json

  # Pipe from bpftrace (-B line ensures unbuffered streaming)
  sudo bpftrace -B line observer/observer.bt 5000 | python3 main.py --stdin
"""

import argparse
import sys
import logging
import sys
import time
from pathlib import Path

# ------------------------------------------------------------------
# Ensure project root is on sys.path
# ------------------------------------------------------------------
_ROOT = Path(__file__).parent
sys.path.insert(0, str(_ROOT))

from collector.event_parser import Event, Operation
from collector.collector import (
    collect_from_pid, collect_from_exec,
    collect_from_file, collect_from_stdin,
    CollectorError,
)
from graph.models import DeadlockResult
from graph.rag import ResourceAllocationGraph
from graph.cycle_detector import CycleDetector
from diagnosis.explainer import DeadlockExplainer
from dna import DeadlockStore, fingerprint_cycle
from risk import LockOrderTracker, RiskCycleDetector, RiskStore, LockOrderRisk
from recovery import RecoveryPolicyEngine
from ui.dashboard import Dashboard


def _setup_logging(verbose: bool = False) -> None:
    logs_dir = _ROOT / "logs"
    logs_dir.mkdir(exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.FileHandler(logs_dir / "detector.log", mode="a")]
    if verbose:
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )


logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Pipeline
# ------------------------------------------------------------------

def run(collector, target_name: str, pid: int, is_disposable: bool = False) -> None:
    """
    Core pipeline:
      event → RAG.process_event → cycle_detector.detect → explainer.explain → dna.fingerprint → risk_tracker.process → recovery_engine.evaluate → dashboard.update
    """
    rag             = ResourceAllocationGraph()
    detector        = CycleDetector()
    explainer       = DeadlockExplainer()
    store           = DeadlockStore()
    risk_tracker    = LockOrderTracker(session_id=target_name)
    risk_detector   = RiskCycleDetector()
    risk_store      = RiskStore()
    recovery_engine = RecoveryPolicyEngine()
    dash            = Dashboard(target_name=target_name, pid=pid)

    deadlocks: list[DeadlockResult] = []
    active_risks: list[LockOrderRisk] = []
    notified  = False

    logger.info("pipeline started — target=%s pid=%d (disposable=%s)", target_name, pid, is_disposable)

    try:
        with dash.live_context():
            for event in collector:
                # Discover PID from first event (exec / stdin modes)
                if pid == 0 and event.pid:
                    pid = event.pid
                    dash.pid = pid

                # Step 1: update RAG
                rag.process_event(event)

                # Step 2: detect RAG cycles (live circular waits)
                new_dl = detector.detect(rag.get_graph(), event.timestamp_ns,
                                         operation=event.operation.name)

                if new_dl:
                    for dl in new_dl:
                        # Feature A: Generate explainable diagnosis
                        dl.diagnosis = explainer.explain(dl.cycle, rag, event.timestamp_ns)

                        # Feature B: Deadlock DNA Fingerprinting and SQLite history
                        try:
                            fp, canon = fingerprint_cycle(dl.cycle)
                            dl.fingerprint = fp
                            dl.canonical_pattern = canon.pattern
                            confidence = dl.diagnosis.confidence if dl.diagnosis else "complete"
                            count = store.record(
                                fingerprint=fp,
                                canonical_pattern=canon.pattern,
                                detected_at_ns=event.timestamp_ns,
                                pid=event.pid or pid,
                                tids=dl.threads,
                                resources=dl.resources,
                                confidence=confidence,
                            )
                            dl.occurrence_count = count
                        except Exception as e:
                            logger.warning("fingerprint recording error: %s", e)

                        # Feature E: Cost-aware recovery recommendations
                        try:
                            dl.recovery_plan = recovery_engine.evaluate_deadlock(
                                deadlock=dl,
                                pid=event.pid or pid,
                                is_disposable_workload=is_disposable,
                            )
                        except Exception as e:
                            logger.warning("recovery plan generation error: %s", e)

                    deadlocks = new_dl
                    if not notified:
                        logger.warning("DEADLOCK DETECTED — %d cycle(s)", len(new_dl))
                        notified = True
                elif notified:
                    deadlocks = []
                    notified  = False
                    logger.info("deadlock cycle resolved")

                # Step 3: Feature D - Lock-order tracking & predictive risk analysis
                new_edges = risk_tracker.process_event(event)
                for edge_ev in new_edges:
                    try:
                        risk_store.record_edge(edge_ev)
                    except Exception as e:
                        logger.debug("risk edge record error: %s", e)

                detected_risks = risk_detector.detect_risks(risk_tracker.graph)
                active_risks = detected_risks
                for rk in detected_risks:
                    try:
                        risk_store.record_risk(rk)
                    except Exception as e:
                        logger.debug("risk warning record error: %s", e)

                # Step 4: refresh dashboard with RAG, active deadlocks, and predictive risks
                dash.update(event, rag, deadlocks, risks=active_risks)

    except KeyboardInterrupt:
        logger.info("pipeline interrupted by user")
    except CollectorError:
        raise
    except Exception as exc:
        logger.error("pipeline error: %s", exc, exc_info=True)
        raise
    finally:
        store.close()
        risk_store.close()

    logger.info("pipeline stopped")


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(
        description="DeadlockDNA — Runtime Deadlock Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pid",   type=int,     metavar="PID",
                      help="attach to running process (root + bpftrace)")
    mode.add_argument("--exec",  dest="exec_p", metavar="PROGRAM",
                      help="launch program and observe (root + bpftrace)")
    mode.add_argument("--file",  dest="file_p", metavar="FILE",
                      help="replay saved event file (no root needed)")
    mode.add_argument("--stdin", action="store_true",
                      help="read JSON events from stdin")
    p.add_argument("--delay", type=float, default=0.5,
                      help="delay between events in seconds for file replay (default: 0.5s)")
    p.add_argument("--disposable", action="store_true",
                      help="indicate target is an isolated disposable test workload (enables test recovery options)")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    _setup_logging(args.verbose)

    try:
        if args.pid:
            print("[deadlockdna] WARNING: --pid mode attaches to a running process. Events before attachment are missed and the deadlock may have already occurred.", file=sys.stderr)
            name, pid, gen = f"pid-{args.pid}", args.pid, collect_from_pid(args.pid)

        elif args.exec_p:
            name, pid = Path(args.exec_p).name, 0
            gen = collect_from_exec(args.exec_p)

        elif args.file_p:
            name, pid = Path(args.file_p).name, 0
            gen = collect_from_file(args.file_p, delay=args.delay)

        else:
            name, pid = "stdin", 0
            gen = collect_from_stdin()

        run(gen, target_name=name, pid=pid, is_disposable=args.disposable)

    except CollectorError as e:
        print(f"\n[deadlockdna] ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[deadlockdna] stopped.")


if __name__ == "__main__":
    main()
