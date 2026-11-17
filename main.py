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
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Optional

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
from ci import CIReporter


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

def run(collector, target_name: str, pid: int, is_disposable: bool = False,
        port: int = 8080, open_browser: bool = True,
        ci_mode: bool = False, fail_on_deadlock: bool = True,
        fail_on_risk: bool = False, junit_xml: Optional[str] = None,
        report_json: Optional[str] = None) -> int:
    """
    Core pipeline:
      event → RAG.process_event → cycle_detector.detect → explainer.explain → dna.fingerprint → risk_tracker.process → recovery_engine.evaluate → dashboard.update / ci_reporter
    """
    rag             = ResourceAllocationGraph()
    detector        = CycleDetector()
    from diagnosis.symbol_resolver import SymbolResolver
    explainer       = DeadlockExplainer(symbol_resolver=SymbolResolver(target_hint=target_name))
    store           = DeadlockStore()
    risk_tracker    = LockOrderTracker(session_id=target_name)
    risk_detector   = RiskCycleDetector()
    risk_store      = RiskStore()
    recovery_engine = RecoveryPolicyEngine()

    ci_reporter = None
    dash = None
    if ci_mode:
        ci_reporter = CIReporter(
            target_name=target_name,
            pid=pid,
            fail_on_deadlock=fail_on_deadlock,
            fail_on_risk=fail_on_risk,
            junit_xml=junit_xml,
            report_json=report_json,
        )
        ctx = nullcontext()
    else:
        dash = Dashboard(target_name=target_name, pid=pid, port=port, open_browser=open_browser)
        ctx = dash.live_context()

    deadlocks: list[DeadlockResult] = []
    active_risks: list[LockOrderRisk] = []
    notified  = False

    logger.info("pipeline started — target=%s pid=%d (disposable=%s, ci=%s)", target_name, pid, is_disposable, ci_mode)

    try:
        with ctx:
            for event in collector:
                # Discover PID from first event (exec / stdin modes)
                if pid == 0 and event.pid:
                    pid = event.pid
                    if dash:
                        dash.pid = pid

                # Step 1: update RAG
                rag.process_event(event)
                if ci_reporter:
                    ci_reporter.on_event(event, rag)

                # Step 2: detect RAG cycles (live circular waits)
                new_dl = detector.detect(rag.get_graph(), event.timestamp_ns,
                                         operation=event.operation.name)

                if new_dl:
                    for dl in new_dl:
                        # Feature A: Generate explainable diagnosis with source symbols (Upgrade 1)
                        dl.diagnosis = explainer.explain(dl.cycle, rag, event.timestamp_ns, pid=event.pid or pid)

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
                    if ci_reporter:
                        ci_reporter.on_deadlocks(new_dl)
                    elif not notified:
                        logger.warning("DEADLOCK DETECTED — %d cycle(s)", len(new_dl))
                        notified = True
                elif notified:
                    deadlocks = []
                    notified  = False
                    logger.info("deadlock cycle resolved")

                # Step 3: Feature D - Lock-order tracking & predictive risk analysis
                new_edges = risk_tracker.process_event(event)
                truly_new_edges = [e for e in new_edges if e.count == 1]
                if truly_new_edges:
                    for edge_ev in truly_new_edges:
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

                    if ci_reporter and detected_risks:
                        ci_reporter.on_risks(detected_risks)

                # Step 4: refresh dashboard with RAG, active deadlocks, and predictive risks
                if dash:
                    dash.update(event, rag, deadlocks, risks=active_risks)

            # In CI mode, finalize reporter and return exit code immediately
            if ci_reporter:
                return ci_reporter.finish()

            # If the event stream completed (e.g. file replay), keep the Web UI alive
            # until user interrupts with Ctrl+C so they can explore the interactive dashboard.
            print(f"\n[deadlockdna] Event stream finished.", file=sys.stderr)
            print(f"[deadlockdna] 🚀 Interactive Web UI is active at: http://127.0.0.1:{dash.port if dash else port}", file=sys.stderr)
            print("[deadlockdna] Press Ctrl+C to exit.\n", file=sys.stderr)
            try:
                while True:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                pass

            return 0

    except KeyboardInterrupt:
        logger.info("pipeline interrupted by user")
        return 0
    except CollectorError:
        raise
    except Exception as exc:
        logger.error("pipeline error: %s", exc, exc_info=True)
        raise
    finally:
        store.close()
        risk_store.close()

    logger.info("pipeline stopped")
    return 0


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
    p.add_argument("--port", type=int, default=8080,
                   help="web UI server port (default: 8080)")
    p.add_argument("--ui", action="store_true", default=True,
                   help="enable real-time web UI visualizer (enabled by default)")
    p.add_argument("--no-browser", action="store_true",
                   help="do not open web browser automatically")
    p.add_argument("--ci", "--check", action="store_true", dest="ci",
                   help="run in headless CI/CD mode (concurrency linter; no web UI)")
    p.add_argument("--fail-on-deadlock", action=argparse.BooleanOptionalAction, default=True,
                   help="exit with code 1 if a deadlock cycle is detected (default: true)")
    p.add_argument("--fail-on-risk", action="store_true",
                   help="exit with code 2 if a predictive lock-order hierarchy risk is detected")
    p.add_argument("--junit-xml", type=str, metavar="PATH",
                   help="path to output JUnit XML test report")
    p.add_argument("--report-json", type=str, metavar="PATH",
                   help="path to output machine-readable JSON report")
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
            delay = 0.0 if (args.ci and "--delay" not in sys.argv) else args.delay
            gen = collect_from_file(args.file_p, delay=delay)

        else:
            name, pid = "stdin", 0
            gen = collect_from_stdin()

        code = run(
            gen,
            target_name=name,
            pid=pid,
            is_disposable=args.disposable,
            port=args.port,
            open_browser=not args.no_browser,
            ci_mode=args.ci,
            fail_on_deadlock=args.fail_on_deadlock,
            fail_on_risk=args.fail_on_risk,
            junit_xml=args.junit_xml,
            report_json=args.report_json,
        )
        sys.exit(code)

    except CollectorError as e:
        print(f"\n[deadlockdna] ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[deadlockdna] stopped.")


if __name__ == "__main__":
    main()
