"""
ci/reporter.py — DeadlockDNA Headless CI/CD Reporter & Concurrency Linter (Upgrade 2)

Provides automated deadlock gatekeeping for CI pipelines (GitHub Actions, GitLab CI,
Jenkins) without launching a web server or browser.

Outputs:
  - Concise terminal diagnostics with ANSI highlights
  - Standard JUnit XML test reports for CI test suites
  - Machine-readable JSON summaries for build artifacts
  - Precise exit codes:
      0 = Clean concurrency run (no violations)
      1 = Deadlock cycle detected (live circular wait)
      2 = Lock-order hierarchy inversion detected (--fail-on-risk)
"""

import json
import logging
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from graph.models import DeadlockResult, Event
from graph.rag import ResourceAllocationGraph
from risk.risk_cycle_detector import LockOrderRisk

logger = logging.getLogger(__name__)


class CIReporter:
    """
    Headless CI/CD test reporter for automated deadlock & concurrency linting.
    """

    def __init__(
        self,
        target_name: str,
        pid: int = 0,
        fail_on_deadlock: bool = True,
        fail_on_risk: bool = False,
        junit_xml: Optional[str] = None,
        report_json: Optional[str] = None,
    ) -> None:
        self.target_name = target_name
        self.pid = pid
        self.fail_on_deadlock = fail_on_deadlock
        self.fail_on_risk = fail_on_risk
        self.junit_xml_path = Path(junit_xml) if junit_xml else None
        self.report_json_path = Path(report_json) if report_json else None

        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.events_count: int = 0

        self.seen_threads: Set[int] = set()
        self.seen_resources: Set[str] = set()

        self.deadlocks: List[DeadlockResult] = []
        self._deadlock_keys: Set[str] = set()

        self.risks: List[LockOrderRisk] = []
        self._risk_keys: Set[str] = set()

        self._print_header()

    def _print_header(self) -> None:
        print("======================================================================", flush=True)
        print("  ⚡ DeadlockDNA Concurrency Gatekeeper (Headless CI Mode)", flush=True)
        print(f"  Target: {self.target_name} (PID: {self.pid or 'discovering...'})", flush=True)
        print(f"  Policies: fail_on_deadlock={self.fail_on_deadlock}, fail_on_risk={self.fail_on_risk}", flush=True)
        print("======================================================================\n", flush=True)

    def on_event(self, event: Event, rag: ResourceAllocationGraph) -> None:
        """Track event progression and graph footprint."""
        self.events_count += 1
        if self.pid == 0 and event.pid:
            self.pid = event.pid
        if event.tid:
            self.seen_threads.add(event.tid)
        if event.resource:
            self.seen_resources.add(event.scoped_resource)

    def on_deadlocks(self, new_deadlocks: List[DeadlockResult]) -> None:
        """Record and immediately alert on live deadlock cycles."""
        for dl in new_deadlocks:
            key = dl.fingerprint or "->".join(dl.cycle)
            if key not in self._deadlock_keys:
                self._deadlock_keys.add(key)
                self.deadlocks.append(dl)

                cycle_str = " ➔ ".join(dl.cycle)
                print(f"[deadlockdna:ci] 🚨 DEADLOCK DETECTED! Cycle: {cycle_str}", flush=True)
                if dl.fingerprint:
                    print(f"                 DNA Fingerprint: {dl.fingerprint}", flush=True)
                if dl.diagnosis and getattr(dl.diagnosis, "steps", None):
                    for step in dl.diagnosis.steps:
                        src = f" ({step.thread_function} @ {step.source_location})" if step.source_location else ""
                        h_sym = f" ({step.held_symbol})" if step.held_symbol else ""
                        w_sym = f" ({step.waiting_symbol})" if step.waiting_symbol else ""
                        print(
                            f"                 • T{step.thread_id}{src} holds {step.held_resource_id or 'none'}{h_sym} "
                            f"and waits for {step.resource_id}{w_sym}",
                            flush=True,
                        )

    def on_risks(self, new_risks: List[LockOrderRisk]) -> None:
        """Record and alert on lock-order hierarchy inversions."""
        for rk in new_risks:
            if rk.risk_id not in self._risk_keys:
                self._risk_keys.add(rk.risk_id)
                self.risks.append(rk)
                print(f"[deadlockdna:ci] ⚠️ LOCK-ORDER RISK! Inversion: {rk.pattern}", flush=True)

    def finish(self) -> int:
        """
        Finalize CI run, print summary, export JUnit XML & JSON reports, and return exit code.
        """
        self.end_time = time.time()
        duration = max(0.001, self.end_time - self.start_time)

        # Determine pass/fail status
        has_deadlocks = len(self.deadlocks) > 0
        has_risks = len(self.risks) > 0

        failed = (has_deadlocks and self.fail_on_deadlock) or (has_risks and self.fail_on_risk)
        if has_deadlocks and self.fail_on_deadlock:
            exit_code = 1
            verdict = "FAILED (Deadlock Detected)"
        elif has_risks and self.fail_on_risk:
            exit_code = 2
            verdict = "FAILED (Lock-Order Hierarchy Inversion)"
        else:
            exit_code = 0
            verdict = "PASSED"

        # Terminal Summary Table
        print("\n======================================================================", flush=True)
        print("  DeadlockDNA CI/CD Concurrency Gatekeeper Summary", flush=True)
        print("======================================================================", flush=True)
        print(f"  Target:            {self.target_name} (PID: {self.pid})", flush=True)
        print(f"  Duration:          {duration:.3f}s", flush=True)
        print(f"  Events Processed:  {self.events_count}", flush=True)
        print(f"  Concurrency Scope: {len(self.seen_threads)} threads, {len(self.seen_resources)} mutexes", flush=True)
        dl_tag = "[FAIL]" if (has_deadlocks and self.fail_on_deadlock) else ("[WARN]" if has_deadlocks else "[OK]")
        risk_tag = "[FAIL]" if (has_risks and self.fail_on_risk) else ("[WARN]" if has_risks else "[OK]")
        print(f"  Deadlocks:         {len(self.deadlocks)} detected {dl_tag}", flush=True)
        print(f"  Lock-Order Risks:  {len(self.risks)} detected {risk_tag}", flush=True)

        if self.deadlocks:
            print("----------------------------------------------------------------------", flush=True)
            print("  Deadlock Breakdown:", flush=True)
            for idx, dl in enumerate(self.deadlocks, 1):
                print(f"    [{idx}] Cycle: {' ➔ '.join(dl.cycle)}", flush=True)
                if dl.fingerprint:
                    print(f"        Fingerprint: {dl.fingerprint} (seen {dl.occurrence_count}x)", flush=True)
                if dl.diagnosis and getattr(dl.diagnosis, "steps", None):
                    for step in dl.diagnosis.steps:
                        loc = f" in {step.thread_function} ({step.source_location})" if step.source_location else ""
                        held = f"{step.held_symbol or step.held_resource_id}"
                        waiting = f"{step.waiting_symbol or step.resource_id}"
                        print(f"        • Thread {step.thread_id}{loc}: holding {held}, blocked on {waiting}", flush=True)

        if self.risks:
            print("----------------------------------------------------------------------", flush=True)
            print("  Lock-Order Hierarchy Inversion Breakdown:", flush=True)
            for idx, rk in enumerate(self.risks, 1):
                tids = ", ".join(str(t) for t in rk.threads_involved)
                print(f"    [{idx}] Pattern: {rk.pattern} (Threads: {tids})", flush=True)

        print("======================================================================", flush=True)
        print(f"  OVERALL RESULT: {verdict} (Exit Code: {exit_code})", flush=True)
        print("======================================================================\n", flush=True)

        # Export reports
        if self.junit_xml_path:
            self._write_junit_xml(duration)
        if self.report_json_path:
            self._write_json_report(duration, exit_code, verdict)

        return exit_code

    def _write_junit_xml(self, duration: float) -> None:
        """Write JUnit XML test suite report for CI engines."""
        try:
            self.junit_xml_path.parent.mkdir(parents=True, exist_ok=True)
            total_tests = 2
            failures = 0

            root = ET.Element("testsuites", name="DeadlockDNA", time=f"{duration:.4f}")
            suite = ET.SubElement(
                root,
                "testsuite",
                name="deadlockdna.concurrency",
                tests=str(total_tests),
                errors="0",
                time=f"{duration:.4f}",
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

            # Testcase 1: Deadlock cycle detection
            tc_deadlock = ET.SubElement(
                suite,
                "testcase",
                classname=f"deadlockdna.{self.target_name}",
                name="deadlock_cycle_check",
                time=f"{duration / 2.0:.4f}",
            )
            if self.deadlocks and self.fail_on_deadlock:
                failures += 1
                failure_lines = [f"{len(self.deadlocks)} deadlock cycle(s) detected:"]
                for idx, dl in enumerate(self.deadlocks, 1):
                    failure_lines.append(f"\n[Deadlock #{idx}]")
                    failure_lines.append(f"Cycle: {' ➔ '.join(dl.cycle)}")
                    if dl.fingerprint:
                        failure_lines.append(f"DNA Fingerprint: {dl.fingerprint}")
                    if dl.diagnosis and getattr(dl.diagnosis, "steps", None):
                        failure_lines.append("Trace:")
                        for step in dl.diagnosis.steps:
                            loc = f" [{step.source_location}]" if step.source_location else ""
                            held = f"{step.held_symbol or step.held_resource_id}"
                            waiting = f"{step.waiting_symbol or step.resource_id}"
                            failure_lines.append(f"  Thread {step.thread_id}{loc}: holds {held}, waiting for {waiting}")

                fail_elem = ET.SubElement(
                    tc_deadlock,
                    "failure",
                    message=f"{len(self.deadlocks)} deadlock cycle(s) detected",
                    type="DeadlockDetectedError",
                )
                fail_elem.text = "\n".join(failure_lines)

            # Testcase 2: Lock-order hierarchy inversion check
            tc_risk = ET.SubElement(
                suite,
                "testcase",
                classname=f"deadlockdna.{self.target_name}",
                name="lock_order_hierarchy_check",
                time=f"{duration / 2.0:.4f}",
            )
            if self.risks and self.fail_on_risk:
                failures += 1
                failure_lines = [f"{len(self.risks)} lock-order inversion risk(s) detected:"]
                for idx, rk in enumerate(self.risks, 1):
                    failure_lines.append(f"\n[Risk #{idx}]")
                    failure_lines.append(f"Inversion Pattern: {rk.pattern}")
                    failure_lines.append(f"Threads Involved: {rk.threads_involved}")
                fail_elem = ET.SubElement(
                    tc_risk,
                    "failure",
                    message=f"{len(self.risks)} lock-order inversion risk(s) detected",
                    type="LockOrderInversionError",
                )
                fail_elem.text = "\n".join(failure_lines)

            suite.set("failures", str(failures))
            root.set("failures", str(failures))

            tree = ET.ElementTree(root)
            ET.indent(tree, space="  ", level=0)
            tree.write(self.junit_xml_path, encoding="utf-8", xml_declaration=True)
            print(f"[deadlockdna:ci] 📄 JUnit XML report saved to: {self.junit_xml_path}", flush=True)

        except Exception as e:
            logger.error("Failed to write JUnit XML report: %s", e)
            print(f"[deadlockdna:ci] Warning: Could not write JUnit XML: {e}", file=sys.stderr)

    def _write_json_report(self, duration: float, exit_code: int, verdict: str) -> None:
        """Write machine-readable JSON report."""
        try:
            self.report_json_path.parent.mkdir(parents=True, exist_ok=True)

            deadlock_list = []
            for dl in self.deadlocks:
                diag_dict = dl.diagnosis.to_dict() if hasattr(dl.diagnosis, "to_dict") else None
                rec_dict = dl.recovery_plan.to_dict() if hasattr(dl.recovery_plan, "to_dict") else None
                deadlock_list.append({
                    "fingerprint": dl.fingerprint,
                    "canonical_pattern": dl.canonical_pattern,
                    "cycle": dl.cycle,
                    "threads": dl.threads,
                    "resources": dl.resources,
                    "occurrence_count": dl.occurrence_count,
                    "latency_us": dl.latency_us,
                    "diagnosis": diag_dict,
                    "recovery_plan": rec_dict,
                })

            risk_list = [rk.to_dict() if hasattr(rk, "to_dict") else str(rk) for rk in self.risks]

            report = {
                "target": self.target_name,
                "pid": self.pid,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(duration, 4),
                "events_processed": self.events_count,
                "threads_observed": sorted(list(self.seen_threads)),
                "resources_observed": sorted(list(self.seen_resources)),
                "deadlocks_detected": len(self.deadlocks),
                "lock_order_risks_detected": len(self.risks),
                "exit_code": exit_code,
                "verdict": verdict,
                "passed": (exit_code == 0),
                "deadlocks": deadlock_list,
                "lock_order_risks": risk_list,
            }

            with open(self.report_json_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"[deadlockdna:ci] 📄 JSON report saved to: {self.report_json_path}", flush=True)

        except Exception as e:
            logger.error("Failed to write JSON report: %s", e)
            print(f"[deadlockdna:ci] Warning: Could not write JSON report: {e}", file=sys.stderr)
