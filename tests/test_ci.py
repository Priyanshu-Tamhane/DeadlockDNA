"""
tests/test_ci.py — Unit Tests for Headless CI/CD Reporter & Gatekeeper (Upgrade 2)
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
import pytest

from collector.collector import collect_from_file
from ci.reporter import CIReporter
from main import run

_TESTS_DIR = Path(__file__).parent
_CLEAN_EVENTS = str(_TESTS_DIR / "sample_clean_events.json")
_DEADLOCK_EVENTS = str(_TESTS_DIR / "sample_events.json")
_RISK_EVENTS = str(_TESTS_DIR / "sample_risk_events.json")


def test_ci_clean_run_passes():
    """Clean synchronization stream must return exit code 0."""
    gen = collect_from_file(_CLEAN_EVENTS, delay=0.0)
    code = run(
        collector=gen,
        target_name="clean_test",
        pid=5000,
        ci_mode=True,
        fail_on_deadlock=True,
        fail_on_risk=False,
    )
    assert code == 0


def test_ci_deadlock_detection_fails():
    """Deadlock stream must return exit code 1."""
    gen = collect_from_file(_DEADLOCK_EVENTS, delay=0.0)
    code = run(
        collector=gen,
        target_name="deadlock_test",
        pid=5000,
        ci_mode=True,
        fail_on_deadlock=True,
        fail_on_risk=False,
    )
    assert code == 1


def test_ci_risk_advisory_vs_strict():
    """Lock order inversions return 0 by default, or 2 when fail_on_risk is active."""
    # Advisory mode
    gen1 = collect_from_file(_RISK_EVENTS, delay=0.0)
    code_advisory = run(
        collector=gen1,
        target_name="risk_test",
        pid=6000,
        ci_mode=True,
        fail_on_deadlock=True,
        fail_on_risk=False,
    )
    assert code_advisory == 0

    # Strict gatekeeper mode
    gen2 = collect_from_file(_RISK_EVENTS, delay=0.0)
    code_strict = run(
        collector=gen2,
        target_name="risk_test",
        pid=6000,
        ci_mode=True,
        fail_on_deadlock=True,
        fail_on_risk=True,
    )
    assert code_strict == 2


def test_ci_junit_xml_generation(tmp_path: Path):
    """JUnit XML report must be syntactically valid and contain failure traces."""
    junit_path = tmp_path / "junit_report.xml"
    gen = collect_from_file(_DEADLOCK_EVENTS, delay=0.0)
    code = run(
        collector=gen,
        target_name="sample_events.json",
        pid=5000,
        ci_mode=True,
        fail_on_deadlock=True,
        junit_xml=str(junit_path),
    )
    assert code == 1
    assert junit_path.exists()

    tree = ET.parse(junit_path)
    root = tree.getroot()
    assert root.tag == "testsuites"
    assert root.attrib.get("failures") == "1"

    suite = root.find("testsuite")
    assert suite is not None
    assert suite.attrib.get("failures") == "1"

    failure = root.find(".//failure")
    assert failure is not None
    assert "deadlock" in failure.attrib.get("message", "").lower()
    assert "DNA Fingerprint:" in (failure.text or "")


def test_ci_json_report_generation(tmp_path: Path):
    """JSON report must contain full metadata, fingerprint, and diagnosis steps."""
    json_path = tmp_path / "summary.json"
    gen = collect_from_file(_DEADLOCK_EVENTS, delay=0.0)
    code = run(
        collector=gen,
        target_name="sample_events.json",
        pid=5000,
        ci_mode=True,
        fail_on_deadlock=True,
        report_json=str(json_path),
    )
    assert code == 1
    assert json_path.exists()

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["target"] == "sample_events.json"
    assert data["pid"] == 5000
    assert data["exit_code"] == 1
    assert data["passed"] is False
    assert data["deadlocks_detected"] == 1
    assert len(data["deadlocks"]) == 1

    dl0 = data["deadlocks"][0]
    assert "fingerprint" in dl0
    assert dl0["fingerprint"] == "9f2cbc7f533f8642d6ee3e8c5b4481e74fdb980a57c3d50e3389294f6747ec74"
    assert "diagnosis" in dl0
    assert len(dl0["diagnosis"]["steps"]) == 2
