"""
tests/test_events.py — Unit tests for the event parser (collector/)
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from collector.event_parser import parse_line, Operation


class TestParseValidEvents:
    def test_lock_request(self):
        line = '{"timestamp_ns":1,"pid":5000,"tid":5001,"resource":"0x1000","operation":"LOCK_REQUEST"}'
        ev = parse_line(line)
        assert ev is not None
        assert ev.pid == 5000
        assert ev.tid == 5001
        assert ev.resource == "0x1000"
        assert ev.operation == Operation.LOCK_REQUEST

    def test_lock_acquired(self):
        line = '{"timestamp_ns":2,"pid":5000,"tid":5001,"resource":"0x1000","operation":"LOCK_ACQUIRED"}'
        ev = parse_line(line)
        assert ev is not None
        assert ev.operation == Operation.LOCK_ACQUIRED

    def test_lock_released(self):
        line = '{"timestamp_ns":3,"pid":5000,"tid":5001,"resource":"0x1000","operation":"LOCK_RELEASED"}'
        ev = parse_line(line)
        assert ev.operation == Operation.LOCK_RELEASED

    def test_scoped_resource(self):
        line = '{"timestamp_ns":1,"pid":5000,"tid":5001,"resource":"0x1234","operation":"LOCK_REQUEST"}'
        ev = parse_line(line)
        assert ev.scoped_resource == "M@5000:0x1234"

    def test_valid_owner_tid(self):
        line = '{"timestamp_ns":1,"pid":5000,"tid":5001,"resource":"0x1000","operation":"LOCK_REQUEST","owner_tid":5002}'
        ev = parse_line(line)
        assert ev is not None
        assert ev.owner_tid == 5002


class TestSkippedLines:
    def test_empty_line(self):
        assert parse_line("") is None

    def test_whitespace_only(self):
        assert parse_line("   \n") is None

    def test_comment_line(self):
        assert parse_line("# deadlockdna observer started") is None

    def test_bpftrace_banner_lines(self):
        assert parse_line("Attaching 8 probes...") is None
        assert parse_line("Attached 6 probes") is None


class TestMalformedEvents:
    def test_bad_json(self):
        assert parse_line("{not valid json}") is None

    def test_non_dict_json(self):
        assert parse_line("123") is None
        assert parse_line('"hello"') is None
        assert parse_line("true") is None
        assert parse_line("[1, 2, 3]") is None

    def test_missing_pid(self):
        line = '{"timestamp_ns":1,"tid":5001,"resource":"0x1000","operation":"LOCK_REQUEST"}'
        assert parse_line(line) is None

    def test_missing_operation(self):
        line = '{"timestamp_ns":1,"pid":5000,"tid":5001,"resource":"0x1000"}'
        assert parse_line(line) is None

    def test_unknown_operation(self):
        line = '{"timestamp_ns":1,"pid":5000,"tid":5001,"resource":"0x1000","operation":"MAGIC_OP"}'
        assert parse_line(line) is None

    def test_non_integer_tid(self):
        line = '{"timestamp_ns":1,"pid":5000,"tid":"abc","resource":"0x1000","operation":"LOCK_REQUEST"}'
        assert parse_line(line) is None

    def test_non_integer_owner_tid(self):
        line = '{"timestamp_ns":1,"pid":5000,"tid":5001,"resource":"0x1000","operation":"LOCK_REQUEST","owner_tid":"invalid"}'
        assert parse_line(line) is None
