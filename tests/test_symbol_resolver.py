"""
tests/test_symbol_resolver.py — Unit Tests for Source-Code Symbol Resolution (Upgrade 1)
"""

from diagnosis.symbol_resolver import SymbolResolver, SymbolInfo


def test_symbol_resolver_offline_fallbacks():
    resolver = SymbolResolver(target_hint="test_2way")

    # Test resolving mutex 0x1000 and 0x2000
    sym1 = resolver.resolve_resource("0x1000")
    assert sym1.name == "L1"
    assert "test_2way.c" in sym1.file
    assert sym1.line == 24
    assert sym1.display_str == "L1 (test_2way.c:24)"

    sym2 = resolver.resolve_resource("M@5000:0x2000")
    assert sym2.name == "L2"
    assert "test_2way.c" in sym2.file
    assert sym2.line == 25
    assert sym2.display_str == "L2 (test_2way.c:25)"


def test_symbol_resolver_thread_function():
    resolver = SymbolResolver(target_hint="test_2way")
    f1 = resolver.resolve_thread_function(5001)
    f2 = resolver.resolve_thread_function(5002)

    assert f1 == "thread1"
    assert f2 == "thread2"


def test_symbol_resolver_three_way_fallbacks():
    resolver = SymbolResolver(target_hint="test_3way")
    sym3 = resolver.resolve_resource("M@5000:0x40c0")
    assert sym3.name == "L3"
    assert "test_3way.c" in sym3.file
    assert sym3.line == 26


def test_symbol_resolver_generic_fallback():
    resolver = SymbolResolver(target_hint="unknown_app")
    sym = resolver.resolve_resource("0xdeadbeef")
    assert "deadbeef" in sym.name
    assert sym.location_str == "unknown"
