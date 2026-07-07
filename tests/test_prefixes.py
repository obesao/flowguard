"""Testes de collector/prefixes.py: match_protected_prefix e resolve_dst_prefix."""

from collector.prefixes import match_protected_prefix, resolve_dst_prefix

PROTECTED = [
    {"prefix": "177.86.16.0/24", "customer": "POX Network Core"},
    {"prefix": "177.86.17.0/24", "customer": "POX Network Core"},
    {"prefix": "100.64.0.0/10", "customer": "CGNAT-PPPOE"},
    # Prefixo mais específico dentro de um mais largo já cadastrado —
    # match_protected_prefix deve escolher o mais específico (maior prefixlen).
    {"prefix": "100.64.109.0/24", "customer": "Cliente específico"},
]


def test_match_returns_prefix_when_ip_inside():
    assert match_protected_prefix("177.86.16.55", PROTECTED) == "177.86.16.0/24"


def test_match_returns_none_when_ip_outside_any_protected_prefix():
    assert match_protected_prefix("8.8.8.8", PROTECTED) is None


def test_match_picks_most_specific_overlapping_prefix():
    assert match_protected_prefix("100.64.109.5", PROTECTED) == "100.64.109.0/24"


def test_match_falls_back_to_wider_prefix_outside_the_specific_one():
    assert match_protected_prefix("100.64.5.1", PROTECTED) == "100.64.0.0/10"


def test_match_ignores_entry_with_invalid_prefix_string():
    entries = [{"prefix": "not-a-cidr"}, {"prefix": "177.86.16.0/24"}]
    assert match_protected_prefix("177.86.16.1", entries) == "177.86.16.0/24"


def test_match_ignores_entry_missing_prefix_key():
    entries = [{"customer": "sem prefixo"}, {"prefix": "177.86.16.0/24"}]
    assert match_protected_prefix("177.86.16.1", entries) == "177.86.16.0/24"


def test_match_returns_none_for_invalid_ip():
    assert match_protected_prefix("not-an-ip", PROTECTED) is None


def test_match_supports_ipv6():
    entries = [{"prefix": "2001:db8::/32"}]
    assert match_protected_prefix("2001:db8::1", entries) == "2001:db8::/32"


def test_resolve_returns_protected_prefix_when_matched():
    assert resolve_dst_prefix("177.86.16.1", PROTECTED) == "177.86.16.0/24"


def test_resolve_falls_back_to_slash24_for_unprotected_ipv4():
    assert resolve_dst_prefix("8.8.8.8", PROTECTED) == "8.8.8.0/24"


def test_resolve_falls_back_to_slash64_for_unprotected_ipv6():
    assert resolve_dst_prefix("2001:4860:4860::8888", []) == "2001:4860:4860::/64"


def test_resolve_returns_raw_ip_for_invalid_input():
    assert resolve_dst_prefix("not-an-ip", []) == "not-an-ip"
