"""The prefix trie is pure logic with no I/O, so it is tested exhaustively.

Every ownership decision in the tool rests on it: a wrong overlap answer puts a
rule in the wrong team's report, or hides it from the right one.
"""

from __future__ import annotations

import ipaddress

import pytest

from panorama_team_review.resolve.nettrie import NetworkTrie


def payloads(results) -> set[str]:
    return {value for _, value in results}


def test_exact_match():
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("10.0.0.0/8", "a")
    assert payloads(trie.find_overlaps("10.0.0.0/8")) == {"a"}


def test_query_inside_stored_network():
    """A /24 inside a stored /16 overlaps it."""
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("10.1.0.0/16", "team")
    assert payloads(trie.find_overlaps("10.1.5.0/24")) == {"team"}


def test_stored_network_inside_query():
    """A stored /32 inside a queried /16 also overlaps -- the other direction."""
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("10.1.5.7/32", "host")
    assert payloads(trie.find_overlaps("10.1.0.0/16")) == {"host"}


def test_disjoint_networks_do_not_match():
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("10.1.0.0/16", "a")
    assert trie.find_overlaps("10.2.0.0/16") == []
    assert trie.find_overlaps("192.168.0.0/16") == []


def test_sibling_networks_do_not_match():
    """/25 halves of the same /24 must not be reported as overlapping."""
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("10.0.0.0/25", "lower")
    assert payloads(trie.find_overlaps("10.0.0.128/25")) == set()


def test_multiple_ancestors_all_returned():
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("10.0.0.0/8", "wide")
    trie.insert("10.1.0.0/16", "medium")
    trie.insert("10.1.5.0/24", "narrow")
    assert payloads(trie.find_overlaps("10.1.5.7/32")) == {"wide", "medium", "narrow"}


def test_multiple_descendants_all_returned():
    trie: NetworkTrie[str] = NetworkTrie()
    for last in range(5):
        trie.insert(f"10.1.{last}.0/24", f"net{last}")
    found = payloads(trie.find_overlaps("10.1.0.0/16"))
    assert found == {f"net{i}" for i in range(5)}


def test_default_route_overlaps_everything():
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("0.0.0.0/0", "everything")
    assert payloads(trie.find_overlaps("192.0.2.1/32")) == {"everything"}
    assert payloads(trie.find_overlaps("10.0.0.0/8")) == {"everything"}


def test_ipv4_and_ipv6_are_separate():
    """Mixing address families would make prefix comparison meaningless."""
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("10.0.0.0/8", "v4")
    trie.insert("2001:db8::/32", "v6")
    assert payloads(trie.find_overlaps("10.1.1.1/32")) == {"v4"}
    assert payloads(trie.find_overlaps("2001:db8:1::/48")) == {"v6"}


def test_ipv6_overlap():
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("2001:db8:20::/64", "payments")
    assert payloads(trie.find_overlaps("2001:db8:20::5/128")) == {"payments"}
    assert payloads(trie.find_overlaps("2001:db8:21::/64")) == set()


def test_same_network_multiple_payloads():
    """Two teams may legitimately claim the same shared network."""
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("10.0.0.0/8", "team-a")
    trie.insert("10.0.0.0/8", "team-b")
    assert payloads(trie.find_overlaps("10.1.1.1/32")) == {"team-a", "team-b"}


def test_find_containing_excludes_descendants():
    """find_containing answers 'who covers this', not 'who is inside this'."""
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("10.0.0.0/8", "wide")
    trie.insert("10.1.5.0/24", "narrow")
    assert payloads(trie.find_containing("10.1.0.0/16")) == {"wide"}
    assert payloads(trie.find_overlaps("10.1.0.0/16")) == {"wide", "narrow"}


def test_accepts_network_objects_and_strings():
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert(ipaddress.ip_network("10.0.0.0/8"), "obj")
    assert payloads(trie.find_overlaps("10.1.1.1/32")) == {"obj"}


def test_len_counts_inserts():
    trie: NetworkTrie[str] = NetworkTrie()
    assert len(trie) == 0
    trie.insert("10.0.0.0/8", "a")
    trie.insert("10.0.0.0/8", "b")
    assert len(trie) == 2


def test_host_address_without_prefix():
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert("10.1.2.3", "host")
    assert payloads(trie.find_overlaps("10.1.0.0/16")) == {"host"}


@pytest.mark.parametrize(
    ("stored", "query", "expected"),
    [
        ("10.0.0.0/8", "10.255.255.255/32", True),
        ("10.0.0.0/8", "11.0.0.0/8", False),  # allow-customer-data-check
        ("172.16.0.0/12", "172.31.255.0/24", True),
        ("172.16.0.0/12", "172.32.0.0/24", False),  # allow-customer-data-check
        ("192.168.1.0/24", "192.168.0.0/16", True),
    ],
)
def test_overlap_matches_ipaddress_semantics(stored, query, expected):
    """The trie must agree with the standard library on every boundary case."""
    trie: NetworkTrie[str] = NetworkTrie()
    trie.insert(stored, "x")
    found = bool(trie.find_overlaps(query))
    assert found is expected
    assert found is ipaddress.ip_network(stored).overlaps(ipaddress.ip_network(query))
