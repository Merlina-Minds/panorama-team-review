"""A binary prefix trie for IP network overlap queries.

Ownership resolution asks, for every address in every rule, which team assets
it touches.  Done naively that is ``rules x networks x assets`` comparisons --
for a realistic estate (5 000 rules, 20 networks each, 500 assets) that is
50 million ``ipaddress`` comparisons and takes minutes.

A prefix trie answers the same question in time proportional to the prefix
length plus the number of actual matches.  Two networks overlap if and only if
one is a prefix of the other, which is precisely the ancestor/descendant
relation in this trie.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Generic, TypeVar

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

T = TypeVar("T")


@dataclass(slots=True)
class _Node(Generic[T]):
    children: list[_Node[T] | None] = field(default_factory=lambda: [None, None])
    values: list[tuple[IPNetwork, T]] = field(default_factory=list)


class NetworkTrie(Generic[T]):
    """Maps IP networks to arbitrary payloads, queried by overlap.

    IPv4 and IPv6 live in separate tries: their address spaces are unrelated
    and mixing them would make prefix comparison meaningless.
    """

    def __init__(self) -> None:
        self._roots: dict[int, _Node[T]] = {4: _Node(), 6: _Node()}
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def insert(self, network: IPNetwork | str, value: T) -> None:
        net = _coerce(network)
        node = self._roots[net.version]
        bits = int(net.network_address)
        total = net.max_prefixlen

        for depth in range(net.prefixlen):
            bit = (bits >> (total - 1 - depth)) & 1
            child = node.children[bit]
            if child is None:
                child = _Node()
                node.children[bit] = child
            node = child

        node.values.append((net, value))
        self._size += 1

    def find_overlaps(self, network: IPNetwork | str) -> list[tuple[IPNetwork, T]]:
        """Return every stored entry whose network overlaps ``network``.

        Covers both directions: stored networks containing the query (found on
        the way down) and stored networks contained by it (found in the subtree
        below the query's terminal node).
        """
        net = _coerce(network)
        node = self._roots.get(net.version)
        if node is None:
            return []

        out: list[tuple[IPNetwork, T]] = list(node.values)
        bits = int(net.network_address)
        total = net.max_prefixlen

        for depth in range(net.prefixlen):
            bit = (bits >> (total - 1 - depth)) & 1
            child = node.children[bit]
            if child is None:
                return out
            node = child
            out.extend(node.values)

        out.extend(_collect_subtree(node))
        return out

    def find_containing(self, address: IPNetwork | str) -> list[tuple[IPNetwork, T]]:
        """Return only the stored networks that contain ``address``."""
        net = _coerce(address)
        node = self._roots.get(net.version)
        if node is None:
            return []

        out: list[tuple[IPNetwork, T]] = list(node.values)
        bits = int(net.network_address)
        total = net.max_prefixlen

        for depth in range(net.prefixlen):
            bit = (bits >> (total - 1 - depth)) & 1
            child = node.children[bit]
            if child is None:
                break
            node = child
            out.extend(node.values)
        return out

    def all_entries(self) -> list[tuple[IPNetwork, T]]:
        out: list[tuple[IPNetwork, T]] = []
        for root in self._roots.values():
            out.extend(root.values)
            out.extend(_collect_subtree(root))
        return out


def _collect_subtree(node: _Node[T]) -> list[tuple[IPNetwork, T]]:
    """Iteratively gather every value below ``node``, excluding its own."""
    out: list[tuple[IPNetwork, T]] = []
    stack: list[_Node[T]] = [child for child in node.children if child is not None]
    while stack:
        current = stack.pop()
        out.extend(current.values)
        stack.extend(child for child in current.children if child is not None)
    return out


def _coerce(network: IPNetwork | str) -> IPNetwork:
    if isinstance(network, str):
        return ipaddress.ip_network(network, strict=False)
    return network
