"""Pseudonymise a configuration so a bug can be reproduced without the estate.

The intended workflow: something goes wrong on a real configuration, and the
maintainer needs a reproducer. Sending the original is not an option, so this
produces a structurally identical configuration with every identifying value
replaced.

**Read this before relying on it.** Pseudonymisation is not anonymisation:

* Structure is preserved exactly -- rule counts, group nesting, topology. For a
  small or distinctive estate that structure alone can be identifying.
* Mapping is deterministic per salt, which is what keeps the configuration
  self-consistent, and therefore reversible by anyone holding the salt.
* Free text is replaced wholesale rather than parsed, because a description
  field can contain anything at all.

So: scrubbed output is safe to share with people you would already trust with a
network diagram. It is not safe to publish. Nothing produced by this command
belongs in a public repository -- ``tests/fixtures/generator.py`` exists for
that, and it invents its data rather than transforming real data.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
from dataclasses import dataclass, field

from lxml import etree

# Replacement space.
#
# IPv4 maps into RFC 1918 rather than the RFC 5737 documentation ranges, and
# that choice matters: the documentation ranges are /24s, so anything broader
# than a /24 cannot be represented inside one. An earlier version tried, and
# produced 203.0.0.0/16 -- a real, routable, non-documentation network. Private  # allow-customer-data-check
# space is large enough to hold any prefix length an address object can carry,
# is equally non-identifying (every estate uses the same 10.0.0.0/8), and is
# what the repository's data guard accepts.
#
# IPv6 uses the documentation prefix, which is a /32 and therefore roomy enough.
V4_POOL = ipaddress.ip_network("10.0.0.0/8")
V6_POOL = ipaddress.ip_network("2001:db8::/32")

# Values that carry no information about the estate and must survive intact,
# because replacing them would change what the configuration means.
PRESERVED_VALUES = {
    "any", "application-default", "universal", "intrazone", "interzone",
    "allow", "deny", "drop", "reset-client", "reset-server", "reset-both",
    "yes", "no", "shared", "vsys1", "localhost.localdomain",
}

# Element names whose text is free-form and gets replaced wholesale.
FREE_TEXT_ELEMENTS = {"description", "comments", "comment"}

# Attributes and elements holding names that need consistent pseudonyms.
NAMED_ELEMENTS = {
    "address", "address-group", "service", "service-group", "tag", "zone",
    "device-group", "template", "template-stack", "rules", "entry",
}


@dataclass
class Scrubber:
    """Deterministic pseudonymiser. One instance per configuration."""

    salt: str
    preserve_structure: bool = True
    _names: dict[str, str] = field(default_factory=dict)
    _networks: dict[str, str] = field(default_factory=dict)
    _used_replacements: set[str] = field(default_factory=set)
    _text_counter: int = 0

    @classmethod
    def with_random_salt(cls) -> Scrubber:
        """A salt nobody keeps: the mapping becomes irreversible in practice."""
        return cls(salt=secrets.token_hex(16))

    # -- names ----------------------------------------------------------

    def name(self, original: str, kind: str = "obj") -> str:
        if not original or original.lower() in PRESERVED_VALUES:
            return original
        if original in self._names:
            return self._names[original]

        digest = hashlib.sha256(f"{self.salt}:{original}".encode()).hexdigest()[:8]
        replacement = f"{kind}-{digest}"
        self._names[original] = replacement
        return replacement

    # -- addresses ------------------------------------------------------

    def network(self, value: str) -> str:
        """Map an address, network or range into the documentation pools.

        Prefix length is preserved so the report's breadth findings still
        behave the same way on the scrubbed copy -- which is usually the point
        of producing one.
        """
        value = value.strip()
        if value in self._networks:
            return self._networks[value]

        replacement = self._map_network(value)
        self._networks[value] = replacement
        return replacement

    def _map_network(self, value: str) -> str:
        if "-" in value:
            # An ip-range takes bare addresses; a prefix here would make the
            # scrubbed configuration syntactically invalid on reimport.
            start, _, end = value.partition("-")
            return (
                f"{self._strip_prefix(self._map_network(start.strip()))}"
                f"-{self._strip_prefix(self._map_network(end.strip()))}"
            )

        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                return value
            network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")

        pool = V4_POOL if network.version == 4 else V6_POOL
        return self._map_into_pool(network, pool)

    def _map_into_pool(self, network, pool) -> str:
        """Place a network inside ``pool``, keeping its prefix length.

        Prefix length is preserved because it carries meaning the scrubbed copy
        still needs: a rule covering a /8 must keep covering a /8, or the
        breadth findings behave differently on the reproducer than on the
        original.

        A network broader than the pool itself cannot keep its prefix and stay
        inside; those are clamped to the pool and recorded as such, which is
        both rare and harmless -- 'broader than a /8' is already 'effectively
        everything'.
        """
        prefixlen = max(network.prefixlen, pool.prefixlen)
        subnet_bits = prefixlen - pool.prefixlen
        digest = int(
            hashlib.sha256(f"{self.salt}:{network}".encode()).hexdigest()[:16], 16
        )

        span = 1 << subnet_bits
        host_bits = network.max_prefixlen - prefixlen

        # Linear probing keeps two different source networks from collapsing
        # onto one replacement, which would silently merge unrelated rules.
        for attempt in range(min(span, 1024)):
            index = (digest + attempt) % span
            address = type(network.network_address)(
                int(pool.network_address) | (index << host_bits)
            )
            candidate = f"{address}/{prefixlen}"
            if candidate not in self._used_replacements:
                self._used_replacements.add(candidate)
                return candidate

        # Pool exhausted for this prefix length: reuse deterministically rather
        # than fail, since a reproducer with a collision still reproduces.
        index = digest % span
        address = type(network.network_address)(
            int(pool.network_address) | (index << host_bits)
        )
        return f"{address}/{prefixlen}"

    @staticmethod
    def _strip_prefix(value: str) -> str:
        """Drop a /32 or /128 so the value is a bare address again."""
        address, _, prefix = value.partition("/")
        return address if prefix in ("32", "128") else value

    # -- free text ------------------------------------------------------

    def free_text(self, original: str) -> str:
        """Replace a description wholesale.

        Not parsed and selectively redacted: a description field can contain
        anything -- names, phone numbers, an entire email thread -- and a
        redactor that tries to be clever will eventually miss something.
        """
        if not original.strip():
            return original
        self._text_counter += 1
        digest = hashlib.sha256(f"{self.salt}:{original}".encode()).hexdigest()[:6]
        # Keep a synthetic ticket reference so metadata extraction still has
        # something to find on the scrubbed copy.
        return f"CHG{self._text_counter:07d} scrubbed description {digest}"

    def fqdn(self, original: str) -> str:
        if not original:
            return original
        digest = hashlib.sha256(f"{self.salt}:{original}".encode()).hexdigest()[:8]
        return f"host-{digest}.example.com"

    def serial(self, original: str) -> str:
        if not original:
            return original
        digest = hashlib.sha256(f"{self.salt}:{original}".encode()).hexdigest()
        return "".join(character for character in digest if character.isdigit())[:12].ljust(12, "0")


# ---------------------------------------------------------------------------
# Document walking
# ---------------------------------------------------------------------------

_IPISH_RE = re.compile(r"^\s*[\da-fA-F:.]+(?:/\d{1,3})?(?:\s*-\s*[\da-fA-F:.]+)?\s*$")


def scrub_tree(tree: etree._ElementTree, scrubber: Scrubber) -> etree._ElementTree:
    """Pseudonymise a parsed configuration in place and return it."""
    root = tree.getroot()

    for element in root.iter():
        _scrub_attributes(element, scrubber)
        _scrub_text(element, scrubber)

    return tree


def _scrub_attributes(element: etree._Element, scrubber: Scrubber) -> None:
    name = element.get("name")
    if name is not None:
        element.set("name", _scrub_name_value(element, name, scrubber))

    # UUIDs identify a rule across configurations; regenerate deterministically.
    uuid = element.get("uuid")
    if uuid:
        digest = hashlib.sha256(f"{scrubber.salt}:{uuid}".encode()).hexdigest()
        element.set(
            "uuid",
            f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}",
        )


def _scrub_name_value(element: etree._Element, name: str, scrubber: Scrubber) -> str:
    parent = element.getparent()
    kind = parent.tag if parent is not None else "obj"

    if kind == "devices" or _looks_like_serial(name):
        return scrubber.serial(name)
    if kind in ("vsys", "device-group", "template", "template-stack"):
        return scrubber.name(name, kind)
    return scrubber.name(name, _short_kind(kind))


def _short_kind(tag: str) -> str:
    return {
        "address": "addr",
        "address-group": "grp",
        "service": "svc",
        "service-group": "svcgrp",
        "tag": "tag",
        "zone": "zone",
        "rules": "rule",
    }.get(tag, "obj")


def _looks_like_serial(value: str) -> bool:
    return value.isdigit() and len(value) == 12


def _scrub_text(element: etree._Element, scrubber: Scrubber) -> None:
    if element.text is None or not element.text.strip():
        return
    text = element.text.strip()
    tag = etree.QName(element).localname

    if tag in FREE_TEXT_ELEMENTS:
        element.text = scrubber.free_text(text)
        return

    if tag == "fqdn":
        element.text = scrubber.fqdn(text)
        return

    if tag in ("ip-netmask", "ip-range", "ip-wildcard", "translated-address"):
        element.text = scrubber.network(text)
        return

    if tag == "hostname":
        element.text = scrubber.fqdn(text).split(".")[0]
        return

    if tag == "filter":
        # A dynamic address group's membership is a tag expression such as
        # 'owner:payments' and 'prod'. The quoted names are references to tag
        # objects that are being renamed, so the expression has to be rewritten
        # alongside them -- otherwise the group matches nothing on the scrubbed
        # copy and every rule using it resolves to an empty address list.
        element.text = _scrub_tag_expression(text, scrubber)
        return

    if tag == "parent-dg":
        # A cross-reference to another device group by name. Renaming the group
        # without renaming the reference silently breaks the inheritance chain,
        # so objects defined in the parent stop resolving -- and a reproducer
        # that resolves differently from the original is worse than none.
        element.text = scrubber.name(text, "device-group")
        return

    if tag == "member":
        element.text = _scrub_member(text, element, scrubber)
        return

    if tag in ("domain", "dns-name"):
        element.text = "example.com"


def _scrub_tag_expression(expression: str, scrubber: Scrubber) -> str:
    """Rewrite the quoted tag names in a dynamic address group filter.

    Only the quoted literals are touched; the ``and``/``or``/``not`` operators
    and the parentheses are grammar, not data.
    """

    def replace(match: re.Match[str]) -> str:
        single, double = match.group(1), match.group(2)
        if single is not None:
            return f"'{scrubber.name(single, 'tag')}'"
        return f'"{scrubber.name(double or "", "tag")}"'

    return re.sub(r"'([^']*)'|\"([^\"]*)\"", replace, expression)


def _scrub_member(text: str, element: etree._Element, scrubber: Scrubber) -> str:
    """A <member> holds an object name, a literal address, or a keyword."""
    if text.lower() in PRESERVED_VALUES:
        return text

    parent = element.getparent()
    parent_tag = etree.QName(parent).localname if parent is not None else ""

    # Application and category members are vendor identifiers, not customer data.
    if parent_tag in ("application", "category", "source-user", "profile-setting", "group"):
        return text

    if _IPISH_RE.match(text):
        try:
            ipaddress.ip_network(text.split("-")[0].strip(), strict=False)
        except ValueError:
            pass
        else:
            return scrubber.network(text)

    return scrubber.name(text, "obj")


def scrub_string(xml: str, scrubber: Scrubber) -> str:
    """Convenience wrapper: scrub a configuration given as a string."""
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True)
    tree = etree.ElementTree(etree.fromstring(xml.encode("utf-8"), parser))
    scrub_tree(tree, scrubber)
    return etree.tostring(tree, pretty_print=True, encoding="unicode")
