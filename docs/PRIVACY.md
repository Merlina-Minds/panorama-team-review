# Data policy

This project analyses firewall configurations. Those files describe, in
complete detail, how an organisation's network is segmented and what can reach
what. A leaked one is a gift to an attacker and a serious breach of trust
towards whoever provided it.

The policy is therefore short and absolute.

---

## The rule

**No configuration traceable to a real estate is ever committed to this
repository.** Not raw, not partially redacted, not anonymised, not "just a
snippet to reproduce the bug".

This applies to:

- configuration exports, whole or partial
- test fixtures derived from a real configuration
- issue reports, pull request descriptions and code comments
- screenshots of reports
- committed report output of any format

## Where test data comes from

`tests/fixtures/generator.py` — the only sanctioned source. It builds
synthetic Panorama and PAN-OS configurations that are structurally realistic
(nested device groups, dynamic address groups, broken references, expired
rules, the shapes that actually cause bugs) and are **invented rather than
transformed from real data**.

Everything it emits uses:

| Kind | Range |
|---|---|
| IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) and RFC 1918 space |
| IPv6 | `2001:db8::/32` (RFC 3849) |
| Names | `example.com` and friends (RFC 2606) |

Generation is deterministic given a seed, so tests can assert on exact output.
Need a case the generator does not produce? **Extend the generator.** That is a
normal, welcome contribution — see [CONTRIBUTING.md](../CONTRIBUTING.md).

## How this is enforced

Not by everyone remembering it. `tools/check_no_customer_data.py` runs as a
pre-commit hook and as the first CI job, and blocks:

- IPv4/IPv6 addresses outside the documentation and private ranges
- hostnames and email domains that are not RFC 2606 example names
- 12-digit PAN-OS device serial numbers
- PAN-OS API keys, password hashes, private keys, cloud credentials
- filenames that look like configuration exports (`running-config.xml`, dated
  `.tgz` archives, …) regardless of their content

It is biased towards false positives on purpose: an unnecessary block costs a
maintainer a minute, a missed leak is permanent and public.

Install it:

```bash
pip install pre-commit
pre-commit install
```

If a hit is genuinely wrong, append `# allow-customer-data-check` to the line
and explain why in the commit message. Use this sparingly and never to silence
a real address.

## Working with a real backup

Your own backups are fine to work with locally — the tool is built for exactly
that. Keep them outside version control:

```text
private/     # gitignored
backups/     # gitignored
out/         # gitignored
reports/     # gitignored
```

`.gitignore` already covers these, plus `config/config.yaml` and
`config/inventory.yaml`, since a real inventory maps your networks to your
teams and is itself sensitive. Only the `*.example.yaml` files are tracked.

The tool never writes anything outside its configured output directory and
never transmits anything anywhere.

## Reporting a bug against a real configuration

Do **not** attach the configuration. Instead, in order of preference:

**1. Reproduce it with the generator.** Best outcome by far: the reproducer
becomes a regression test and stays in the suite forever.

**2. Describe the structure.** Very often enough: "a rule whose destination is
a nested address group where the inner group is defined in the parent device
group and contains an ip-range" is a complete bug report.

**3. Send a scrubbed configuration privately**, if the first two fail.

```bash
pan-review scrub running-config.xml scrubbed.xml
```

### What `scrub` does and does not do

It replaces addresses, object names, group names, zone names, device-group
names, hostnames, FQDNs, serial numbers, rule UUIDs and **all free text**
(descriptions are replaced wholesale, not parsed — a description field can
contain anything, and a redactor that tries to be selective will eventually
miss something). Cross-references are rewritten consistently, so the scrubbed
configuration still resolves the same way the original did.

**It is pseudonymisation, not anonymisation.** Read this before sharing
anything it produces:

- **Structure is preserved exactly.** Rule counts, group nesting, device-group
  topology, the number of vsys. For a small or distinctive estate, that shape
  alone can identify the organisation.
- **The mapping is deterministic per salt**, which is what keeps the
  configuration self-consistent — and therefore reversible by anyone holding
  the salt. Omit `--salt` for a random one that is never stored.
- **Semantics are preserved.** Prefix lengths, port numbers, application names
  and rule ordering survive, because a reproducer that behaves differently from
  the original is useless. Some of that is information.

So: scrubbed output may be shared with people you would already trust with a
network diagram. **It must never be published**, attached to a public issue, or
committed. The data guard blocks scrubbed files too, by design.

## Reports contain the same data

Generated reports describe your network as completely as the configuration
does. Treat them accordingly:

- Send a team's report to that team, not to a company-wide share.
- The Excel workbook is designed to be filled in and returned — agree a channel
  for that which is not a public wiki.
- The PDF carries the configuration checksum, which is useful for audit and
  also identifies the exact backup it came from.

## Questions

If you are unsure whether something is safe to share, it is not. Ask first:

- Open an issue describing the *situation* without the data, or
- email [kontakt@merlina-minds.de](mailto:kontakt@merlina-minds.de) if even the question would reveal
  something.

There is no such thing as a wasted question here. Sending a configuration you
should not have sent cannot be undone; asking about it first costs a day.
