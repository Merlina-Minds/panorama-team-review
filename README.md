# panorama-team-review

Generate **owner-centric firewall rule reviews** from offline Palo Alto Panorama
and PAN-OS configuration backups.

Existing tools export firewall rules from a firewall administrator's point of
view: a flat list of rules. This one answers the two questions a system owner
actually has:

- **What can my systems reach?**
- **Who can reach my systems?**

It reads a configuration backup from disk, resolves address and service objects
into real networks and ports, works out which team each rule concerns and on
which side of the connection they sit, and produces a report per team as HTML,
Excel, PDF and JSON.

The tool performs **no network access** by default. There are two optional,
opt-in exceptions: hit-count collection and live configuration fetch. Both are
disabled unless explicitly enabled, and both are read-only.

---

## Table of contents

- [Why](#why)
- [Quick start](#quick-start)
- [See it first](#see-it-first)
- [How rules are attributed to teams](#how-rules-are-attributed-to-teams)
- [Output formats](#output-formats)
- [Tickets and dates in rule descriptions](#tickets-and-dates-in-rule-descriptions)
- [Cleanup findings](#cleanup-findings)
- [Rule hit counts](#rule-hit-counts)
- [Fetching the configuration live](#fetching-the-configuration-live)
- [Running from cron](#running-from-cron)
- [Commands](#commands)
- [Installation](#installation)
- [Customer data](#customer-data)
- [Documentation](#documentation)
- [How this project was built](#how-this-project-was-built)
- [License](#license)

---

## Why

Firewall rule reviews fail for a predictable reason: the people who know
whether a rule is still needed — the system owners — are handed a spreadsheet
of five thousand rules written in the firewall's vocabulary. Object group
names, zones, device groups. They cannot tell which rules concern them, so they
approve everything, and the rulebase never shrinks.

This tool inverts the direction. It starts from *your systems*, uses an
inventory that maps networks to teams, and gives each team only the rules that
touch their own address space — labelled inbound or outbound, with the far side
resolved to actual addresses, the ticket that authorised the rule linked, and
the cleanup candidates called out.

## Quick start

The package is not published to PyPI yet, so install it from a checkout of this
repository (see [Installation](#installation) for uv and venv details):

```bash
# Not available yet — the package is not on PyPI:
# pip install panorama-team-review

git clone https://github.com/Merlina-Minds/panorama-team-review
cd panorama-team-review
uv sync                                      # create the env and install

# Write a commented configuration and inventory to the current directory
uv run pan-review init .

# Edit inventory.yaml: map your networks to teams
# Edit config.yaml: point input.backup_dir at your backup directory

uv run pan-review -c config.yaml validate    # check the configuration
uv run pan-review -c config.yaml inspect     # see what the tool reads from a backup
uv run pan-review -c config.yaml run         # produce the reports
```

## See it first

[`example/`](example/) holds finished reports from a complete — invented —
estate, together with the configuration and inventory that produced them. The
HTML files are self-contained, so they open in a browser with nothing
installed:

| File | What it shows |
|---|---|
| [`example/reports/payments_firewall-review.html`](example/reports/payments_firewall-review.html) | A typical owner's report |
| [`example/reports/reporting_firewall-review.html`](example/reports/reporting_firewall-review.html) | A team that owns one host inside somebody else's network, so almost nothing in its report is its own to decide |
| [`example/reports/00_OVERVIEW_all-teams.html`](example/reports/00_OVERVIEW_all-teams.html) | The firewall team's cross-team view |

Nothing in it comes from a real configuration; see
[example/README.md](example/README.md).

To build your own synthetic estate instead:

```bash
git clone https://github.com/Merlina-Minds/panorama-team-review
cd panorama-team-review
uv sync --extra dev --extra pdf
# Plain venv instead: python -m venv .venv && source .venv/bin/activate && pip install -e ".[dev,pdf]"

mkdir -p demo/backups
uv run python -c "
import sys; sys.path.insert(0, 'tests')
from fixtures.generator import generate_panorama
open('demo/backups/config.xml','w').write(generate_panorama())
"
cp config/inventory.example.yaml demo/inventory.yaml
printf 'input:\n  backup_dir: ./backups\nteams_file: inventory.yaml\noutput:\n  directory: ./reports\n' > demo/config.yaml
uv run pan-review -c demo/config.yaml run
```

## How rules are attributed to teams

Five resolvers, applied in a configurable order. They fall into two classes,
and the distinction is the core of the design:

| Resolver | Matches on | Knows direction |
|---|---|---|
| `inventory` | The rule's resolved networks vs. the team's assets | **yes** |
| `zone` | A `from`/`to` zone assigned to the team | **yes** |
| `tag` | A rule tag matching a configured ownership convention, such as `owner:payments` | no |
| `regex` | Rule name or description pattern | no |
| `device_group` | The device group the rule lives in | no |

Only `inventory` and `zone` can tell **inbound** from **outbound**, because
only they know *which side* of the rule matched. The others attribute a rule to
a team without direction, and those land in a `related` section.

`inventory` always runs. The others honour `stop_after_first_match`, so a
precise tag is not drowned out by a broad device-group assignment.

The `tag` resolver reads only tags shaped like the convention you configure in
`ownership.tag_prefixes` / `tag_suffixes`. A PAN-OS tag is a classification
first — `GlobalProtect-Clients` says what an object is, and dynamic address
groups are built on that — so anything not matching the convention is left
alone rather than read as an owner.

### Your rules, and the rules that merely cover you

Cutting across all five resolvers is a second question, and it decides what a
report may *ask* of its reader.

A rule that names an object inside a team's address space — or carries their
tag or zone — was written for them. Somebody requested it on their behalf, and
they are the ones who can say whether it is still needed. Those are **your
rules**.

A rule that names `10.0.0.0/8`, or `any`, covers that team along with everybody
else. Ping anywhere, DNS, Active Directory, patching, monitoring: the
estate-wide baseline. Those are **rules that also cover your networks**, and
they are reported very differently:

- they are listed, because a team that cannot see them requests access they
  already have — and because somebody who must *not* have it needs the chance
  to say so;
- they carry no findings, no severity badges and no *Decision* column, because
  the rule is not theirs to fix and a finding they cannot act on is just work
  arriving in the wrong inbox. Those findings stay in the combined report,
  which is the firewall team's list.

Formally: a rule is yours when one of its resolved networks lies *inside* one of
your networks, and merely covers you when your network lies inside a larger one
the rule names. CIDR blocks either nest or are disjoint, so there is no third
case. `ownership.covering_supernet_bits` widens the tolerance for inventories
that list individual hosts, where a rule naming the /24 those hosts live in is
still recognisably about them.

On the estate this was built against, the split moved about a third of every
report out of the review pile and halved the cleanup candidates.

### Names, not addresses

`10.20.12.0/24` tells a system owner nothing. `grp-time-servers` tells them what
the rule is for — and it is the string a change request has to cite, because the
firewall does not accept an address where it expects an object.

So the rule tables lead with the object names and keep the addresses behind
them, one tooltip per object: hovering `grp-dns-servers` shows what is in it,
without a group of forty hosts taking forty lines of the page. The Excel
workbook, which has no tooltips, carries names and addresses as separate
columns.

Each report also lists **the objects and groups that live inside that team's
networks** — every address object and group whose addresses fall entirely within
their address space. That is the answer to "what is my network called in the
firewall?", which nobody can derive from the outside: a naming convention is
only obvious to the people who wrote it.

### Rule order

Rules appear in the order the firewall evaluates them, because that order is
part of their meaning: the first match wins, so a broad allow above a narrow
rule makes the narrow one dead, and a deny above an allow silently overrides it.

Panorama stores that order nowhere — it follows from where a rule was defined:

```text
shared pre-rules
device-group pre-rules    top-most parent first, the firewall's own group last
the firewall's own local rules
device-group post-rules   the firewall's own group first, top-most parent last
shared post-rules
the default rules
```

Reports group rules into those blocks and label each with the firewalls that
evaluate it and how many rules it holds in total — so a reader can see that
rules they are not shown sit between the ones they are.

One honest limitation: that sequence is per firewall. Rules in two sibling
device groups are never evaluated by the same device, so no single total order
over a whole estate exists. Where a team's rules share one device-group chain —
the common case — the order shown is exact. Where they do not, sibling branches
are kept in separate labelled blocks rather than interleaved into a sequence no
firewall ever evaluates.

### Teams from a naming convention

Estates that provision networks automatically already encode ownership in their
object names. Rather than maintaining a parallel inventory that drifts, read the
convention directly — a new account then appears in the next report with no
configuration change:

```yaml
ownership:
  derive_teams:
    - id: aws-accounts
      source: address-group        # or address-object, or tag
      pattern: '^aws-(?P<app>.+)-(?P<stage>[pdust])-(?P<nr>\d+)$'
      team_id: "{app}-{stage}"
```

Derived teams are merged with `teams_file`, and an explicit entry always wins —
so the convention covers the regular part of the estate while infrastructure and
exceptions stay hand-written. Placeholder addresses that appear in many groups
at once (loopback and friends) are excluded, since one of them would otherwise
make every rule touching it land in every team's report.

A rule legitimately belongs to two teams at once — the source team and the
destination team — and appears in both reports, described from each one's
perspective. Every rule in a report carries the evidence for why it is there,
so a wrong attribution can be spotted and corrected.

### Starting the inventory

Writing one from scratch is where adoption usually stalls, so the tool derives
a draft from how the configuration already groups its addresses:

```bash
# Which grouping fits this estate? Writes nothing, just reports.
pan-review suggest-inventory --backup config.xml --compare

# Produce the draft using the grouping that fits best
pan-review suggest-inventory --backup config.xml --group-by zone -o inventory.draft.yaml
```

Four groupings are available — `device-group`, `usage` (which device group's
rules actually use a network), `zone` and `tag` — and which one works depends
entirely on how the estate was built. `--compare` runs all four and reports the
share of rule-referenced networks each would cover, so the choice is made on
evidence rather than on a guess.

The draft marks team names and contacts as `TODO` rather than inventing them,
lists the networks no candidate claims, and never widens a network past
`--min-prefix`, because an over-wide asset silently claims other teams' rules.
It is a starting point to read and cut down.

### The inventory

```yaml
teams:
  - id: payments
    name: Payments Platform
    contact: payments-team@example.com
    assets:
      - cidr: 10.20.10.0/24
        label: Payments production
      - cidr: 10.20.12.5/32
        label: payment-gw01 (settlement gateway)
    tags: [owner:payments]        # optional, additive
    device_groups: [DG-Payments]  # optional
    zones: [zone-payments]        # optional, carries direction
    name_patterns: ['^PAY-']      # optional
```

Only `id` is required. A team with no matching criteria at all can never
receive a rule, and `pan-review validate` says so.

Address and service **groups are flattened**, including nested groups and
dynamic address groups, whose tag expressions (`'prod' and not 'legacy'`) are
evaluated offline. Device-group inheritance is followed exactly as PAN-OS does
it: nearest scope first, then each parent, then `shared`.

Things that genuinely cannot be resolved from a backup — external dynamic
lists, regions, FQDNs — are reported as unresolved rather than dropped, because
a silently omitted EDL understates a system's exposure.

## Output formats

| Format | Purpose |
|---|---|
| **HTML** | What owners actually use. One self-contained file, no external requests, searchable, collapsible sections, a jump bar, severity filters, per-rule detail, clickable ticket links. Opens fine on an air-gapped management host. |
| **Excel** | The working format. Owners fill in the *Decision* (keep / remove / modify / unclear) and *Comment* columns and send the workbook back. One sheet per direction for the team's own rules, one for the rules that merely cover them — that one without a Decision column. Every row carries the object names a change request has to cite. |
| **PDF** | The audit artefact: frozen per date, with the configuration checksum on the cover page. |
| **JSON** | The complete machine-readable record. Input to `pan-review diff`, and a feed for a CMDB or ticket system. |

## Tickets and dates in rule descriptions

In practice a rule's change history lives in its description field:

```text
CHG0041234 open 443 for payment gw, requested by A. Beck, valid until 31.12.2026
```

Configurable patterns turn that into a linked ticket reference, a requester and
an expiry date that drives the `EXPIRED_RULE` and `EXPIRING_SOON` findings:

```yaml
metadata:
  ticket_patterns:
    - name: servicenow
      regex: '\b(?P<id>(?:CHG|INC|REQ)\d{7,})\b'
      url_template: "https://example.service-now.com/nav_to.do?uri=task.do?sysparm_query=number={id}"

  # One keyword list, applied to every date format below.
  role_keywords:
    expires: [until, expires, "valid until", bis, "gueltig bis"]
    created: [created, requested, erstellt, beantragt]

  date_patterns:
    - name: iso                    # 2026-12-31
      regex: '\b\d{4}-\d{2}-\d{2}\b'
      date_format: "%Y-%m-%d"
    - name: dot-dmy                # 31.12.2026
      regex: '\b\d{1,2}\.\d{1,2}\.\d{4}\b'
      date_format: "%d.%m.%Y"
```

ISO and dotted dates are both recognised out of the box, along with
`31/12/2026`. The keyword list is shared across formats — the words around a
date do not change because the date is written differently — so an estate using
more than one format maintains it once.

### Dates that no keyword explains

Plenty of estates record edits positionally instead:

```text
CHG0041234 (a.beck: 2024-05-30)      ticket, the admin who touched the rule, the date
CHG0041299 a.beck 2027-07-18
```

There is no word here for the keyword matcher to find, so the date comes out as
*purpose not stated* — throwing away both halves: who, and the fact that it is
an edit rather than an expiry. `metadata.change_patterns` spells the convention
out:

```yaml
metadata:
  change_patterns:
    - '\((?P<requester>[A-Za-z][\w.-]{1,29})\s*[:,]?\s*(?P<date>\d{4}-\d{2}-\d{2})\)'
    - '\b(?P<requester>[A-Za-z][A-Za-z0-9._-]{1,19})\s+(?P<date>\d{4}-\d{2}-\d{2})\b'
```

Nothing is recognised by default, because a pattern loose enough to catch a bare
username also matches the word before *any* date. These run only against dates
the keywords could not explain, so `valid until 2026-12-31` stays an expiry
rather than becoming "changed by until".

The payoff beyond a better label: a change dated in the future has not happened,
so `IMPOSSIBLE_DATE` reports it. On the estate this was written against that
turned almost every anonymous date into an attributed edit, and surfaced a
handful stamped years ahead.

## Cleanup findings

`pan-review checks` lists them all. The severity scale is deliberately
conservative — a report that flags a correct rule is one that stops being read.

| Code | Severity | Meaning |
|---|---|---|
| `ANY_ANY` | high | Source and destination both `any` |
| `EXPIRED_RULE` | high | Past the expiry stated in its own description |
| `ANY_SOURCE` / `ANY_DESTINATION` | medium | One side unrestricted. `ANY_DESTINATION` stays silent when every destination zone is in `analysis.internet_zones` — an egress rule's destination *is* the internet, and there is no tighter way to write it. |
| `ANY_SERVICE` | medium | No service and no App-ID restriction |
| `NO_LOGGING` | medium | Traffic leaves no record |
| `UNUSED_RULE` | medium | Zero hits — **requires hit counts** |
| `BROAD_NETWORK` | low | Network broader than the configured threshold |
| `FLAGGED_OBJECT` | configurable | References an object whose name matches one of your own markers, e.g. `OUTDATED_` |
| `STALE_RULE` | low | No traffic for a long time — **requires hit counts** |
| `EMPTY_GROUP` | low | Resolves to no addresses; matches nothing |
| `NO_DESCRIPTION` | low | Purpose cannot be established |
| `IMPOSSIBLE_DATE` | low | The description records a change, creation or review dated in the future — almost always a mistyped year |
| `EXPIRING_SOON` / `NO_TICKET` / `DISABLED_RULE` / `UNRESOLVED_OBJECT` | info | — |

Checks that need data the backup does not contain **do not run at all** rather
than guessing. Telling an owner to delete a rule that is in fact in use costs
more trust than the finding is worth.

## Rule hit counts

Hit counters are **runtime state and are never contained in a configuration
backup**. A PAN-OS or Panorama export holds the policy, not the counters. So
"is this rule still used?" — the most useful question in a cleanup — cannot be
answered offline.

Collecting them is therefore a separate, opt-in module. It is one of only two
parts of this tool that touch the network, it issues read-only `show`
operational commands exclusively, and the command is checked against that
before it is sent.

```yaml
hitcounts:
  enabled: true
  devices: [panorama.example.com]
  api_key_env: PAN_API_KEY     # never read from the config file
  verify_tls: true
  cache_dir: ./cache
```

The recommended arrangement keeps reporting offline:

```cron
# Collect counters once a night (this one talks to the network)
0 2 * * *  PAN_API_KEY=... pan-review -c /etc/ptr/config.yaml collect-hitcounts

# Reports stay fully offline and reuse the cache
0 6 * * 1  pan-review -c /etc/ptr/config.yaml -q run --no-network
```

Use an API key bound to a read-only administrator role.

## Fetching the configuration live

If the tool already reaches the devices for hit counts, it can pull the
configuration backup from the same place instead of depending on a separate
scheduled export landing on disk. This is the second optional network feature,
and like hit-count collection it is off by default and read-only — only the
configuration export endpoint is ever called.

**The connection is the same as hit-count collection**: devices, API key and
TLS come from the `hitcounts` section, so the access is configured once. You do
not have to collect hit counts to fetch — leave `hitcounts.enabled: false` and
still list the devices there.

```yaml
input:
  backup_dir: /var/backups/panorama
  fetch:
    enabled: true
hitcounts:
  devices: [panorama.example.com]   # connection only; collection stays off
  api_key_env: PAN_API_KEY
```

With `input.fetch.enabled`, `pan-review run` downloads each device's running
configuration into `backup_dir` first, then analyses the newest exactly as if a
scheduled export had written it there. A fetch failure is a warning, not fatal:
the run falls back to what is already on disk, and `max_age_days` still guards
against that being stale. It can also be scheduled on its own so reporting
stays offline:

```cron
0 1 * * *  PAN_API_KEY=... pan-review -c /etc/ptr/config.yaml fetch-backup
0 6 * * 1  pan-review -c /etc/ptr/config.yaml -q run --no-network
```

## Running from cron

`pan-review run` with no arguments takes the newest backup from the configured
directory, writes into a dated subdirectory, and stays silent on success with
`-q`.

```cron
0 6 * * 1  pan-review -c /etc/panorama-team-review/config.yaml -q run
```

Exit codes are meaningful, so monitoring can distinguish *the tool is broken*
from *the firewall stopped writing backups*:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected failure |
| 2 | Configuration or inventory problem |
| 3 | No usable backup found, or the newest one is too old |

Set `input.max_age_days` to make a silently broken backup job fail loudly
instead of feeding stale data into a review cycle.

## Commands

```text
pan-review run                Produce the reports. The cron entry point.
pan-review validate           Check configuration and inventory, touch no backup.
pan-review inspect            Summarise what the tool reads from a backup.
pan-review checks             List the analysis checks and their codes.
pan-review diff OLD NEW       Compare two JSON reports: what changed since last time.
pan-review init [DIR]         Write a commented example configuration.
pan-review suggest-inventory  Derive a draft inventory from a configuration.
pan-review collect-hitcounts  Refresh the hit-count cache (network access).
pan-review fetch-backup       Pull the running configuration from the devices (network access).
pan-review scrub SRC DST      Pseudonymise a configuration for a bug report.
```

Useful flags on `run`: `--backup FILE` for a manual one-off, `--team ID` to
limit the run, `-f FORMAT` to override output formats, `--no-network` to force
offline operation, `--as-of DATE` to reproduce a past review date.

`--sample N` writes only N per-team reports while still analysing the whole
estate, which is the fast way to check a configuration change without producing
hundreds of files:

```bash
pan-review -c config.yaml run --sample 5 -f html
```

The five are picked as a spread across team size and naming families rather
than as the first five — otherwise the sample is five variations on the largest
team, and on an estate whose ids share a prefix (`nonstandard-*` from a
convention that did not match) every one of them can come from that family and
none from the teams the report is for.

## Installation

Requires Python 3.11 or newer. Linux is the primary target; macOS and Windows
work.

The package is not published to PyPI yet, so install it from a checkout of this
repository. Once it is on PyPI, the direct install will be:

```bash
# Not available yet:
# pip install panorama-team-review          # core: HTML, Excel, JSON
# pip install 'panorama-team-review[pdf]'   # adds PDF output
# pip install 'panorama-team-review[api]'   # adds hit-count collection
```

### With uv (recommended)

[uv](https://docs.astral.sh/uv/) creates the virtual environment and installs
the project in one step:

```bash
git clone https://github.com/Merlina-Minds/panorama-team-review
cd panorama-team-review

uv sync                            # core: HTML, Excel, JSON
uv sync --extra pdf                # adds PDF output
uv sync --extra pdf --extra api    # adds PDF output and hit-count collection

uv run pan-review --help           # run without activating the environment
```

### With a plain venv

```bash
git clone https://github.com/Merlina-Minds/panorama-team-review
cd panorama-team-review

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e .                   # core: HTML, Excel, JSON
pip install -e '.[pdf]'            # adds PDF output
pip install -e '.[pdf,api]'        # adds PDF output and hit-count collection

pan-review --help
```

PDF output uses WeasyPrint, which needs system libraries:

```bash
# Debian / Ubuntu
apt install libpango-1.0-0 libpangoft2-1.0-0 libcairo2
# RHEL / Fedora
dnf install pango cairo
```

Without them the other three formats work unchanged, and `pan-review validate`
tells you PDF is unavailable rather than failing mid-run.

## Customer data

**No real configuration, from any source, is ever committed to this
repository.** All test data comes from a generator
(`tests/fixtures/generator.py`) that invents its own estates using only
documentation address ranges (RFC 5737, RFC 3849) and `example.com` names.

That guarantee is enforced mechanically, not by convention: a pre-commit hook
and a CI job (`tools/check_no_customer_data.py`) scan for routable addresses,
real hostnames, device serials and secrets, and block the commit. If you are
reporting a bug against a real configuration, `pan-review scrub` produces a
pseudonymised reproducer — but read [docs/PRIVACY.md](docs/PRIVACY.md) first,
because pseudonymisation is not anonymisation and scrubbed output must not be
published either.

## Documentation

| Document | Contents |
|---|---|
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every setting, with examples |
| [docs/PRIVACY.md](docs/PRIVACY.md) | The data policy, the guard, and the scrubber's limits |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, architecture, how to add a check |
| [SECURITY.md](SECURITY.md) | Threat model and how to report a vulnerability |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## How this project was built

The implementation was written by an AI assistant (Anthropic's Claude), working
from a specification, review and acceptance by the maintainers. Design
decisions — the owner-centric data model, the offline-by-default constraint,
the rule that a check without data stays silent — came out of that dialogue and
are documented in the code where they are not obvious.

This is stated because it is relevant to anyone deciding whether to trust the
tool or contribute to it:

- **What that means for correctness.** The test suite is comprehensive
  (379 tests, ~90% line coverage) and every module carries reasoning for why it
  behaves the way it does. It is not a substitute for review, and the areas
  where coverage is thinnest are named openly in
  [CONTRIBUTING.md](CONTRIBUTING.md).
- **What has not been verified.** As of the first release, the tool has been
  exercised only against synthetically generated configurations. It has not yet
  been run against a production Panorama estate. Treat early reports as
  something to check, not something to sign off.
- **What that means for contributions.** Nothing is different. Pull requests
  are reviewed on their merits, and the architecture notes in
  [CONTRIBUTING.md](CONTRIBUTING.md) exist so that changes do not have to
  reverse-engineer the intent.

## License

Apache License 2.0. See [LICENSE](LICENSE).

Not affiliated with or endorsed by Palo Alto Networks. "Palo Alto Networks",
"PAN-OS" and "Panorama" are trademarks of Palo Alto Networks, Inc.
