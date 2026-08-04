# Contributing

Thanks for considering it. This document covers the setup, the architecture,
and the two rules that are not negotiable.

## How this codebase came about

The implementation was written by an AI assistant (Anthropic's Claude), from a
specification and under review by the maintainers. It is stated here rather
than buried, because it changes what you should expect when reading the code.

**What follows from it, practically:**

- **The comments are load-bearing.** Where a decision went one way and could
  reasonably have gone another, the reason is written down at that spot. If you
  are about to change something and the comment explains why it is the way it
  is, that reasoning is the thing to argue with.
- **Consistency is high, judgement is not guaranteed.** The code is uniform and
  the tests are thorough, but uniformity is not correctness. Several real bugs
  were found only by rendering output and looking at it, or by a reviewer
  asking a question the tests did not.
- **Coverage is not evenly distributed.** The gaps are listed under
  [Testing](#testing) rather than left for you to discover.
- **Nothing about review changes.** Pull requests are judged on their merits.
  Whether a human or a model wrote a patch does not make it more or less
  welcome, and does not exempt it from tests.

If you find something that looks confidently wrong, it probably is — those are
the most valuable issues to open.

## The two rules

1. **No customer data, ever.** Not in code, tests, issues, screenshots or
   commit messages. All test data comes from `tests/fixtures/generator.py`.
   See [docs/PRIVACY.md](docs/PRIVACY.md) — this is enforced by a pre-commit
   hook and a CI job, not by trust.

   **The hook cannot see the case that actually happens.** It catches routable
   addresses, serials, hostnames and secrets. What it cannot catch is a real
   object name, ticket id, administrator or naming convention quoted in a
   *comment* — and that is precisely what a good explanation reaches for, since
   the bug being explained came from a real estate. `net_aws_prod_orders-db-…`
   and `CHG0041234 (a.beck: 2024-05-30)` are indistinguishable to a regex, and
   only one of them is safe.

   So: every example in a comment, docstring, test or document comes from the
   invented estate — the teams, networks, object names, tickets and people that
   `tests/fixtures/generator.py` and `example/` already use. Describe the shape
   of what you found; use their vocabulary to say it.

2. **A check that cannot be sure stays silent.** The tool's value rests on
   system owners believing what it tells them. One rule wrongly flagged as
   unused teaches a team to ignore the whole report. Where the data to decide
   is absent — hit counts above all — the correct behaviour is to say nothing.

## Setup

```bash
git clone https://github.com/Merlina-Minds/panorama-team-review
cd panorama-team-review

uv venv && uv pip install -e ".[dev,pdf,api]"
# or: python -m venv .venv && .venv/bin/pip install -e ".[dev,pdf,api]"

pre-commit install     # installs the customer-data guard
pytest                 # should be green
```

PDF tests need the WeasyPrint system libraries; they skip cleanly without them:

```bash
apt install libpango-1.0-0 libpangoft2-1.0-0 libcairo2   # Debian/Ubuntu
dnf install pango cairo                                   # RHEL/Fedora
```

Try a change end to end against a synthetic estate:

```bash
mkdir -p demo/backups
python -c "
import sys; sys.path.insert(0, 'tests')
from fixtures.generator import generate_panorama
open('demo/backups/config.xml','w').write(generate_panorama())
"
cp config/inventory.example.yaml demo/inventory.yaml
printf 'input:\n  backup_dir: ./backups\nteams_file: inventory.yaml\noutput:\n  directory: ./reports\n' > demo/config.yaml
pan-review -c demo/config.yaml -v run
```

## Architecture

A one-way pipeline. Each stage only knows about the one before it.

```text
  [optional, opt-in, network access]  fetch.py + panos_api.py  pull the running config over the API
    ▼
backup file
    │  parse/loader.py      find, decompress, parse XML safely
    ▼
  Snapshot                  parse/panos.py, parse/common.py
    │  resolve/objects.py   groups → networks, services → ports
    │  enrich/metadata.py   descriptions → tickets, dates, requester
    │  enrich/hitcount.py   [optional, opt-in, network access]
    │  resolve/ownership.py rules → teams, with direction and coverage
    │  resolve/evaluation.py where a rule sits in the evaluation order
    │  analyze/findings.py  cleanup checks
    │  analyze/inventory_gaps.py  object names vs. the inventory
    ▼
  ReportBundle              report/build.py
    │
    ▼
  html.py  excel.py  pdf.py  json_report.py
```

Two boundaries carry most of the design:

**`model.py` is the contract.** The parsers are the only code that knows PAN-OS
XML exists. Everything downstream works on the normalised model, which is why
supporting another vendor would mean writing another parser and touching
nothing else.

**`ReportBundle` is fully serialisable.** That is what makes the JSON output a
complete record rather than a summary, and what makes `pan-review diff`
possible. It is also why presentation-relevant facts that are *derived* --
which policy block a rule sits in, its rank in the evaluation order, whether it
is a team's own rule -- are computed in `build.py` and stored on the model
rather than recomputed in each renderer. Four renderers deriving the same thing
four times is four chances to derive it differently.

### Where things live

| Path | Responsibility |
|---|---|
| `model.py` | The normalised data model. Start here. |
| `config.py` | Configuration schema and validation |
| `parse/` | PAN-OS and Panorama XML → `Snapshot` |
| `resolve/objects.py` | Group flattening, scope inheritance, tag filters |
| `resolve/nettrie.py` | Prefix trie for fast CIDR overlap queries |
| `resolve/ownership.py` | Rule → team attribution, direction, and whether the rule is the team's own or merely covers it |
| `resolve/evaluation.py` | PAN-OS evaluation order and the policy blocks it falls into |
| `resolve/inventory.py` | Team/asset inventory loading |
| `enrich/metadata.py` | Tickets, dates and requesters from free text |
| `enrich/hitcount.py` | Optional hit-count collection |
| `panos_api.py` | Shared read-only PAN-OS/Panorama XML-API transport (the only network code) |
| `fetch.py` | Optional live configuration fetch, reusing the hitcounts connection |
| `analyze/findings.py` | The cleanup checks |
| `analyze/inventory_gaps.py` | Object names checked against the inventory: who owns which network |
| `report/` | Assembly and the four renderers |
| `privacy/scrub.py` | Pseudonymiser for bug reports |
| `tools/check_no_customer_data.py` | The repository data guard |

## Testing

```bash
pytest                                        # all
pytest tests/test_ownership.py -v             # one module
pytest --cov=panorama_team_review --cov-report=term-missing
```

Guidelines that matter here more than usual:

- **Assert on behaviour that would mislead a reader if wrong.** Direction,
  resolved addresses, whether a check fires. Not on incidental formatting.
- **Every bug fix gets a regression test**, expressed through the generator.
- **Name the case, not the function.** `test_any_source_to_our_systems_is_inbound`
  says what the system does; `test_resolve_2` does not.
- **Test data comes from the generator.** No exceptions.

### Where coverage is thin

Line coverage sits around 90%, which is not the useful number. These are the
areas where a contribution would genuinely reduce risk, worst first:

| Area | State |
|---|---|
| Real configurations | **None.** Everything runs against the generator, which encodes assumptions about what real estates look like |
| Hit-count API | Fakes only. `_list_vsys` and `_list_device_groups` have never spoken to a device |
| Configuration fetch | Fakes only. The export transport in `panos_api.py` has never spoken to a device |
| Multi-vsys, template stacks, `dg-meta-data` | Code paths exist, no test case — no sample was available |
| PDF and Excel content | Verified as "is a PDF" and "has these sheets", not on cell or page content |
| Scale | Nothing above ~100 rules. The prefix trie should hold up; that is a claim, not a measurement |
| CLI error paths | `keep_runs` pruning, `init` fallback, partial failure under `select: all` |

The first three close as soon as anyone runs this against a production estate
and reports what broke — structurally, without the data. See
[docs/PRIVACY.md](docs/PRIVACY.md) for how to do that safely.

## Common tasks

### Add a cleanup check

Register a function in `analyze/findings.py`:

```python
@check("MY_CHECK")
def _my_check(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    """One-line summary shown by `pan-review checks`."""
    if not <condition>:
        return []
    return [_finding(
        rule, "MY_CHECK", "Short title", Severity.MEDIUM,
        "What is true about this rule.",
        "What the owner should do about it.",
    )]
```

Then: add the code to `AnalysisConfig.enabled_checks` and to
`config/config.example.yaml`, add tests for both the firing and the
non-firing case, and document it in the README table.

If your check needs data a backup does not contain, return `[]` when that data
is absent. See `UNUSED_RULE` for the pattern.

### Add an ownership resolver

Add a `_resolve_<name>` method to `OwnershipResolver`, extend the `order`
literal in `OwnershipConfig`, and dispatch to it in `resolve()`. Two decisions
have to be made deliberately rather than by default:

- **Direction.** If the resolver cannot tell which side of the rule the team is
  on, use `_add_related` rather than inventing one.
- **Coverage.** Call `view.claim_own(reason)` when the match is evidence that
  somebody wrote this rule *for* the team — a tag, a zone, an object inside
  their address space. Call `view.note_covered(reason)` when the team was
  merely included in something broader. The reason is shown to the reader, so
  write it as a sentence they can check, not as a code.

Getting the second one wrong is the more expensive mistake: claiming ownership
too eagerly puts estate-wide rules back into the pile a team is asked to
review, which is the failure the split exists to fix.

### Support another PAN-OS construct

Extend `parse/common.py` (for anything that appears in both hierarchies) or
`parse/panos.py` (for hierarchy-specific placement), add it to `model.py`, and
teach the generator to emit it so it is covered by tests.

### Change a report's appearance

Templates are in `report/templates/`. `team_report.html.j2` is the interactive
report, `team_report_print.html.j2` the PDF layout — deliberately separate,
because the two want genuinely different layouts and one template with a print
stylesheet produces a bad version of both.

Colour never carries meaning alone: every severity and direction badge pairs
its colour with an icon and a word, so reports stay readable in greyscale
print and for readers with colour vision deficiency. Keep that property.

Note that Jinja autoescaping is on and must stay on — rule names come out of a
file this tool does not control. Stylesheets are the one exception, loaded as
`Markup` in `report/html.py`.

## Style

- `ruff check src tests tools` and `ruff format --diff` before pushing
- Type hints on public functions; `mypy src` should not regress
- 100-column lines
- Comments explain *why*, not *what*. If a decision was between two reasonable
  options, say which and why — that is the comment worth reading in a year.

## Pull requests

1. Branch off `main`
2. Make the change with tests
3. `pytest && ruff check src tests tools`
4. Update the README or `docs/` if behaviour changed
5. Add a `CHANGELOG.md` entry under *Unreleased*
6. Open the PR describing what changed and why

CI runs the data guard, the test suite on Python 3.11–3.13 across Linux, macOS
and Windows, lint, and an end-to-end run that also verifies the tool produces
reports with outbound network traffic blocked.

## Reporting bugs

Read [docs/PRIVACY.md](docs/PRIVACY.md) first if a real configuration is
involved. The best bug report is a failing test expressed through the
generator; the second best is a description of the *structure* that triggers
it.

Security vulnerabilities: see [SECURITY.md](SECURITY.md), not the public
tracker.
