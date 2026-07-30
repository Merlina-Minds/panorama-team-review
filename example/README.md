# A worked example

Finished reports, from a complete configuration, with the inputs that produced
them. Open one of the HTML files in a browser — they are self-contained, so no
server and no installation is needed to look around.

| Start here | Why |
|---|---|
| [`reports/payments_firewall-review.html`](reports/payments_firewall-review.html) | A typical owner's report: 53 rules of their own against 5 that merely cover them, and 61 cleanup candidates to work through. |
| [`reports/reporting_firewall-review.html`](reports/reporting_firewall-review.html) | The opposite case: a team owning a single host inside somebody else's network. Two rules of its own, fourteen that merely cover it — so almost the whole report is *nothing to decide*. |
| [`reports/platform_firewall-review.html`](reports/platform_firewall-review.html) | The largest: 69 rules across several device groups, so the evaluation-order grouping and the object list are worth looking at. |
| [`reports/00_OVERVIEW_all-teams.html`](reports/00_OVERVIEW_all-teams.html) | The firewall team's own view: every team, the policy blocks in evaluation order, and the rules nobody owns. |
| [`reports/payments_firewall-review.xlsx`](reports/payments_firewall-review.xlsx) | The working format. *Decision* and *Comment* are the columns an owner fills in and sends back. |
| [`reports/payments_firewall-review.pdf`](reports/payments_firewall-review.pdf) | The audit artefact: frozen per date, with the configuration checksum on the cover page. |

## What to look for

- **Two kinds of rule.** *Your rules* name the team's own address space and are
  the ones to decide on. *Rules that also cover your networks* are the
  estate-wide permissions — ping, DNS, directory services — which the team
  benefits from, did not request and cannot change. They carry no findings,
  because a finding nobody can act on is not work, it is noise.
- **Names, not addresses.** Every address cell leads with the object name the
  rule uses, because that is what a change request has to cite. Hover one to
  see what it resolves to.
- **Evaluation order.** Rules appear in the order the firewall reads them,
  grouped into the blocks it evaluates as a unit, each labelled with the
  firewalls it reaches and how many rules it holds in total.
- **The `reporting` team.** Worth opening next to `payments`: 53 rules to
  review there, 2 here, out of the same configuration. The difference is
  entirely whether a rule names the team's address space or merely contains
  it, and that split is the point of the tool.

## Reproducing it

```bash
pan-review -c example/config.yaml run
```

The inputs are [`config.yaml`](config.yaml) and [`inventory.yaml`](inventory.yaml),
both commented. To rebuild the estate as well:

```bash
python example/generate.py
```

## Where the data comes from

**Nothing here is real.** The estate in `backup/` is produced by
`tests/fixtures/generator.py`, which invents its own configuration using only

- documentation address ranges (RFC 5737, RFC 3849) and private space (RFC 1918),
- `example.com` names,
- a reserved fake device-serial range (`001901……`),
- ticket references and requesters that resolve to nothing.

That is what makes it safe to commit, and being committed is the point: anyone
deciding whether this tool is worth installing should be able to read a
finished report first. The same guard that protects the rest of the repository
runs over this directory — see [docs/PRIVACY.md](../docs/PRIVACY.md) — and no real
configuration, from any source, is ever committed here.

One deviation from a real run, marked in `config.yaml`: the date is dropped
from the report file names, so regenerating the example does not produce a diff
full of renames.

Two files a real run writes are missing. The cross-team JSON repeats every rule
once per team that sees it and outgrows the repository's file-size limit — it
is the same schema as the per-team JSON beside it. And rebuilding the PDFs
needs the optional WeasyPrint dependency (`pip install
'panorama-team-review[pdf]'`); without it `generate.py` refreshes the other
formats and leaves the committed PDFs alone.
