# Configuration reference

Two files:

- **`config.yaml`** — how the tool behaves
- **`inventory.yaml`** — which networks belong to which team

Both are validated on load. A typo fails immediately with the offending field
named, rather than producing a subtly wrong report three minutes later. Check
your changes with:

```bash
pan-review -c config.yaml validate
```

Relative paths inside `config.yaml` resolve against the file itself, so a
configuration directory can be moved or mounted elsewhere without editing it.
Environment variables (`$VAR`) and `~` are expanded.

Get a fully commented starting pair with `pan-review init .`.

---

## Table of contents

- [`input` — where backups come from](#input--where-backups-come-from)
- [`output` — where reports go](#output--where-reports-go)
- [`teams_file` and the inventory](#teams_file-and-the-inventory)
- [`ownership` — how rules reach teams](#ownership--how-rules-reach-teams)
- [`metadata` — tickets and dates](#metadata--tickets-and-dates)
- [`analysis` — cleanup checks](#analysis--cleanup-checks)
- [`hitcounts` — optional network access](#hitcounts--optional-network-access)
- [`report` — presentation](#report--presentation)
- [Running several estates](#running-several-estates)
- [Minimal configurations](#minimal-configurations)

---

## `input` — where backups come from

```yaml
input:
  backup_dir: /var/backups/panorama
  patterns: ["*.xml", "*.xml.gz", "*.tgz", "*.tar.gz"]
  recursive: false
  select: latest
  max_age_days: 7
```

| Key | Default | Meaning |
|---|---|---|
| `backup_dir` | — | Directory the firewall writes scheduled backups into |
| `patterns` | xml, xml.gz, tgz, tar.gz | Globs treated as backups |
| `recursive` | `false` | Search subdirectories |
| `select` | `latest` | `latest` for the newest file (the cron case), `all` to process every match, each producing its own reports |
| `max_age_days` | unset | Refuse to run if the newest backup is older than this |
| `select_by` | `mtime` | `mtime` uses the file timestamp; `filename` reads a date out of the name |
| `filename_date_pattern` | `(?P<date>\d{4}-?\d{2}-?\d{2})` | Regex with a named group `date` |
| `filename_date_formats` | `%Y%m%d`, `%Y-%m-%d` | strptime formats tried against the captured date |

`--backup FILE` on the command line overrides all of it, which is the manual
one-off case.

**`max_age_days` is worth setting.** Without it, a backup job that quietly
stopped six weeks ago produces confident reports from a stale configuration.
With it, the run exits 3 and says the backup job is most likely broken.

A Panorama scheduled backup is often a `.tgz` containing one XML per managed
device — one Panorama configuration plus one per managed firewall. All of them
are read and merged into a single view, so a rule path spanning Panorama and a
firewall stays in one report. Each firewall keeps its own namespace, because
`shared` and `vsys1` exist once per device.

### `select_by`: when the file timestamp lies

The default, `mtime`, is right whenever the timestamp is written by the job
that produced the backup — which covers the firewall writing directly into the
directory, and equally a scheduled job rotating files through several
directories. In both cases the timestamp *is* the truth, and it is finer
grained than a date in a name.

Switch to `filename` only when backups reach the host in a way that rewrites
mtimes without regard to their content — an archive extracted after the fact, a
copy that does not preserve times, a restore from a file share. The symptom to
watch for is a backup whose timestamp does not fit the schedule that produced
it.

The symptom is nasty: reports keep being produced, look healthy, and describe a
policy from weeks ago.

```yaml
input:
  backup_dir: /var/backups/panorama
  recursive: true              # rotating A/ and B/ directories
  patterns: ["*.tgz"]
  select_by: filename          # trust the name, not the timestamp
```

The date is read from the file name with `filename_date_pattern` and parsed
with `filename_date_formats`; `panorama-20260728.tgz` and
`backup-2026-07-28.tgz` both work out of the box. Files whose name carries no
date sort *below* every dated file rather than being mixed in, and the mtime
breaks ties between files bearing the same date — which is what makes the
rotating-directory case resolve sensibly.

### `fetch`: pulling the configuration live

```yaml
input:
  backup_dir: /var/backups/panorama
  fetch:
    enabled: false
    filename_template: "{device}_{date}.xml"
```

| Key | Default | Meaning |
|---|---|---|
| `fetch.enabled` | `false` | Download the running configuration from the devices before analysing it |
| `fetch.filename_template` | `{device}_{date}.xml` | Name for each downloaded file. Placeholders: `{device}`, `{date}` |

Off by default, because the tool's contract is that it works offline. When it
is on, `pan-review run` first downloads each device's running configuration into
`backup_dir`, then proceeds exactly as if those files had been written there by
a scheduled export — the newest is picked, `max_age_days` still applies, and the
downstream parser sees an identical document.

**The connection is the same as hit-count collection.** Devices, API key and
TLS come from the [`hitcounts`](#hitcounts--optional-network-access) section, so
the access to the firewalls is configured once. You do not have to collect hit
counts to fetch: leave `hitcounts.enabled: false` and still list the devices
there.

```yaml
input:
  backup_dir: /var/backups/panorama
  fetch:
    enabled: true
hitcounts:
  # connection only; hit-count collection stays off
  devices: [panorama.example.com]
  api_key_env: PAN_API_KEY
```

Read-only: only the configuration export endpoint is ever called, so the fetch
cannot change a device. Like hit-count collection, it can be scheduled on its
own so reporting stays offline:

```cron
0 1 * * *  PAN_API_KEY=... pan-review -c config.yaml fetch-backup
0 6 * * 1  pan-review -c config.yaml -q run --no-network
```

During `run`, a fetch failure is a warning, not a fatal error: the tool falls
back to whatever is already in `backup_dir`, and `max_age_days` still catches a
directory that has gone stale. `--no-network` skips the fetch entirely. An
explicit `--backup FILE` is the manual case and never triggers a fetch.

A firewall writes a single `.xml`. A **Panorama** writes a `.tgz` containing the
Panorama config plus every managed firewall's running config (pulled through
Panorama by serial), the shape of a scheduled Panorama backup — so the managed
firewalls' locally configured rules are included, which a plain Panorama config
export omits. With several *firewalls* listed directly, each writes its own file
and `select` decides what `run` then does with them; list them together with
`select: all`.

## `output` — where reports go

```yaml
output:
  directory: ./reports
  formats: [html, xlsx, pdf, json]
  per_team: true
  combined: true
  filename_template: "{date}_{team_id}_firewall-review"
  combined_filename_template: "{date}_00_OVERVIEW_all-teams"
  timestamped_subdir: true
  timestamped_subdir_format: "%Y-%m-%d"
  keep_runs: 12
  render_workers: 0
```

| Key | Default | Meaning |
|---|---|---|
| `directory` | `./out` | Base output directory |
| `formats` | `[html, xlsx, json]` | Any of `html`, `xlsx`, `pdf`, `json` |
| `per_team` | `true` | One file per team |
| `combined` | `true` | Plus one cross-team overview |
| `filename_template` | see above | Placeholders: `{date}`, `{team_id}`, `{team_name}` |
| `timestamped_subdir` | `true` | Write into `<directory>/<run>/` |
| `timestamped_subdir_format` | `%Y-%m-%d` | strftime format for that run directory |
| `keep_runs` | unset | Delete all but the N newest run directories |
| `render_workers` | `0` | Rendering worker processes; `0` auto, `1` sequential |

### Several runs on the same day

`timestamped_subdir_format` is the strftime pattern for the per-run directory.
The default, `%Y-%m-%d`, is one directory per day, so a second run on the same
day overwrites the first. To keep both, add a time:

```yaml
output:
  timestamped_subdir: true
  timestamped_subdir_format: "%Y-%m-%d_%H-%M-%S"
```

Use a format that sorts chronologically as text (year first) — `keep_runs`
prunes by the time parsed out of the name, and a listing reads in order. The
format may not contain a path separator: a run directory is a single level.

`pdf` requires the `[pdf]` extra and its system libraries; `validate` reports
it as a problem if it is configured but unusable.

When `html` is among the formats, each run also writes an `index.html` beside
the reports — a table of contents linking to every team's report and the
cross-team overview, so opening the run's directory lands on a page to click
through rather than a bare file listing.

JSON output is written gzip-compressed, as `.json.gz`: the complete record
repeats every rule once per team that sees it, so on a large estate it runs to
hundreds of megabytes uncompressed and shrinks roughly tenfold. `pan-review
diff` reads the compression directly, and older plain-`.json` reports still
load.

### Rendering speed

Turning the analysed estate into files is CPU-bound and, on a large estate with
`pdf` enabled, is the bulk of a run's wall-clock time. Every output file is
independent, so they are rendered across worker processes. `render_workers: 0`
(the default) picks one worker per CPU, capped; a run of only a handful of files
stays sequential, where a pool would not repay its start-up. Set a fixed number
to pin it, or `1` to render sequentially. Each worker keeps its own copy of the
estate in memory, so raise a fixed value only if there is room for it.

PDF rendering also needs at least one installed font. On a minimal host with
none, WeasyPrint still writes a PDF but warns `No fonts configured in
FontConfig. Expect ugly output.` and uses fallback glyphs. Install a font
package to fix it — `fonts-dejavu` (Debian/Ubuntu) or `dejavu-sans-fonts`
(RHEL/Fedora); see the [README](../README.md#installation). The warning affects
only the PDF, never the other formats.

## `teams_file` and the inventory

```yaml
teams_file: inventory.yaml
```

The inventory answers the one question a firewall configuration cannot: which
network belongs to which team. It is a separate file so it can be generated
from a CMDB and held under different access control.

```yaml
teams:
  - id: payments                    # required, referenced by tags and --team
    name: Payments Platform         # defaults to the id
    contact: payments@example.com
    description: Card processing and settlement

    assets:
      - cidr: 10.20.10.0/24
        label: Payments production  # shown in the report so owners recognise the box
      - cidr: 10.20.12.5/32
        label: payment-gw01
      - 2001:db8:20::/64            # short form when a label adds nothing

    tags: [owner:payments, pci]     # rules with these tags belong to this team
    device_groups: [DG-Payments]    # every rule in these device groups
    zones: [zone-payments]          # carries direction (from = outbound)
    name_patterns: ['^PAY-']        # regex on the rule name
```

Only `id` is required, but a team with none of `assets`, `tags`,
`device_groups`, `zones` or `name_patterns` can never receive a rule —
`validate` reports that.

Addresses are normalised: `10.1.2.3` becomes `10.1.2.3/32`, `10.1.2.3/24`
becomes `10.1.2.0/24`. Overlapping assets between teams are allowed (a shared
management network genuinely belongs to several) and reported as a note.

Running with no inventory at all is legitimate — tag, zone and device-group
attribution work on their own, and it is a reasonable first step before an
estate has mapped its networks.

## `ownership` — how rules reach teams

```yaml
ownership:
  order: [inventory, tag, regex, device_group, zone]
  stop_after_first_match: true
  tag_prefixes: ["owner:", "team:"]
  tag_suffixes: []
  tag_case_sensitive: false
  derive_from_object_tags: false
  name_patterns: []
  description_patterns: []
  match_mode: overlap
  covering_supernet_bits: 1
  include_any_rules: true
  max_any_rules_per_team: 50
```

### The resolvers

| Resolver | Matches on | Direction |
|---|---|---|
| `inventory` | Resolved rule networks vs. team assets | inbound / outbound / internal |
| `zone` | A `from`/`to` zone assigned to the team | outbound / inbound |
| `tag` | Rule tag `owner:<team-id>`, or a tag listed in the inventory | related |
| `regex` | Rule name or description pattern | related |
| `device_group` | The device group the rule is defined in | related |

`inventory` **always runs**, regardless of `order` and
`stop_after_first_match`, because it is the only source of direction — and
direction is the point of the report. The other four honour
`stop_after_first_match`, so a precise tag is not drowned out by a broad
device-group assignment.

### `derive_teams` — teams from a naming convention

Estates that provision networks automatically already encode ownership in their
object names. An address group called `aws-acme-shop-p-01` names the
account it belongs to, and it does so reliably, because a machine generated it.

Maintaining a parallel inventory of those by hand guarantees drift: a new
account exists in the firewall the day it is created, and in the inventory
whenever somebody remembers. Reading the convention removes that gap — a new
account appears in the next report with no configuration change at all.

```yaml
ownership:
  derive_teams:
    - id: aws-accounts
      source: address-group          # address-group | address-object | tag
      # aws-acme-retail-shop-p-01
      pattern: '^aws-(?P<org>[a-z0-9]+)-(?P<cat>[a-z0-9]+)-(?P<app>.+)-(?P<stage>[pdust])-(?P<nr>\d+)$'
      team_id: "{app}-{stage}"       # one team per account
      team_name: "{app} ({stage})"   # defaults to team_id
      contact: "{app}@example.com"   # optional
      min_assets: 1
```

The pattern needs at least one named group; any of them can be used in
`team_id`, `team_name` and `contact` as `{name}`. A template referencing a group
the pattern does not capture is rejected at load time, not at render time.

| `source` | Team is | Assets are |
|---|---|---|
| `address-group` | one per matching group name | the group's members, resolved |
| `address-object` | one per capture | the objects whose names matched |
| `tag` | one per matching tag | every object carrying that tag |

`address-group` is usually the strongest signal: a group exists precisely
because someone decided those addresses belong together.

**Placeholder addresses are excluded.** Generated groups often contain a
loopback or an unspecified address standing in for "nothing here yet". Left in,
one of them becomes an asset of dozens of teams at once and every rule touching
it lands in all their reports. `127.0.0.0/8`, `0.0.0.0/32`, `255.255.255.255/32`,
`::1/128` and `169.254.0.0/16` are skipped by default; override with
`exclude_networks`.

**Derived and explicit teams are merged**, and an explicit entry always wins —
whoever wrote it knew something the pattern does not. Networks the pattern found
that the explicit entry lacks are added to it rather than dropped. So keep
`teams_file` for infrastructure, overarching teams and exceptions, and let the
convention handle the regular part of the estate.

Use `exclude_pattern` to skip names, and add a second rule with the inverse
pattern to catch what does not follow the convention — that way nothing is
silently dropped:

```yaml
    - id: aws-accounts-nonstandard
      source: address-group
      pattern: '^aws-(?P<alias>.+)$'
      exclude_pattern: '^aws-[a-z0-9]+-[a-z0-9]+-.+-[pdust]-\d+$'
      team_id: "nonstandard-{alias}"
```

`pan-review validate` lists the configured rules, and every run reports how many
objects each matched — a rule that matched nothing says so instead of quietly
producing no teams.

### `derive_from_object_tags` — assets from ownership tags on objects

An ownership tag on an *object* says more than the same tag on a rule. A rule
tag lands in the team's non-directional "related" section, because a tag on a
rule cannot say which side of the connection the team is on. An address object,
though, is on a definite side — so a tag on it carries the same information the
inventory does, direction included.

With `derive_from_object_tags: true`, every address object and address group
carrying a tag that matches `tag_prefixes`/`tag_suffixes` contributes its
addresses to the named team, exactly as if `teams_file` had listed them:

```yaml
ownership:
  tag_prefixes: ["owner:"]
  derive_from_object_tags: true
```

```
address object  db-payments-01   10.20.0.0/24   tag: owner:payments
   ->  team 'payments' gains the asset 10.20.0.0/24, directionally
```

Only tags shaped like the ownership convention count; every other tag is a
classification (`prod`, `GlobalProtect-Clients`, a dynamic-group filter tag) and
is ignored — which is what keeps a single tag on hundreds of objects from
claiming rules for the wrong team. An object can carry more than one ownership
tag and then belongs to each named team.

The result is merged with `teams_file` the same way derived teams are: an
explicit entry wins, but the tagged addresses are folded into it. So this
**extends** a hand-written inventory, or — on an estate that tags consistently
— **replaces** it, which is the point: the ownership lives in Panorama, next to
the objects, and the report reads it directly rather than from a parallel list
that drifts. The same placeholder addresses `derive_teams` skips are skipped
here too. Off by default.

### `name_patterns` and `description_patterns`

Global patterns that capture the team id themselves:

```yaml
ownership:
  name_patterns:
    - '^(?P<team>PAY|PLT|DEV)-'          # PAY-allow-https → team "PAY"
  description_patterns:
    - 'owner=(?P<team>[\w-]+)'
```

They must contain a named group `team`, and the captured value must be a team
id from the inventory. Per-team patterns without a capture group go in the
inventory's `name_patterns` instead.

### `tag_prefixes` and `tag_suffixes` — what counts as an ownership tag

A PAN-OS tag is a **classification** before it is anything else. `GlobalProtect-Clients`,
`Outdated-Object`, `OnPrem` say what an object *is*; dynamic address groups are
built on precisely that. Ownership-by-tag is a convention an estate adds on top,
and the tool can only read it once the convention is written down:

```yaml
ownership:
  tag_prefixes: ["owner:"]   # 'owner:payments' names team 'payments'
  tag_suffixes: ["-owner"]   # 'payments-owner' names team 'payments'
```

A tag not shaped that way is treated as a classification and ignored for
ownership. Both empty means no tag ever attributes a rule, which is the right
answer for an estate that does not tag for ownership — attribution then comes
from the inventory.

This also governs what a **derived** team inherits. A team built from an address
group takes only the tags that name *it*; it used to take all of them, and on a
real estate one classification tag sitting on 137 address groups was inherited
by 107 of 110 derived teams. Since the tag index keeps one team per tag, all 161
rules carrying it were attributed to whichever team sorted last — as its own
rules, with findings, to review. Which team that was depended on nothing but
alphabetical order.

A tag claimed by more than one team is reported in the run notes for the same
reason: exactly one of them will receive the rules, and the choice is an
accident of ordering rather than a decision.

### `match_mode`

- `overlap` (default) — any intersection between a rule network and a team
  asset counts. A rule covering `10.0.0.0/8` reaches a team owning
  `10.20.0.0/16`, which is true and worth telling them.
- `contained` — the rule network must lie entirely inside the asset. Quieter,
  but hides broad rules from the teams they affect.

### `covering_supernet_bits`

Decides whether a rule is reported as the team's **own** or as one that
**merely covers** them — the split that runs through every report. See
[Your rules, and the rules that merely cover
you](../README.md#your-rules-and-the-rules-that-merely-cover-you).

A rule's network either lies inside one of your networks or around it; CIDR
blocks nest or are disjoint, so there is no third case. Inside means the rule
was written for your address space and is yours. Around it means you were swept
up in something broader — `10.0.0.0/8`, the site supernet — and the rule is not
yours to justify.

The default of `1` means *any* strictly larger network counts as merely
covering you. Raise it when the inventory lists individual hosts rather than
networks: with `covering_supernet_bits: 9`, a rule naming the `/24` a `/32`
asset lives in still counts as that team's own, while a rule naming the `/16`
does not.

This is independent of `match_mode`, which decides whether a rule appears in
the report at all.

### `object_naming` — checking the inventory against the object names

Where an estate names its address objects after the account they belong to,
that name is a second, independent record of ownership. The inventory is the
first. Where the two disagree, one of them is wrong — and the disagreement is
otherwise silent: rules touching that network never reach the team's report,
which then looks complete.

```yaml
ownership:
  object_naming:
    - pattern: '^net-prod-(?P<app>[a-z0-9]+)-'
      team_id: "{app}-p"
    - pattern: '^net-staging-(?P<app>[a-z0-9]+)-'
      team_id: "{app}-t"
```

Same shape as `derive_teams`: a regex with named groups and a template that
builds the team id. Write one rule per environment rather than one rule with a
translation table — an estate whose `staging` networks belong to accounts ending
in `-t` is exactly the case that has to be stated.

Two disagreements are reported, in the *Inventory gaps* section of the
cross-team overview and as a worksheet in the combined workbook:

| | Meaning |
|---|---|
| **A network the name assigns to a team the inventory does not give it** | Usually the account's address group is missing a member. Every rule touching that network is absent from the team's report until it is added. |
| **A network two teams' names both claim** | Either the range was reassigned and the older object outlived it, or both describe the same addresses. A rule touching it is attributed to both, and neither attribution is the more trustworthy. |

An object whose name points at a team that does not exist is *not* reported
here — that is an account missing from the inventory entirely, and the
`show_unassigned_section` list already speaks to it.

This never attributes a rule. A name is a claim; an address is what the
firewall matches on.

### `include_any_rules`

A rule with `any` on **both** sides affects every team. They are reported as
rules that cover the team, never as the team's own — nobody requested a rule
that permits everything to everything on their behalf. Showing them everywhere
is honest but noisy, so they are capped per team by
`max_any_rules_per_team`. Catch-all *deny* rules are never distributed this way
— they restrict nothing.

A rule with `any` on only one side is not affected by this setting: `any →
your-server` is inbound and among the most important lines in the report.

## `metadata` — tickets and dates

Turns the description field into structured data.

```yaml
metadata:
  ticket_patterns:
    - name: jira
      regex: '\b(?P<id>[A-Z][A-Z0-9]{1,9}-\d{1,6})\b'
      url_template: "https://jira.example.com/browse/{id}"
      fields: [description, tag]

    - name: servicenow
      regex: '\b(?P<id>(?:CHG|INC|REQ)\d{7,})\b'
      url_template: "https://example.service-now.com/nav_to.do?uri=task.do?sysparm_query=number={id}"

  # What a date MEANS, decided by the words shortly before it. Shared by every
  # date format below -- add your own language here, once.
  role_keywords:
    expires: [until, expires, "valid until", "temp until", bis, "gueltig bis"]
    created: [created, requested, opened, erstellt, beantragt]
    reviewed: [reviewed, recertified, geprueft]

  date_patterns:
    - name: iso                                  # 2026-12-31
      regex: '\b\d{4}-\d{2}-\d{2}\b'
      date_format: "%Y-%m-%d"

    - name: dot-dmy                              # 31.12.2026
      regex: '\b\d{1,2}\.\d{1,2}\.\d{4}\b'
      date_format: "%d.%m.%Y"

  requester_patterns:
    - '(?:requested by|owner|contact)[:\s]+(?P<requester>[\w.\- ]{3,40})'
```

**Ticket patterns** need a named group `id`. Capture the *whole* reference
including its prefix (`CHG0041234`, not `0041234`) — the report is read by
people who paste that string into a ticket system. `url_template` is formatted
with the regex's named groups and is validated at load time, so a template
referencing a group the regex does not capture fails immediately.

Without a `url_template` the reference is still extracted; it renders as plain
text instead of a link.

**Dates** are handled in two independent halves, and keeping them apart is what
makes mixed conventions work:

- **`date_patterns`** recognise the *format*. ISO (`2026-12-31`) and dotted
  (`31.12.2026`) are both enabled by default, along with `31/12/2026`, so an
  estate that uses more than one needs no configuration at all.
- **`role_keywords`** decide the *meaning*, from the words shortly before the
  date. `valid until 2026-12-31` becomes an expiry (driving `EXPIRED_RULE` and
  `EXPIRING_SOON`); `created 2024-03-01` becomes a creation date.

The keyword list is shared across every format on purpose: the words around a
date do not change because the date is written differently. Configuring them
per pattern — as an earlier version required — meant an organisation using both
`31.12.2026` and `2026-12-31` had to maintain the list twice, and silently got
only the format whose list had been filled in.

A single pattern may still override the shared list with its own
`role_keywords:`, which is the right tool only when the formats genuinely
correlate with different languages.

Only the text *before* a date is searched, within `keyword_window` characters
(default 40), because descriptions are written `valid until <date>`, not
`<date> is the expiry`.

A date with no recognised keyword nearby is still extracted and shown in the
report, with the role `unknown` — it is not silently dropped, but it does not
trigger an expiry finding either.

### `change_patterns` — edits recorded by position

Some estates write the change history without a keyword:

```text
CHG0041234 (a.beck: 2024-05-30)
CHG0041299 a.beck 2027-07-18
```

The keyword matcher has nothing to go on, so those dates are reported as being
of unstated purpose. A pattern with a named group `date` — and optionally
`requester` — turns them into change dates with the editor's name:

```yaml
metadata:
  change_patterns:
    - '\((?P<requester>[A-Za-z][\w.-]{1,29})\s*[:,]?\s*(?P<date>\d{4}-\d{2}-\d{2})\)'
    - '\b(?P<requester>[A-Za-z][A-Za-z0-9._-]{1,19})\s+(?P<date>\d{4}-\d{2}-\d{2})\b'
```

Empty by default, deliberately: a pattern loose enough to catch a bare username
also matches the word before any date, and guessing would turn expiries into
edits. For the same reason these run **after** the keyword pass and only on
dates it could not explain — `valid until 2026-12-31` is an expiry no matter
what sits next to it.

A word that is not a name occasionally lands in `requester`. That costs little:
the date is still correctly a change date, which is what `IMPOSSIBLE_DATE` and
the "last changed" line depend on.

## `analysis` — cleanup checks

```yaml
analysis:
  enabled_checks: [ANY_ANY, ANY_SOURCE, ...]
  broad_network_prefix_v4: 16
  broad_network_prefix_v6: 48
  expiring_soon_days: 60
  stale_rule_days: 180
  require_ticket: true
  internet_zones: [outside, untrust, internet, wan]
  ignore_tags: []
  ignore_rule_patterns: []
```

`pan-review checks` lists every available code. An unknown code in
`enabled_checks` is reported by `validate` and skipped at runtime rather than
crashing a nightly run.

| Key | Meaning |
|---|---|
| `broad_network_prefix_v4` | An IPv4 network shorter than this prefix is flagged. `16` flags `/8` and `/12`. |
| `expiring_soon_days` | Warning horizon before a stated expiry |
| `stale_rule_days` | Days without a hit before `STALE_RULE` fires (needs hit counts) |
| `require_ticket` | Flag rules whose description holds no recognisable reference |
| `internet_zones` | Destination zones that lead off the estate — see below |
| `ignore_tags` | Rules with any of these tags are exempt from **all** findings |
| `ignore_rule_patterns` | Rule names matching these regexes are exempt |

`ignore_tags` is the escape hatch for approved exceptions: tag the rule
`approved-exception` on the firewall, list it here, and it stops appearing as a
finding while remaining in the report.

### `internet_zones`

A rule permitting traffic to the internet has `any` as its destination because
the internet *is* its destination. Flagging it with `ANY_DESTINATION` and
advising the owner to "name the destinations this access is meant for" asks for
something nobody can produce — and a report that asks for the impossible is one
that gets skimmed.

`ANY_DESTINATION` therefore stays silent when **every** destination zone of a
rule is listed here. Requiring all of them is deliberate: a rule going to both
`outside` and `inside` really does permit unrestricted internal access.

The defaults (`outside`, `untrust`, `internet`, `wan`) cover the usual naming;
replace them with the names your estate uses, or set `internet_zones: []` to
flag egress rules as well. What such a rule may *carry* is unaffected —
`ANY_SERVICE` still fires on one that permits every port and application.

### `flag_object_patterns` — your own markers

Estates mark objects for their own purposes: `OUTDATED_` for something
scheduled for deletion, `TEMP_` for something that was never meant to last.
Those markers mean something to the people who wrote them and nothing to a
generic check, so the patterns are configuration.

```yaml
analysis:
  enabled_checks: [..., FLAGGED_OBJECT]
  flag_object_patterns:
    - pattern: '^OUTDATED_'
      title: "Uses an object marked OUTDATED"
      severity: medium
      detail: "The rule references an object whose name marks it for deletion."
      recommendation: "Confirm with the owner, then remove the rule or repoint it."
```

A rule still pointing at an object marked for deletion is exactly what a review
should surface: somebody decided it should go, and it is still carrying
traffic.

`UNUSED_RULE` and `STALE_RULE` produce nothing at all without hit-count data.
They are not disabled — they simply have nothing to say, which is the intended
behaviour.

## `hitcounts` — optional network access

```yaml
hitcounts:
  enabled: false
  devices: []
  api_key_env: PAN_API_KEY
  # api_key_file: /etc/panorama-team-review/api.key
  # username: readonly-api
  # password_env: PAN_PASSWORD
  # password_file: /etc/panorama-team-review/api.pass
  verify_tls: true
  # ca_bundle: /etc/ssl/certs/internal-ca.pem
  timeout_seconds: 30
  rulebases: [security]
  cache_dir: ./cache
  cache_max_age_hours: 24
```

Rule hit counters are runtime state and are **never** contained in a
configuration backup. This is one of only two parts of the tool that touch the
network (the other is [`input.fetch`](#fetch-pulling-the-configuration-live),
which reuses the connection settings below). It is disabled by default and
issues read-only `show` operational commands exclusively.

### Panorama: counters come from the firewalls

Point `devices` at a Panorama and the connection is used as a gateway, not as a
source of counters — Panorama holds none of its own. The tool lists the
connected firewalls and runs the hit-count query on each of them *through*
Panorama (the API `target` parameter, still a read-only `show` command).

A device-group rule is pushed to every firewall in that group (and its child
groups), so its usage in the report is the **sum** of those firewalls' counters,
with the most recent match and a per-firewall breakdown — visible as a tooltip
in HTML and a cell comment in Excel. This is why a rule that is busy on one
firewall and idle on the four others it was pushed to is not reported as unused.

For the firewalls' *locally* configured rules to appear at all, the backup must
contain their configs — a scheduled Panorama backup `.tgz` does, and so does a
live [`input.fetch`](#fetch-pulling-the-configuration-live).

### Authentication: API key or username and password

Authentication is either an API key or a username plus password. **Secrets are
never read from the configuration file**, so it stays shareable — only the
username, which is not a secret, may live there.

| Key | Meaning |
|---|---|
| `api_key_env` | Environment variable holding an API key (default `PAN_API_KEY`) |
| `api_key_file` | A file containing only the key, instead of the env var |
| `username` | Username for password authentication; used only when no API key is configured |
| `password_env` | Environment variable holding the password (default `PAN_PASSWORD`) |
| `password_file` | A file containing only the password, instead of the env var |

An API key is used as-is against every device. If no key is configured but a
username and password are, the tool obtains a key from each device itself with a
read-only `keygen` call — the path for a read-only account that was only ever
given a username and password, not an API key:

```cron
0 2 * * *  PAN_PASSWORD=... pan-review -c config.yaml collect-hitcounts
```

with `username: readonly-api` in the configuration. Use an account bound to a
**read-only administrator role** either way.

### TLS and self-signed certificates

Management interfaces frequently present a self-signed certificate or one issued
by an internal CA, which fails verification with a message like:

```
SSLError(... CERTIFICATE_VERIFY_FAILED ... self-signed certificate in certificate chain ...)
```

There are two ways to resolve it, and one is much better than the other:

- **`ca_bundle: /path/to/cert.pem`** — verify against a pinned certificate or
  your internal CA. This keeps TLS meaningful: the connection is still
  authenticated, just against a certificate you chose to trust rather than a
  public root. **Preferred.**
- **`verify_tls: false`** — turn verification off entirely. This makes the
  connection vulnerable to interception on a management network, which is
  exactly where it matters. Use only as a last resort.

To obtain the certificate for `ca_bundle`, use the built-in helper, which
fetches it and prints its fingerprint:

```bash
pan-review -c config.yaml fetch-cert
# or for a host not yet in the config:
pan-review fetch-cert panorama.example.com -o panorama-ca.pem
```

```yaml
hitcounts:
  ca_bundle: ./panorama-ca.pem
```

`fetch-cert` connects **without** verification — that is the point, since
verification is what is failing — so it is *trust on first use*. Check the
printed SHA-256 fingerprint against the device (in its web UI, or over SSH with
`show system state | match certificate`) before trusting the file. If the device
uses a certificate signed by an internal CA rather than a self-signed one,
prefer obtaining the CA certificate itself from your PKI, so verification keeps
working across certificate renewals.

Collected counters are cached as sidecar JSON in `cache_dir`. The recommended
arrangement keeps reporting offline:

```cron
0 2 * * *  PAN_API_KEY=... pan-review -c config.yaml collect-hitcounts
0 6 * * 1  pan-review -c config.yaml -q run --no-network
```

`--no-network` forces cache-only operation even when collection is enabled.
Collection failure is never fatal: the report is produced without usage data
and says so.

## `report` — presentation

```yaml
report:
  title: "Firewall Rule Review"
  organisation: "Example Organisation"
  language: en
  contact_text: >-
    Questions about a rule? Contact netsec@example.com and quote the rule
    name and location.
  change_request_url: "https://example.service-now.com/firewall-change"
  include_disabled_rules: true
  include_nat_rules: true
  include_rule_uuid: false
  max_addresses_shown: 25
  show_unassigned_section: true
  sort_rules_by: order
```

| Key | Meaning |
|---|---|
| `contact_text` | Shown in the "how to request a change" section of every report |
| `change_request_url` | Linked from the same section |
| `include_disabled_rules` | Disabled rules are shown greyed out. Keep them: an owner asking "why can't I reach X" is often looking at one. |
| `max_addresses_shown` | Truncation limit for long address lists in rendered output. The JSON always keeps everything. |
| `show_unassigned_section` | Rules no team could be determined for. **Read this section.** A long list means the inventory is incomplete, not that the rules do not matter — it is the best guide to what is missing. |
| `sort_rules_by` | `order` (the default), `name`, or `severity` |

### `sort_rules_by: order`

The order the firewall evaluates the rules in: shared pre-rules, device groups
from the top of the hierarchy down, the firewall's own rules, then post-rules
from the innermost device group back out to shared. Reports group the rules
into those blocks and name the firewalls each block reaches.

This is the only ordering that carries information — the first matching rule
wins, so a broad rule above a narrow one makes the narrow one dead. `name` and
`severity` are for reading a report as a list rather than as a policy; both
lose that.

## Running several estates

One configuration file per estate. There is no shared state between runs — no
global cache, no cross-estate lookups — so runs are independent and can
execute concurrently.

```text
/etc/panorama-team-review/
├── customer-a/
│   ├── config.yaml
│   └── inventory.yaml
├── customer-b/
│   ├── config.yaml
│   └── inventory.yaml
└── customer-c/
    ├── config.yaml
    └── inventory.yaml
```

Each `config.yaml` points at its own backup directory and its own output
directory. Because relative paths resolve against the configuration file, the
same file content works for every estate as long as the directory layout
matches.

```cron
0 6 * * 1  pan-review -c /etc/panorama-team-review/customer-a/config.yaml -q run
15 6 * * 1 pan-review -c /etc/panorama-team-review/customer-b/config.yaml -q run
30 6 * * 1 pan-review -c /etc/panorama-team-review/customer-c/config.yaml -q run
```

Or in one entry, so a single failure is visible in the exit code:

```bash
#!/bin/sh
set -e
for estate in /etc/panorama-team-review/*/config.yaml; do
    pan-review -c "$estate" -q run || echo "FAILED: $estate" >&2
done
```

If you run this as a service provider, two points are worth being deliberate
about:

- **Separate output directories per estate**, and separate access control on
  them. A report describes a network as completely as the configuration does.
- **Separate API keys** if hit-count collection is enabled, each with its own
  `cache_dir`. Sharing a cache directory between estates would mix counters
  from different devices, and rule names are not unique across estates.

Isolation is asserted by the test suite rather than assumed — see
`test_separate_estates_stay_isolated`.

## Minimal configurations

Smallest useful configuration:

```yaml
input:
  backup_dir: /var/backups/panorama
teams_file: inventory.yaml
```

```yaml
teams:
  - id: payments
    name: Payments Platform
    assets: ["10.20.0.0/16"]
```

Everything else has a working default.

Tag-based only, before any network inventory exists:

```yaml
input:
  backup_dir: /var/backups/panorama
teams_file: inventory.yaml
ownership:
  order: [tag, device_group]
```

```yaml
teams:
  - id: payments
    name: Payments Platform
    tags: [owner:payments]
    device_groups: [DG-Payments]
```

This produces reports without direction — everything lands in *related* — but
it works on day one and shows which rules each team owns. Add `assets` later to
get the inbound/outbound split.
