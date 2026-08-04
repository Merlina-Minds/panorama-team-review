# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Ownership can come from tags on the objects, not just the inventory.** With
  `ownership.derive_from_object_tags`, an address object or group tagged with the
  ownership convention (`owner:payments`, using the existing
  `tag_prefixes`/`tag_suffixes`) contributes its addresses to that team as if the
  inventory had listed them. Because an object sits on a definite side of a rule,
  this carries direction — inbound/outbound — which a tag on a *rule* cannot, so
  it feeds the inventory resolver rather than the flat "related" section. Only
  convention-shaped tags count; every other tag stays a classification and is
  ignored. It merges with `teams_file` (an explicit entry wins, the addresses
  fold in), so it extends a hand-written inventory or, on an estate that tags
  consistently, replaces it — keeping ownership in Panorama next to the objects
  instead of in a parallel list that drifts. Off by default.
- **An `index.html` ties the HTML reports together.** Whenever HTML is written,
  a run now also writes an `index.html` beside the reports: a table of contents
  linking to each team's report and to the cross-team overview, with each team's
  own-rule, covering-rule and finding counts. Opening the run's directory lands
  on a page to click through rather than a bare file listing, which matters when
  the reports are served over HTTP or dropped on a file share.
- **Reports are rendered in parallel.** Turning the analysed estate into files
  is CPU-bound and, on a large estate, is the bulk of a run — every team's
  HTML, Excel, PDF and JSON, plus the cross-team overview, is an independent
  file. They are now spread across worker processes instead of written one at a
  time. The new `output.render_workers` sets the count: `0` (default) auto-picks
  one per CPU, capped; a run of only a handful of files stays sequential; `1`
  forces sequential rendering. Each worker keeps its own copy of the estate, so
  raise a fixed value only if there is memory to spare.
- **Live progress on a terminal during the network steps.** `run`,
  `collect-hitcounts` and `fetch-backup` now print per-device status (to stderr)
  while fetching configs and hit counts, so an interactive run is no longer
  silent for minutes. Detected by the TTY: cron (no terminal) and `-q` output is
  unchanged.
- **`pan-review fetch-cert`** retrieves a device's TLS certificate into a CA
  bundle and prints its SHA-256 fingerprint. For a management interface with a
  self-signed or internal-CA certificate, point `hitcounts.ca_bundle` at the
  result instead of turning verification off with `verify_tls: false` — the
  connection stays authenticated. The fetch is unverified by necessity (trust on
  first use), so verify the fingerprint against the device.
- **Username and password authentication for the network features.** Where a
  read-only account has only a username and password and was never issued an API
  key, hit-count collection and configuration fetch now obtain a key from each
  device themselves with a read-only `keygen` call. Set `username` in the config
  and supply the password through `password_env`/`password_file`; an explicit
  API key still takes precedence. Passwords, like keys, are never read from the
  configuration file.
- **`output.timestamped_subdir_format`** makes the per-run directory name
  configurable (strftime, default `%Y-%m-%d`). Extend it with a time, e.g.
  `%Y-%m-%d_%H-%M-%S`, to keep several runs on the same day instead of
  overwriting. `keep_runs` prunes by the time parsed out of the name.
- **Optional live configuration fetch.** With `input.fetch.enabled`, the tool
  pulls each device's running configuration into `backup_dir` before analysing
  it, instead of depending on a scheduled export landing on disk. It reuses the
  `hitcounts` connection (devices, API key, TLS), so the access is configured
  once, and it can be run on its own with the new `pan-review fetch-backup`
  command to keep reporting offline. Off by default and read-only. During `run`
  a fetch failure is a warning that falls back to the backups already on disk,
  with `max_age_days` still guarding against staleness.

### Fixed

- **The PDF and Excel reports now order the address columns by direction, like
  the HTML report.** On the inbound sheets and tables the far side comes before
  a team's own networks, so every row reads left to right in the direction the
  traffic travels ("who reaches you → your networks"); outbound keeps the team's
  own side first. The HTML report already did this; the other two had kept a
  fixed order.
- **Shared rules no longer show "not collected" when they have hits.** A shared
  pre/post rule is pushed to every managed firewall, so its counters arrive
  keyed by each firewall's serial rather than by any device group -- and the
  matcher only aggregated per-firewall counters for rules that named a device
  group, so shared rules fell through to a scope-qualified lookup that a
  Panorama-collected cache never contains. They are now summed across every
  firewall, the same way a device-group rule sums its subtree.
- **The Excel writer no longer re-parses the same networks millions of times.**
  Matching a team's assets against a rule's members parsed every CIDR string
  afresh for each comparison, and estate-wide rules repeat across every team, so
  the combined workbook spent almost all its time re-parsing identical strings.
  Parsing each once turns that into a lookup: the cross-team workbook on the
  estate this was measured on dropped from about three minutes to well under
  one, and the same matching in the HTML and PDF reports sped up with it. This
  also makes the empty combined workbook far less likely — it was a run
  interrupted mid-write, not a broken file.
- **Panorama hit counts are now collected from the managed firewalls, not from
  Panorama.** Panorama holds no rule hit counters of its own, so the previous
  query returned zeros. Each connected firewall is now queried through Panorama
  (with the `target` parameter), and a device-group rule's usage is the sum of
  its firewalls' counters, with the most recent match and a per-firewall
  breakdown kept for the report. A rule pushed to five firewalls but used on one
  no longer looks unused.
- **A live Panorama fetch now includes the managed firewalls' local rules.** A
  Panorama configuration export holds only the Panorama-side config, so rules
  configured locally on a firewall were missing. The fetch now pulls each
  managed firewall's running config too and writes everything into one `.tgz`,
  the shape of a scheduled Panorama backup, which the parser merges into a single
  view.
- **Credential, TLS and asset file paths now resolve relative to the config
  file**, like `backup_dir`, `teams_file` and the output directory already did.
  A relative `api_key_file`, `password_file`, `ca_bundle`, `cache_dir` or
  `report.logo_path` was previously looked up relative to the working directory,
  so it broke as soon as the tool ran from anywhere but the config's directory.
- **`validate` checks the connection credentials.** With hit-count collection
  or configuration fetch enabled, it now reports the credential method and
  flags a configured API-key, password or CA-bundle file that is missing or
  empty, instead of leaving it to fail at run time. Environment variables are
  not checked, since the secret is supplied at run time by design.

### Changed

- **Usage is shown for the rules that also cover a team, and reads as an age.**
  The "Rules that also cover your networks" section now carries the same usage
  column as a team's own rules -- knowing an estate-wide rule is heavily used or
  long idle is exactly the kind of thing worth seeing there. And the summary now
  says how long ago the last hit was ("last today", "last 2 weeks ago", "last
  1 year ago") rather than a bare date, which is what a reader judging whether a
  rule is still live actually wants; the exact date stays in the per-firewall
  breakdown and the expanded row.
- **Reports separate a team's own rules from the ones that merely cover them.**
  A rule naming an object inside a team's address space was written for that
  team; a rule naming `10.0.0.0/8`, or `any`, covers them along with everyone
  else — the estate-wide permissions for ping, DNS or Active Directory. Both
  belong in a report, but only the first is the team's to justify. The second
  now appears under *Rules that also cover your networks*, stated as
  information rather than as a request: the access exists, nobody needs to
  apply for it, and anyone who must be excluded can say so. On a real estate
  this moved about a third of every report out of the review pile.
- **Findings are raised only against a team's own rules.** A finding on an
  estate-wide rule is addressed to whoever maintains it; a team can neither fix
  it nor safely ignore it, because it arrives looking like work. Those findings
  remain in the combined report, which is the firewall team's list. Cleanup
  candidates in a per-team report dropped by roughly half on the estate this
  was developed against.
- **Rules are listed in the order the firewall evaluates them**, grouped into
  the blocks it evaluates as a unit: shared pre-rules, device groups from the
  top of the hierarchy down, the firewall's own rules, then post-rules from the
  innermost device group back out to shared. Sorting previously fell back to
  the device-group *name*, which put `DC/post` ahead of `shared/pre` — not an
  approximation of the evaluation order but unrelated to it, while looking
  authoritative. Each block states which firewalls evaluate it and how many
  rules it holds in total, so a reader can see that rules they are not shown
  sit between the ones they are.
- The asset list moved above the rules and is now called **Your networks**.
  Everything in the report follows from it, so a wrong entry there is worth
  catching before reading a single rule.
- *Internal* is spelled out as **Both ends yours**. In a firewall report
  "internal" reads as "the internal network" rather than as what it means.
- The header names the configuration file only when there is one. A Panorama
  scheduled backup holds a document per managed firewall, and listing several dozen
  of them helps nobody; the PAN-OS version is gone from per-team reports for the
  same reason — it differs across the firewalls one report covers, and no owner
  decision depends on it. Both remain in the JSON output, on the PDF cover page
  and in the combined report.
- The *Usage* column is omitted when hit counts were not collected, rather than
  repeating "not collected" on every row.
- Managed firewalls are identified by hostname rather than by
  `hostname_serial`, and a device's two half-records — device-group membership
  from the Panorama document, hostname from its own — are joined instead of one
  being dropped.
- Excel: separate sheets for a team's own rules and for the ones that cover
  them, the latter without a Decision column; new *Block* and *Position*
  columns that survive re-sorting the sheet; the assets sheet is now
  *Your networks*.
- **Addresses are shown by name.** A cell of resolved networks is unreadable to
  everyone outside the network team and is not what a change request cites, so
  the *Your networks* and *Other side* columns now lead with the object name --
  `grp-time-servers` rather than forty addresses — and hold the addresses in a
  tooltip. The workbook carries both as separate columns, since it has no
  tooltip. `ResolvedAddresses.members` records the per-object breakdown that
  makes this possible.
- **`ANY_DESTINATION` no longer fires on rules that leave the estate.** An
  egress rule has `any` as its destination because the internet is its
  destination; "name the destinations this access is meant for" is advice
  nobody can take. Controlled by `analysis.internet_zones`, which defaults to
  the usual names (`outside`, `untrust`, `internet`, `wan`). What such a rule
  may *carry* is still flagged by `ANY_SERVICE`.
- **Rules that also cover your networks are split by direction**, like a team's
  own rules. Who may already reach you and what your systems may already reach
  are different questions, and that does not stop being true because the rule
  was written centrally.
- Blocking rules (`deny`, `drop`, the resets) carry a loud badge. A rule that
  stops traffic must not read like one that permits it.
- A date whose purpose could not be established is labelled as such instead of
  as "Unknown date", and the source text is shown only when it differs from the
  date it produced — `2024-12-09 [from "2024-12-09"]` said the same thing twice.
- "Why this rule is in your report" no longer repeats itself when the ownership
  evidence and the coverage reason are the same sentence.
- **The column header row stays on screen** while scrolling a long table, at
  every window width; the filter bar no longer does. The sticky header on the
  table was previously inert: the wrapper providing horizontal overflow made
  itself the scroll container, so the header stuck to a box that never scrolls.
  The wrapper no longer scrolls at all — below roughly 1060px, where a rule
  table stops fitting, the page scrolls sideways instead. That is deliberate: a
  narrower window, or 175% browser zoom, otherwise lost the column names with
  nothing to say why.
- The page header shrinks on a two-step threshold rather than one, so it no
  longer flickers when the scroll position sits exactly on the boundary — the
  shrink makes the page shorter, which used to push the position back across it.
- The object name that explains a rule is bold as well as the network it
  resolves to, in *Source objects* / *Destination objects* — marking only the
  address left the reader to work back up to the group holding it.
- **The address columns follow the direction of travel**: inbound reads
  *Other side → Your networks*, outbound the reverse. Reading "who reaches you"
  right to left costs attention on every row.
- **Line breaks in a rule description are kept**, and no longer read across.
  A description is a change log with one entry per line; run together, the
  ticket from one line reads as though it belonged to the date on the next.
  The keyword search behind a date now stops at the line start for the same
  reason — `CHG0041201 gueltig bis 31.12.2026` on the line above no longer turns the
  next line's date into an expiry, and with it `EXPIRED_RULE` against a rule
  that never had one.
- **Only the last change is reported.** A description holding a rule's whole
  history yielded one "last changed" line per edit; the count of earlier ones
  is stated instead.
- The name beside a change date is no longer reported as the *requester*. The
  administrator who made a change is rarely the person who asked for it, and
  `CHG0041299 a.beck 2027-07-18` never said a.beck wanted the rule.
- **The *Your networks* column names the object the rule actually uses.** It
  showed the *inventory's* name for the team's network, which on a derived
  inventory is the address group the team was created from — so the rule
  `payments-prod-to-gitlab`, whose source is
  `net-payments-app-10.20.12.0-24`, had its cell announce
  `grp-aws-payments-prod-01`, a name that rule never mentions. Quoting it
  in a change request would have targeted the wrong object with nothing in the
  report to contradict it. Both address columns now name objects as the rule
  writes them; where a rule names a group far wider than the team —
  `grp-all-internal-10.0.0.0-8` around a /21 — that group is what appears,
  because that is what a change request has to argue with. The tooltip says
  which of the reader's networks it covers and what it resolves to.

  Where a rule was attributed by zone, tag or device group it names no object
  covering the team at all; those cells show the team's own networks, with the
  inventory label in the tooltip rather than in the cell.

### Fixed

- **A configured resolver order could skip the inventory entirely.** The
  documented contract is that `inventory` runs regardless of `order` and
  `stop_after_first_match`, because it is the only resolver that can tell
  inbound from outbound. The cascade honoured that only for the default order:
  with `order: [tag, inventory]`, a matching tag ended the loop before the
  inventory ran, and the rule reached the team as a bare *related* entry — no
  direction, no peer team, no matched network — while looking like a complete
  attribution. `inventory` now runs first and outside the cascade, whether or
  not `order` names it.

- **A derived team inherited every tag from the objects it was built from,
  including classification tags.** A PAN-OS tag is a classification before it
  is anything else — it says what an object *is*, and dynamic address groups
  are built on exactly that. Treating all of them as ownership meant that on a
  real estate one tag sitting on 137 address groups was inherited by 107 of the
  110 derived teams; since the tag index keeps one team per tag, all 161 rules
  carrying it were handed to whichever team sorted last, presented as its own
  rules with findings to work through. Which team received them depended on
  nothing but alphabetical order.

  A derived team now takes only tags that match a configured ownership
  convention *and* name that team. On the estate this was found on, the
  affected team went from 161 own rules and 111 findings to 2 and 0, and the
  161 rules are attributed by address instead — which is what actually decides
  whom they concern.
- **The customer-data guard missed a serial attached to a hostname.**
  `\b\d{12}\b` does not match inside `<hostname>_<serial>` — an underscore is
  a word character, so there is no boundary before the digits — and that is
  exactly the shape a serial arrives in, because Panorama names the members of
  a backup archive that way. One had been sitting in a source comment. The
  pattern is now digit-bounded, a second rule catches the member-name shape at
  any serial width, and both are covered by tests.
- Every example in the documentation, comments and tests now comes from the
  repository's own invented estate rather than from a real one. Object naming
  conventions, ticket ids, administrator names, device and backup file names
  and address plans had accumulated in explanatory prose, where the guard
  cannot see them.

### Added

- **`ownership.object_naming` and an *Inventory gaps* section.** Where an
  estate names its address objects after the account they belong to, that name
  is a second, independent record of ownership — and where it disagrees with
  the inventory, one of them is wrong. The disagreement was previously silent:
  rules touching that network never reached the team's report, which then
  looked complete.

  Two disagreements are reported, in the cross-team overview and as a worksheet
  in the combined workbook: a network the name assigns to a team the inventory
  does not give it (usually the account's address group is missing a member),
  and a network two teams' names both claim (a range reassigned while the older
  object outlived it). On the estate this was built against, 50 objects of the
  first kind across 18 accounts, and 7 of the second.

  It never attributes a rule. A name is a claim; an address is what the
  firewall matches on. This was built *instead of* reading ownership tags for
  attribution, which would have made the same rules appear while leaving the
  address groups wrong — for this tool and for everything else that uses them.
- **`ownership.tag_suffixes`**, for estates that write the team before the
  marker: `payments-owner` alongside `owner:payments`. Empty by default,
  because a suffix is the rarer convention and a wrong one silently claims
  rules for the wrong team. Together with `tag_prefixes` it is now the single
  definition of what an ownership tag looks like — used by the tag resolver and
  by the team derivation, which previously disagreed.
- A tag claimed by more than one team is reported in the run notes. Exactly one
  of them receives the rules carrying it, and the choice is an accident of
  ordering rather than a decision.
- **`example/`** — finished reports from a complete estate, with the
  configuration and inventory that produced them, committed so that anyone
  deciding whether the tool is worth installing can read one first. Built by
  `example/generate.py` from the fixture generator, so it contains no real
  configuration and cannot drift from the code.
- A reserved fake device-serial range (`001901……`) that the customer-data guard
  recognises, alongside the documentation address ranges and example domains it
  already allowed. Without it the generated example could not pass the guard
  that exists to protect it.
- **Every section collapses**, the header sticks to the top of the window as
  you scroll (shrinking to one line), and a jump bar links to each section with
  a way back to the top. A report of several hundred rows was navigable only by
  scrollbar.
- **A per-team list of the address objects and groups inside their networks** —
  what their networks are called in the firewall. A change request has to cite
  an object name, and the naming convention is invisible from the outside:
  nobody guesses that their 10.20.12.0/24 is `grp-aws-payments-prod-01`.
  Present in the HTML, PDF and workbook, and as `TeamReport.objects` in JSON.
- The network that explains why a rule is in the report is shown bold among the
  resolved addresses, so the stated reason points at something visible.
- **The summary tiles link to the sections they count**, expanding one that has
  been collapsed.
- **The cross-team overview gained the navigation the team reports have**: a
  sticky header with jump links, collapsible sections, and tiles that link to
  what they count.
- **Rules without an owner expand.** That section is the one that says the
  inventory is incomplete, and deciding *whose* a rule is means seeing the
  object names and what they resolve to — which was the one thing the table
  did not show.
- The overview is written as `{date}_00_OVERVIEW_all-teams` rather than
  `{date}_firewall-review-overview`. It lands beside one report per team, all
  sharing the date prefix, and the old name sorted into the middle of them.
  Configurable as before via `output.combined_filename_template`.
- A far side owned by dozens of teams is reported as a count — `60 teams` —
  with the names in the tooltip. The endpoint rule that prompted this listed
  every team in the inventory across a dozen wrapped lines, pushing the rest of
  the row off the page, and said nothing the count does not.
- **`metadata.change_patterns`** reads edits recorded by position rather than by
  keyword — `CHG0041234 (a.beck: 2024-05-30)` becomes a change date with the
  editor's name instead of a date of unstated purpose. Empty by default, and run
  only against dates the keywords could not explain, so an expiry stays an
  expiry. `changed` joins the date roles, with keywords of its own.
- **`IMPOSSIBLE_DATE`** reports a change, creation or review dated after the day
  the report covers. `CHG0041299 a.beck 2027-07-18` on a 2026 review records an
  edit that has not happened — nearly always a mistyped year, and one that
  quietly corrupts every "last touched" calculation built on it. Expiries are
  excluded: those are supposed to be in the future.
- `pan-review run --sample N` writes only N per-team reports, picked as a
  spread across team size and naming families rather than the first N. The
  analysis still runs over the whole estate, so the reports written are
  identical to those of a full run — it is for trying a configuration out
  without producing hundreds of files.
- `ownership.covering_supernet_bits` controls how much larger than one of your
  networks a rule's network may be and still count as your own rule. The
  default of 1 means any strictly larger network counts as merely covering you;
  raise it for an inventory that lists individual hosts.
- `ReportBundle.scopes` records every policy block and its position in the
  evaluation order; `RuleView.coverage`, `RuleView.scope_id` and
  `RuleView.evaluation_rank` expose the classification and the ordering to JSON
  consumers.
- The combined report lists the policy blocks in evaluation order, with the
  firewalls each one reaches.

## [0.1.0] — 2026-07-28

First release.

### Added

#### Reading configurations

- Parser for Panorama configurations: device groups with inheritance, shared
  scope, pre- and post-rulebases, templates, managed device serials
- Parser for standalone PAN-OS firewall configurations: vsys, local rulebase,
  NAT rules, zones
- Backup discovery: newest file from a directory, or an explicit file; plain
  XML, gzip, and tar archives containing one configuration per managed device
- `input.select_by: filename` for estates where mtimes are rewritten in transit
- Device-group hierarchy read from the `readonly` block, which is where
  Panorama actually keeps the parent links
- External dynamic lists and built-in regions reported as such rather than as
  unknown objects
- Each firewall in a multi-device archive keeps its own `shared` and `vsys`
  namespace, so identically named objects on different devices stay distinct
- `input.max_age_days` guard against a silently broken backup job
- XML parsed with entity resolution and network access disabled; compressed
  members capped at 2 GiB

#### Resolving what a rule actually permits

- Address and service groups flattened, including nested groups, with cycle
  and depth protection
- Dynamic address groups evaluated offline: full tag-expression grammar with
  `and`, `or`, `not` and parentheses
- Device-group scope inheritance followed as PAN-OS does it — nearest scope,
  then each parent, then `shared`
- IP ranges converted to minimal covering CIDRs
- External dynamic lists, regions and FQDNs reported as unresolved rather than
  dropped, so a report never understates exposure

#### Attributing rules to owners

- `ownership.derive_teams` creates teams from a naming convention — address
  group, address object or tag names — so an estate that provisions networks
  automatically needs no hand-maintained inventory for the generated part.
  Merged with the explicit inventory, which always wins.
- Placeholder addresses (loopback, unspecified, link-local) never count as team
  assets; one of them in a generated group would otherwise attribute every rule
  touching it to every team holding it.
- Five resolvers: inventory (CIDR), tag, regex, device group and zone
- Inbound / outbound / internal direction from the inventory and zone
  resolvers; the other three attribute without direction
- Prefix trie for CIDR overlap, so attribution stays fast on large estates
- Per-rule provenance: every rule in a report states why it is there
- Configurable cascade with `stop_after_first_match`
- Per-team cap on `any`-to-`any` rules

#### Reading rule descriptions

- Configurable ticket patterns with URL templates, validated at load time
- ISO (`2026-12-31`), dotted (`31.12.2026`) and slashed (`31/12/2026`) dates all
  recognised out of the box
- Role keywords are configured once under `metadata.role_keywords` and apply to
  every date format, so an estate using more than one maintains a single list.
  A pattern may still override them.
- Requester extraction

#### Findings

- 16 cleanup checks covering overly broad rules, missing documentation,
  lifecycle and object hygiene
- `FLAGGED_OBJECT` surfaces rules that still reference an object marked by a
  local convention, e.g. `OUTDATED_`; the patterns are configuration
- Checks that need absent data produce nothing rather than guessing
- Exemptions by tag and by rule-name pattern

#### Output

- Self-contained HTML with search, severity filters, per-rule detail and
  clickable ticket links
- Excel workbook with *Decision* and *Comment* columns for the return path
- PDF for audit and sign-off, carrying the configuration checksum
- JSON as the complete machine-readable record
- Light and dark themes, each stepped deliberately; colour is never the sole
  carrier of meaning

#### Commands

- `run`, `validate`, `inspect`, `checks`, `init`, `diff`, `scrub`,
  `collect-hitcounts`, `suggest-inventory`
- `suggest-inventory` derives a draft inventory from how a configuration
  already groups its addresses — by device group, by rule usage, by zone or by
  tag. `--compare` reports how well each grouping fits before committing to
  one. Names and contacts come out as TODO rather than being guessed.
- Meaningful exit codes for cron and monitoring

#### Optional hit-count collection

- Opt-in module, the only network access in the tool, read-only `show`
  commands only, with a sidecar cache so reporting stays offline
- API keys read from the environment or a key file, never from the
  configuration

#### Project

- Synthetic configuration generator as the only source of test data
- Repository data guard as a pre-commit hook and CI job
- Pseudonymiser for bug reports, with its limits documented
- CI across Python 3.11–3.14 on Linux, macOS and Windows, including an
  end-to-end run with outbound network traffic blocked
- Dependabot for Python packages and GitHub Actions, plus a scheduled job
  for pre-commit hook revisions, which Dependabot does not cover
- Provenance stated openly: the implementation was written by an AI
  assistant under maintainer review (see the README)

[Unreleased]: https://github.com/Merlina-Minds/panorama-team-review/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Merlina-Minds/panorama-team-review/releases/tag/v0.1.0
