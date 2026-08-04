# Security policy

## Reporting a vulnerability

Please report security issues privately, **not** in the public issue tracker.

Two routes, either is fine:

- GitHub's [private vulnerability
  reporting](https://github.com/Merlina-Minds/panorama-team-review/security/advisories/new)
  for this repository — preferred, because it keeps the report attached to the
  code.
- Email [kontakt@merlina-minds.de](mailto:kontakt@merlina-minds.de) with `panorama-team-review` in the subject,
  if you would rather not use GitHub or do not have an account.

Include what the issue is, how to trigger it, and what an attacker gains. If
reproducing it requires a configuration file, read
[docs/PRIVACY.md](docs/PRIVACY.md) first — describe the *structure* or send a
scrubbed file, never a real one. **Do not attach a production configuration to
either channel**, including email; if you believe the issue cannot be shown
without one, say so and we will agree a way to handle it.

Expect an acknowledgement within a few working days. Fixes for confirmed issues
are released as soon as practical, with credit unless you prefer otherwise.

## Supported versions

Pre-1.0. Only the latest release receives fixes.

## Threat model

This tool reads **untrusted input** — a configuration backup is a large XML
file, and the tool is designed to run unattended from cron. It also handles
**highly sensitive data**: a firewall configuration is a complete description
of an organisation's network segmentation.

### What the tool does to protect itself

| Risk | Mitigation |
|---|---|
| XXE / entity expansion in a backup | XML parsed with `resolve_entities=False` and `no_network=True` |
| Decompression bomb in a `.gz` or `.tgz` | Members capped at 2 GiB, enforced before extraction |
| Path traversal from archive members | Only in-memory reads; nothing is extracted to disk |
| Malicious rule names or descriptions reaching a report | Jinja autoescaping on for all data; only the tool's own stylesheets bypass it. Tested in `test_html_escapes_rule_content`. |
| Unintended device modification | Both network features are read-only: every operational command is checked to start with `show` before it is sent (including the ones Panorama proxies to a managed firewall via `target`), and configuration fetch only ever requests `type=export&category=configuration`. Password authentication uses only a `keygen` credential exchange |
| Credential exposure | API keys and passwords are read from an environment variable or a file, never from the configuration file; only the username, which is not a secret, may live there. `config/config.yaml` is gitignored |
| Unintended network access | Network code lives only in `panos_api.py` (shared transport) and its two callers `enrich/hitcount.py` and `fetch.py`, all disabled by default; CI verifies a full run completes with outbound traffic blocked |

### What it does not protect against

- **A malicious configuration file is still trusted as input to analysis.** The
  tool parses it safely, but it will faithfully report whatever the file says.
  A tampered backup produces a misleading report.
- **Report contents.** Generated reports describe your network segmentation as
  completely as the configuration does. Distributing them is your decision;
  see [docs/PRIVACY.md](docs/PRIVACY.md).
- **`verify_tls: false`.** Available because some management networks use
  internal CAs that are awkward to distribute, but it defeats the point of TLS
  on a management interface. Prefer `ca_bundle` — `pan-review fetch-cert`
  retrieves a device's certificate and prints its SHA-256 fingerprint so you can
  verify it out of band before trusting it. That fetch is trust-on-first-use
  (unverified by necessity), so the fingerprint check matters.
- **The scrubber is not an anonymiser.** Structure is preserved and the mapping
  is reversible with the salt. See the limits section in
  [docs/PRIVACY.md](docs/PRIVACY.md).

## Deployment recommendations

- Run as an unprivileged user with read access to the backup directory and
  write access to the output directory. Nothing else is needed.
- Keep the network features (hit-count collection and configuration fetch)
  disabled unless you need them. If you enable either, use an account bound to a
  **read-only administrator role**, and supply its secret (API key or password)
  through the environment or a mode-`0600` file — never in the configuration.
- Restrict access to the output directory. Reports are as sensitive as the
  configuration they describe.
- Set `input.max_age_days` so a broken backup job fails loudly rather than
  producing confident reports from a stale configuration.
