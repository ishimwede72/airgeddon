# Offline assessment foundation

This standalone Python 3.9+ CLI is **not a live wireless test engine**. It reviews
an explicitly authorized, normalized JSON inventory. It does not parse native
hostapd/RADIUS/client configuration, discover devices, create APs, transmit frames,
collect credentials, fuzz live protocols, or run shell commands. No extra Python
packages, root privileges, wireless hardware, or network connection are required.
It is intentionally separate from the interactive Bash tool.

For dictionary cataloging, existing-PCAP analysis, approved-AP comparisons,
password-policy checks, synthetic benchmarks, and combined reports, see the
[offline defensive toolkit](TOOLKIT.md). Those commands are separate from this
configuration-inventory assessor.

## Run

From the repository root:

```bash
python3 -m lab.assess lab/examples/inventory.json
python3 -m lab.assess lab/examples/inventory.json --format json --output /tmp/lab-report.json
python3 -m lab.assess lab/examples/inventory.json --fail-on-findings
python3 -m unittest discover -s tests -p 'test_*.py'
```

The example contains synthetic identities only and intentionally raises findings.
Exit codes: **0** report generated; **1** unresolved results with
`--fail-on-findings`; **2** invalid inventory or I/O error. Without that flag, 0
means the assessment ran, not that the configuration is secure. Reports written
with `--output` use mode 0600 and atomically replace that one file. Parent
directories must already exist. Existing reports at that path are overwritten.
Stdout permissions/redirection are the caller's responsibility.

## Inventory schema (version 1)

See `examples/inventory.json` for a complete example. Unknown fields and duplicate
JSON keys are rejected. Do **not** supply passwords, private keys, real credential
material, or executable actions. Network identifiers can be pseudonyms. Treat
reports as sensitive even though credential fields are not supported.

- `schema_version`: integer `1`.
- `scope`: object containing `label` (nonempty text) and `authorized: true`.
  This is an explicit user declaration, **not proof of authorization**.
- `networks`: 1–1000 objects, each with a unique `id`, `security`, and `pmf`.
- `security`: `open`, `wpa2-personal`, `wpa3-personal`, `wpa2-wpa3-personal`,
  `wpa2-enterprise`, `wpa3-enterprise`, or `unknown`.
- `pmf`: `disabled`, `optional`, `required`, or `unknown`.
- Enterprise networks may include an `enterprise` object with:
  - `eap_methods`: nonempty, unique list of `tls`, `peap`, `ttls`, or `unknown`.
  - `validate_server_certificate`, `trusted_ca_configured`,
    `server_names_configured`: booleans. Omit unknown values; omission is never a pass.

Text fields are limited to 128 characters, without control characters. Input is
limited to 1 MiB. Values are strict and case-sensitive. The format deliberately
represents only a small subset of wireless security configuration.

## Checks and interpretation

Stable check IDs cover encryption presence, personal transition mode, PMF policy,
and enterprise certificate validation, CA trust, and server-name restrictions.
EAP methods always require manual review: method names alone cannot establish
secure inner authentication, certificate lifecycle, TLS configuration, or RADIUS
policy. PMF-required is a hardening target, not a universal compatibility claim.
An optional/disabled PMF declaration on a WPA3-only network is high severity.

Results have `pass`, `fail`, `unknown`, or `review` status. Evidence always describes
a supplied declaration, **not observed client or AP behavior**. JSON includes a
SHA-256 of canonicalized validated inventory, stable check IDs, recommendations,
limitations, and per-status counts. Identical inventories produce identical reports;
there is no clock, random run ID, or network-dependent enrichment. The hash is an
input fingerprint, not a signature or authenticity guarantee. Markdown escapes
user-provided text, including HTML and table delimiters.

## Extension boundary

New offline checks should be deterministic functions over validated data with
unit tests. Do not accept command strings or plugin paths in inventory. Native
configuration importers should be separate, read-only adapters that discard
secrets and preserve unknown values. Virtual-radio scenarios, active tests, and
any workflow requiring radio/network changes need a separate design and explicit
approval; none are implemented here.
