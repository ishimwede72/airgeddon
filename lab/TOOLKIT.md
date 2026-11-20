# Offline defensive toolkit

Python 3.9+, standard library only. Run from the repository root; **do not run as
root**. These utilities do not invoke shell commands, start capture services,
transmit frames, harvest credentials, or attempt password recovery. Only review
files and networks you are authorized to assess. Inputs should be stable local
regular files, not files being modified by other users or an active recorder.

## Commands

Global `--format json|markdown` and `--output PATH` go **before** the subcommand:

```bash
python3 -m lab.toolkit --help
python3 -m lab.toolkit catalog lab/examples/catalog.json
python3 -m lab.toolkit capture /path/to/authorized-capture.pcap
python3 -m lab.toolkit capture /path/to/authorized-capture.pcap --baseline lab/examples/baseline.json
python3 -m lab.toolkit policy --blocklist /path/to/licensed-local-blocklist.txt
python3 -m lab.toolkit benchmark --samples 1000 --seconds 1
python3 -m lab.toolkit --format markdown --output /tmp/new-assessment.md report \
  lab/examples/inventory.json \
  --manifest lab/examples/catalog.json
# Optional report arguments:
# --pcap /path/to/capture.pcap --baseline /path/to/approved-aps.json
```

Exit **0** means processing completed, not that results are secure or all checks
passed. Exit **2** means invalid, unsupported, oversized, or inaccessible input,
an unsafe/existing output path, or lack of a secure interactive password prompt.
Exit **130** indicates cancellation. Read the checks and limitations in the report.
Every report includes `schema_version: 1` and an `assessment_type` discriminator.

With `--output`, files are exclusively created with mode 0600. Existing files or
symlinks are never overwritten. On write failure the partial file is removed.
A process killed ungracefully may leave a partial file; this output mode is not
an atomic replacement transaction. Parent directories must already exist.
Stdout/redirection is the caller's responsibility. Reports are sensitive: they
can contain BSSIDs, hex-encoded SSIDs (not anonymization), source/license metadata,
and findings. No raw dictionary entries or submitted passwords are printed.

## 1. Local wordlist catalog and quality checks

`catalog` reads a manifest like `examples/catalog.json`. It requires exact fields:

- `schema_version`: integer `1`.
- `dictionaries`: 1–20 objects with `id`, `path`, `source`, `license`, `language`,
  and an expected lowercase hexadecimal `sha256`.
- Paths are local; relative paths resolve against the manifest's directory.
- IDs are unique. Metadata strings have a 128-character limit. Sources and
  licenses are declarations, not verified legal approval or download URLs.

Reports include byte size, whole-file SHA-256, checksum match status, total/empty lines,
unique/duplicate nonempty entries, invalid UTF-8 counts, and a coarse count of
credential-like patterns. Duplicate detection is exact byte matching after
removing trailing CR/LF; there is no case folding or Unicode normalization.
Only in-memory entry fingerprints are used; none are included in the report.
The credential-material heuristic is **not** a secret scanner and cannot guarantee
that a list is safe to share. A checksum mismatch is a reported finding, not an
I/O failure. Investigate before using the file.

No dictionaries are downloaded or redistributed. Only a tiny synthetic fixture
is checked in. Store large, licensed local files under ignored `.lab-data/` or
outside the repository. This tool neither generates cracking candidates nor
exports a cleaned list for attacks.

## 2. Existing-capture analyzer

`capture` supports **classic PCAP 2.4**, either endianness, microsecond or
nanosecond magic, with linktype **105** (raw 802.11 without appended FCS) or
**127** (radiotap). PCAPNG, Ethernet captures, exotic radiotap layouts, and
non-beacon management frames are not supported. Radiotap TSFT/flags and appended
FCS removal are supported; CRC integrity itself is not verified. Bad-FCS flagged
frames are excluded.

Only beacon headers, SSID bytes, RSN AKM suites, and advertised PMF flags are
interpreted. Data/authentication/EAP payloads are ignored, not extracted. The
whole-file fingerprint covers original input bytes but does not disclose them.
Identical advertised configurations are counted together; different configurations
for the same BSSID remain separate observations.

Supported AKM interpretation is deliberately conservative: PSK, SAE, PSK+SAE,
and generic RSN EAP. Generic EAP is **not** automatically labeled WPA3-Enterprise.
Unrecognized/mixed suites remain unknown; protected networks without RSN are
`legacy-protected`, without guessing WEP versus WPA1. A beacon does not establish
actual encryption strength, PMF enforcement, certificate validation, or AP trust.
Malformed/truncated frames are counted and excluded. Invalid record/file framing
aborts the report. An empty result or zero alerts is not evidence of safety.

## 3. Approved-AP baseline comparison

See `examples/baseline.json`. Required fields are `schema_version: 1`,
`scope: {"label": "...", "authorized": true}`, and `approved_aps`. Authorization
is a user declaration, not independent proof. Each AP needs a unique lowercase
`bssid`, lowercase `ssid_hex` (0–32 bytes), known `security`, and known `pmf`.
There may be 1–4096 approved APs. Unknown fields are rejected.

Security expectations: `open`, `legacy-protected`, `wpa2-personal`,
`wpa3-personal`, `wpa2-wpa3-personal`, or `rsn-enterprise`. PMF expectations:
`disabled`, `optional`, or `required`.

- `AP-UNEXPECTED`: observed BSSID not in the baseline; status **review**.
- `AP-POLICY-CHANGED`: SSID/security/PMF differs from baseline; **review**.
- `AP-NOT-OBSERVED`: approved BSSID absent from this capture; **unknown**.

These are investigation leads, not confirmed rogue-AP detections. An attacker
can spoof a matching BSSID and advertised policy. Missing APs might simply be
outside capture range or time. Multiple APs sharing an SSID are not automatically
considered suspicious.

## 4. Password-policy assessment

Use disposable test passwords only. `policy` prompts with echo disabled and
refuses piped stdin or an echo-fallback prompt. **Never place a password on the
command line**, in an inventory, or in a report. The policy checks:

- Minimum length (default 15 Unicode code points; configurable 8–128).
- Exact UTF-8 membership in the supplied local blocklist.
- Presence of ASCII control characters.

No supplied password or derived hash is saved in results. There is no password
strength score, crack-time estimate, login attempt, hash ingestion, or recovery
algorithm. Blocklist absence is not proof of uniqueness or strength. Python
cannot guarantee erasure of secret strings from process memory; use an isolated
local environment. Password length is capped at 1024 characters.

## 5. Synthetic benchmark

`benchmark` times a small, deterministic synthetic length-policy loop and
returns a benchmark report. It accepts only sample/time limits: 1–10000 samples,
0.01–5 seconds. Timing varies by machine; results are not crack-speed benchmarks.
There are no external passwords, hashes, target accounts, dictionary generators,
or adaptive search. The time budget is checked between fixtures, not enforced
through OS-level resource isolation.

## 6. Combined reports

`report` combines the existing configuration assessor with optional beacon,
baseline, and catalog sections in JSON or escaped Markdown. A baseline requires
a capture. Evidence types and their individual limitations are preserved rather
than collapsed into an unsubstantiated global security score. Submitted passwords
are intentionally excluded. The result is an assessment aid, not a certification.

## Resource and test boundaries

JSON manifests/baselines: 1 MiB, no duplicate keys. Dictionaries: 64 MiB per file,
250000 lines, 4096 bytes per line. Captures: 64 MiB, 100000 packet records, 65535
bytes per packet, 4096 distinct advertised identities. Exceeding these limits
fails rather than silently claiming a complete assessment. Limits are per input,
not an OS sandbox or defense against concurrent local file replacement.

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Tests generate synthetic PCAP bytes and temporary dictionaries locally; no real
capture or production password dataset is required. Tests cover redaction,
parser bounds, endianness, malformed inputs, baseline differences, duplicate and
checksum handling, private outputs, and rejection of noninteractive secrets.
