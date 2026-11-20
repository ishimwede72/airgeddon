# airgeddon
[![Version-shield]](https://raw.githubusercontent.com/v1s1t0r1sh3r3/airgeddon/master/CHANGELOG.md) [![Bash4.2-shield]](http://tldp.org/LDP/abs/html/bashver4.html#AEN21220) [![License-shield]](https://raw.githubusercontent.com/v1s1t0r1sh3r3/airgeddon/master/LICENSE) [![Docker-shield]](https://github.com/v1s1t0r1sh3r3/airgeddon/actions/workflows/master.yml) [![Discord-shield]](https://discord.gg/sQ9dgt9)

[![Paypal-shield]](https://www.paypal.com/paypalme/airgeddon) [![Cryptocurrencies-shield]](https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Contributing-&-Code-of-Conduct)


> This is a multi-use bash script for Linux systems to audit wireless networks.

![Banner]

---

## Offline configuration assessment

For read-only, hardware-independent checks, see [the offline lab foundation](lab/README.md):

```bash
python3 -m lab.assess lab/examples/inventory.json
```

This separate Python CLI reviews declared WPA/PMF and enterprise certificate
settings and generates JSON or Markdown reports. It needs no root privileges,
network access, or wireless hardware. It does not verify runtime enforcement or
perform live wireless tests.

The [offline defensive toolkit](lab/TOOLKIT.md) adds a licensed local dictionary
catalog, beacon-only PCAP summaries, approved-AP baseline comparisons, hidden-input
password-policy checks, a synthetic policy benchmark, and combined reports:

```bash
python3 -m lab.toolkit --help
python3 -m lab.toolkit catalog lab/examples/catalog.json
python3 -m lab.toolkit --format markdown report lab/examples/inventory.json --manifest lab/examples/catalog.json
```

These additions do not run live captures, credential harvesting, or password
cracking. Keep real captures, reports, and licensed dictionaries outside Git or
under ignored `.lab-data/`; the checked-in dictionary is synthetic.

## Terminal console

The English main menu follows the supplied red-and-black dashboard reference:
an original ASCII dragon panel, centered feature navigation, red borders, and
system/wireless/network/quick-action cards. The raster dragon and glow textures
are interpreted as terminal text, not embedded as a bitmap or copied Kali logo.
The existing actions and option numbers are unchanged; both `7` and `07` select
the same existing menu. Cards use the actual application version and reported
interface/mode, not invented IP addresses, connection claims, signal bars,
authorization guarantees, or test counts. No wireless telemetry is collected by
the renderer.

Preview it safely, without root, prerequisite checks, or wireless operations:

```bash
bash airgeddon.sh --ui-preview
bash airgeddon.sh --help
# Full three-column reference layout:
COLUMNS=140 LINES=40 bash airgeddon.sh --ui-preview
```

In the main menu, `h` displays help and `q` exits through normal cleanup.
`NO_COLOR=1`, `TERM=dumb`, or redirected output disables built-in ANSI colors.
The optional dashboard renderer (`lab/console.py`) uses only Python 3.9+'s
standard library. The full layout needs 132 columns and 38 rows; a two-column
layout needs 94 columns and 30 rows; otherwise a compact numbered list is used.
Output is bounded to 160 columns. With Python absent, the renderer missing, or
a non-English language selected, Bash falls back to the existing translated
menu and compact/original banner. Legacy translated lines may wrap in narrow
windows. No startup animation or artificial loading delay is added.

## Quick start

Use only on networks you own or have explicit permission to audit. This tool runs
as root and can interrupt networking; use a dedicated Linux test machine, not a
production host. Bash 4.2+, `flock` (util-linux), a supported wireless adapter,
and the essential tools listed in `airgeddon.sh` are required. Optional features
need additional packages; see the requirements links below.

```bash
# From a trusted checkout; install your distribution's dependencies first.
sudo bash airgeddon.sh
```

The default interface uses X11/xterm. For a terminal-only environment, install
tmux and use `sudo env AIRGEDDON_WINDOWS_HANDLING=tmux bash airgeddon.sh`.
Containers still require compatible Linux host hardware and appropriate device
and networking privileges; they do not emulate a wireless adapter.

### Configuration and trust

Nonempty environment variables override configuration. `/etc/airgeddonrc` takes
precedence over the checkout's `.airgeddonrc`. Use unquoted `KEY=value` lines,
lowercase booleans (`true`/`false`), and `xterm`/`tmux` or `mdk3`/`mdk4` for the
enumerated options. Mixed case is normalized; duplicate keys fall back to defaults.
Shell expansion and inline shell commands are not supported in configuration.

Keep the checkout, configuration, and plugin directories writable only by trusted
administrators. Enabled plugins in `plugins/` and `$HOME/.airgeddon/plugins/` are
executable code with the script's privileges. Language files and the PIN database
are also sourced shell code. Disable plugins with `AIRGEDDON_PLUGINS_ENABLED=false`
when they are not needed. Development mode skips safety/prerequisite checks and
is not a normal installation workaround.

### Updates and recovery

Updates require HTTPS and stage syntax-checked scripts before replacement. The
script and language file are checked for matching versions; `.previous` copies
are kept beside them for rollback. HTTPS/version checks are **not signed-release
verification**. Prefer a reviewed checkout and disable automatic updates with
`AIRGEDDON_AUTO_UPDATE=false` when reproducibility is important. Replacement of
the two files is not a single filesystem transaction: interruption between the
two renames can still require restoring both `.previous` files.

Runtime state is private under `/run/airgeddon/` (owner root, mode 0700). If
firewall restoration fails, the backup `ag.iptables_nftables` is retained there.
Do not delete it until recovery succeeds. From a local console, stop other
instances first and inspect the backup. An administrator can restore it using
`nft -f /run/airgeddon/ag.iptables_nftables` for nftables or
`iptables-restore < /run/airgeddon/ag.iptables_nftables` for iptables, matching the
backend used for the session. These commands change host-wide firewall state;
do not apply a stale backup over newer firewall changes. `/run` is cleared on
reboot. Check NetworkManager, interface mode, and IP forwarding after an abnormal
shutdown. SIGKILL and power loss cannot run cleanup.

**Remaining networking limitation:** sessions can still flush global firewall
rules and restore a snapshot. Use an isolated host; this is not safe alongside
production firewall managers, VPNs, or container networking. Removing global
resets requires a separate backend integration change.

### Container builds

`docker build -t airgeddon .` uses the rolling Kali default. For release builds,
pass `--build-arg KALI_IMAGE=kalilinux/kali-rolling@sha256:<verified-digest>`.
The legacy Hashcat 2.0 binary is retained for the existing container compatibility
path, but its source revision and SHA-256 are now pinned and checked. This is not
a claim that the legacy binary is maintained or vulnerability-free. Kali apt
packages still follow rolling repositories, so a pinned base alone does not make
package installation fully reproducible. CI does not yet enforce a base digest.

All the needed info about how to "install | use | enjoy" `airgeddon` is present at [GitHub's Wiki].

- *I. Content & Features*
  - [Home]
  - [Features]
  - [Screenshots]
  - [Wallpapers]


- *II. Requirements*
  - [Requirements]
  - [Compatibility]
	 - [Cards and Chipsets]
	 - [Wayland]
	 - [Consistent Network Device Naming]
	 - [Kali Nethunter]
  - [Essential Tools]
  - [Optional Tools]
	 - [BeEF Tips]
	 - [Hashcat Tips]
	 - [Bettercap Tips]
  - [Update Tools]
  - [Internal Tools]
  - [Known incompatibilities]


- *III. Getting started*
  - [Installation & Usage]
  - [Options]
  - [Docker]
	 - [Linux]
	 - [Mac OSX]
	 - [Windows]
  - [Other Sources]
  - [FAQ & Troubleshooting]


- *IV. Learning*
  - [CWP Certification]


- *V. Project & Development*
  - [Official Website]
  - [Plugins system]
	 - [Plugins development]
	 - [Plugins Hall of Fame]
  - [Supported Languages]
  - [Contributing & Code of Conduct]
  - [Security Policy]
  - [Merchandising Online Shop]
  - [Changelog]
  - [Disclaimer & License]
  - [Contact]


- *VI. Acknowledgments & References*
  - [Hat Tip To]
  - [Inspiration]

---

[Banner]: https://raw.githubusercontent.com/v1s1t0r1sh3r3/airgeddon/master/imgs/banners/airgeddon_banner.png "We will conquer the earth!!"
[GitHub's Wiki]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki

[Home]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki
[Features]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Features
[Screenshots]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Screenshots
[Wallpapers]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Wallpapers
[Requirements]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Requirements
[Compatibility]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Compatibility
[Cards and Chipsets]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Cards%20and%20Chipsets
[Wayland]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Wayland
[Consistent Network Device Naming]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Consistent%20Network%20Device%20Naming
[Kali Nethunter]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Kali%20Nethunter
[Essential Tools]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Essential%20Tools
[Optional Tools]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Optional%20Tools
[BeEF Tips]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/BeEF%20Tips
[Hashcat Tips]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Hashcat%20Tips
[Bettercap Tips]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Bettercap%20Tips
[Update Tools]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Update%20Tools
[Internal Tools]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Internal%20Tools
[Known incompatibilities]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Known%20incompatibilities
[Installation & Usage]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Installation%20&%20Usage
[Options]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Options
[Docker]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Docker
[Linux]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Docker%20Linux
[Mac OSX]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Docker%20Mac%20OSX
[Windows]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Docker%20Windows
[Other Sources]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Other%20Sources
[FAQ & Troubleshooting]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/FAQ%20&%20Troubleshooting
[CWP Certification]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/CWP%20Certification
[Plugins system]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Plugins%20System
[Plugins development]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Plugins%20Development
[Plugins Hall of Fame]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Plugins%20Hall%20of%20Fame
[Supported Languages]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Supported%20Languages
[Contributing & Code of Conduct]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Contributing-&-Code-of-Conduct
[Security Policy]: https://github.com/v1s1t0r1sh3r3/airgeddon/security/policy
[Merchandising Online Shop]: https://airgeddon.creator-spring.com/
[Changelog]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Changelog
[Disclaimer & License]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Disclaimer%20&%20License
[Contact]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Contact
[Hat Tip To]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Hat%20Tip%20To
[Inspiration]: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Inspiration
[Official Website]: https://airgeddon.pro/

[Version-shield]: https://img.shields.io/badge/version-12.10-blue.svg?style=flat-square&colorA=273133&colorB=0093ee "Latest version"
[Bash4.2-shield]: https://img.shields.io/badge/bash-4.2%2B-blue.svg?style=flat-square&colorA=273133&colorB=00db00 "Bash 4.2 or later"
[License-shield]: https://img.shields.io/badge/license-GPL%20v3%2B-blue.svg?style=flat-square&colorA=273133&colorB=bd0000 "GPL v3+"
[Docker-shield]: https://github.com/v1s1t0r1sh3r3/airgeddon/actions/workflows/master.yml/badge.svg?branch=master "Docker CI master"
[Discord-shield]: https://img.shields.io/discord/629812069964840991.svg?style=flat-square&colorA=273133&colorB=CBA317&logo=discord&label=Discord%20chat
[Paypal-shield]: https://img.shields.io/badge/donate-paypal-blue.svg?style=flat-square&colorA=273133&colorB=b008bb "Paypal"
[Cryptocurrencies-shield]: https://img.shields.io/badge/donate-cryptocurrencies-blue.svg?style=flat-square&colorA=273133&colorB=f7931a "Cryptocurrencies"
