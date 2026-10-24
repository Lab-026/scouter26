# scouter26

[![CI](https://github.com/Lab-026/scouter26/actions/workflows/ci.yml/badge.svg)](https://github.com/Lab-026/scouter26/actions/workflows/ci.yml)

A modular network toolbox CLI for IT support technicians and junior network
administrators — subnet math, port lookups, and TCP scanning in one command.

Named after Zastava's weapon naming convention: a name, plus the year.

## Commands

| Command                      | Description                              |
| ---------------------------- | ---------------------------------------- |
| `scouter26 subnet <cidr>`    | Full IPv4 **and IPv6** subnet breakdown  |
| `scouter26 ports <query>`    | Port lookup by number or service name    |
| `scouter26 scan <target>`    | Parallel TCP connect scan (IPv4 & IPv6)  |
| `scouter26 discover <cidr>`  | Find live hosts in a subnet              |

## subnet

Give it a CIDR — IPv4 **or** IPv6 — and it returns the network address,
netmask, wildcard mask, broadcast address, usable host range, host counts, IP
class, and whether the range is private (RFC 1918) or public. IPv6 reports
network ID, full address range, total counts, and the address kind
(global unicast, link-local, unique-local, ...).

```text
$ scouter26 subnet 192.168.10.0/24

========================================
 Scouter26 - Subnet Analysis (IPv4)
========================================
 Input IP      : 192.168.10.0
 Prefix        : /24
 Netmask       : 255.255.255.0
 Wildcard      : 0.0.0.255
 Network ID    : 192.168.10.0
 Broadcast     : 192.168.10.255
 Host Range    : 192.168.10.1 - 192.168.10.254
 Total IPs     : 256
 Usable Hosts  : 254
 Class         : C
 Type          : Private (RFC 1918)
========================================
```

```text
$ scouter26 subnet 2001:db8::/32

========================================
 Scouter26 - Subnet Analysis (IPv6)
========================================
 Input IP        : 2001:db8::
 Prefix          : /32
 Network ID      : 2001:db8::
 Host Range      : 2001:db8:: - 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff
 Total Addresses : 79,228,162,514,264,337,593,543,950,336
 Usable Addresses: 79,228,162,514,264,337,593,543,950,336
 Type            : Documentation (2001:db8::/32)
========================================
```

A bare address with no `/prefix` means a single host (`/32` or `/128`).

## ports

Look up common ports in either direction — by number or by service name:

```text
$ scouter26 ports 443
$ scouter26 ports ssh
```

Partial names get "did you mean" suggestions — try `scouter26 ports netbios`.

## scan

Resolves the target's DNS once, probes TCP ports in parallel with a tunable
worker pool, and reports which ones are open — with the service name, and the
service's own banner whenever it announces one (SSH, FTP and SMTP servers
typically do).

```text
$ scouter26 scan scanme.nmap.org
$ scouter26 scan scanme.nmap.org --ports 22,80,443
$ scouter26 scan scanme.nmap.org --ports 20-1024 --timeout 2 --workers 500
```

- `--ports` — one port, a comma-separated list, or a range
  (default: the 10 most common ports)
- `--timeout` — seconds to wait per port before calling it closed (default: 1)
- `--workers` — how many ports to probe at the same time (default: 200, max 2000)
- `--ipv6` — prefer the IPv6 address when a hostname has both A and AAAA records
- `--json` — machine-readable JSON report on stdout (warnings and errors go
  to stderr), ready for `jq` and log pipelines

Scans of 100+ ports show live progress. Both IPv4 and IPv6 targets work:
dual-stack hostnames are scanned over IPv4 unless `--ipv6` is given, and a
bare IPv6 address (or an IPv6-only hostname) scans over IPv6 directly.

> **Warning:** Only scan systems you own or have written permission to scan.
> Unauthorized port scanning is illegal in many jurisdictions.

## discover

Sweep a subnet for live machines by probing a handful of classic ports on
every address. A host counts as **ALIVE** if any probe connects — or is
*refused*, because a refusal is still a machine answering. This is how
discovery finds hosts that ignore ICMP ping.

```text
$ scouter26 discover 192.168.1.0/24

========================================
 Scouter26 - Host Discovery
========================================
 Network:      192.168.1.0/24
 Hosts:        254
 Probe ports:  22 (ssh), 80 (http), 443 (https), 445 (smb), 3389 (rdp)
 Total probes: 1270
----------------------------------------
 [!] Only scan networks you own or have permission to scan.
========================================
 192.168.1.1                          ALIVE  80 (http), 443 (https)
 192.168.1.34                         ALIVE  (answered, but no open ports)
========================================
 Found 2 live host(s) out of 254 probed in 6.41s.
```

- `--ports`, `--timeout`, `--workers` work exactly as in `scan`
- `--json` — machine-readable JSON report on stdout; `open_ports: []` on a
  live host means it answered with refusals only
- Sweeps are capped at 4096 hosts — use a longer prefix for anything wider
- A host that silently drops every probe cannot be seen by TCP discovery
  (ICMP and ARP discovery are planned)

> **Warning:** Only scan networks you own or have permission to scan.

## Installation

Requires Rust.

```text
git clone https://github.com/Lab-026/scouter26.git
cd scouter26
cargo install --path .
```

After that, `scouter26` works from any directory.

## Building and testing

```text
cargo build --release
cargo test
```

## License

MIT — see [LICENSE](LICENSE).
