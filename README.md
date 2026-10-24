# scouter26

[![CI](https://github.com/Lab-026/scouter26/actions/workflows/ci.yml/badge.svg)](https://github.com/Lab-026/scouter26/actions/workflows/ci.yml)

A modular network toolbox CLI for IT support technicians and junior network
administrators — subnet math, port lookups, and TCP scanning in one command.

Named after Zastava's weapon naming convention: a name, plus the year.

## Commands

| Command                      | Description                           |
| ---------------------------- | ------------------------------------- |
| `scouter26 subnet <cidr>`    | Full IPv4 subnet breakdown            |
| `scouter26 ports <query>`    | Port lookup by number or service name |
| `scouter26 scan <target>`    | Parallel TCP connect scan (IPv4)      |

## subnet

Give it an IPv4 CIDR and it returns the network address, netmask, wildcard
mask, broadcast address, usable host range, host counts, IP class, and whether
the range is private (RFC 1918) or public.

```text
$ scouter26 subnet 192.168.10.0/24

========================================
 Scouter26 - Subnet Analysis
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

IPv6 is rejected with a clear error message (support planned).

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

Scans of 100+ ports show live progress. scouter26 is IPv4-only: a hostname
that resolves exclusively to IPv6 (AAAA) records is refused with a clear
error rather than silently scanned.

> **Warning:** Only scan systems you own or have written permission to scan.
> Unauthorized port scanning is illegal in many jurisdictions.

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
