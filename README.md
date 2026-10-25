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
| `scouter26 udp <target>`     | Probe UDP services (DNS, NTP, SNMP, ...) |
| `scouter26 syn <target>`     | Half-open SYN scan (needs root, IPv4)    |

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

## udp

UDP has no handshake, so port states are fundamentally different from TCP.
`udp` sends real protocol payloads (a DNS query, an NTP client request, an
SNMP GET) where it knows the dialect, and plain datagrams elsewhere, then
reports one of three verdicts:

| Verdict          | Meaning                                                     |
| ---------------- | ----------------------------------------------------------- |
| `OPEN`           | The service answered — proof of life                        |
| `CLOSED`         | The host's kernel said "nothing listens here" (ICMP)        |
| `OPEN\|FILTERED` | Silence: an open-but-quiet service or a firewall — UDP cannot tell |

```text
$ scouter26 udp 192.168.1.1

 Port 53     dns         OPEN  (47 bytes received)
 Port 123    ntp         OPEN|FILTERED  (no response — open or firewalled)
 Port 161    snmp        CLOSED  host says: nothing listens here
```

- `--ports`, `--timeout`, `--workers`, `--ipv6`, `--json` as in `scan`;
  silent ports are probed twice (the retransmit is how closed ports get
  noticed — the kernel delivers the ICMP verdict to the next syscall)
- Sweeping huge UDP ranges is self-defeating: the target's ICMP rate
  limit makes closed ports look filtered. Keep lists small.

> **Warning:** Only scan systems you own or have written permission to scan.

## syn

The half-open SYN scan — the classic "stealth" scan. Instead of completing
the TCP handshake, it sends only the opening SYN and classifies the reply:
**SYN-ACK** means open (the handshake is then abandoned, so most services
never log you), **RST** means closed, silence means **filtered**.

Forging raw packets is a privileged operation, so this command needs root:

```text
$ sudo scouter26 syn 192.168.1.1 --ports 22,80,443

 Port 22     ssh        OPEN  SYN-ACK received — handshake abandoned
 Port 80     http       OPEN  SYN-ACK received — handshake abandoned
 Port 443    https      FILTERED  (no reply)
```

- IPv4 only for now (raw IPv6 injection follows different kernel rules)
- Every packet's IP and TCP checksums are computed by hand in this
  repository — no packet library involved
- `--timeout` controls the reply window; silent ports are probed twice,
  and `--json` works as in `scan`

> **Warning:** Only scan systems you own or have written permission to scan.

## Installation

Pick whichever fits your distro — or the plain binary, which works everywhere.
Prebuilt packages are attached automatically to every
[GitHub Release](https://github.com/Lab-026/scouter26/releases) — no Rust
required for any of the methods below.

**Debian, Ubuntu, Mint, Kali (.deb):**

```text
wget https://github.com/Lab-026/scouter26/releases/latest/download/scouter26-amd64.deb
sudo apt install ./scouter26-amd64.deb
```

**Fedora, RHEL, openSUSE (.rpm):**

```text
wget https://github.com/Lab-026/scouter26/releases/latest/download/scouter26-x86_64.rpm
sudo dnf install ./scouter26-x86_64.rpm
```

**Arch, Manjaro, EndeavourOS (AUR kit):**

The [packaging/PKGBUILD](packaging/PKGBUILD) builds a `scouter26-bin`
package from the official release tarball — local install and AUR
publishing steps are in [packaging/README.md](packaging/README.md).

**Plain binary, any distro (x86_64 or aarch64):**

```text
wget https://github.com/Lab-026/scouter26/releases/latest/download/scouter26-x86_64-unknown-linux-gnu.tar.gz
tar xf scouter26-x86_64-unknown-linux-gnu.tar.gz
sudo install -m755 scouter26 /usr/local/bin/
```

**Any system with Rust:**

```text
cargo install --locked scouter26
```

(available once scouter26 makes its first crates.io publish; `cargo
binstall scouter26` already works with the release tarballs)

> **Note:** The official Debian, Fedora and Arch *repositories* have their
> own review processes — that milestone (scouter26 in `apt`, `dnf` and the
> AUR proper) is documented as a future goal in
> [packaging/README.md](packaging/README.md). Today's packages install
> directly from GitHub Releases. There is deliberately no Flatpak: see the
> reasoning in [packaging/README.md](packaging/README.md).

## Building and testing

```text
cargo build --release
cargo test
```

## How it's built

- **No packet libraries.** Every DNS, NTP and SNMP payload and every raw
  SYN packet — checksums included — is hand-built byte by byte in this
  repository, and certified against external reference vectors in tests.
- **Pure cores, tested edges.** Calculation functions are separated from
  I/O and unit-tested; the network paths get integration tests against
  real listeners on the loopback.
- **One engine.** All scanning commands share the same worker-pool
  design, tunables validation, and progress reporting.
- **Quality is enforced, not aspirational.** CI runs `cargo test`,
  `cargo clippy -- -D warnings`, and `cargo fmt --check` on every push.
- Every change is recorded in [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).
