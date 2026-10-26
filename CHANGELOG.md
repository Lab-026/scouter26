# Changelog

All notable changes to scouter26 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project sticks to
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-25

### The stability promise

Version 1.0.0 declares the tool's interface stable: the six commands
(`subnet`, `ports`, `scan`, `discover`, `udp`, `syn`), their flags, their
human and JSON output, and their exit codes. From here on, changes land
additively; anything that breaks compatibility requires — and will
honestly carry — a 2.0.0.

### What 1.0.0 is

- **subnet** — full IPv4 and IPv6 breakdowns: netmask, wildcard, ranges,
  counts, address classes and kinds, digit-grouped numbers
- **ports** — a 31-service reference table, lookup by number or name,
  suggestions, script-friendly exit codes
- **scan** — parallel TCP connect scanning, IPv4 & IPv6, tunable
  `--ports/--timeout/--workers/--ipv6`, live progress, banner grabbing,
  `--json`
- **discover** — subnet-wide host discovery where a refusal counts as
  proof of life, capped sweeps, `--json`
- **udp** — service probing with open/closed/open|filtered verdicts and
  hand-built DNS, NTP and SNMP payloads
- **syn** — half-open scanning with raw packets forged byte by byte
  (checksums certified against a reference vector), reader-thread design

48 tests (unit + integration against real listeners), rustfmt and clippy
enforced in CI, a changelog, and packages for Debian, Fedora (including a
COPR repository), Arch, and plain binaries on x86_64 and aarch64.

### The road here

Built across 17 phases in three days — from a first TCP connect scanner
to raw packet surgery — with every phase verified against live networks
(scanme.nmap.org, the author's own LAN) before it shipped.

## [1.1.0] - 2026-10-25

### Added
- `--output FILE` on `scan`, `discover`, `udp` and `syn`: saves the exact
  JSON report to a file while the screen keeps the human view (with
  `--json`, stdout and the file carry the same report).
- Hidden `completions` command generating tab-completion scripts for bash,
  zsh, fish and PowerShell — with a test proving all four render.
- Worked examples at the bottom of `--help`, so the tool teaches itself
  before the README is ever opened.

## [1.2.0] - 2026-10-25

### Added
- `ping` command: the daily-driver diagnostic. Real ICMP echo via Linux
  ping sockets (unprivileged on Fedora-family), with an honest TCP
  fallback (port refused still means "up") for systems without them.
  Latency, loss and min/avg/max statistics; `--count/--interval/
  --timeout/--port/--json/--output`.
- `internet_checksum` is now shared between the SYN and ping engines.

### Changed
- First command of the "true toolbox" realignment: the goal is now the
  commands IT Support runs every day (ping, dns, trace), alongside the
  scanners.

## [1.3.0] - 2026-10-25

### Added
- `dns` command: full DNS lookups (A, AAAA, CNAME, MX, TXT, NS, PTR, SOA)
  against the system resolver by default (`/etc/resolv.conf`) or any
  server via `--server`. Queries are hand-built and responses — including
  DNS name compression — are hand-parsed in this repository. NXDOMAIN and
  other server errors become plain-language messages with proper exit
  codes; `--json` and `--output` work as everywhere.

## [1.4.0] - 2026-10-25

### Added
- `trace` command: classic traceroute with hand-forged IP+ICMP packets
  whose TTL climbs hop by hop — routers betray themselves via ICMP Time
  Exceeded, and the destination closes the trace with an Echo Reply.
  Needs root (like `syn`); IPv4; `--hops/--timeout/--json/--output`.
- The raw-socket engine and local-source detection are now shared
  infrastructure used by both `syn` and `trace`.

## [1.4.1] - 2026-10-26

### Fixed
- **Traceroute reply validation**: an Echo Reply was accepted as "destination
  reached" based on matching identifier and sequence alone — it must now also
  come from the destination's own address, with a regression test for a reply
  from an impostor host. (Found by an external source-level review.)
- README: the crates.io install command appeared before crates.io
  publication — replaced with a working install-from-git command, and the
  plain-binary instructions now have separate x86_64 and aarch64 commands.
- README examples match current output (historic class label), and the SYN
  section no longer calls the technique "stealth" — half-open is not
  invisible, and the text says so.

## [1.4.3] - 2026-10-26

### Fixed
- **Release-process error**: the v1.4.2 tag shipped with a manifest that
  still declared 1.4.1 (the version bump and changelog entry failed to land
  because a commit was made despite failing local checks). The manifest now
  matches the release, and a pre-commit hook runs the quality gates before
  every commit so this class of mistake cannot repeat.

### Hardened
- **Traceroute identifier collisions**: the ICMP identifier is now derived
  from the process id instead of the fixed 0x1964, so two concurrent traces
  from the same machine cannot accept each other's replies.
- **Time Exceeded code check**: only code 0 (TTL exceeded in transit) is
  treated as a router hop; code 1 (fragment reassembly time) cannot occur
  for our probes — they carry the Don't Fragment flag and are far smaller
  than any fragment threshold — and is ignored rather than guessed about.

## [1.4.4] - 2026-10-26

### Fixed
- **Progress lines can no longer hang**: a worker that panicked mid-probe
  could leave the progress counter short of the total forever (scan, udp
  and discover shared the pattern). Work is now counted at dispatch time,
  and the progress thread is released the moment the workers are joined.
- **UDP timeout semantics documented**: a silent port can consume up to
  twice the configured `--timeout`, because each silent port is probed
  twice — now stated in the CLI help and README.
- **Traceroute replay resistance**: sequence numbers are mixed with a
  per-run nonce, and Echo Replies now verify a 64-bit per-run token —
  OS-seeded via std's RandomState, mixed with the pid — carried in the
  payload. A reply from an earlier run (same pid, destination and hop) is
  rejected when its token differs. Honest limits, stated in the docs: the
  token makes accidental cross-run matches astronomically unlikely but is
  not a uniqueness guarantee; the 16-bit sequence nonce only *reduces*
  cross-run matches (it cannot guarantee rejection, and Time Exceeded
  messages are too short to carry the token); and none of these checks are
  cryptographic authentication — the wire format is public.
- **scan.rs progress flag**: the TCP scanner was missing the
  `finished.store(true)` that udp and discover already had after joining
  their workers — found by external review, fixed for consistency.
- **macOS build**: `sockaddr_in` is now constructed by zeroing the struct
  and assigning fields, because Darwin's version carries an extra `sin_len`
  field that a Linux-style struct literal cannot compile against. (Cause of
  the experimental macOS job's failure; confirmed by the job's next run.)
- The traceroute documentation no longer claims PID-derived identifiers
  guarantee uniqueness — a 16-bit ICMP identifier field mathematically
  cannot be collision-free (pids 1 and 65665 collide; a test now pins that
  fact so the docs stay honest).
- Traceroute sequence numbers now start from a per-process base, so
  cross-talk between two traces requires a match on BOTH identifier and
  sequence, not either alone.

## [0.10.0] - 2026-10-25

### Added
- Distribution infrastructure: every version tag now triggers an automated
  release — prebuilt binaries for x86_64 **and** aarch64, a Debian `.deb`
  (via cargo-deb) and an RPM (via cargo-generate-rpm), all attached to a
  GitHub Release. Both packages were built and inspected locally before
  shipping this workflow.
- crates.io publication metadata (keywords, categories, readme, minimum
  supported Rust) — `cargo install scouter26` comes with the first publish;
  `cargo binstall scouter26` already works via release-tarball naming.
- Arch packaging kit: `packaging/PKGBUILD` (`scouter26-bin`) with AUR
  publishing instructions in `packaging/README.md` — including the honest
  reasoning for *not* shipping a Flatpak.
- README installation section rewritten to cover every install path.

## [0.9.0] - 2026-10-25

### Fixed
- `discover` now counts a network's hosts from its prefix length *before*
  generating them, so oversized sweeps (a `/0`, `/8`, or IPv6 `/64` and
  wider) are refused cleanly instead of exhausting memory — with
  regression tests locking the fix in place.

### Changed
- The whole codebase is formatted with rustfmt, and CI now enforces
  `cargo fmt --check` and `cargo clippy -- -D warnings` alongside tests.
- Dependency refresh: `colored` 2 → 3, transitive updates via `cargo update`.
- `discover` port-spec errors now include usage examples, matching `scan`.
- Host counts in the sweep-cap error are digit-grouped (16,777,214, not
  16777214).

## [0.8.0] - 2026-10-25

### Added
- `syn` command: half-open SYN scanning. Raw IPv4+TCP packets are forged
  byte by byte — IP and TCP pseudo-header checksums computed by hand and
  certified against an external reference vector — sent through a raw
  socket (`libc`), with a dedicated reader thread classifying SYN-ACK
  (open), RST (closed) and silence (filtered). Requires root; IPv4 only.

## [0.7.0] - 2026-10-25

### Added
- `udp` command: UDP service probing with three honest verdicts
  (open / closed / open|filtered). Hand-built payloads for DNS, NTP and
  SNMP; connected-socket ICMP detection with retransmission.

## [0.6.0] - 2026-10-25

### Added
- `--json` for `scan` and `discover`: machine-readable reports on stdout,
  JSON errors on stderr, progress suppressed in JSON mode (serde).

## [0.5.0] - 2026-10-25

### Added
- `discover` command: TCP host discovery across a subnet — a host counts
  as alive if any probe connects *or is refused*. IPv4 network/broadcast
  addresses are skipped; RFC 3021 /31 honored; sweeps capped at 4096 hosts.

## [0.4.0] - 2026-10-25

### Added
- Full IPv6: `subnet` breaks down IPv6 CIDRs (address kinds, digit-grouped
  counts), `scan` scans IPv6 with `--ipv6` to prefer AAAA records on
  dual-stack hosts.

## [0.3.0] - 2026-10-25

### Fixed
- `scan` silently scanned IPv6 while `subnet` rejected it — now consistent
  (and superseded by 0.4.0's full dual-stack support).
- README rewritten in real markdown (was pasted plain text) with a CI badge.

### Added
- `--timeout` / `--workers` flags with live progress for large scans.
- Banner grabbing: open TCP ports report the service's own announcement.
- Local-listener integration tests; errors refactored to `Result` with a
  single exit point; clippy clean throughout.

## [0.2.0] - 2026-10-23

### Added
- GitHub Actions CI running `cargo test` on every push; README; MIT license.

## [0.1.0] - 2026-10-23

### Added
- `subnet`, `ports` and `scan` commands: IPv4 subnet math, a 31-port
  reference table, and a multithreaded TCP connect scanner with a
  worker pool — built across phases 1–9.
