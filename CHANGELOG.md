# Changelog

All notable changes to scouter26 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project sticks to
[Semantic Versioning](https://semver.org/).

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
