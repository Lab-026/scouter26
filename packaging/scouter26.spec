# Fedora RPM recipe for scouter26.
#
# Built via COPR (nobody26/scouter26). A personal COPR build is allowed to
# download dependencies from crates.io during the build — that keeps this
# recipe honest and simple. Official Fedora packaging would instead vendor
# every crate into the source (a long review process); this file is the
# practical equivalent for the COPR shelf.

Name:           scouter26
Version:        0.10.0
Release:        1%{?dist}
Summary:        A modular network toolbox: subnet math, port lookup, parallel TCP scan

License:        MIT
URL:            https://github.com/Lab-026/scouter26
Source0:        %{url}/archive/refs/tags/v%{version}/%{name}-%{version}.tar.gz

# The Rust compiler and its package manager come from Fedora's own shelves.
BuildRequires:  cargo
BuildRequires:  rust

%global _description %{expand:
A modular network toolbox for IT support technicians and junior network
administrators. Subnet math for IPv4 and IPv6, a well-known-port reference
table, parallel TCP connect scanning with banner grabbing, UDP service
probing with open|filtered verdicts, half-open SYN scanning over raw
sockets, and TCP host discovery across a subnet — with human and JSON
output.}

%description %{_description}

%prep
%autosetup

%build
# --locked: build with the exact dependency versions the project shipped
# and tested with (Cargo.lock), not whatever is newest today.
cargo build --release --locked

%install
install -Dpm 0755 target/release/scouter26 %{buildroot}%{_bindir}/scouter26
install -Dpm 0644 README.md %{buildroot}%{_pkgdocdir}/README.md
install -Dpm 0644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE

%files
%license LICENSE
%doc README.md
%{_bindir}/scouter26

%changelog
* Sun Oct 25 2026 Umar Farooq <deadmansearching@tutamail.com> - 0.10.0-1
- First COPR release: six commands — subnet, ports, scan, discover, udp, syn
