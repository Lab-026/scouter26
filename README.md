scouter26

A modular network toolbox CLI for IT support technicians and junior networkadministrators — subnet math, port lookups, and TCP scanning in one command.

    Named after Zastava's weapon naming convention: a name, plus the year.

Commands
Command	Description
scouter26 subnet <cidr>	Full IPv4 subnet breakdown
scouter26 ports <query>	Port lookup by number or service name
scouter26 scan <target>	Parallel TCP connect scan
subnet

Give it an IPv4 CIDR and it returns the network address, netmask, wildcardmask, broadcast address, usable host range, host counts, IP class, andwhether the range is private (RFC 1918) or public.

 $ scouter26 subnet 192.168.10.0/24

IPv6 is rejected with a clear error message (support planned).
ports

Look up common ports in either direction — by number or by service name:

 $ scouter26 ports 443 $ scouter26 ports ssh

scan

Resolves the target's DNS once, then probes TCP ports in parallel andreports which ones are open, with the service name for each.

 $ scouter26 scan scanme.nmap.org

Scan specific ports instead of the defaults — a single port, a list, or arange:

 $ scouter26 scan scanme.nmap.org --ports 22,80,443 $ scouter26 scan scanme.nmap.org --ports 20-1024

    Warning: Only scan systems you own or have written permission to scan.Unauthorized port scanning is illegal in many jurisdictions.

Installation

Requires Rust.

 $ git clone https://github.com/Lab-026/scouter26.git $ cd scouter26 $ cargo install --path .

After that, scouter26 works from any directory.
Building and testing

 $ cargo build --release $ cargo test

License

MIT — see LICENSE.