//! Port knowledge base for scouter26.
//!
//! This one module feeds two commands:
//!   * `scouter26 ports <query>` — human lookup by number or name
//!   * `scouter26 scan <target>` — calls `service_name()` to label open ports
//!
//! Both read from the same table below, so every port "fact" lives in
//! exactly one place. (The old version used one giant `match` — adding a
//! port meant editing code in the middle of it. A table means: add one
//! row at the bottom, done.)

use colored::Colorize;

/// One row of the port reference table.
struct PortEntry {
    port: u16,
    name: &'static str,
    proto: &'static str,
    desc: &'static str,
}

/// The single source of truth for well-known ports in scouter26.
/// Kept sorted by port number — a unit test below enforces this.
const TABLE: &[PortEntry] = &[
    PortEntry { port: 20,   name: "ftp-data",    proto: "TCP",     desc: "FTP data channel" },
    PortEntry { port: 21,   name: "ftp",         proto: "TCP",     desc: "File Transfer Protocol (control)" },
    PortEntry { port: 22,   name: "ssh",         proto: "TCP",     desc: "Secure Shell remote login" },
    PortEntry { port: 23,   name: "telnet",      proto: "TCP",     desc: "Legacy remote login (insecure)" },
    PortEntry { port: 25,   name: "smtp",        proto: "TCP",     desc: "Email sending, server to server" },
    PortEntry { port: 53,   name: "dns",         proto: "TCP/UDP", desc: "Domain name resolution" },
    PortEntry { port: 67,   name: "dhcp",        proto: "UDP",     desc: "DHCP server traffic (BOOTP)" },
    PortEntry { port: 68,   name: "dhcp",        proto: "UDP",     desc: "DHCP client traffic" },
    PortEntry { port: 69,   name: "tftp",        proto: "UDP",     desc: "Trivial FTP (no auth)" },
    PortEntry { port: 80,   name: "http",        proto: "TCP",     desc: "World Wide Web" },
    PortEntry { port: 110,  name: "pop3",        proto: "TCP",     desc: "Email retrieval (older)" },
    PortEntry { port: 123,  name: "ntp",         proto: "UDP",     desc: "Network clock synchronisation" },
    PortEntry { port: 137,  name: "netbios-ns",  proto: "UDP",     desc: "NetBIOS name service" },
    PortEntry { port: 138,  name: "netbios-dgm", proto: "UDP",     desc: "NetBIOS datagram service" },
    PortEntry { port: 139,  name: "netbios-ssn", proto: "TCP",     desc: "NetBIOS session service" },
    PortEntry { port: 143,  name: "imap",        proto: "TCP",     desc: "Email retrieval (modern)" },
    PortEntry { port: 161,  name: "snmp",        proto: "UDP",     desc: "Network management queries" },
    PortEntry { port: 162,  name: "snmptrap",    proto: "UDP",     desc: "Network management alerts" },
    PortEntry { port: 389,  name: "ldap",        proto: "TCP/UDP", desc: "Directory services (Active Directory)" },
    PortEntry { port: 443,  name: "https",       proto: "TCP",     desc: "Secure web (HTTP over TLS)" },
    PortEntry { port: 445,  name: "smb",         proto: "TCP",     desc: "Windows file and printer sharing" },
    PortEntry { port: 465,  name: "smtps",       proto: "TCP",     desc: "Email sending over TLS" },
    PortEntry { port: 514,  name: "syslog",      proto: "UDP",     desc: "Log message shipping" },
    PortEntry { port: 587,  name: "submission",  proto: "TCP",     desc: "Email sending, client to server (TLS)" },
    PortEntry { port: 631,  name: "ipp",         proto: "TCP",     desc: "Internet Printing Protocol (CUPS)" },
    PortEntry { port: 993,  name: "imaps",       proto: "TCP",     desc: "Email retrieval over TLS" },
    PortEntry { port: 995,  name: "pop3s",       proto: "TCP",     desc: "Email retrieval over TLS" },
    PortEntry { port: 1433, name: "mssql",       proto: "TCP",     desc: "Microsoft SQL Server" },
    PortEntry { port: 3306, name: "mysql",       proto: "TCP",     desc: "MySQL / MariaDB database" },
    PortEntry { port: 3389, name: "rdp",         proto: "TCP",     desc: "Windows Remote Desktop" },
    PortEntry { port: 5432, name: "postgresql",  proto: "TCP",     desc: "PostgreSQL database" },
    PortEntry { port: 8080, name: "http-alt",    proto: "TCP",     desc: "Alternate HTTP (proxies, dev servers)" },
];

/// Entry point for `scouter26 ports <query>`.
///
/// Accepts a port number ("443") or a service name ("ssh").
/// Returns Err for anything that is not an exact answer, which `main`
/// turns into exit code 1 — so shell scripts can check success the
/// standard Unix way ($?).
pub fn execute(query: &str) -> Result<(), String> {
    // Normalise: trim spaces and lowercase, so "SSH", "ssh " and "Ssh"
    // all behave identically.
    let query = query.trim().to_lowercase();

    if query.is_empty() {
        return Err("no query given. Try: scouter26 ports 443".to_string());
    }

    // Path 1 — the query is a number: look the port up directly.
    if let Ok(number) = query.parse::<u16>() {
        let hits: Vec<&PortEntry> = TABLE
            .iter()
            .filter(|entry| entry.port == number)
            .collect();

        if hits.is_empty() {
            return Err(format!(
                "port {} is valid, but is not in scouter26's table of common ports.",
                number
            ));
        }

        print_table(&hits);
        return Ok(());
    }

    // If it was all digits but did not parse, it is out of range.
    // (Ports are 16-bit numbers: 0 to 65535 — a favourite Network+ fact.)
    if query.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "'{}' is not a valid port number — ports run from 0 to 65535.",
            query
        ));
    }

    // Path 2 — the query is a name: exact match first.
    let hits: Vec<&PortEntry> = TABLE
        .iter()
        .filter(|entry| entry.name == query)
        .collect();

    if !hits.is_empty() {
        print_table(&hits);
        return Ok(());
    }

    // Path 3 — wildcard fallback: nothing exact, so suggest anything
    // whose name contains the query text (e.g. "netbios" -> 3 rows).
    let suggestions: Vec<&PortEntry> = TABLE
        .iter()
        .filter(|entry| entry.name.contains(query.as_str()))
        .collect();

    if suggestions.is_empty() {
        return Err(format!(
            "no entry matches '{}'. Try a number (e.g. 443) or a name (e.g. ssh).",
            query
        ));
    }

    println!("No exact match for '{}' — did you mean:", query);
    print_table(&suggestions);
    Err(format!("no exact match for '{}'", query))
}

/// Look up the well-known service name for a port number.
///
/// Called by the `scan` command to label each open port.
/// Unknown ports get "unknown" instead of crashing or printing nothing.
pub fn service_name(port: u16) -> &'static str {
    TABLE
        .iter()
        .find(|entry| entry.port == port)
        .map(|entry| entry.name)
        .unwrap_or("unknown")
}

/// Print rows as an aligned table.
fn print_table(rows: &[&PortEntry]) {
    // Format the header as a plain string FIRST, then bold the whole line.
    // (Styling first and padding second breaks alignment, because the
    // padding would count the invisible colour codes as characters.)
    let header = format!(
        "{:<7} {:<14} {:<9} {}",
        "PORT", "SERVICE", "PROTO", "DESCRIPTION"
    );
    println!("{}", header.bold());

    for entry in rows {
        println!(
            "{:<7} {:<14} {:<9} {}",
            entry.port, entry.name, entry.proto, entry.desc
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_finds_well_known_ports() {
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(80), "http");
        assert_eq!(service_name(443), "https");
        assert_eq!(service_name(3389), "rdp");
    }

    #[test]
    fn service_name_returns_unknown_for_unlisted_port() {
        assert_eq!(service_name(65534), "unknown");
    }

    #[test]
    fn table_is_sorted_with_no_duplicate_ports() {
        // windows(2) hands us every neighbouring pair. If every pair is
        // strictly ascending, the whole table is sorted AND duplicate-free.
        assert!(
            TABLE.windows(2).all(|pair| pair[0].port < pair[1].port),
            "TABLE must stay sorted by port, with no duplicates"
        );
    }
}