use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use colored::*;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

// ============================================================
// Pure calculation functions.
//
// These do math only - no printing, no user input. That is what
// makes them easy to unit-test with `cargo test`.
// ============================================================

/// Total number of addresses in a subnet = 2^(32 - prefix).
/// Calculated in u64 so even /0 (4,294,967,296 addresses) works.
pub fn total_addresses(prefix: u8) -> u64 {
    1u64 << (32 - prefix)
}

/// Usable host addresses:
///   - normally "total - 2" (network ID and broadcast are reserved)
///   - /31 is the point-to-point exception (RFC 3021): both usable
///   - /32 is a single host address
pub fn usable_hosts(prefix: u8) -> u64 {
    if prefix >= 32 {
        1
    } else if prefix == 31 {
        2
    } else {
        total_addresses(prefix) - 2
    }
}

/// The wildcard (inverse) mask, e.g. /24 -> 0.0.0.255
pub fn wildcard_mask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        // 2^32 - 1 does not fit the shift math below, so /0 is a special case
        Ipv4Addr::from(u32::MAX)
    } else {
        Ipv4Addr::from((1u32 << (32 - prefix)) - 1)
    }
}

/// The historic class of an address, decided by its first octet.
pub fn address_class(first_octet: u8) -> &'static str {
    match first_octet {
        0..=127 => "A",
        128..=191 => "B",
        192..=223 => "C",
        224..=239 => "D (Multicast)",
        _ => "E (Experimental)",
    }
}

/// What kind of IPv4 address this is. Rust's standard library already
/// knows the special ranges, so we don't have to check them by hand.
pub fn address_type(addr: Ipv4Addr) -> &'static str {
    if addr.is_loopback() {
        "Loopback (127.0.0.0/8)"
    } else if addr.is_private() {
        "Private (RFC 1918)"
    } else if addr.is_link_local() {
        "Link-local (APIPA, 169.254.0.0/16)"
    } else {
        "Public"
    }
}

/// The first-to-last usable host range, e.g. "192.168.1.1 - 192.168.1.254".
/// This is the "network + 1 through broadcast - 1" rule from your studies.
pub fn host_range(net: Ipv4Net) -> String {
    let prefix = net.prefix_len();
    if prefix >= 32 {
        format!("{} (single host)", net.network())
    } else if prefix == 31 {
        format!("{} - {}", net.network(), net.broadcast())
    } else {
        let first = Ipv4Addr::from(u32::from(net.network()) + 1);
        let last = Ipv4Addr::from(u32::from(net.broadcast()) - 1);
        format!("{} - {}", first, last)
    }
}

// ============================================================
// Pure calculation functions - IPv6.
//
// The ideas carry over, but several IPv4 habits do not: IPv6 has
// no "class", no wildcard mask, and no reserved network/broadcast
// pair, so every address in the subnet is usable.
// ============================================================

/// Total addresses in an IPv6 subnet = 2^(128 - prefix), formatted with
/// digit separators (raw u128 digit walls are unreadable).
///
/// Returns a String because a /0 holds 2^128 addresses — one more than
/// fits in any integer type Rust has — so the /0 case is spelled out.
pub fn total_addresses6(prefix: u8) -> String {
    if prefix >= 128 {
        "1".to_string()
    } else if prefix == 0 {
        group_digits("340282366920938463463374607431768211456") // 2^128
    } else {
        group_digits(&(1u128 << (128 - prefix)).to_string())
    }
}

/// The first-to-last address range. IPv6 reserves nothing inside the
/// subnet (the all-zeros address is the "subnet-router anycast", but
/// it is still an address of the subnet), so the range is the full one.
pub fn host_range6(net: Ipv6Net) -> String {
    if net.prefix_len() >= 128 {
        format!("{} (single host)", net.network())
    } else {
        format!("{} - {}", net.network(), net.broadcast())
    }
}

/// What kind of IPv6 address this is. The std library only knows
/// loopback, unspecified and multicast, so the rest are checked by
/// hand against their first bytes.
pub fn address_type6(addr: Ipv6Addr) -> &'static str {
    let o = addr.octets();
    if addr.is_loopback() {
        "Loopback (::1/128)"
    } else if o[0] == 0xff {
        "Multicast (ff00::/8)"
    } else if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
        "Link-local (fe80::/10)"
    } else if (o[0] & 0xfe) == 0xfc {
        "Unique-local (fc00::/7) — IPv6's RFC 1918"
    } else if o[0..2] == [0x20, 0x01] && o[2..4] == [0x0d, 0xb8] {
        "Documentation (2001:db8::/32)"
    } else if addr.is_unspecified() {
        "Unspecified (::)"
    } else {
        "Global unicast"
    }
}

/// A bare address with no "/prefix" means a single host: /32 for IPv4,
/// /128 for IPv6. Everything else passes through untouched.
pub fn normalize_cidr(input: &str) -> String {
    if input.contains('/') {
        input.to_string()
    } else if input.contains(':') {
        format!("{}/128", input)
    } else {
        format!("{}/32", input)
    }
}

/// Insert commas every three digits from the right, so "18446744073709551616"
/// becomes "18,446,744,073,709,551,616". Counts like 2^96 are unreadable raw.
fn group_digits(digits: &str) -> String {
    let mut out = Vec::new();
    for (i, ch) in digits.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.into_iter().rev().collect()
}

// ============================================================
// The command
// ============================================================

pub fn execute(cidr: &str) -> Result<(), String> {
    // Parse as IPv4 or IPv6 CIDR — both families get a full report.
    let net = match IpNet::from_str(&normalize_cidr(cidr)) {
        Ok(net) => net,
        Err(error) => {
            return Err(format!(
                "invalid CIDR '{}'\nDetails: {}\nExamples: 192.168.1.0/24, 2001:db8::/32",
                cidr, error
            ));
        }
    };

    match net {
        IpNet::V4(v4) => print_v4_report(v4),
        IpNet::V6(v6) => print_v6_report(v6),
    }

    println!("{}", "========================================".cyan());
    Ok(())
}

fn print_v4_report(net: Ipv4Net) {
    let addr = net.addr();
    let prefix = net.prefix_len();

    println!("{}", "========================================".cyan());
    println!("{}", " Scouter26 - Subnet Analysis (IPv4)".cyan().bold());
    println!("{}", "========================================".cyan());
    println!(" {:<14}: {}", "Input IP", addr);
    println!(" {:<14}: /{}", "Prefix", prefix);
    println!(" {:<14}: {}", "Netmask", net.netmask());
    println!(" {:<14}: {}", "Wildcard", wildcard_mask(prefix));
    println!(" {:<14}: {}", "Network ID", net.network().to_string().green());
    println!(" {:<14}: {}", "Broadcast", net.broadcast().to_string().yellow());
    println!(" {:<14}: {}", "Host Range", host_range(net));
    println!(" {:<14}: {}", "Total IPs", group_digits(&total_addresses(prefix).to_string()));
    println!(
        " {:<14}: {}",
        "Usable Hosts",
        group_digits(&usable_hosts(prefix).to_string()).green()
    );
    println!(" {:<14}: {}", "Class", address_class(addr.octets()[0]));
    println!(" {:<14}: {}", "Type", address_type(addr));
}

fn print_v6_report(net: Ipv6Net) {
    let addr = net.addr();
    let prefix = net.prefix_len();

    println!("{}", "========================================".cyan());
    println!("{}", " Scouter26 - Subnet Analysis (IPv6)".cyan().bold());
    println!("{}", "========================================".cyan());
    println!(" {:<17}: {}", "Input IP", addr);
    println!(" {:<17}: /{}", "Prefix", prefix);
    println!(" {:<17}: {}", "Network ID", net.network().to_string().green());
    println!(" {:<17}: {}", "Host Range", host_range6(net));
    println!(" {:<17}: {}", "Total Addresses", total_addresses6(prefix));
    println!(
        " {:<17}: {} (IPv6 reserves no network/broadcast)",
        "Usable Addresses",
        total_addresses6(prefix).green()
    );
    println!(" {:<17}: {}", "Type", address_type6(addr));
}

// ============================================================
// Unit tests - run with: cargo test
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_address_counts() {
        assert_eq!(total_addresses(32), 1);
        assert_eq!(total_addresses(30), 4);
        assert_eq!(total_addresses(24), 256);
        assert_eq!(total_addresses(22), 1024);
        assert_eq!(total_addresses(16), 65_536);
        assert_eq!(total_addresses(8), 16_777_216);
        assert_eq!(total_addresses(0), 4_294_967_296);
    }

    #[test]
    fn usable_host_counts() {
        assert_eq!(usable_hosts(24), 254);
        assert_eq!(usable_hosts(30), 2);
        assert_eq!(usable_hosts(31), 2); // RFC 3021 point-to-point exception
        assert_eq!(usable_hosts(32), 1);
        assert_eq!(usable_hosts(16), 65_534);
        assert_eq!(usable_hosts(0), 4_294_967_294);
    }

    #[test]
    fn wildcard_masks() {
        assert_eq!(wildcard_mask(32), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(wildcard_mask(30), Ipv4Addr::new(0, 0, 0, 3));
        assert_eq!(wildcard_mask(24), Ipv4Addr::new(0, 0, 0, 255));
        assert_eq!(wildcard_mask(22), Ipv4Addr::new(0, 0, 3, 255));
        assert_eq!(wildcard_mask(8), Ipv4Addr::new(0, 255, 255, 255));
        assert_eq!(wildcard_mask(0), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn address_classes() {
        assert_eq!(address_class(10), "A");
        assert_eq!(address_class(126), "A");
        assert_eq!(address_class(128), "B");
        assert_eq!(address_class(172), "B");
        assert_eq!(address_class(191), "B");
        assert_eq!(address_class(192), "C");
        assert_eq!(address_class(223), "C");
        assert_eq!(address_class(224), "D (Multicast)");
        assert_eq!(address_class(240), "E (Experimental)");
    }

    #[test]
    fn address_types() {
        assert_eq!(address_type(Ipv4Addr::new(192, 168, 1, 1)), "Private (RFC 1918)");
        assert_eq!(address_type(Ipv4Addr::new(10, 0, 0, 1)), "Private (RFC 1918)");
        assert_eq!(address_type(Ipv4Addr::new(172, 16, 5, 5)), "Private (RFC 1918)");
        assert_eq!(address_type(Ipv4Addr::new(8, 8, 8, 8)), "Public");
        assert_eq!(address_type(Ipv4Addr::new(1, 1, 1, 1)), "Public");
        assert_eq!(address_type(Ipv4Addr::new(127, 0, 0, 1)), "Loopback (127.0.0.0/8)");
        assert_eq!(
            address_type(Ipv4Addr::new(169, 254, 1, 1)),
            "Link-local (APIPA, 169.254.0.0/16)"
        );
    }

    #[test]
    fn host_ranges() {
        let net = Ipv4Net::from_str("192.168.1.55/24").unwrap();
        assert_eq!(host_range(net), "192.168.1.1 - 192.168.1.254");

        let point_to_point = Ipv4Net::from_str("10.0.0.4/31").unwrap();
        assert_eq!(host_range(point_to_point), "10.0.0.4 - 10.0.0.5");

        let single = Ipv4Net::from_str("10.0.0.7/32").unwrap();
        assert_eq!(host_range(single), "10.0.0.7 (single host)");
    }

    #[test]
    fn garbage_input_is_rejected() {
        assert!(IpNet::from_str("not_an_ip/24").is_err());
        assert!(IpNet::from_str("192.168.1.0/33").is_err());
    }

    // ---------- IPv6 ----------

    #[test]
    fn total_address_counts_v6() {
        assert_eq!(total_addresses6(128), "1");
        assert_eq!(total_addresses6(126), "4");
        assert_eq!(total_addresses6(64), "18,446,744,073,709,551,616");
        // /0 is 2^128: one more than u128 can even hold.
        assert_eq!(total_addresses6(0), "340,282,366,920,938,463,463,374,607,431,768,211,456");
    }

    #[test]
    fn ipv6_address_types() {
        assert_eq!(address_type6("::1".parse().unwrap()), "Loopback (::1/128)");
        assert_eq!(
            address_type6("fe80::1".parse().unwrap()),
            "Link-local (fe80::/10)"
        );
        assert_eq!(
            address_type6("fd00::1".parse().unwrap()),
            "Unique-local (fc00::/7) — IPv6's RFC 1918"
        );
        assert_eq!(
            address_type6("2001:db8::1".parse().unwrap()),
            "Documentation (2001:db8::/32)"
        );
        assert_eq!(
            address_type6("ff02::1".parse().unwrap()),
            "Multicast (ff00::/8)"
        );
        assert_eq!(
            address_type6("2600:3c01::f03c:91ff:fe18:bb2f".parse().unwrap()),
            "Global unicast"
        );
    }

    #[test]
    fn ipv6_host_ranges() {
        let small = Ipv6Net::from_str("2001:db8::/126").unwrap();
        assert_eq!(host_range6(small), "2001:db8:: - 2001:db8::3");

        let single = Ipv6Net::from_str("2001:db8::1/128").unwrap();
        assert_eq!(host_range6(single), "2001:db8::1 (single host)");
    }

    #[test]
    fn bare_addresses_get_a_default_prefix() {
        assert_eq!(normalize_cidr("192.168.1.55"), "192.168.1.55/32");
        assert_eq!(normalize_cidr("2001:db8::1"), "2001:db8::1/128");
        assert_eq!(normalize_cidr("2001:db8::/32"), "2001:db8::/32");
    }

    #[test]
    fn ipv6_subnets_parse_for_real() {
        // Both families go through the same IpNet parser now.
        assert!(IpNet::from_str("2001:db8::/32").is_ok());
        assert!(IpNet::from_str("192.168.1.0/24").is_ok());
    }

    #[test]
    fn digits_are_grouped_in_threes() {
        assert_eq!(group_digits("1"), "1");
        assert_eq!(group_digits("654321"), "654,321");
        assert_eq!(group_digits("18446744073709551616"), "18,446,744,073,709,551,616");
    }
}
