use std::net::Ipv4Addr;
use std::str::FromStr;

use colored::*;
use ipnet::Ipv4Net;

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

/// What kind of address this is. Rust's standard library already
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
// The command
// ============================================================

pub fn execute(cidr: &str) -> Result<(), String> {
    // Parse strictly as IPv4 CIDR. IPv6 fails here and gets a clear
    // error message instead of a crash.
    let net = match Ipv4Net::from_str(cidr) {
        Ok(net) => net,
        Err(error) => {
            return if cidr.contains(':') {
                Err("IPv6 is not supported yet. Use an IPv4 address like 192.168.1.55/24".to_string())
            } else {
                Err(format!("invalid IPv4 CIDR '{}'\nDetails: {}", cidr, error))
            };
        }
    };

    let addr = net.addr();
    let prefix = net.prefix_len();

    println!("{}", "========================================".cyan());
    println!("{}", " Scouter26 - Subnet Analysis".cyan().bold());
    println!("{}", "========================================".cyan());
    println!(" {:<14}: {}", "Input IP", addr);
    println!(" {:<14}: /{}", "Prefix", prefix);
    println!(" {:<14}: {}", "Netmask", net.netmask());
    println!(" {:<14}: {}", "Wildcard", wildcard_mask(prefix));
    println!(" {:<14}: {}", "Network ID", net.network().to_string().green());
    println!(" {:<14}: {}", "Broadcast", net.broadcast().to_string().yellow());
    println!(" {:<14}: {}", "Host Range", host_range(net));
    println!(" {:<14}: {}", "Total IPs", total_addresses(prefix));
    println!(" {:<14}: {}", "Usable Hosts", usable_hosts(prefix).to_string().green());
    println!(" {:<14}: {}", "Class", address_class(addr.octets()[0]));
    println!(" {:<14}: {}", "Type", address_type(addr));
    println!("{}", "========================================".cyan());
    Ok(())
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
    fn ipv6_input_is_rejected() {
        assert!(Ipv4Net::from_str("2001:db8::1/64").is_err());
        assert!(Ipv4Net::from_str("::1/128").is_err());
    }

    #[test]
    fn garbage_input_is_rejected() {
        assert!(Ipv4Net::from_str("not_an_ip").is_err());
        assert!(Ipv4Net::from_str("192.168.1.0/33").is_err());
    }
}