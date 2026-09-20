use std::str::FromStr;
use ipnet::IpNet;

pub fn execute(cidr: &str) {
    // 1. Try to parse the string
    let network_info = match IpNet::from_str(cidr) {
        Ok(valid_ip) => valid_ip,
        Err(error) => {
            eprintln!("Error: Invalid CIDR format. '{}'", cidr);
            eprintln!("Details: {}", error);
            return; 
        }
    };

    // 2. Extract information
    let addr = network_info.addr();
    let network = network_info.network();
    let broadcast = network_info.broadcast();
    let prefix = network_info.prefix_len();
    let netmask = network_info.netmask();
    
    // 3. Calculate hosts correctly!
    // The hosts() method ALREADY excludes the Network ID and Broadcast.
    let usable_hosts = network_info.hosts().count();
    
    // To get the TOTAL IPs, we calculate 2^(32 - prefix).
    // In Rust, 1u32 means "the number 1 stored as an unsigned 32-bit integer".
    // We use << which is a "bitwise shift left" (which is equivalent to 2^x).
    let total_hosts = 1u32 << (32 - prefix);

    // 4. Print the results
    println!("========================================");
    println!(" Scouter26 - Subnet Analysis");
    println!("========================================");
    println!(" Input IP      : {}", addr);
    println!(" Prefix        : /{}", prefix);
    println!(" Netmask       : {}", netmask);
    println!(" Network ID    : {}", network);
    println!(" Broadcast     : {}", broadcast);
    println!(" Total IPs     : {}", total_hosts);
    println!(" Usable Hosts  : {}", usable_hosts);
    println!("========================================");
}