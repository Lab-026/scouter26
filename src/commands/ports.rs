pub fn execute(query: &str) {
    // Convert the user's input to lowercase so "HTTP" and "http" both work
    let query_lower = query.to_lowercase();

    // Match the input against known Network+ ports and protocols
    let result = match query_lower.as_str() {
        // Numbers
        "20" | "21" => "FTP (File Transfer Protocol) - TCP",
        "22" => "SSH (Secure Shell) - TCP",
        "23" => "Telnet - TCP",
        "25" => "SMTP (Simple Mail Transfer Protocol) - TCP",
        "53" => "DNS (Domain Name System) - TCP/UDP",
        "67" | "68" => "DHCP (Dynamic Host Configuration Protocol) - UDP",
        "80" => "HTTP (Hypertext Transfer Protocol) - TCP",
        "110" => "POP3 (Post Office Protocol v3) - TCP",
        "143" => "IMAP (Internet Message Access Protocol) - TCP",
        "161" | "162" => "SNMP (Simple Network Management Protocol) - UDP",
        "389" => "LDAP (Lightweight Directory Access Protocol) - TCP",
        "443" => "HTTPS (HTTP Secure) - TCP",
        "445" => "SMB (Server Message Block) - TCP",
        "3389" => "RDP (Remote Desktop Protocol) - TCP",
        
        // Names
        "ftp" => "Ports 20, 21",
        "ssh" => "Port 22",
        "telnet" => "Port 23",
        "smtp" => "Port 25",
        "dns" => "Port 53",
        "dhcp" => "Ports 67, 68",
        "http" => "Port 80",
        "pop3" => "Port 110",
        "imap" => "Port 143",
        "snmp" => "Ports 161, 162",
        "ldap" => "Port 389",
        "https" => "Port 443",
        "smb" => "Port 445",
        "rdp" => "Port 3389",
        
        // The wildcard "_" means "anything else"
        _ => "Unknown port or service. Try common ones like 80, 443, 22, or 'http', 'dns'."
    };

    println!("========================================");
    println!(" Scouter26 - Port Lookup");
    println!("========================================");
    println!(" Query: {} -> {}", query, result);
    println!("========================================");
}