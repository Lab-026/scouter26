use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use std::thread;

pub fn execute(target: &str) {
    let common_ports = [
        (22, "SSH"),
        (23, "Telnet"),
        (25, "SMTP"),
        (53, "DNS"),
        (80, "HTTP"),
        (110, "POP3"),
        (143, "IMAP"),
        (443, "HTTPS"),
        (445, "SMB"),
        (3389, "RDP"),
    ];

    println!("========================================");
    println!(" Scouter26 - Port Scanner");
    println!(" Target: {}", target);
    println!("========================================");

    // We will store our threads here
    let mut threads = Vec::new();

    // 1. Spawn a thread for EVERY port
    for (port, service) in common_ports.iter() {
        // We need to clone these because threads take ownership of variables
        let target = String::from(target);
        let port = *port;
        let service = *service;

        // Spawn a new OS thread
        let handle = thread::spawn(move || {
            let address = format!("{}:{}", target, port);
            
            let socket_addr = match address.to_socket_addrs() {
                Ok(mut addrs) => match addrs.next() {
                    Some(addr) => addr,
                    None => return (port, service, false),
                },
                Err(_) => return (port, service, false),
            };

            let connection = TcpStream::connect_timeout(
                &socket_addr,
                Duration::from_secs(1)
            );

            // Return a tuple: (port, service, is_it_open?)
            (port, service, connection.is_ok())
        });

        threads.push(handle);
    }

    // 2. Collect the results
    let mut open_ports = Vec::new();

    for handle in threads {
        // .join() waits for the thread to finish
        let result = handle.join().unwrap();
        if result.2 { // If is_it_open == true
            open_ports.push(result);
        }
    }

    // 3. Sort the results by port number so they print in order
    open_ports.sort_by_key(|(port, _, _)| *port);

    // 4. Print them
    if open_ports.is_empty() {
        println!(" No open ports found.");
    } else {
        for (port, service, _) in open_ports {
            println!(" Port {:<5} ({:<5}) : OPEN", port, service);
        }
    }

    println!("========================================");
    println!(" Scan complete.");
}