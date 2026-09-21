use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use std::thread;
use colored::*;

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

    // Color the header cyan!
    println!("{}", "========================================".cyan());
    println!("{}", " Scouter26 - Port Scanner".cyan());
    println!(" {}{}", "Target: ".cyan(), target.cyan());
    println!("{}", "========================================".cyan());

    let mut threads = Vec::new();

    for (port, service) in common_ports.iter() {
        let target = String::from(target);
        let port = *port;
        let service = *service;

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

            (port, service, connection.is_ok())
        });

        threads.push(handle);
    }

    let mut open_ports = Vec::new();

    for handle in threads {
        let result = handle.join().unwrap();
        if result.2 {
            open_ports.push(result);
        }
    }

    open_ports.sort_by_key(|(port, _, _)| *port);

    if open_ports.is_empty() {
        // Make the "no ports" message yellow
        println!("{}", " No open ports found.".yellow());
    } else {
        for (port, service, _) in open_ports {
            // Make the OPEN message bright green
            println!(" Port {:<5} ({:<5}) : {}", port, service, "OPEN".green().bold());
        }
    }

    println!("{}", "========================================".cyan());
    println!("{}", " Scan complete.".cyan());
}