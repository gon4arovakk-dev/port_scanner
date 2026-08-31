// port_scanner.rs
use clap::{App, Arg};
use crossbeam::channel;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use colored::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ScanResult {
    port: u16,
    state: String,
    banner: String,
}

struct Scanner {
    host: String,
    ip: IpAddr,
    ports: Vec<u16>,
    timeout: Duration,
    threads: usize,
    verbose: bool,
    color: bool,
    results: Arc<Mutex<Vec<ScanResult>>>,
}

impl Scanner {
    fn new(host: &str, port_str: &str, timeout: f64, threads: usize, verbose: bool, color: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let ip = host.parse::<IpAddr>().or_else(|_| {
            let addrs = (host, 0).to_socket_addrs()?;
            let addr = addrs.into_iter().next().map(|s| s.ip()).ok_or("No IP")?;
            Ok(addr)
        })?;
        let ports = parse_ports(port_str)?;
        Ok(Scanner {
            host: host.to_string(),
            ip,
            ports,
            timeout: Duration::from_secs_f64(timeout),
            threads,
            verbose,
            color,
            results: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn scan_port(&self, port: u16) -> ScanResult {
        let addr = (self.ip, port);
        match TcpStream::connect_timeout(&addr, self.timeout) {
            Ok(_) => ScanResult { port, state: "open".to_string(), banner: "".to_string() },
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    ScanResult { port, state: "closed".to_string(), banner: "".to_string() }
                } else if e.kind() == std::io::ErrorKind::TimedOut {
                    ScanResult { port, state: "filtered".to_string(), banner: "".to_string() }
                } else {
                    ScanResult { port, state: "error".to_string(), banner: e.to_string() }
                }
            }
        }
    }

    fn print_result(&self, res: &ScanResult) {
        let state_colored = match res.state.as_str() {
            "open" => res.state.green(),
            "closed" => res.state.red(),
            "filtered" => res.state.yellow(),
            _ => res.state.normal(),
        };
        if self.color {
            println!("{}Port {}/tcp  {}  {}", state_colored, res.port, res.state, res.banner);
        } else {
            println!("Port {}/tcp  {}  {}", res.port, res.state, res.banner);
        }
    }

    fn scan(&self) {
        println!("Scanning {} ({})...", self.host, self.ip);
        let start_time = std::time::Instant::now();
        let (tx, rx) = channel::bounded::<u16>(self.ports.len());
        for &p in &self.ports {
            tx.send(p).unwrap();
        }
        drop(tx);
        let results = self.results.clone();
        let scanner = self;
        let handles: Vec<_> = (0..self.threads).map(|_| {
            let rx = rx.clone();
            let results = results.clone();
            std::thread::spawn(move || {
                for port in rx {
                    let res = scanner.scan_port(port);
                    {
                        let mut r = results.lock().unwrap();
                        r.push(res.clone());
                    }
                    if scanner.verbose {
                        scanner.print_result(&res);
                    }
                }
            })
        }).collect();
        for h in handles { h.join().unwrap(); }
        let elapsed = start_time.elapsed().as_secs_f64();
        let open_count = self.results.lock().unwrap().iter().filter(|r| r.state == "open").count();
        println!("\nScan completed in {:.2}s. Found {} open ports.", elapsed, open_count);
    }

    fn export_json(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::json!({
            "host": self.host,
            "ip": self.ip.to_string(),
            "results": &*self.results.lock().unwrap(),
        });
        let json = serde_json::to_string_pretty(&data)?;
        std::fs::write(filename, json)?;
        Ok(())
    }

    fn export_csv(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut wtr = csv::Writer::from_path(filename)?;
        wtr.write_record(&["port", "state", "banner"])?;
        for r in self.results.lock().unwrap().iter() {
            wtr.write_record(&[r.port.to_string(), r.state.clone(), r.banner.clone()])?;
        }
        wtr.flush()?;
        Ok(())
    }
}

fn parse_ports(port_str: &str) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let mut ports = Vec::new();
    for part in port_str.split(',') {
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            let start: u16 = range[0].parse()?;
            let end: u16 = range[1].parse()?;
            for p in start..=end {
                ports.push(p);
            }
        } else {
            ports.push(part.parse()?);
        }
    }
    Ok(ports)
}

fn main() {
    let matches = App::new("TCP Port Scanner")
        .arg(Arg::with_name("host").long("host").takes_value(true).required(true).help("Target host"))
        .arg(Arg::with_name("ports").long("ports").takes_value(true).default_value("22,80,443,1-1024").help("Ports to scan"))
        .arg(Arg::with_name("timeout").long("timeout").takes_value(true).default_value("2.0").help("Timeout in seconds"))
        .arg(Arg::with_name("threads").long("threads").takes_value(true).default_value("10").help("Number of threads"))
        .arg(Arg::with_name("json").long("json").takes_value(true).help("Export to JSON"))
        .arg(Arg::with_name("csv").long("csv").takes_value(true).help("Export to CSV"))
        .arg(Arg::with_name("verbose").long("verbose").help("Verbose output"))
        .arg(Arg::with_name("no-color").long("no-color").help("Disable color"))
        .get_matches();

    let host = matches.value_of("host").unwrap();
    let ports = matches.value_of("ports").unwrap();
    let timeout: f64 = matches.value_of("timeout").unwrap().parse().unwrap();
    let threads: usize = matches.value_of("threads").unwrap().parse().unwrap();
    let verbose = matches.is_present("verbose");
    let no_color = matches.is_present("no-color");
    let color = !no_color && atty::is(atty::Stream::Stdout);

    let scanner = Scanner::new(host, ports, timeout, threads, verbose, color)
        .expect("Failed to initialize scanner");
    scanner.scan();

    if let Some(json) = matches.value_of("json") {
        if let Err(e) = scanner.export_json(json) {
            eprintln!("Export JSON error: {}", e);
        } else {
            println!("Results exported to {}", json);
        }
    }
    if let Some(csv) = matches.value_of("csv") {
        if let Err(e) = scanner.export_csv(csv) {
            eprintln!("Export CSV error: {}", e);
        } else {
            println!("Results exported to {}", csv);
        }
    }
}
