
```python
#!/usr/bin/env python3
# port_scanner.py
import argparse
import socket
import threading
import time
import json
import csv
import sys
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

class TCPScanner:
    def __init__(self, host, ports, timeout=2, threads=10, verbose=False, color=True):
        self.host = host
        try:
            self.ip = socket.gethostbyname(host)
        except:
            self.ip = host
        self.ports = self.parse_ports(ports)
        self.timeout = timeout
        self.threads = min(threads, len(self.ports))
        self.verbose = verbose
        self.color = color and sys.stdout.isatty()
        self.results = []
        self.lock = threading.Lock()
        self._stop = False

    def parse_ports(self, port_str):
        ports = set()
        for part in port_str.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end+1))
            else:
                ports.add(int(part))
        return sorted(ports)

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            sock.close()
            if result == 0:
                return {"port": port, "state": "open", "banner": ""}
            else:
                return {"port": port, "state": "closed", "banner": ""}
        except socket.timeout:
            return {"port": port, "state": "filtered", "banner": ""}
        except Exception as e:
            return {"port": port, "state": "error", "banner": str(e)}

    def worker(self, port_list):
        for port in port_list:
            if self._stop:
                break
            res = self.scan_port(port)
            with self.lock:
                self.results.append(res)
                if self.verbose:
                    self.print_result(res)

    def scan(self):
        print(f"Scanning {self.host} ({self.ip})...")
        start_time = time.time()
        # Разбиваем порты на чанки для потоков
        chunk_size = max(1, len(self.ports) // self.threads)
        chunks = [self.ports[i:i+chunk_size] for i in range(0, len(self.ports), chunk_size)]
        threads = []
        for chunk in chunks:
            t = threading.Thread(target=self.worker, args=(chunk,))
            t.start()
            threads.append(t)
        # Ожидаем завершения всех потоков
        for t in threads:
            t.join()
        elapsed = time.time() - start_time
        open_count = len([r for r in self.results if r['state'] == 'open'])
        print(f"\nScan completed in {elapsed:.2f}s. Found {open_count} open ports.")
        return self.results

    def print_result(self, res):
        if self.color:
            if res['state'] == 'open':
                color = Fore.GREEN
            elif res['state'] == 'closed':
                color = Fore.RED
            elif res['state'] == 'filtered':
                color = Fore.YELLOW
            else:
                color = Fore.WHITE
            print(f"{color}Port {res['port']}/tcp  {res['state']}{' '*10} {res['banner'][:30]}")
        else:
            print(f"Port {res['port']}/tcp  {res['state']}  {res['banner'][:30]}")

    def export_json(self, filename):
        with open(filename, 'w') as f:
            json.dump({"host": self.host, "ip": self.ip, "results": self.results}, f, indent=2)

    def export_csv(self, filename):
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["port", "state", "banner"])
            for r in self.results:
                writer.writerow([r['port'], r['state'], r['banner']])

def main():
    parser = argparse.ArgumentParser(description="TCP Port Scanner")
    parser.add_argument("--host", required=True, help="Target host (IP or domain)")
    parser.add_argument("--ports", default="22,80,443,1-1024", help="Ports to scan (e.g., 80,443,1-1000)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Connection timeout in seconds")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--json", help="Export results to JSON file")
    parser.add_argument("--csv", help="Export results to CSV file")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    scanner = TCPScanner(
        host=args.host,
        ports=args.ports,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
        color=not args.no_color
    )
    results = scanner.scan()
    if args.json:
        scanner.export_json(args.json)
        print(f"Results exported to {args.json}")
    if args.csv:
        scanner.export_csv(args.csv)
        print(f"Results exported to {args.csv}")

if __name__ == "__main__":
    main()
