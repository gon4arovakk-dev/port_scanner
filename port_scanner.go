// port_scanner.go
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	Port   int    `json:"port"`
	State  string `json:"state"`
	Banner string `json:"banner"`
}

type Scanner struct {
	host    string
	ip      net.IP
	ports   []int
	timeout time.Duration
	threads int
	verbose bool
	color   bool
	results []ScanResult
	mu      sync.Mutex
}

func NewScanner(host string, portStr string, timeout float64, threads int, verbose, color bool) (*Scanner, error) {
	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, err
	}
	ports, err := parsePorts(portStr)
	if err != nil {
		return nil, err
	}
	return &Scanner{
		host:    host,
		ip:      ip.IP,
		ports:   ports,
		timeout: time.Duration(timeout * float64(time.Second)),
		threads: threads,
		verbose: verbose,
		color:   color,
	}, nil
}

func parsePorts(portStr string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(portStr, ",") {
		if strings.Contains(part, "-") {
			r := strings.Split(part, "-")
			start, err := strconv.Atoi(r[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(r[1])
			if err != nil {
				return nil, err
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

func (s *Scanner) scanPort(port int) ScanResult {
	addr := net.TCPAddr{IP: s.ip, Port: port}
	conn, err := net.DialTimeout("tcp", addr.String(), s.timeout)
	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			return ScanResult{Port: port, State: "closed", Banner: ""}
		}
		if strings.Contains(err.Error(), "timeout") {
			return ScanResult{Port: port, State: "filtered", Banner: ""}
		}
		return ScanResult{Port: port, State: "error", Banner: err.Error()}
	}
	defer conn.Close()
	return ScanResult{Port: port, State: "open", Banner: ""}
}

func (s *Scanner) worker(ports <-chan int, wg *sync.WaitGroup) {
	defer wg.Done()
	for port := range ports {
		res := s.scanPort(port)
		s.mu.Lock()
		s.results = append(s.results, res)
		if s.verbose {
			s.printResult(res)
		}
		s.mu.Unlock()
	}
}

func (s *Scanner) printResult(res ScanResult) {
	stateColor := ""
	switch res.State {
	case "open":
		stateColor = "\033[32m"
	case "closed":
		stateColor = "\033[31m"
	case "filtered":
		stateColor = "\033[33m"
	default:
		stateColor = "\033[37m"
	}
	if s.color {
		fmt.Printf("%sPort %d/tcp  %s\033[0m  %s\n", stateColor, res.Port, res.State, res.Banner)
	} else {
		fmt.Printf("Port %d/tcp  %s  %s\n", res.Port, res.State, res.Banner)
	}
}

func (s *Scanner) Scan() {
	fmt.Printf("Scanning %s (%s)...\n", s.host, s.ip.String())
	startTime := time.Now()
	var wg sync.WaitGroup
	portsChan := make(chan int, len(s.ports))
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go s.worker(portsChan, &wg)
	}
	for _, p := range s.ports {
		portsChan <- p
	}
	close(portsChan)
	wg.Wait()
	elapsed := time.Since(startTime).Seconds()
	openCount := 0
	for _, r := range s.results {
		if r.State == "open" {
			openCount++
		}
	}
	fmt.Printf("\nScan completed in %.2fs. Found %d open ports.\n", elapsed, openCount)
}

func (s *Scanner) ExportJSON(filename string) error {
	data := struct {
		Host    string       `json:"host"`
		IP      string       `json:"ip"`
		Results []ScanResult `json:"results"`
	}{s.host, s.ip.String(), s.results}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, b, 0644)
}

func (s *Scanner) ExportCSV(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"port", "state", "banner"})
	for _, r := range s.results {
		w.Write([]string{strconv.Itoa(r.Port), r.State, r.Banner})
	}
	return nil
}

func main() {
	var (
		host    string
		ports   string
		timeout float64
		threads int
		jsonOut string
		csvOut  string
		verbose bool
		noColor bool
	)
	flag.StringVar(&host, "host", "", "Target host")
	flag.StringVar(&ports, "ports", "22,80,443,1-1024", "Ports to scan")
	flag.Float64Var(&timeout, "timeout", 2.0, "Timeout in seconds")
	flag.IntVar(&threads, "threads", 10, "Number of threads")
	flag.StringVar(&jsonOut, "json", "", "Export to JSON")
	flag.StringVar(&csvOut, "csv", "", "Export to CSV")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&noColor, "no-color", false, "Disable color")
	flag.Parse()

	if host == "" {
		fmt.Fprintln(os.Stderr, "Error: --host is required")
		os.Exit(1)
	}
	color := !noColor && isTerminal()
	scanner, err := NewScanner(host, ports, timeout, threads, verbose, color)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	scanner.Scan()
	if jsonOut != "" {
		if err := scanner.ExportJSON(jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "Export JSON error: %v\n", err)
		} else {
			fmt.Printf("Results exported to %s\n", jsonOut)
		}
	}
	if csvOut != "" {
		if err := scanner.ExportCSV(csvOut); err != nil {
			fmt.Fprintf(os.Stderr, "Export CSV error: %v\n", err)
		} else {
			fmt.Printf("Results exported to %s\n", csvOut)
		}
	}
}

func isTerminal() bool {
	stat, _ := os.Stdout.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}
