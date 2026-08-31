// PortScanner.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace PortScanner
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var opts = ParseArgs(args);
            if (opts.Host == null)
            {
                Console.Error.WriteLine("Error: --host is required");
                return;
            }
            var scanner = new Scanner(opts);
            await scanner.ScanAsync();
            if (opts.Json != null) scanner.ExportJson(opts.Json);
            if (opts.Csv != null) scanner.ExportCsv(opts.Csv);
        }

        static Options ParseArgs(string[] args)
        {
            var opts = new Options();
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--host": opts.Host = args[++i]; break;
                    case "--ports": opts.Ports = args[++i]; break;
                    case "--timeout": opts.Timeout = int.Parse(args[++i]); break;
                    case "--threads": opts.Threads = int.Parse(args[++i]); break;
                    case "--json": opts.Json = args[++i]; break;
                    case "--csv": opts.Csv = args[++i]; break;
                    case "--verbose": opts.Verbose = true; break;
                    case "--no-color": opts.NoColor = true; break;
                }
            }
            return opts;
        }

        class Options
        {
            public string Host { get; set; }
            public string Ports { get; set; } = "22,80,443,1-1024";
            public int Timeout { get; set; } = 2;
            public int Threads { get; set; } = 10;
            public string Json { get; set; }
            public string Csv { get; set; }
            public bool Verbose { get; set; }
            public bool NoColor { get; set; }
        }

        class ScanResult
        {
            public int Port { get; set; }
            public string State { get; set; }
            public string Banner { get; set; }
        }

        class Scanner
        {
            private Options opts;
            private IPAddress ip;
            private List<int> ports;
            private ConcurrentBag<ScanResult> results = new ConcurrentBag<ScanResult>();
            private bool color;

            public Scanner(Options opts)
            {
                this.opts = opts;
                this.ip = Dns.GetHostEntry(opts.Host).AddressList.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (this.ip == null) throw new Exception("No IPv4 address found");
                this.ports = ParsePorts(opts.Ports);
                this.color = !opts.NoColor && !Console.IsOutputRedirected;
            }

            private List<int> ParsePorts(string s)
            {
                var set = new HashSet<int>();
                foreach (var part in s.Split(','))
                {
                    if (part.Contains('-'))
                    {
                        var r = part.Split('-');
                        int start = int.Parse(r[0]);
                        int end = int.Parse(r[1]);
                        for (int p = start; p <= end; p++) set.Add(p);
                    }
                    else
                    {
                        set.Add(int.Parse(part));
                    }
                }
                return set.ToList();
            }

            private ScanResult ScanPort(int port)
            {
                var res = new ScanResult { Port = port };
                try
                {
                    using (var client = new TcpClient())
                    {
                        var task = client.ConnectAsync(ip, port);
                        if (task.Wait(opts.Timeout * 1000))
                        {
                            res.State = "open";
                            res.Banner = "";
                        }
                        else
                        {
                            res.State = "filtered";
                            res.Banner = "";
                        }
                    }
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                        res.State = "closed";
                    else
                    {
                        res.State = "error";
                        res.Banner = ex.Message;
                    }
                }
                catch (Exception ex)
                {
                    res.State = "error";
                    res.Banner = ex.Message;
                }
                return res;
            }

            public async Task ScanAsync()
            {
                Console.WriteLine($"Scanning {opts.Host} ({ip})...");
                var start = DateTime.UtcNow;
                var options = new ParallelOptions { MaxDegreeOfParallelism = opts.Threads };
                await Task.Run(() =>
                {
                    Parallel.ForEach(ports, options, port =>
                    {
                        var res = ScanPort(port);
                        results.Add(res);
                        if (opts.Verbose) PrintResult(res);
                    });
                });
                var elapsed = (DateTime.UtcNow - start).TotalSeconds;
                int openCount = results.Count(r => r.State == "open");
                Console.WriteLine($"\nScan completed in {elapsed:F2}s. Found {openCount} open ports.");
            }

            private void PrintResult(ScanResult res)
            {
                if (color)
                {
                    ConsoleColor colorState = ConsoleColor.Gray;
                    if (res.State == "open") colorState = ConsoleColor.Green;
                    else if (res.State == "closed") colorState = ConsoleColor.Red;
                    else if (res.State == "filtered") colorState = ConsoleColor.Yellow;
                    Console.ForegroundColor = colorState;
                    Console.WriteLine($"Port {res.Port}/tcp  {res.State}  {res.Banner}");
                    Console.ResetColor();
                }
                else
                {
                    Console.WriteLine($"Port {res.Port}/tcp  {res.State}  {res.Banner}");
                }
            }

            public void ExportJson(string filename)
            {
                var data = new { host = opts.Host, ip = ip.ToString(), results = results.ToList() };
                var json = JsonConvert.SerializeObject(data, Formatting.Indented);
                File.WriteAllText(filename, json);
                Console.WriteLine($"Results exported to {filename}");
            }

            public void ExportCsv(string filename)
            {
                using (var sw = new StreamWriter(filename))
                {
                    sw.WriteLine("port,state,banner");
                    foreach (var r in results)
                        sw.WriteLine($"{r.Port},{r.State},\"{r.Banner}\"");
                }
                Console.WriteLine($"Results exported to {filename}");
            }
        }
    }
}
