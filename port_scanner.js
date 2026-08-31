#!/usr/bin/env node
// port_scanner.js
const { program } = require('commander');
const net = require('net');
const fs = require('fs');
const chalk = require('chalk');

class TCPScanner {
    constructor(host, ports, timeout, threads, verbose, color) {
        this.host = host;
        this.ip = this.resolveIP(host);
        this.ports = this.parsePorts(ports);
        this.timeout = timeout * 1000;
        this.threads = Math.min(threads, this.ports.length);
        this.verbose = verbose;
        this.color = color && process.stdout.isTTY;
        this.results = [];
        this.lock = false;
        this._stop = false;
    }

    resolveIP(host) {
        try {
            return require('dns').lookupSync(host).address;
        } catch (e) {
            return host;
        }
    }

    parsePorts(portStr) {
        const ports = new Set();
        portStr.split(',').forEach(part => {
            if (part.includes('-')) {
                const [start, end] = part.split('-').map(Number);
                for (let p = start; p <= end; p++) ports.add(p);
            } else {
                ports.add(Number(part));
            }
        });
        return Array.from(ports).sort((a,b) => a-b);
    }

    scanPort(port) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            let resolved = false;
            const timer = setTimeout(() => {
                if (!resolved) {
                    resolved = true;
                    socket.destroy();
                    resolve({ port, state: 'filtered', banner: '' });
                }
            }, this.timeout);

            socket.on('connect', () => {
                if (!resolved) {
                    resolved = true;
                    clearTimeout(timer);
                    socket.destroy();
                    resolve({ port, state: 'open', banner: '' });
                }
            });

            socket.on('error', (err) => {
                if (!resolved) {
                    resolved = true;
                    clearTimeout(timer);
                    socket.destroy();
                    let state = 'error';
                    if (err.code === 'ECONNREFUSED') state = 'closed';
                    else if (err.code === 'ETIMEDOUT') state = 'filtered';
                    resolve({ port, state, banner: err.message });
                }
            });

            socket.connect(port, this.ip);
        });
    }

    async scanChunk(chunk) {
        const promises = chunk.map(p => this.scanPort(p));
        const results = await Promise.all(promises);
        for (const res of results) {
            this.results.push(res);
            if (this.verbose) this.printResult(res);
        }
    }

    async scan() {
        console.log(`Scanning ${this.host} (${this.ip})...`);
        const start = Date.now();
        const chunkSize = Math.ceil(this.ports.length / this.threads);
        const chunks = [];
        for (let i = 0; i < this.ports.length; i += chunkSize) {
            chunks.push(this.ports.slice(i, i+chunkSize));
        }
        const promises = chunks.map(chunk => this.scanChunk(chunk));
        await Promise.all(promises);
        const elapsed = (Date.now() - start) / 1000;
        const open = this.results.filter(r => r.state === 'open').length;
        console.log(`\nScan completed in ${elapsed.toFixed(2)}s. Found ${open} open ports.`);
        return this.results;
    }

    printResult(res) {
        if (this.color) {
            let colorFn = chalk.white;
            if (res.state === 'open') colorFn = chalk.green;
            else if (res.state === 'closed') colorFn = chalk.red;
            else if (res.state === 'filtered') colorFn = chalk.yellow;
            console.log(colorFn(`Port ${res.port}/tcp  ${res.state}  ${res.banner.slice(0,30)}`));
        } else {
            console.log(`Port ${res.port}/tcp  ${res.state}  ${res.banner.slice(0,30)}`);
        }
    }

    exportJSON(filename) {
        fs.writeFileSync(filename, JSON.stringify({ host: this.host, ip: this.ip, results: this.results }, null, 2));
    }

    exportCSV(filename) {
        const lines = ['port,state,banner'];
        this.results.forEach(r => {
            lines.push(`${r.port},${r.state},"${r.banner}"`);
        });
        fs.writeFileSync(filename, lines.join('\n'));
    }
}

program
    .requiredOption('--host <host>', 'Target host')
    .option('--ports <ports>', 'Ports to scan', '22,80,443,1-1024')
    .option('--timeout <seconds>', 'Timeout in seconds', parseFloat, 2)
    .option('--threads <number>', 'Number of threads', parseInt, 10)
    .option('--json <file>', 'Export to JSON')
    .option('--csv <file>', 'Export to CSV')
    .option('--verbose', 'Verbose output')
    .option('--no-color', 'Disable color')
    .parse(process.argv);

const opts = program.opts();
const scanner = new TCPScanner(
    opts.host,
    opts.ports,
    opts.timeout,
    opts.threads,
    opts.verbose,
    !opts.noColor
);
scanner.scan().then(() => {
    if (opts.json) {
        scanner.exportJSON(opts.json);
        console.log(`Results exported to ${opts.json}`);
    }
    if (opts.csv) {
        scanner.exportCSV(opts.csv);
        console.log(`Results exported to ${opts.csv}`);
    }
});
