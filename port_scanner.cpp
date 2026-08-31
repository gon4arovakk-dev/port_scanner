// port_scanner.cpp
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <fstream>
#include <json/json.h> // using jsoncpp

using namespace std;

struct ScanResult {
    int port;
    string state;
    string banner;
};

class Scanner {
private:
    string host;
    string ip;
    vector<int> ports;
    double timeout;
    int threads;
    bool verbose;
    bool color;
    vector<ScanResult> results;
    mutex mtx;

    string resolveHost(const string& host) {
        struct hostent* he = gethostbyname(host.c_str());
        if (he == nullptr) return host;
        return inet_ntoa(*(struct in_addr*)he->h_addr);
    }

    vector<int> parsePorts(const string& s) {
        vector<int> res;
        stringstream ss(s);
        string part;
        while (getline(ss, part, ',')) {
            if (part.find('-') != string::npos) {
                int dash = part.find('-');
                int start = stoi(part.substr(0, dash));
                int end = stoi(part.substr(dash+1));
                for (int p = start; p <= end; ++p) res.push_back(p);
            } else {
                res.push_back(stoi(part));
            }
        }
        return res;
    }

    ScanResult scanPort(int port) {
        ScanResult res;
        res.port = port;
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { res.state = "error"; res.banner = "socket"; return res; }
        // Устанавливаем таймаут
        struct timeval tv;
        tv.tv_sec = (int)timeout;
        tv.tv_usec = (int)((timeout - tv.tv_sec) * 1e6);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        auto start = chrono::steady_clock::now();
        int conn = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        double elapsed = chrono::duration<double>(chrono::steady_clock::now() - start).count();
        if (conn == 0) {
            res.state = "open";
            res.banner = "";
        } else {
            if (errno == ECONNREFUSED) {
                res.state = "closed";
            } else if (errno == ETIMEDOUT) {
                res.state = "filtered";
            } else {
                res.state = "error";
                res.banner = strerror(errno);
            }
        }
        close(sock);
        return res;
    }

    void worker(int start, int end) {
        for (int i = start; i < end; ++i) {
            auto res = scanPort(ports[i]);
            lock_guard<mutex> lock(mtx);
            results.push_back(res);
            if (verbose) printResult(res);
        }
    }

    void printResult(const ScanResult& res) {
        if (color) {
            string colorCode = "";
            if (res.state == "open") colorCode = "\033[32m";
            else if (res.state == "closed") colorCode = "\033[31m";
            else if (res.state == "filtered") colorCode = "\033[33m";
            else colorCode = "\033[37m";
            cout << colorCode << "Port " << res.port << "/tcp  " << res.state << "\033[0m  " << res.banner << endl;
        } else {
            cout << "Port " << res.port << "/tcp  " << res.state << "  " << res.banner << endl;
        }
    }

public:
    Scanner(const string& host, const string& portStr, double timeout, int threads, bool verbose, bool color)
        : host(host), timeout(timeout), threads(threads), verbose(verbose), color(color) {
        ip = resolveHost(host);
        ports = parsePorts(portStr);
        if (threads > (int)ports.size()) threads = ports.size();
    }

    void scan() {
        cout << "Scanning " << host << " (" << ip << ")..." << endl;
        auto start = chrono::steady_clock::now();
        int chunkSize = max(1, (int)ports.size() / threads);
        vector<thread> pool;
        for (int i = 0; i < (int)ports.size(); i += chunkSize) {
            int end = min(i + chunkSize, (int)ports.size());
            pool.emplace_back(&Scanner::worker, this, i, end);
        }
        for (auto& t : pool) t.join();
        auto elapsed = chrono::duration<double>(chrono::steady_clock::now() - start).count();
        int openCount = count_if(results.begin(), results.end(), [](const ScanResult& r){ return r.state == "open"; });
        cout << "\nScan completed in " << elapsed << "s. Found " << openCount << " open ports." << endl;
    }

    void exportJSON(const string& filename) {
        Json::Value root;
        root["host"] = host;
        root["ip"] = ip;
        for (auto& r : results) {
            Json::Value item;
            item["port"] = r.port;
            item["state"] = r.state;
            item["banner"] = r.banner;
            root["results"].append(item);
        }
        ofstream ofs(filename);
        ofs << root.toStyledString();
        cout << "Results exported to " << filename << endl;
    }

    void exportCSV(const string& filename) {
        ofstream ofs(filename);
        ofs << "port,state,banner\n";
        for (auto& r : results) {
            ofs << r.port << "," << r.state << ",\"" << r.banner << "\"\n";
        }
        cout << "Results exported to " << filename << endl;
    }
};

int main(int argc, char* argv[]) {
    string host, ports = "22,80,443,1-1024", jsonFile, csvFile;
    double timeout = 2.0;
    int threads = 10;
    bool verbose = false, noColor = false;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--host" && i+1 < argc) host = argv[++i];
        else if (arg == "--ports" && i+1 < argc) ports = argv[++i];
        else if (arg == "--timeout" && i+1 < argc) timeout = stod(argv[++i]);
        else if (arg == "--threads" && i+1 < argc) threads = stoi(argv[++i]);
        else if (arg == "--json" && i+1 < argc) jsonFile = argv[++i];
        else if (arg == "--csv" && i+1 < argc) csvFile = argv[++i];
        else if (arg == "--verbose") verbose = true;
        else if (arg == "--no-color") noColor = true;
    }
    if (host.empty()) {
        cerr << "Error: --host required" << endl;
        return 1;
    }
    bool color = !noColor && isatty(fileno(stdout));
    Scanner scanner(host, ports, timeout, threads, verbose, color);
    scanner.scan();
    if (!jsonFile.empty()) scanner.exportJSON(jsonFile);
    if (!csvFile.empty()) scanner.exportCSV(csvFile);
    return 0;
}
