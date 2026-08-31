// PortScanner.java
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.*;

public class PortScanner {
    @Parameter(names = "--host", required = true)
    private String host;
    @Parameter(names = "--ports")
    private String ports = "22,80,443,1-1024";
    @Parameter(names = "--timeout")
    private int timeout = 2;
    @Parameter(names = "--threads")
    private int threads = 10;
    @Parameter(names = "--json")
    private String jsonFile;
    @Parameter(names = "--csv")
    private String csvFile;
    @Parameter(names = "--verbose")
    private boolean verbose;
    @Parameter(names = "--no-color")
    private boolean noColor;

    private InetAddress ip;
    private List<Integer> portList;
    private List<ScanResult> results = Collections.synchronizedList(new ArrayList<>());
    private ExecutorService executor;
    private boolean color;

    static class ScanResult {
        int port;
        String state;
        String banner;
    }

    public void run() throws Exception {
        ip = InetAddress.getByName(host);
        portList = parsePorts(ports);
        threads = Math.min(threads, portList.size());
        color = !noColor && System.console() != null;
        executor = Executors.newFixedThreadPool(threads);

        System.out.println("Scanning " + host + " (" + ip.getHostAddress() + ")...");
        long start = System.currentTimeMillis();

        List<Future<ScanResult>> futures = new ArrayList<>();
        for (int port : portList) {
            futures.add(executor.submit(() -> scanPort(port)));
        }
        for (Future<ScanResult> f : futures) {
            ScanResult res = f.get();
            results.add(res);
            if (verbose) printResult(res);
        }
        executor.shutdown();
        long elapsed = (System.currentTimeMillis() - start) / 1000.0;
        long openCount = results.stream().filter(r -> "open".equals(r.state)).count();
        System.out.printf("\nScan completed in %.2fs. Found %d open ports.\n", elapsed, openCount);

        if (jsonFile != null) exportJSON();
        if (csvFile != null) exportCSV();
    }

    private List<Integer> parsePorts(String s) {
        Set<Integer> set = new HashSet<>();
        for (String part : s.split(",")) {
            if (part.contains("-")) {
                String[] range = part.split("-");
                int start = Integer.parseInt(range[0]);
                int end = Integer.parseInt(range[1]);
                for (int p = start; p <= end; p++) set.add(p);
            } else {
                set.add(Integer.parseInt(part));
            }
        }
        return new ArrayList<>(set);
    }

    private ScanResult scanPort(int port) {
        ScanResult res = new ScanResult();
        res.port = port;
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), timeout * 1000);
            res.state = "open";
            res.banner = "";
        } catch (SocketTimeoutException e) {
            res.state = "filtered";
            res.banner = "";
        } catch (ConnectException e) {
            if (e.getMessage().contains("refused")) {
                res.state = "closed";
                res.banner = "";
            } else {
                res.state = "error";
                res.banner = e.getMessage();
            }
        } catch (Exception e) {
            res.state = "error";
            res.banner = e.getMessage();
        }
        return res;
    }

    private void printResult(ScanResult res) {
        if (color) {
            String colorCode = res.state.equals("open") ? "\u001B[32m" : res.state.equals("closed") ? "\u001B[31m" : res.state.equals("filtered") ? "\u001B[33m" : "\u001B[37m";
            System.out.printf("%sPort %d/tcp  %s\033[0m  %s%n", colorCode, res.port, res.state, res.banner);
        } else {
            System.out.printf("Port %d/tcp  %s  %s%n", res.port, res.state, res.banner);
        }
    }

    private void exportJSON() throws IOException {
        Map<String, Object> data = new HashMap<>();
        data.put("host", host);
        data.put("ip", ip.getHostAddress());
        data.put("results", results);
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(data);
        try (FileWriter fw = new FileWriter(jsonFile)) {
            fw.write(json);
        }
        System.out.println("Results exported to " + jsonFile);
    }

    private void exportCSV() throws IOException {
        try (PrintWriter pw = new PrintWriter(new FileWriter(csvFile))) {
            pw.println("port,state,banner");
            for (ScanResult r : results) {
                pw.printf("%d,%s,\"%s\"%n", r.port, r.state, r.banner);
            }
        }
        System.out.println("Results exported to " + csvFile);
    }

    public static void main(String[] args) throws Exception {
        PortScanner scanner = new PortScanner();
        JCommander.newBuilder().addObject(scanner).build().parse(args);
        scanner.run();
    }
}
