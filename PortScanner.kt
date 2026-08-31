// PortScanner.kt
import com.beust.jcommander.JCommander
import com.beust.jcommander.Parameter
import com.google.gson.GsonBuilder
import java.io.File
import java.net.*
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

data class ScanResult(val port: Int, val state: String, val banner: String = "")

class PortScanner {
    @Parameter(names = ["--host"], required = true)
    private lateinit var host: String

    @Parameter(names = ["--ports"])
    private var portsSpec: String = "22,80,443,1-1024"

    @Parameter(names = ["--timeout"])
    private var timeout: Int = 2

    @Parameter(names = ["--threads"])
    private var threads: Int = 10

    @Parameter(names = ["--json"])
    private var jsonFile: String? = null

    @Parameter(names = ["--csv"])
    private var csvFile: String? = null

    @Parameter(names = ["--verbose"])
    private var verbose: Boolean = false

    @Parameter(names = ["--no-color"])
    private var noColor: Boolean = false

    private lateinit var ip: InetAddress
    private lateinit var ports: List<Int>
    private val results = ConcurrentLinkedQueue<ScanResult>()
    private var color: Boolean = false

    fun run() {
        ip = InetAddress.getByName(host)
        ports = parsePorts(portsSpec)
        threads = minOf(threads, ports.size)
        color = !noColor && System.console() != null

        println("Scanning $host (${ip.hostAddress})...")
        val start = System.currentTimeMillis()

        val executor = Executors.newFixedThreadPool(threads)
        val futures = ports.map { port ->
            executor.submit<ScanResult> { scanPort(port) }
        }
        futures.forEach { future ->
            val res = future.get()
            results.add(res)
            if (verbose) printResult(res)
        }
        executor.shutdown()
        executor.awaitTermination(1, TimeUnit.MINUTES)

        val elapsed = (System.currentTimeMillis() - start) / 1000.0
        val openCount = results.count { it.state == "open" }
        println("\nScan completed in ${String.format("%.2f", elapsed)}s. Found $openCount open ports.")

        jsonFile?.let { exportJSON(it) }
        csvFile?.let { exportCSV(it) }
    }

    private fun parsePorts(s: String): List<Int> {
        val set = mutableSetOf<Int>()
        s.split(',').forEach { part ->
            if (part.contains('-')) {
                val (start, end) = part.split('-').map { it.toInt() }
                (start..end).forEach { set.add(it) }
            } else {
                set.add(part.toInt())
            }
        }
        return set.toList()
    }

    private fun scanPort(port: Int): ScanResult {
        return try {
            val socket = Socket()
            socket.soTimeout = timeout * 1000
            val addr = InetSocketAddress(ip, port)
            socket.connect(addr, timeout * 1000)
            socket.close()
            ScanResult(port, "open")
        } catch (e: SocketTimeoutException) {
            ScanResult(port, "filtered")
        } catch (e: ConnectException) {
            if (e.message?.contains("refused") == true) {
                ScanResult(port, "closed")
            } else {
                ScanResult(port, "error", e.message ?: "")
            }
        } catch (e: Exception) {
            ScanResult(port, "error", e.message ?: "")
        }
    }

    private fun printResult(res: ScanResult) {
        if (color) {
            val colorCode = when (res.state) {
                "open" -> "\u001B[32m"
                "closed" -> "\u001B[31m"
                "filtered" -> "\u001B[33m"
                else -> "\u001B[37m"
            }
            println("$colorCodePort ${res.port}/tcp  ${res.state}\u001B[0m  ${res.banner}")
        } else {
            println("Port ${res.port}/tcp  ${res.state}  ${res.banner}")
        }
    }

    private fun exportJSON(filename: String) {
        val data = mapOf(
            "host" to host,
            "ip" to ip.hostAddress,
            "results" to results.toList()
        )
        val gson = GsonBuilder().setPrettyPrinting().create()
        File(filename).writeText(gson.toJson(data))
        println("Results exported to $filename")
    }

    private fun exportCSV(filename: String) {
        File(filename).printWriter().use { pw ->
            pw.println("port,state,banner")
            results.forEach { pw.println("${it.port},${it.state},\"${it.banner}\"") }
        }
        println("Results exported to $filename")
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val scanner = PortScanner()
            JCommander.newBuilder().addObject(scanner).build().parse(*args)
            scanner.run()
        }
    }
}
