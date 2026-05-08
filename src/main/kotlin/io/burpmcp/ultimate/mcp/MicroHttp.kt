package io.burpmcp.ultimate.mcp

import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/**
 * Minimal HTTP/1.1 server. Replaces com.sun.net.httpserver because Burp's
 * bundled JRE is a jlink'd image that does not include the jdk.httpserver
 * module. We only need the surface McpServer and SseHub use.
 *
 * Semantics mirror com.sun.net.httpserver.HttpExchange:
 *  - sendResponseHeaders(code, len > 0)  -> Content-Length: len
 *  - sendResponseHeaders(code, 0)        -> Transfer-Encoding: chunked (streaming),
 *                                           except for 1xx/204/304 which forbid bodies
 *                                           and get neither header.
 */

class HttpHeaders {
    private val headers = LinkedHashMap<String, MutableList<String>>()

    fun add(name: String, value: String) {
        headers.getOrPut(name.lowercase()) { mutableListOf() }.add(value)
    }

    fun getFirst(name: String): String? = headers[name.lowercase()]?.firstOrNull()

    internal fun writeWire(out: StringBuilder) {
        for ((nameLower, values) in headers) {
            val canonical = nameLower.split('-').joinToString("-") { part ->
                if (part.isEmpty()) part else part[0].uppercaseChar() + part.substring(1)
            }
            for (v in values) {
                out.append(canonical).append(": ").append(v).append("\r\n")
            }
        }
    }
}

class HttpExchange internal constructor(
    val requestMethod: String,
    val requestURI: URI,
    val requestHeaders: HttpHeaders,
    val requestBody: InputStream,
    private val rawOut: OutputStream,
    private val socket: Socket,
) {
    val responseHeaders: HttpHeaders = HttpHeaders()

    @Volatile private var headersSent: Boolean = false
    @Volatile private var chunked: Boolean = false
    @Volatile internal var bodyClosed: Boolean = false
        private set

    val responseBody: OutputStream = object : OutputStream() {
        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
            check(headersSent) { "must call sendResponseHeaders before write" }
            if (len <= 0) return
            if (chunked) {
                val sizeLine = (Integer.toHexString(len) + "\r\n").toByteArray(CRLF_CHARSET)
                rawOut.write(sizeLine)
                rawOut.write(b, off, len)
                rawOut.write(CRLF)
            } else {
                rawOut.write(b, off, len)
            }
        }

        override fun flush() {
            rawOut.flush()
        }

        @Synchronized
        override fun close() {
            if (bodyClosed) return
            bodyClosed = true
            try {
                if (chunked) rawOut.write(CHUNKED_TERMINATOR)
                rawOut.flush()
            } catch (_: IOException) {
                // already closed by peer; ignore
            } finally {
                try { socket.close() } catch (_: IOException) {}
            }
        }
    }

    fun sendResponseHeaders(code: Int, contentLength: Long) {
        require(!headersSent) { "headers already sent" }
        val noBody = code == 204 || code == 304 || code in 100..199
        chunked = !noBody && contentLength == 0L
        when {
            chunked -> responseHeaders.add("Transfer-Encoding", "chunked")
            !noBody -> responseHeaders.add("Content-Length", contentLength.toString())
        }
        val sb = StringBuilder()
        sb.append("HTTP/1.1 ").append(code).append(' ').append(reasonPhrase(code)).append("\r\n")
        responseHeaders.writeWire(sb)
        sb.append("\r\n")
        rawOut.write(sb.toString().toByteArray(StandardCharsets.UTF_8))
        rawOut.flush()
        headersSent = true
    }

    private fun reasonPhrase(code: Int): String = when (code) {
        200 -> "OK"
        201 -> "Created"
        202 -> "Accepted"
        204 -> "No Content"
        301 -> "Moved Permanently"
        302 -> "Found"
        304 -> "Not Modified"
        400 -> "Bad Request"
        401 -> "Unauthorized"
        403 -> "Forbidden"
        404 -> "Not Found"
        405 -> "Method Not Allowed"
        500 -> "Internal Server Error"
        501 -> "Not Implemented"
        else -> "OK"
    }

    private companion object {
        val CRLF_CHARSET = StandardCharsets.US_ASCII
        val CRLF = "\r\n".toByteArray(StandardCharsets.US_ASCII)
        val CHUNKED_TERMINATOR = "0\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
    }
}

class MicroHttpServer private constructor(private val address: InetSocketAddress) {

    companion object {
        fun create(addr: InetSocketAddress, @Suppress("UNUSED_PARAMETER") backlog: Int = 0): MicroHttpServer =
            MicroHttpServer(addr)
    }

    @Volatile var executor: Executor = Executors.newCachedThreadPool { r ->
        Thread(r, "burp-mcp-conn").apply { isDaemon = true }
    }

    private val contexts = ConcurrentHashMap<String, (HttpExchange) -> Unit>()
    @Volatile private var serverSocket: ServerSocket? = null
    @Volatile private var running = false
    private var acceptThread: Thread? = null

    fun createContext(path: String, handler: (HttpExchange) -> Unit) {
        contexts[path] = handler
    }

    val boundPort: Int? get() = serverSocket?.localPort

    fun start() {
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(address, 0)
        serverSocket = ss
        running = true
        acceptThread = Thread({
            while (running) {
                val client = try {
                    ss.accept()
                } catch (_: IOException) {
                    // ServerSocket closed (stop()) -> exit accept loop cleanly.
                    break
                } catch (_: Throwable) {
                    // Anything else (transient I/O, OOM in accept buffer alloc):
                    // log via stderr and continue. We never let one bad accept
                    // kill the whole listener.
                    System.err.println("[burp-mcp] transient accept error; continuing")
                    continue
                }
                try {
                    executor.execute { handleConnection(client) }
                } catch (_: Throwable) {
                    // RejectedExecutionException (executor saturated/shut down)
                    // or any other throwable from execute(): close the orphaned
                    // socket and continue accepting. Better to drop one
                    // connection than the whole listener.
                    try { client.close() } catch (_: IOException) {}
                }
            }
        }, "burp-mcp-accept").apply { isDaemon = true; start() }
    }

    fun stop(@Suppress("UNUSED_PARAMETER") timeoutSeconds: Int = 0) {
        running = false
        try { serverSocket?.close() } catch (_: IOException) {}
    }

    private fun handleConnection(socket: Socket) {
        val input: BufferedInputStream
        val output: OutputStream
        try {
            input = BufferedInputStream(socket.getInputStream())
            output = socket.getOutputStream()
        } catch (_: IOException) {
            try { socket.close() } catch (_: IOException) {}
            return
        }

        val exch = try {
            parseRequest(input, output, socket)
        } catch (_: IOException) {
            try { socket.close() } catch (_: IOException) {}
            return
        }
        if (exch == null) {
            try { socket.close() } catch (_: IOException) {}
            return
        }

        val handler = contexts.entries
            .filter { exch.requestURI.path?.startsWith(it.key) == true }
            .maxByOrNull { it.key.length }
            ?.value

        if (handler == null) {
            try {
                // Emit JSON so MCP SDKs probing /.well-known/oauth-* paths
                // (RFC 9728 protected-resource metadata discovery) can parse
                // the response without crashing on a plain-text body.
                exch.responseHeaders.add("Content-Type", "application/json")
                val body = "{\"error\":\"not_found\"}".toByteArray(StandardCharsets.UTF_8)
                exch.sendResponseHeaders(404, body.size.toLong())
                exch.responseBody.write(body)
            } catch (_: IOException) {}
            try { exch.responseBody.close() } catch (_: IOException) {}
            return
        }

        try {
            handler(exch)
        } catch (_: Throwable) {
            try { exch.responseBody.close() } catch (_: IOException) {}
            return
        }

        // If the handler completed without closing the body, this is a
        // streaming response (SSE). The socket stays open until the holder
        // (SseHub) calls close() or the peer disconnects.
        if (!exch.bodyClosed) {
            // No-op: socket lifetime now owned by the streaming consumer.
        }
    }

    private fun parseRequest(input: InputStream, output: OutputStream, socket: Socket): HttpExchange? {
        val statusLine = readLine(input) ?: return null
        if (statusLine.isEmpty()) return null
        val parts = statusLine.split(' ')
        if (parts.size < 3) return null
        val method = parts[0]
        val target = parts[1]

        val headers = HttpHeaders()
        while (true) {
            val line = readLine(input) ?: return null
            if (line.isEmpty()) break
            val idx = line.indexOf(':')
            if (idx <= 0) continue
            headers.add(line.substring(0, idx).trim(), line.substring(idx + 1).trim())
        }

        val contentLength = headers.getFirst("content-length")?.toLongOrNull() ?: 0L
        val body: InputStream = if (contentLength > 0) {
            val buf = ByteArray(contentLength.toInt())
            var read = 0
            while (read < buf.size) {
                val n = input.read(buf, read, buf.size - read)
                if (n < 0) break
                read += n
            }
            ByteArrayInputStream(buf, 0, read)
        } else {
            ByteArrayInputStream(ByteArray(0))
        }

        val uri = try {
            URI.create(target)
        } catch (_: IllegalArgumentException) {
            URI.create("/")
        }
        return HttpExchange(method, uri, headers, body, output, socket)
    }

    private fun readLine(input: InputStream): String? {
        val buf = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (buf.isEmpty()) null else buf.toString()
            if (b == 0x0D) {
                val next = input.read()
                if (next == 0x0A) return buf.toString()
                if (next < 0) return buf.toString()
                buf.append('\r').append(next.toChar())
            } else if (b == 0x0A) {
                return buf.toString()
            } else {
                buf.append(b.toChar())
            }
        }
    }
}
