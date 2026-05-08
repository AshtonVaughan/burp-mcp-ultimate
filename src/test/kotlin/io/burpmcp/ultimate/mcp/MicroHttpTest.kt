package io.burpmcp.ultimate.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets

class MicroHttpTest {

    private fun freePort(): Int {
        java.net.ServerSocket(0).use { return it.localPort }
    }

    private fun raw(host: String, port: Int, request: String): String {
        Socket(host, port).use { sock ->
            sock.getOutputStream().write(request.toByteArray(StandardCharsets.UTF_8))
            sock.getOutputStream().flush()
            return sock.getInputStream().readBytes().toString(StandardCharsets.UTF_8)
        }
    }

    @Test
    fun `GET dispatches to longest-prefix context with 200`() {
        val port = freePort()
        val srv = MicroHttpServer.create(InetSocketAddress("127.0.0.1", port))
        srv.createContext("/healthz") { exch ->
            val body = "ok".toByteArray(StandardCharsets.UTF_8)
            exch.responseHeaders.add("Content-Type", "text/plain")
            exch.sendResponseHeaders(200, body.size.toLong())
            exch.responseBody.use { it.write(body) }
        }
        srv.start()
        try {
            val resp = raw("127.0.0.1", port,
                "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            assertTrue(resp.startsWith("HTTP/1.1 200 OK"), "got: $resp")
            assertTrue(resp.contains("Content-Length: 2"))
            assertTrue(resp.endsWith("ok"))
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `POST body is delivered to handler with correct length`() {
        val port = freePort()
        val srv = MicroHttpServer.create(InetSocketAddress("127.0.0.1", port))
        var captured: String? = null
        srv.createContext("/echo") { exch ->
            captured = exch.requestBody.readBytes().toString(StandardCharsets.UTF_8)
            val body = (captured ?: "").toByteArray(StandardCharsets.UTF_8)
            exch.sendResponseHeaders(200, body.size.toLong())
            exch.responseBody.use { it.write(body) }
        }
        srv.start()
        try {
            val payload = """{"hello":"world"}"""
            val req = "POST /echo HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "Content-Length: ${payload.length}\r\n" +
                "Connection: close\r\n\r\n$payload"
            val resp = raw("127.0.0.1", port, req)
            assertEquals(payload, captured)
            assertTrue(resp.endsWith(payload), "got: $resp")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `unknown path returns 404 with parseable JSON body`() {
        val port = freePort()
        val srv = MicroHttpServer.create(InetSocketAddress("127.0.0.1", port))
        srv.createContext("/mcp") { _ -> /* never reached */ }
        srv.start()
        try {
            val resp = raw("127.0.0.1", port,
                "GET /.well-known/oauth-protected-resource HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\nConnection: close\r\n\r\n")
            assertTrue(resp.startsWith("HTTP/1.1 404"), "got: $resp")
            assertTrue(resp.contains("Content-Type: application/json"),
                "404 must declare JSON content-type so MCP SDK OAuth probes don't crash: $resp")
            assertTrue(resp.contains("{\"error\":\"not_found\"}"),
                "404 body must be JSON: $resp")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `204 response carries no body or transfer-encoding header`() {
        val port = freePort()
        val srv = MicroHttpServer.create(InetSocketAddress("127.0.0.1", port))
        srv.createContext("/empty") { exch ->
            exch.sendResponseHeaders(204, 0)
            exch.responseBody.use { /* write nothing */ }
        }
        srv.start()
        try {
            val resp = raw("127.0.0.1", port,
                "GET /empty HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            assertTrue(resp.startsWith("HTTP/1.1 204"), "got: $resp")
            assertTrue(!resp.contains("Transfer-Encoding"), "204 must not be chunked: $resp")
            assertTrue(!resp.contains("Content-Length:"), "204 must not have Content-Length: $resp")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `query string is preserved on requestURI`() {
        val port = freePort()
        val srv = MicroHttpServer.create(InetSocketAddress("127.0.0.1", port))
        var rawQuery: String? = null
        srv.createContext("/q") { exch ->
            rawQuery = exch.requestURI.rawQuery
            exch.sendResponseHeaders(200, 0)
            exch.responseBody.use { it.write("ok".toByteArray()) }
        }
        srv.start()
        try {
            raw("127.0.0.1", port,
                "GET /q?token=abc&x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            assertEquals("token=abc&x=1", rawQuery)
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `chunked streaming writes hex sizes and terminator on close`() {
        val port = freePort()
        val srv = MicroHttpServer.create(InetSocketAddress("127.0.0.1", port))
        srv.createContext("/stream") { exch ->
            exch.responseHeaders.add("Content-Type", "text/event-stream")
            exch.sendResponseHeaders(200, 0)
            val out: OutputStream = exch.responseBody
            out.write("hello".toByteArray(StandardCharsets.UTF_8))
            out.flush()
            out.write("world".toByteArray(StandardCharsets.UTF_8))
            out.flush()
            out.close()
        }
        srv.start()
        try {
            val resp = raw("127.0.0.1", port,
                "GET /stream HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            assertTrue(resp.contains("Transfer-Encoding: chunked"), "got: $resp")
            assertTrue(resp.contains("5\r\nhello\r\n"), "got: $resp")
            assertTrue(resp.contains("5\r\nworld\r\n"), "got: $resp")
            assertTrue(resp.endsWith("0\r\n\r\n"), "missing terminator: $resp")
        } finally {
            srv.stop()
        }
    }
}
