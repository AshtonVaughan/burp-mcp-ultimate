package io.burpmcp.ultimate.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class HttpToolsTest {

    @Test
    fun `JCA HMAC name maps HS256 to HmacSHA256`() {
        assertEquals("HmacSHA256", JwtTools.jcaHmacName("HS256"))
        assertEquals("HmacSHA384", JwtTools.jcaHmacName("HS384"))
        assertEquals("HmacSHA512", JwtTools.jcaHmacName("HS512"))
        assertEquals("HmacSHA256", JwtTools.jcaHmacName("hs256"))
    }

    @Test
    fun `JCA HMAC name rejects non-HMAC algs`() {
        assertThrows(IllegalArgumentException::class.java) { JwtTools.jcaHmacName("RS256") }
        assertThrows(IllegalArgumentException::class.java) { JwtTools.jcaHmacName("none") }
    }

    @Test
    fun `JCA HMAC names actually load via Mac getInstance`() {
        // Regression for the original "Hmac256" bug: ensure the produced
        // algorithm strings are real JCA names that can be instantiated.
        listOf("HS256", "HS384", "HS512").forEach { alg ->
            javax.crypto.Mac.getInstance(JwtTools.jcaHmacName(alg))
        }
    }

    @Test
    fun `coerceJsonInput accepts a Map under the object key`() {
        val args = mapOf("payload" to mapOf("sub" to "u", "iat" to 1700000000))
        val out = JwtTools.coerceJsonInput(args, "payload", "payload_json")
        // Json.write is via jacksonObjectMapper which doesn't promise key order,
        // but for two keys we can assert content presence.
        assertEquals(true, out!!.contains("\"sub\":\"u\""))
        assertEquals(true, out.contains("\"iat\":1700000000"))
    }

    @Test
    fun `coerceJsonInput accepts a raw string under the json key`() {
        val args = mapOf("payload_json" to "{\"already\":\"a string\"}")
        assertEquals("{\"already\":\"a string\"}",
            JwtTools.coerceJsonInput(args, "payload", "payload_json"))
    }

    @Test
    fun `coerceJsonInput prefers the object key when both are present`() {
        val args = mapOf(
            "payload"      to mapOf("from" to "object"),
            "payload_json" to "{\"from\":\"string\"}",
        )
        val out = JwtTools.coerceJsonInput(args, "payload", "payload_json")
        assertEquals(true, out!!.contains("\"from\":\"object\""))
    }

    @Test
    fun `coerceJsonInput returns null when neither key is present`() {
        val args = mapOf("unrelated" to "x")
        kotlin.test.assertNull(JwtTools.coerceJsonInput(args, "payload", "payload_json"))
    }

    @Test
    fun `coerceJsonInput tolerates a String under the object key`() {
        // Some clients put the JSON string under the object-typed key by mistake.
        // We accept it as-is rather than re-serializing.
        val args = mapOf("payload" to "{\"already\":\"string\"}")
        assertEquals("{\"already\":\"string\"}",
            JwtTools.coerceJsonInput(args, "payload", "payload_json"))
    }


    @Test
    fun `LF-only headers are normalized to CRLF and trailing separator added`() {
        val input = "GET / HTTP/1.1\nHost: example.com\nUser-Agent: x\n\n"
        val out = HttpTools.normalizeRawRequest(input)
        assertEquals(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n",
            out,
        )
    }

    @Test
    fun `already-CRLF input is returned unchanged`() {
        val input = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assertEquals(input, HttpTools.normalizeRawRequest(input))
    }

    @Test
    fun `body bytes are preserved exactly when headers are LF-only`() {
        val body = "{\"a\":1,\n\"b\":\"line\\nwith\\nliterals\"}"
        val input = "POST /x HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n$body"
        val out = HttpTools.normalizeRawRequest(input)
        val sep = out.indexOf("\r\n\r\n")
        assertEquals(body, out.substring(sep + 4))
    }

    @Test
    fun `missing trailing separator is appended`() {
        val input = "GET / HTTP/1.1\r\nHost: example.com"
        val out = HttpTools.normalizeRawRequest(input)
        assertEquals("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", out)
    }

    @Test
    fun `empty input becomes minimal CRLFCRLF`() {
        assertEquals("\r\n\r\n", HttpTools.normalizeRawRequest(""))
    }

    @Test
    fun `mixed line endings in headers are all normalized`() {
        val input = "GET / HTTP/1.1\r\nA: 1\nB: 2\r\nC: 3\n\nbody"
        val out = HttpTools.normalizeRawRequest(input)
        assertEquals("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\nbody", out)
    }
}
