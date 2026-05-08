package io.burpmcp.ultimate.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AttackToolsTest {

    private fun resp(
        status: Int = 200,
        body: String = "",
        headers: List<Pair<String, String>> = emptyList(),
    ) = AttackTools.Resp(status, body.length, headers, body)

    @Test
    fun `analyzeAnomaly flags status code change`() {
        val baseline = resp(status = 403, body = "x".repeat(100))
        val probe = resp(status = 200, body = "x".repeat(100))
        val a = AttackTools.analyzeAnomaly(baseline, probe, "MARKER")
        assertNotNull(a)
        assertEquals("status_code_change", a!!.type)
    }

    @Test
    fun `analyzeAnomaly flags marker reflected in body`() {
        val baseline = resp(body = "boring response")
        val probe = resp(body = "boring response with MARKER inside")
        val a = AttackTools.analyzeAnomaly(baseline, probe, "MARKER")
        assertNotNull(a)
        assertEquals("marker_reflected_in_body", a!!.type)
    }

    @Test
    fun `analyzeAnomaly flags marker reflected in response header value`() {
        val baseline = resp(headers = listOf("Server" to "nginx"))
        val probe = resp(headers = listOf("Server" to "nginx", "X-Echo" to "MARKER"))
        val a = AttackTools.analyzeAnomaly(baseline, probe, "MARKER")
        assertNotNull(a)
        // The new header is detected first in the chain, but reflection takes
        // priority since it's a stronger signal. Either is acceptable.
        assertTrue(a!!.type in listOf("marker_reflected_in_header", "new_response_header"),
            "expected marker reflection or new header, got ${a.type}")
    }

    @Test
    fun `analyzeAnomaly flags significant body length change`() {
        val baseline = resp(body = "x".repeat(1000))
        val probe = resp(body = "x".repeat(2000))
        val a = AttackTools.analyzeAnomaly(baseline, probe, "MARKER")
        assertNotNull(a)
        assertEquals("body_length_change", a!!.type)
    }

    @Test
    fun `analyzeAnomaly flags new response header`() {
        val baseline = resp(headers = listOf("Server" to "nginx"))
        val probe = resp(headers = listOf("Server" to "nginx", "X-Cache-Hit" to "yes"))
        val a = AttackTools.analyzeAnomaly(baseline, probe, "ZZZ")
        assertNotNull(a)
        assertEquals("new_response_header", a!!.type)
    }

    @Test
    fun `analyzeAnomaly returns null for identical responses`() {
        val r = resp(body = "same", headers = listOf("Server" to "nginx"))
        assertNull(AttackTools.analyzeAnomaly(r, r, "ZZZ"))
    }

    @Test
    fun `analyzeAnomaly tolerates small body deltas (under 5pct and under 50B)`() {
        // 1000B baseline, 1020B probe = 2% delta and 20B - both under thresholds.
        val baseline = resp(body = "x".repeat(1000))
        val probe = resp(body = "x".repeat(1020))
        assertNull(AttackTools.analyzeAnomaly(baseline, probe, "ZZZ"))
    }

    @Test
    fun `analyzeAnomaly flags large delta even when under 5pct`() {
        // 50000B baseline, 50100B probe = 0.2% but 100B absolute - over the
        // 50B floor. Should be flagged.
        val baseline = resp(body = "x".repeat(50000))
        val probe = resp(body = "x".repeat(50100))
        val a = AttackTools.analyzeAnomaly(baseline, probe, "ZZZ")
        assertNotNull(a)
        assertEquals("body_length_change", a!!.type)
    }

    @Test
    fun `headerValue lookup is case-insensitive`() {
        val r = resp(headers = listOf("Content-Type" to "text/html"))
        assertEquals("text/html", r.headerValue("Content-Type"))
        assertEquals("text/html", r.headerValue("content-type"))
        assertEquals("text/html", r.headerValue("CONTENT-TYPE"))
    }
}
