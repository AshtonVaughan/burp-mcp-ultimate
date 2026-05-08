package io.burpmcp.ultimate.mcp

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class EventBusTest {

    @Test
    fun `subscribe poll unsubscribe roundtrip`() {
        val bus = EventBus(capacityPerChannel = 50)
        bus.pushExternal("ch1", mapOf("k" to 1))
        bus.pushExternal("ch1", mapOf("k" to 2))

        val sub = bus.subscribe("ch1")
        val first = bus.poll(sub.id, 100)
        assertEquals(2, first.size)
        assertEquals(1, first[0].data["k"])
        assertEquals(2, first[1].data["k"])

        // Second poll with no new events returns empty.
        assertEquals(0, bus.poll(sub.id, 100).size)

        // New event after subscription cursor.
        bus.pushExternal("ch1", mapOf("k" to 3))
        val second = bus.poll(sub.id, 100)
        assertEquals(1, second.size)
        assertEquals(3, second[0].data["k"])

        assertTrue(bus.unsubscribe(sub.id))
    }

    @Test
    fun `ring buffer evicts oldest beyond capacity`() {
        val bus = EventBus(capacityPerChannel = 5)
        repeat(20) { bus.pushExternal("ch", mapOf("i" to it)) }
        val sub = bus.subscribe("ch")
        val items = bus.poll(sub.id, 100)
        assertEquals(5, items.size, "ring should keep only last 5")
        // Last value pushed was i=19; ring's tail must be 19.
        assertEquals(19, items.last().data["i"])
    }

    @Test
    fun `listChannels reports counts and includes ad-hoc channels`() {
        val bus = EventBus(capacityPerChannel = 100)
        bus.pushExternal("a", mapOf<String, Any?>())
        bus.pushExternal("b", mapOf<String, Any?>())
        bus.pushExternal("a", mapOf<String, Any?>())
        val ch = bus.listChannels()
        assertEquals(2, ch["a"])
        assertEquals(1, ch["b"])
    }

    @Test
    fun `listChannels advertises all known channels with zero when unobserved`() {
        val bus = EventBus()
        val ch = bus.listChannels()
        for (name in EventBus.KNOWN_CHANNELS) {
            assertTrue(ch.containsKey(name), "missing canonical channel: $name")
            assertEquals(0, ch[name], "expected 0 for unobserved channel $name")
        }
    }

    @Test
    fun `listChannels still surfaces ad-hoc and known channels together`() {
        val bus = EventBus()
        bus.pushExternal("http_request", mapOf<String, Any?>())
        bus.pushExternal("custom_channel", mapOf<String, Any?>())
        val ch = bus.listChannels()
        assertEquals(1, ch["http_request"])
        assertEquals(1, ch["custom_channel"])
        assertEquals(0, ch["scan_issue"], "unobserved canonical channel should be 0")
    }

    @Test
    fun `unknown subscription throws`() {
        val bus = EventBus()
        assertThrows(McpException::class.java) { bus.poll("nope", 10) }
    }
}
