package io.burpmcp.ultimate.mcp

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class HandleStoreTest {

    @Test
    fun `put returns sequential ids and stores objects`() {
        val s = HandleStore()
        val a = s.put("hello")
        val b = s.put(42)
        assertEquals("hello", s.get(a))
        assertEquals(42, s.get(b))
        assertNotEquals(a, b)
    }

    @Test
    fun `drop removes the entry`() {
        val s = HandleStore()
        val id = s.put(Any())
        assertTrue(s.drop(id))
        assertNull(s.get(id))
        assertFalse(s.drop(id))
    }

    @Test
    fun `dropAll empties the store`() {
        val s = HandleStore()
        repeat(5) { s.put("x$it") }
        assertEquals(5, s.size)
        s.dropAll()
        assertEquals(0, s.size)
    }

    @Test
    fun `cap eviction drops oldest`() {
        val s = HandleStore(cap = 3)
        val ids = (1..5).map { s.put("v$it") }
        assertTrue(s.size <= 3, "size should be <= cap, got ${s.size}")
        // The earliest two entries should have been evicted
        assertNull(s.get(ids[0]))
        assertNull(s.get(ids[1]))
        assertEquals("v3", s.get(ids[2]))
        assertEquals("v5", s.get(ids[4]))
    }

    @Test
    fun `describe returns class name and id`() {
        val s = HandleStore()
        val id = s.put("x")
        val d = s.describe(id)!!
        assertEquals(id, d["id"])
        assertEquals("java.lang.String", d["class"])
    }

    @Test
    fun `keys are sorted`() {
        val s = HandleStore()
        repeat(3) { s.put(it) }
        val keys = s.keys()
        assertEquals(keys.sorted(), keys)
    }
}
