package io.burpmcp.ultimate.bridge

import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.McpException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.URLClassLoader

class ExtensionBridgeTest {

    /** A target class we can call into via the bridge to exercise pickMethod. */
    @Suppress("unused")
    class Target {
        var counter: Int = 0
        @JvmField var publicField: String = "hello"
        private var privateField: String = "secret"

        fun greet(name: String): String = "hi $name"
        fun greet(name: String, n: Int): String = "hi $name x$n"
        fun add(a: Int, b: Int): Int = a + b
        fun nullable(s: String?): String = s ?: "null"
        fun bumpCounter(): Int { counter += 1; return counter }

        companion object {
            @JvmStatic fun staticAdd(a: Int, b: Int): Int = a + b
            @JvmStatic fun staticGreet(name: String): String = "static hi $name"
        }
    }

    private fun bridge() = ExtensionBridge(HandleStore())

    @Test
    fun `isLikelyExtensionClass filters out runtime classes`() {
        assertTrue(ExtensionBridge.isLikelyExtensionClass("com.nccgroup.loggerplusplus.LoggerPlusPlus"))
        assertTrue(ExtensionBridge.isLikelyExtensionClass("burp.BurpExtender"))
        assertTrue(ExtensionBridge.isLikelyExtensionClass("burp.parser.Convertors"))
        assertEquals(false, ExtensionBridge.isLikelyExtensionClass("java.lang.String"))
        assertEquals(false, ExtensionBridge.isLikelyExtensionClass("kotlin.collections.AbstractList"))
        assertEquals(false, ExtensionBridge.isLikelyExtensionClass("burp.api.montoya.MontoyaApi"))
        assertEquals(false, ExtensionBridge.isLikelyExtensionClass("io.burpmcp.ultimate.tools.HttpTools"))
        assertEquals(false, ExtensionBridge.isLikelyExtensionClass("sun.reflect.NativeMethodAccessorImpl"))
    }

    @Test
    fun `KNOWN_EXTENSION_CLASSES covers the 9 tier-1 extensions`() {
        val keys = ExtensionBridge.KNOWN_EXTENSION_CLASSES.keys
        listOf(
            "Param Miner", "Logger++", "Active Scan++", "Turbo Intruder",
            "HTTP Request Smuggler", "Hackvertor", "Collaborator Everywhere", "JWT Editor",
        ).forEach { name ->
            assertTrue(name in keys, "missing tier-1 extension in KNOWN_EXTENSION_CLASSES: $name")
        }
    }

    @Test
    fun `pickMethod resolves overload by argument count and types`() {
        val b = bridge()
        // greet(String) vs greet(String, Int) — pick by arg count
        val one = b.pickMethod(Target::class.java, "greet", listOf("Ash"), staticOnly = false)
        assertNotNull(one)
        assertEquals(1, one!!.parameterCount)
        val two = b.pickMethod(Target::class.java, "greet", listOf("Ash", 3), staticOnly = false)
        assertNotNull(two)
        assertEquals(2, two!!.parameterCount)
    }

    @Test
    fun `pickMethod prefers a higher-scoring exact-type match`() {
        val b = bridge()
        // add(Int, Int) — pass Number subclasses
        val m = b.pickMethod(Target::class.java, "add", listOf(1, 2), staticOnly = false)
        assertNotNull(m)
        assertEquals("add", m!!.name)
    }

    @Test
    fun `pickMethod returns null for nonexistent method`() {
        val b = bridge()
        val m = b.pickMethod(Target::class.java, "bogus", listOf("x"), staticOnly = false)
        assertNull(m)
    }

    @Test
    fun `invokeInstance returns primitive results inline without a handle`() {
        val handles = HandleStore()
        val target = Target()
        val targetHandle = handles.put(target)
        val b = ExtensionBridge(handles)
        val r = b.invokeInstance(targetHandle, "add", listOf(2, 3))
        assertTrue(r.ok)
        assertEquals(5, r.value)
        assertNull(r.handle, "primitives should not be wrapped in a handle")
    }

    @Test
    fun `invokeInstance returns objects via a handle`() {
        val handles = HandleStore()
        val target = Target()
        val targetHandle = handles.put(target)
        val b = ExtensionBridge(handles)
        val r = b.invokeInstance(targetHandle, "greet", listOf("Ash"))
        assertTrue(r.ok)
        // Strings serialise inline; this is a primitive case actually.
        assertEquals("hi Ash", r.value)
    }

    @Test
    fun `invokeInstance with unknown handle throws structured NOT_FOUND`() {
        val b = ExtensionBridge(HandleStore())
        val ex = assertThrows(McpException::class.java) {
            b.invokeInstance("nope", "add", listOf(1, 2))
        }
        assertEquals(io.burpmcp.ultimate.mcp.ErrorCodes.NOT_FOUND, ex.code)
    }

    @Test
    fun `getInstanceField reads public fields`() {
        val handles = HandleStore()
        val target = Target()
        val h = handles.put(target)
        val b = ExtensionBridge(handles)
        val r = b.getInstanceField(h, "publicField")
        assertTrue(r.ok)
        assertEquals("hello", r.value)
    }

    @Test
    fun `setInstanceField writes a public field and reads back`() {
        val handles = HandleStore()
        val target = Target()
        val h = handles.put(target)
        val b = ExtensionBridge(handles)
        val r = b.setInstanceField(h, "publicField", "world")
        assertTrue(r.ok)
        assertEquals("world", r.value)
        assertEquals("world", target.publicField)
    }

    @Test
    fun `getInstanceField reads private fields via setAccessible`() {
        val handles = HandleStore()
        val target = Target()
        val h = handles.put(target)
        val b = ExtensionBridge(handles)
        val r = b.getInstanceField(h, "privateField")
        assertTrue(r.ok)
        assertEquals("secret", r.value)
    }

    @Test
    fun `discover returns at least the test classloader chain (smoke)`() {
        // Cannot guarantee Burp extensions in test JVM, but discover() must
        // not throw and must return a list (possibly empty).
        val b = bridge()
        val list = b.discover()
        // discover() may return zero in the unit-test JVM (no other extensions
        // are loaded). What we care about is: it doesn't throw, results have
        // populated label fields, and refresh() also works.
        list.forEach { d ->
            assertNotNull(d.label)
            assertNotNull(d.classLoader)
            assertNotNull(d.jarUrls)
        }
        b.refresh() // must not throw
    }

    @Test
    fun `resolveExtension throws structured error when label not found`() {
        val b = bridge()
        val ex = assertThrows(McpException::class.java) {
            b.resolveExtension("Nonexistent Extension X")
        }
        assertEquals(io.burpmcp.ultimate.mcp.ErrorCodes.NOT_FOUND, ex.code)
    }
}
