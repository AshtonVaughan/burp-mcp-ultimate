package io.burpmcp.ultimate.mcp

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Reflect's pickMethod scoring is exercised against a small Java-style
 * fixture class with overlapping overloads, since instantiating the
 * MontoyaApi here would require a Burp host.
 */
class ReflectTest {

    open class Fixture {
        fun take(s: String) = "string:$s"
        fun take(i: Int)    = "int:$i"
        fun take(b: Boolean) = "bool:$b"
        fun multi(a: Int, b: String) = "$a/$b"
        fun multi(a: String, b: String) = "ss:$a/$b"
        fun nullable(s: String?) = "n:${s ?: "null"}"
    }

    /** Minimal Reflect that doesn't need a real Montoya. */
    private fun reflectFor(target: Any) = Reflect(
        api     = NoopMontoya,
        handles = HandleStore(),
    ).also { /* api isn't used in invoke if we resolve target manually */ }

    @Test
    fun `picks the int overload over string when arg is Int`() {
        val r = reflectFor(Fixture())
        val method = pickPrivate(r, Fixture::class.java, "take", listOf(7))
        assertEquals(java.lang.Integer.TYPE, method.parameterTypes[0])
    }

    @Test
    fun `picks the string overload when arg is String`() {
        val r = reflectFor(Fixture())
        val method = pickPrivate(r, Fixture::class.java, "take", listOf("hi"))
        assertEquals(String::class.java, method.parameterTypes[0])
    }

    @Test
    fun `picks the boolean overload when arg is Boolean`() {
        val r = reflectFor(Fixture())
        val method = pickPrivate(r, Fixture::class.java, "take", listOf(true))
        assertEquals(java.lang.Boolean.TYPE, method.parameterTypes[0])
    }

    @Test
    fun `multi-arg disambiguation prefers exact match`() {
        val r = reflectFor(Fixture())
        val withInt = pickPrivate(r, Fixture::class.java, "multi", listOf(1, "x"))
        assertEquals(java.lang.Integer.TYPE, withInt.parameterTypes[0])
        val withStr = pickPrivate(r, Fixture::class.java, "multi", listOf("a", "x"))
        assertEquals(String::class.java, withStr.parameterTypes[0])
    }

    @Test
    fun `null arg is acceptable for reference param`() {
        val r = reflectFor(Fixture())
        val method = pickPrivate(r, Fixture::class.java, "nullable", listOf<Any?>(null))
        assertEquals(String::class.java, method.parameterTypes[0])
    }

    /** Reach into the private pickMethod via reflection-on-reflection. */
    private fun pickPrivate(r: Reflect, cls: Class<*>, name: String, args: List<Any?>) =
        Reflect::class.java.getDeclaredMethod("pickMethod",
            Class::class.java, String::class.java, List::class.java, java.lang.Boolean.TYPE)
            .apply { isAccessible = true }
            .invoke(r, cls, name, args, false) as java.lang.reflect.Method
}

/** Minimal MontoyaApi placeholder for tests - never invoked. */
private object NoopMontoya : burp.api.montoya.MontoyaApi {
    override fun burpSuite()      = throw UnsupportedOperationException()
    override fun collaborator()   = throw UnsupportedOperationException()
    override fun comparer()       = throw UnsupportedOperationException()
    override fun decoder()        = throw UnsupportedOperationException()
    override fun extension()      = throw UnsupportedOperationException()
    override fun http()           = throw UnsupportedOperationException()
    override fun intruder()       = throw UnsupportedOperationException()
    override fun logging()        = throw UnsupportedOperationException()
    override fun organizer()      = throw UnsupportedOperationException()
    override fun persistence()    = throw UnsupportedOperationException()
    override fun project()        = throw UnsupportedOperationException()
    override fun proxy()          = throw UnsupportedOperationException()
    override fun repeater()       = throw UnsupportedOperationException()
    override fun scanner()        = throw UnsupportedOperationException()
    override fun scope()          = throw UnsupportedOperationException()
    override fun siteMap()        = throw UnsupportedOperationException()
    override fun userInterface()  = throw UnsupportedOperationException()
    override fun utilities()      = throw UnsupportedOperationException()
    override fun websockets()     = throw UnsupportedOperationException()
}
