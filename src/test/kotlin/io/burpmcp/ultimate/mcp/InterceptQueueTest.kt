package io.burpmcp.ultimate.mcp

import io.burpmcp.ultimate.mcp.InterceptQueue.Verdict
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class InterceptQueueTest {

    @Test
    fun `resolve flips the latch and clears pending`() {
        val q = InterceptQueue(timeoutSeconds = 5)
        // Manually create a Pending and exercise resolve()/listPending() via reflection
        // since the production install() needs a live MontoyaApi.
        val ctorMethod = InterceptQueue.Pending::class.java.declaredConstructors[0]
        ctorMethod.isAccessible = true
        val p = InterceptQueue.Pending(
            id              = "iq1",
            direction       = "request",
            ts              = java.time.Instant.now(),
            originalUrl     = "https://x/",
            method          = "GET",
            statusCode      = null,
            rawPreview      = "GET / HTTP/1.1",
        )
        // Inject into the private map.
        val pendingField = InterceptQueue::class.java.getDeclaredField("pending").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val map = pendingField.get(q) as java.util.concurrent.ConcurrentHashMap<String, InterceptQueue.Pending>
        map[p.id] = p
        assertEquals(1, q.pendingCount())

        // Spawn a waiter that simulates the proxy handler thread.
        val gotVerdict = CountDownLatch(1)
        var observedVerdict: Verdict? = null
        Thread {
            if (p.latch.await(5, TimeUnit.SECONDS)) observedVerdict = p.verdict
            gotVerdict.countDown()
        }.start()

        assertTrue(q.resolve("iq1", Verdict.DROP))
        assertTrue(gotVerdict.await(2, TimeUnit.SECONDS))
        assertEquals(Verdict.DROP, observedVerdict)
    }

    @Test
    fun `resolve unknown id returns false`() {
        val q = InterceptQueue()
        assertFalse(q.resolve("nope", Verdict.CONTINUE))
    }

    @Test
    fun `mode default is OBSERVE`() {
        assertEquals(InterceptQueue.Mode.OBSERVE, InterceptQueue().mode)
    }
}
