package io.burpmcp.ultimate.mcp

import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Stores opaque object handles so the agent can chain operations across
 * tool calls without us serialising the full object every time.
 *
 * - put(obj) -> short id
 * - get(id) -> object or null
 * - drop(id), dropAll(), keys()
 *
 * Entries auto-evict after `ttlSeconds` since last access. The agent is
 * expected to keep a working set of <100 handles; the cap is a safety net.
 */
class HandleStore(
    private val ttlSeconds: Long = 3600,
    private val cap: Int = 5000,
) {
    private data class Entry(val ref: Any, var lastTouched: Instant)

    private val data = ConcurrentHashMap<String, Entry>()
    private val seq = AtomicLong()

    fun put(obj: Any): String {
        val id = "h${seq.incrementAndGet()}"
        data[id] = Entry(obj, Instant.now())
        evictIfNeeded()
        return id
    }

    fun get(id: String): Any? {
        val e = data[id] ?: return null
        e.lastTouched = Instant.now()
        return e.ref
    }

    fun drop(id: String): Boolean = data.remove(id) != null
    fun dropAll() = data.clear()
    fun keys(): List<String> = data.keys.sorted()
    val size: Int get() = data.size

    fun describe(id: String): Map<String, Any?>? {
        val e = data[id] ?: return null
        return mapOf(
            "id"           to id,
            "class"        to e.ref.javaClass.name,
            "last_touched" to e.lastTouched.toString(),
        )
    }

    private fun evictIfNeeded() {
        if (data.size <= cap) {
            // Time-based eviction only.
            val cutoff = Instant.now().minusSeconds(ttlSeconds)
            data.entries.removeIf { it.value.lastTouched.isBefore(cutoff) }
            return
        }
        // Cap exceeded: drop the oldest until back under cap.
        val sorted = data.entries.sortedBy { it.value.lastTouched }
        val toRemove = sorted.size - cap + 1
        sorted.take(toRemove).forEach { data.remove(it.key) }
    }
}
