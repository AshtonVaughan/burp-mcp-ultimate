package io.burpmcp.ultimate.ui

import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

class RequestLog(private val capacity: Int = 200) {

    data class Entry(val ts: Instant, val tool: String, val argsPreview: String)

    private val total = AtomicLong()
    private val ring = ArrayDeque<Entry>(capacity)
    private val listeners = mutableListOf<() -> Unit>()

    @Synchronized
    fun record(tool: String, args: Map<String, Any?>) {
        total.incrementAndGet()
        val preview = args.entries.joinToString(", ", "{", "}") { (k, v) ->
            "$k=${v.toString().take(40)}"
        }
        ring.addLast(Entry(Instant.now(), tool, preview))
        while (ring.size > capacity) ring.removeFirst()
        listeners.toList().forEach { runCatching { it() } }
    }

    @Synchronized
    fun snapshot(): List<Entry> = ring.toList()

    fun totalCalls(): Long = total.get()

    fun onUpdate(cb: () -> Unit) { synchronized(this) { listeners.add(cb) } }
}
