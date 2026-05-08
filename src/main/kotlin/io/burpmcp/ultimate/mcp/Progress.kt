package io.burpmcp.ultimate.mcp

import java.util.concurrent.atomic.AtomicLong

/**
 * Pushes notifications/progress messages on SSE for long-running tools
 * (scanner crawl/audit, bulk send, intruder runs).
 *
 * Tools call: progress.start(label) -> token; progress.tick(token, n, total?, msg?); progress.end(token).
 */
class Progress(private val sseHub: SseHub) {
    private val seq = AtomicLong()

    fun start(label: String): String {
        val token = "p${seq.incrementAndGet()}"
        sseHub.notify("notifications/progress", mapOf(
            "progressToken" to token,
            "label"         to label,
            "progress"      to 0,
            "total"         to null,
        ))
        return token
    }

    fun tick(token: String, progress: Number, total: Number? = null, message: String? = null) {
        sseHub.notify("notifications/progress", mapOf(
            "progressToken" to token,
            "progress"      to progress,
            "total"         to total,
            "message"       to message,
        ))
    }

    fun end(token: String, finalMessage: String? = null) {
        sseHub.notify("notifications/progress", mapOf(
            "progressToken" to token,
            "done"          to true,
            "message"       to finalMessage,
        ))
    }
}
