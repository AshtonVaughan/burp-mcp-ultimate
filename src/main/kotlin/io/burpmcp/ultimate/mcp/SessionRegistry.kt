package io.burpmcp.ultimate.mcp

import io.burpmcp.ultimate.ui.RequestLog
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Per-client session: separates tool logs across multiple agents talking
 * to the same Burp, and powers per-session rate limiting.
 *
 * Session id is sourced from header `Mcp-Session-Id`; if absent we mint
 * one and echo it back. Clients that do not honour it just share the
 * synthetic "anonymous" session.
 */
class SessionRegistry(private val rateLimitCallsPer10s: Int) {

    data class Session(
        val id: String,
        val createdAt: Instant,
        val log: RequestLog = RequestLog(capacity = 200),
        @Volatile var lastSeen: Instant = Instant.now(),
        // ring-buffer of call timestamps (for rate limiter)
        val recentCalls: ArrayDeque<Long> = ArrayDeque(),
    )

    private val sessions = ConcurrentHashMap<String, Session>()
    private val seq = AtomicLong()
    private val anonymousId = "anon"

    init {
        sessions[anonymousId] = Session(anonymousId, Instant.now())
    }

    fun getOrCreate(id: String?): Session {
        val key = id?.takeIf { it.isNotBlank() } ?: return sessions[anonymousId]!!
        return sessions.computeIfAbsent(key) { Session(it, Instant.now()) }
            .also { it.lastSeen = Instant.now() }
    }

    fun mintNewId(): String = "s${seq.incrementAndGet()}"

    fun recordCall(session: Session, tool: String, args: Map<String, Any?>) {
        session.log.record(tool, args)
        if (rateLimitCallsPer10s > 0) {
            val now = System.currentTimeMillis()
            val cutoff = now - 10_000
            synchronized(session.recentCalls) {
                while (session.recentCalls.isNotEmpty() && session.recentCalls.first() < cutoff)
                    session.recentCalls.removeFirst()
                session.recentCalls.addLast(now)
                if (session.recentCalls.size > rateLimitCallsPer10s) {
                    throw McpException(ErrorCodes.RATE_LIMITED,
                        "rate limit exceeded for session ${session.id}: ${rateLimitCallsPer10s} calls/10s")
                }
            }
        }
    }

    fun list(): List<Map<String, Any?>> = sessions.values.map {
        mapOf(
            "id"         to it.id,
            "created_at" to it.createdAt.toString(),
            "last_seen"  to it.lastSeen.toString(),
            "calls"      to it.log.totalCalls(),
        )
    }

    val size: Int get() = sessions.size
}
