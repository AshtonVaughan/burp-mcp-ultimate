package io.burpmcp.ultimate.mcp

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Tracks active SSE clients and pushes server-initiated MCP notifications
 * to all of them. MCP "Streamable HTTP" treats GET /mcp as a long-poll SSE
 * channel; the server can send notifications/X messages whenever it
 * wants without the client polling.
 */
class SseHub {

    private data class Client(val id: String, val exchange: HttpExchange)
    private val clients = ConcurrentHashMap<String, Client>()
    private val seq = AtomicLong()

    fun register(exch: HttpExchange): String {
        val id = "c${seq.incrementAndGet()}"
        clients[id] = Client(id, exch)
        return id
    }

    fun drop(id: String) { clients.remove(id) }

    val activeCount: Int get() = clients.size

    /** Push an MCP-style notification to every connected SSE client. */
    fun notify(method: String, params: Any?) {
        val frame = JsonRpcRequest(method = method, params = if (params is Map<*, *>) {
            @Suppress("UNCHECKED_CAST")
            params as Map<String, Any?>
        } else mapOf("data" to params))
        val payload = Json.write(frame)
        val data = "event: message\ndata: $payload\n\n".toByteArray(StandardCharsets.UTF_8)

        val dead = ArrayList<String>()
        for ((id, c) in clients) {
            try {
                c.exchange.responseBody.write(data)
                c.exchange.responseBody.flush()
            } catch (_: IOException) {
                dead.add(id)
            }
        }
        dead.forEach { clients.remove(it) }
    }
}
