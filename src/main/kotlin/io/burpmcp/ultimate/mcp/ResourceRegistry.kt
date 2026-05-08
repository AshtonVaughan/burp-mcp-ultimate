package io.burpmcp.ultimate.mcp

import java.util.concurrent.ConcurrentHashMap

class ResourceRegistry(private val sseHub: SseHub? = null) {

    data class Resource(
        val uri: String,
        val name: String,
        val description: String,
        val mimeType: String,
        val read: () -> String,
    )

    private val resources = LinkedHashMap<String, Resource>()
    /** sessionId -> set of subscribed URIs. */
    private val subs = ConcurrentHashMap<String, MutableSet<String>>()

    fun register(
        uri: String,
        name: String,
        description: String,
        mimeType: String = "application/json",
        read: () -> String,
    ) {
        resources[uri] = Resource(uri, name, description, mimeType, read)
    }

    fun list(): List<Map<String, Any?>> = resources.values.map {
        mapOf(
            "uri"         to it.uri,
            "name"        to it.name,
            "description" to it.description,
            "mimeType"    to it.mimeType,
        )
    }

    fun read(uri: String): Map<String, Any?> {
        val r = resources[uri]
            ?: throw McpException(ErrorCodes.NOT_FOUND, "unknown resource: $uri")
        return mapOf(
            "contents" to listOf(
                mapOf("uri" to r.uri, "mimeType" to r.mimeType, "text" to r.read())
            ),
        )
    }

    fun subscribe(sessionId: String, uri: String) {
        if (uri !in resources) throw McpException(ErrorCodes.NOT_FOUND, "unknown resource: $uri")
        subs.computeIfAbsent(sessionId) { ConcurrentHashMap.newKeySet() }.add(uri)
    }

    fun unsubscribe(sessionId: String, uri: String) {
        subs[sessionId]?.remove(uri)
    }

    /** Push a "resource updated" notification to any session subscribed to this URI. */
    fun notifyUpdated(uri: String) {
        if (sseHub == null) return
        val anySub = subs.values.any { uri in it }
        if (!anySub) return
        sseHub.notify("notifications/resources/updated", mapOf("uri" to uri))
    }

    val size: Int get() = resources.size
    fun subscriberCount(): Int = subs.values.sumOf { it.size }
}
